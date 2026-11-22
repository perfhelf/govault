package ui

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/loginprofile"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestExportAndDropLoginProfilePrefillsAPIKeyAndFocusesPassword(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.trustedServer = "https://vault.example.com"
	dest := filepath.Join(t.TempDir(), "my-account.gvprofile")

	app, m, _ := startSecurityApp(t, svc, PlatformHooks{
		ChooseSavePath: func(_ string, done func(string, bool, error)) { done(dest, true, nil) },
	})
	app.Post(func() { m.Route.Set(RouteSettings) })
	app.WaitFor("id:settings-export-login-profile", 2*time.Second)
	app.Press("id:settings-export-login-profile")
	app.WaitFor("id:profile-export-dialog", 2*time.Second)

	app.Press("id:profile-export-mode-apikey")
	app.WaitFor("id:profile-export-client-id", 2*time.Second)
	app.Type("id:profile-export-client-id", "user.api-client-id")
	app.Type("id:profile-export-client-secret", "api-client-secret")

	// Enforce >= 8 rune passphrase and matching confirmation.
	app.Type("id:profile-export-passphrase", "short")
	app.Type("id:profile-export-passphrase-confirm", "short")
	app.Press("id:profile-export-confirm")
	app.WaitFor("text:Use at least 8 characters.", 2*time.Second)

	app.Clear("id:profile-export-passphrase")
	app.Clear("id:profile-export-passphrase-confirm")
	app.Type("id:profile-export-passphrase", "profile-passphrase-1")
	app.Type("id:profile-export-passphrase-confirm", "mismatch-passphrase")
	app.Press("id:profile-export-confirm")
	app.WaitFor("text:The passphrases do not match.", 2*time.Second)

	app.Clear("id:profile-export-passphrase-confirm")
	app.Type("id:profile-export-passphrase-confirm", "profile-passphrase-1")
	app.Press("id:profile-export-confirm")
	app.WaitUntil(5*time.Second, func() bool { _, err := os.Stat(dest); return err == nil })

	if fi, err := os.Stat(dest); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("exported profile stat = (%v, %v), want 0600", fi.Mode().Perm(), err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "api-client-secret") || strings.Contains(string(raw), "master-password") {
		t.Fatal("exported .gvprofile contains unencrypted secret")
	}
	prof, err := loginprofile.Decrypt(raw, []byte("profile-passphrase-1"))
	if err != nil || prof.AuthMode != loginprofile.AuthModeAPIKey || prof.ClientID != "user.api-client-id" || prof.ClientSecret != "api-client-secret" {
		t.Fatalf("decrypted exported profile = (%+v, %v)", prof, err)
	}

	// Drop the exported .gvprofile onto a fresh Login screen.
	svc2 := newMockVaultService(state.StatusLoggedOut)
	var m2 *AppModel
	app2 := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m2 = NewAppModel(cx, svc2, PlatformHooks{})
		m2.MainWinVisible.Set(true)
		return MainWindowView(cx, m2)
	}, nsgotest.Size(980, 720))

	app2.WaitFor("id:login-profile-dropzone", 2*time.Second)
	fileURI := (&url.URL{Scheme: "file", Path: dest}).String()
	app2.DropFiles("id:login-profile-dropzone", fileURI)
	app2.WaitFor("id:profile-import-dialog", 2*time.Second)

	app2.Type("id:profile-import-passphrase", "wrong-passphrase")
	app2.Press("id:profile-import-confirm")
	app2.WaitFor("text:Incorrect profile passphrase.", 3*time.Second)

	app2.Clear("id:profile-import-passphrase")
	app2.Type("id:profile-import-passphrase", "profile-passphrase-1")
	app2.Press("id:profile-import-confirm")
	app2.WaitUntil(3*time.Second, func() bool { return !m2.ProfileImportOpen.Get() })
	app2.Advance(500 * time.Millisecond)
	app2.WaitForGone("id:profile-import-dialog", 2*time.Second)

	app2.WaitUntil(2*time.Second, func() bool {
		return m2.LoginAuthMode.Get() == AuthModeAPIKey &&
			m2.LoginServer.Get() == "https://vault.example.com" &&
			m2.LoginEmail.Get() == "alice@example.com" &&
			m2.LoginClientID.Get() == "user.api-client-id" &&
			m2.LoginClientSecret.Get() == "api-client-secret" &&
			app2.Find("id:login-password").Focused
	})

	// Type only master password and sign in.
	app2.Type("id:login-password", "master-password")
	app2.Press("id:login-submit")
	app2.WaitFor("id:vault-shell", 2*time.Second)
}

func TestPickLoginProfilePasswordModeAndInvalidDrops(t *testing.T) {
	dir := t.TempDir()
	pwProfilePath := filepath.Join(dir, "pw.gvprofile")
	enc, err := loginprofile.Encrypt(loginprofile.Profile{
		ServerURL: "https://vault.example.eu",
		Email:     "bob@example.com",
		AuthMode:  loginprofile.AuthModePassword,
	}, []byte("passphrase-1"), crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pwProfilePath, enc, 0o600); err != nil {
		t.Fatal(err)
	}

	badPath := filepath.Join(dir, "not-a-profile.json")
	if err := os.WriteFile(badPath, []byte(`{"not":"a profile"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	svc := newMockVaultService(state.StatusLoggedOut)
	var m *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(980, 720))

	// Dropping a non-profile file rejects cleanly without prompting for passphrase.
	app.DropFiles("id:login-profile-dropzone", (&url.URL{Scheme: "file", Path: badPath}).String())
	app.WaitFor("id:login-error >> text:Not a valid GoVault encrypted login profile.", 2*time.Second)
	if app.Exists("id:profile-import-dialog") {
		t.Fatal("passphrase dialog opened for invalid profile file")
	}

	// Pre-populate API key state, then import a Password profile via PickFiles.
	app.Press("id:login-mode-apikey")
	app.WaitFor("id:login-client-id", 2*time.Second)
	app.Post(func() {
		m.LoginClientID.Set("stale-id")
		m.LoginClientSecret.Set("stale-secret")
		m.LoginPassword.Set("stale-pw")
	})

	app.PickFiles = func(core.FilesRequest) []core.File {
		return []core.File{{Name: "pw.gvprofile", Path: pwProfilePath}}
	}
	app.Press("id:login-import-profile")
	app.WaitFor("id:profile-import-dialog", 2*time.Second)
	app.Type("id:profile-import-passphrase", "passphrase-1")
	app.Press("id:profile-import-confirm")
	app.WaitUntil(3*time.Second, func() bool { return !m.ProfileImportOpen.Get() })
	app.Advance(500 * time.Millisecond)
	app.WaitForGone("id:profile-import-dialog", 2*time.Second)

	app.WaitUntil(2*time.Second, func() bool {
		return m.LoginAuthMode.Get() == AuthModePassword &&
			m.LoginServer.Get() == "https://vault.example.eu" &&
			m.LoginEmail.Get() == "bob@example.com" &&
			m.LoginClientID.Get() == "" &&
			m.LoginClientSecret.Get() == "" &&
			m.LoginPassword.Get() == "" &&
			app.Find("id:login-password").Focused
	})
}

func TestLoginProfileStaleCallbacksAndSleepBackToUnlockCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api.gvprofile")
	enc, err := loginprofile.Encrypt(loginprofile.Profile{
		ServerURL:    "https://vault.example",
		Email:        "alice@example.com",
		AuthMode:     loginprofile.AuthModeAPIKey,
		ClientID:     "user.id",
		ClientSecret: "secret-val",
	}, []byte("passphrase-1"), crypto.KDFConfig{Type: crypto.KDFArgon2id, Iterations: 2, MemoryMB: 16, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, enc, 0o600); err != nil {
		t.Fatal(err)
	}

	svc := newMockVaultService(state.StatusUnlocked)
	svc.localOnly = true
	svc.trustedServer = "https://vault.example"
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		m.RefreshVaultData()
		m.SyncState.Set(SyncAuthExpired)
	})
	app.WaitFor("id:signin-banner-action", 2*time.Second)
	app.Press("id:signin-banner-action")
	app.WaitFor("id:login-profile-dropzone", 2*time.Second)

	// Start decrypting, then trigger BackToUnlock before it completes: stale callback must not apply.
	app.DropFiles("id:login-profile-dropzone", (&url.URL{Scheme: "file", Path: path}).String())
	app.WaitFor("id:profile-import-dialog", 2*time.Second)
	app.Type("id:profile-import-passphrase", "passphrase-1")
	app.Post(func() {
		m.ConfirmProfileImport()
		m.BackToUnlock()
	})
	app.WaitFor("id:lock-screen", 2*time.Second)
	app.Settle()
	time.Sleep(150 * time.Millisecond)
	app.Settle()
	if m.LoginClientID.Get() != "" || m.LoginClientSecret.Get() != "" || len(m.profileImportPending) != 0 || m.ProfileImportOpen.Get() {
		t.Fatalf("stale profile import leaked after BackToUnlock: id=%q secret=%q open=%v pending=%d",
			m.LoginClientID.Get(), m.LoginClientSecret.Get(), m.ProfileImportOpen.Get(), len(m.profileImportPending))
	}

	// Open again, trigger sleep while passphrase dialog is open: pending buffer and passphrase must clear.
	app.Post(m.SignInAgain)
	app.WaitFor("id:login-profile-dropzone", 2*time.Second)
	app.DropFiles("id:login-profile-dropzone", (&url.URL{Scheme: "file", Path: path}).String())
	app.WaitFor("id:profile-import-dialog", 2*time.Second)
	app.Type("id:profile-import-passphrase", "passphrase-1")
	app.Post(func() { m.LockOnSystemEvent() })
	app.WaitUntil(2*time.Second, func() bool {
		return !m.ProfileImportOpen.Get() && m.ProfileImportPW.Get() == "" && len(m.profileImportPending) == 0
	})
	app.Advance(500 * time.Millisecond)
	app.WaitForGone("id:profile-import-dialog", 2*time.Second)
}
