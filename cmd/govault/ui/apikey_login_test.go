package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestLoginAPIKeyModeSwitchAndSignIn(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	app.Find("id:login-screen")
	app.Find("id:login-auth-mode")
	if app.Exists("id:login-client-id") || app.Exists("id:login-client-secret") {
		t.Fatal("API key fields shown in Password mode")
	}

	app.Press("id:login-mode-apikey")
	app.WaitFor("id:login-client-id", 2*time.Second)
	app.Find("id:login-client-secret")
	app.Find("id:login-apikey-local-note")

	// Switching back hides API key fields.
	app.Press("id:login-mode-password")
	app.WaitForGone("id:login-client-id", 2*time.Second)

	// Switch back to API Key mode and test validation error, then valid sign-in.
	app.Press("id:login-mode-apikey")
	app.WaitFor("id:login-client-id", 2*time.Second)
	app.Press("id:login-submit")
	app.WaitFor("id:login-error", 2*time.Second)

	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-client-id", "user.api-client-id")
	app.Type("id:login-client-secret", "wrong-secret")
	app.Press("id:login-toggle-client-secret")
	app.Type("id:login-password", "wrong-password")
	app.Press("id:login-submit")
	app.WaitFor("id:login-error >> text:Invalid client ID or client secret.", 2*time.Second)

	app.Clear("id:login-client-secret")
	app.Type("id:login-client-secret", "api-client-secret")
	app.Press("id:login-submit")
	app.WaitFor("id:login-error >> text:Incorrect master password.", 2*time.Second)

	app.Clear("id:login-password")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)

	svc.mu.RLock()
	req := svc.lastAPIKeyLogin
	svc.mu.RUnlock()
	if req.ServerURL != "https://vault.example.com" ||
		req.Email != "alice@example.com" ||
		req.ClientID != "user.api-client-id" ||
		req.ClientSecret != "api-client-secret" ||
		string(req.MasterPassword) != "master-password" {
		t.Fatalf("lastAPIKeyLogin = %+v", req)
	}

	if model.LoginClientID.Get() != "" || model.LoginClientSecret.Get() != "" || model.LoginPassword.Get() != "" {
		t.Fatalf("auth inputs survived login: id=%q secret=%q pw=%q",
			model.LoginClientID.Get(), model.LoginClientSecret.Get(), model.LoginPassword.Get())
	}
	if raw, ok := app.Storage().GetItem(DefaultPrefsKey); ok &&
		(strings.Contains(raw, "api-client-secret") || strings.Contains(raw, "user.api-client-id")) {
		t.Fatalf("API credentials leaked into persisted prefs: %s", raw)
	}
}

func TestLoginAPIKeySecretsClearedOnSleepLogoutAndBackToUnlock(t *testing.T) {
	// 1. Sleep while API key sign-in is in flight revokes the attempt and clears credentials.
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.apiKeyLoginStarted = make(chan struct{})
	svc.apiKeyLoginGate = make(chan struct{})
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 720))

	app.Press("id:login-mode-apikey")
	app.WaitFor("id:login-client-id", 2*time.Second)
	app.Post(func() {
		model.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		model.LoginServer.Set("https://vault.example.com")
		model.LoginEmail.Set("alice@example.com")
		model.LoginClientID.Set("user.api-client-id")
		model.LoginClientSecret.Set("api-client-secret")
		model.LoginPassword.Set("master-password")
		model.Login()
	})
	app.WaitUntil(2*time.Second, func() bool {
		select {
		case <-svc.apiKeyLoginStarted:
			return true
		default:
			return false
		}
	})
	app.Post(func() { model.LockOnSystemEvent() })
	app.WaitUntil(2*time.Second, func() bool {
		return !model.LoginBusy.Get() && model.LoginClientID.Get() == "" && model.LoginClientSecret.Get() == "" && model.LoginPassword.Get() == ""
	})
	close(svc.apiKeyLoginGate)
	app.Settle()
	if model.LockState.Get() == state.StatusUnlocked {
		t.Fatal("stale API key login completion opened the vault after sleep")
	}

	// 2. Back to Unlock clears client_id, client_secret, and password.
	svc2 := newMockVaultService(state.StatusUnlocked)
	svc2.localOnly = true
	svc2.trustedServer = "https://vault.example"
	app2, m2, _ := startSecurityApp(t, svc2, PlatformHooks{})
	app2.Post(func() {
		m2.RefreshVaultData()
		m2.SyncState.Set(SyncAuthExpired)
	})
	app2.WaitFor("id:signin-banner-action", 2*time.Second)
	app2.Press("id:signin-banner-action")
	app2.WaitFor("id:login-back-to-unlock", 2*time.Second)
	app2.Press("id:login-mode-apikey")
	app2.WaitFor("id:login-client-id", 2*time.Second)
	app2.Type("id:login-client-id", "user.temp-id")
	app2.Type("id:login-client-secret", "temp-secret")
	app2.Type("id:login-password", "temp-pw")
	app2.Press("id:login-back-to-unlock")
	app2.WaitFor("id:lock-screen", 2*time.Second)
	if m2.LoginClientID.Get() != "" || m2.LoginClientSecret.Get() != "" || m2.LoginPassword.Get() != "" {
		t.Fatalf("BackToUnlock left credentials: id=%q secret=%q pw=%q",
			m2.LoginClientID.Get(), m2.LoginClientSecret.Get(), m2.LoginPassword.Get())
	}

	// 3. Logout clears client_id, client_secret, and password.
	app2.OnAlert = func(core.AlertConfig) int { return 1 }
	app2.Post(func() {
		m2.LoginClientID.Set("user.logout-id")
		m2.LoginClientSecret.Set("logout-secret")
		m2.LoginPassword.Set("logout-pw")
	})
	app2.Press("id:lock-logout")
	app2.WaitFor("id:login-screen", 2*time.Second)
	if m2.LoginClientID.Get() != "" || m2.LoginClientSecret.Get() != "" || m2.LoginPassword.Get() != "" {
		t.Fatalf("Logout left credentials: id=%q secret=%q pw=%q",
			m2.LoginClientID.Get(), m2.LoginClientSecret.Get(), m2.LoginPassword.Get())
	}
}

func TestSignInAgainWithAPIKeyUsesTrustedServerAndFitsMinWindow(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.localOnly = true
	svc.trustedServer = "https://vault.example"

	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(MainWindowMinWidth, MainWindowMinHeight))

	app.Post(func() { model.SyncState.Set(SyncAuthExpired) })
	app.WaitFor("id:signin-banner-action", 2*time.Second)
	app.Press("id:signin-banner-action")
	app.WaitFor("id:login-mode-apikey", 2*time.Second)
	app.Press("id:login-mode-apikey")
	app.WaitFor("id:login-client-id", 2*time.Second)
	app.Type("id:login-client-id", "user.api-client-id")
	app.Type("id:login-client-secret", "api-client-secret")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)

	svc.mu.RLock()
	req := svc.lastAPIKeyLogin
	svc.mu.RUnlock()
	if req.SameAccount == nil || req.SameAccount.ID != "acct-1" || req.ServerURL != "https://vault.example" || req.Email != "alice@example.com" {
		t.Fatalf("Sign In Again with API key sent %+v", req)
	}
}
