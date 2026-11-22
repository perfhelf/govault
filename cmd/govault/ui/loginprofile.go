package ui

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/loginprofile"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func (m *AppModel) showingSignInScreen() bool {
	return (m.LockState.Get() == state.StatusLoggedOut || m.CanReturnToUnlock()) && m.TwoFactor.Get() == nil
}

func (m *AppModel) clearProfileImportState() {
	m.profileImportOp++
	if m.profileImportPending != nil {
		crypto.ZeroBytes(m.profileImportPending)
		m.profileImportPending = nil
	}
	m.ProfileImportOpen.Set(false)
	m.ProfileImportName.Set("")
	m.ProfileImportPW.Set("")
	m.ProfileImportError.Set("")
	m.ProfileImportBusy.Set(false)
}

func (m *AppModel) clearProfileExportState() {
	m.profileExportOp++
	m.ProfileExportOpen.Set(false)
	m.ProfileExportServer.Set("")
	m.ProfileExportEmail.Set("")
	m.ProfileExportMode.Set(AuthModePassword)
	m.ProfileExportClientID.Set("")
	m.ProfileExportClientSecret.Set("")
	m.ProfileExportPW.Set("")
	m.ProfileExportPW2.Set("")
	m.ProfileExportError.Set("")
	m.ProfileExportBusy.Set(false)
}

func (m *AppModel) CloseProfileImportDialog() {
	m.clearProfileImportState()
	m.ReleaseSecureInput()
}

func (m *AppModel) CloseProfileExportDialog() {
	m.clearProfileExportState()
	m.ReleaseSecureInput()
}

func (m *AppModel) DropLoginProfile(uris []string) {
	if !m.showingSignInScreen() || m.LoginBusy.Get() || m.ProfileImportBusy.Get() || len(uris) == 0 {
		return
	}
	if len(uris) > 1 {
		m.LoginError.Set("Drop a single .gvprofile file.")
		return
	}
	f, err := core.FileFromURL(uris[0])
	if err != nil {
		m.LoginError.Set("Could not read dropped profile: " + err.Error())
		return
	}
	m.loadLoginProfileFile(f)
}

func (m *AppModel) PickLoginProfile(cx *core.Scope) {
	if !m.showingSignInScreen() || m.LoginBusy.Get() || m.ProfileImportBusy.Get() {
		return
	}
	gen := m.LockGeneration()
	op := m.profileImportOp
	cx.PickFiles(core.PickFilesOptions{
		Title:     "Import Encrypted Login Profile",
		Button:    "Import",
		Types:     []string{".gvprofile", ".json"},
		TypesName: "GoVault Login Profile",
	}, func(files []core.File, err error) {
		if gen != m.LockGeneration() || op != m.profileImportOp || !m.showingSignInScreen() {
			return
		}
		if err != nil {
			m.LoginError.Set("Could not open profile: " + err.Error())
			return
		}
		if len(files) == 0 {
			return
		}
		m.loadLoginProfileFile(files[0])
	})
}

func (m *AppModel) loadLoginProfileFile(f core.File) {
	if f.Size > loginprofile.MaxFileSize {
		m.LoginError.Set(profileLoadError(loginprofile.ErrProfileTooLarge))
		return
	}
	gen := m.LockGeneration()
	m.profileImportOp++
	op := m.profileImportOp

	go func() {
		data, err := readBoundedProfileFile(f)
		m.Scope.Post(func() {
			if gen != m.LockGeneration() || op != m.profileImportOp || !m.showingSignInScreen() {
				crypto.ZeroBytes(data)
				return
			}
			if err != nil {
				crypto.ZeroBytes(data)
				m.LoginError.Set(profileLoadError(err))
				return
			}
			if err := loginprofile.ValidateContainer(data); err != nil {
				crypto.ZeroBytes(data)
				m.LoginError.Set(profileLoadError(err))
				return
			}
			if m.profileImportPending != nil {
				crypto.ZeroBytes(m.profileImportPending)
			}
			m.profileImportPending = data
			m.LoginError.Set("")
			m.ProfileImportName.Set(f.Name)
			m.ProfileImportPW.Set("")
			m.ProfileImportError.Set("")
			m.ProfileImportBusy.Set(false)
			m.ProfileImportOpen.Set(true)
		})
	}()
}

func readBoundedProfileFile(f core.File) ([]byte, error) {
	if f.Temporary && f.Path != "" {
		defer os.Remove(f.Path)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, loginprofile.MaxFileSize+1))
	if err != nil {
		crypto.ZeroBytes(data)
		return nil, err
	}
	if len(data) > loginprofile.MaxFileSize {
		crypto.ZeroBytes(data)
		return nil, loginprofile.ErrProfileTooLarge
	}
	return data, nil
}

func (m *AppModel) ConfirmProfileImport() {
	if m.ProfileImportBusy.Get() || len(m.profileImportPending) == 0 || !m.showingSignInScreen() {
		return
	}
	pw := m.ProfileImportPW.Get()
	if pw == "" {
		m.ProfileImportError.Set("Enter the profile passphrase.")
		return
	}
	m.ReleaseSecureInput()
	m.ProfileImportBusy.Set(true)
	m.ProfileImportError.Set("")
	gen := m.LockGeneration()
	m.profileImportOp++
	op := m.profileImportOp
	pwBytes := []byte(pw)
	data := bytes.Clone(m.profileImportPending)

	go func() {
		defer crypto.ZeroBytes(pwBytes)
		defer crypto.ZeroBytes(data)
		prof, err := loginprofile.Decrypt(data, pwBytes)
		m.Scope.Post(func() {
			if gen != m.LockGeneration() || op != m.profileImportOp || !m.showingSignInScreen() {
				return
			}
			m.ProfileImportBusy.Set(false)
			if errors.Is(err, loginprofile.ErrWrongPassphrase) {
				m.ProfileImportError.Set("Incorrect profile passphrase.")
				return
			}
			if err != nil {
				m.CloseProfileImportDialog()
				m.LoginError.Set(profileLoadError(err))
				return
			}
			if m.CanReturnToUnlock() {
				acct := m.Core.Account()
				if crypto.NormalizeEmail(prof.Email) != crypto.NormalizeEmail(acct.Email) {
					m.CloseProfileImportDialog()
					m.LoginError.Set("This login profile belongs to a different email than the locked vault.")
					return
				}
				if trusted := m.ReSignInServer.Get(); trusted != "" && !sameServerOrigin(trusted, prof.ServerURL) {
					m.CloseProfileImportDialog()
					m.LoginError.Set("This login profile belongs to a different server than the locked vault.")
					return
				}
			}

			m.CloseProfileImportDialog()
			m.LoginError.Set("")
			m.LoginPassword.Set("")
			m.LoginShowPW.Set(false)
			m.LoginShowClientSecret.Set(false)
			if !m.CanReturnToUnlock() || m.ReSignInServer.Get() == "" {
				m.LoginServer.Set(prof.ServerURL)
			}
			if !m.CanReturnToUnlock() {
				m.LoginEmail.Set(prof.Email)
			}
			if prof.AuthMode == loginprofile.AuthModeAPIKey {
				m.LoginAuthMode.Set(AuthModeAPIKey)
				m.LoginClientID.Set(prof.ClientID)
				m.LoginClientSecret.Set(prof.ClientSecret)
			} else {
				m.LoginAuthMode.Set(AuthModePassword)
				m.LoginClientID.Set("")
				m.LoginClientSecret.Set("")
			}
			m.LoginPasswordRef.Focus()
			m.Scope.Post(func() {
				if m.showingSignInScreen() && !m.ProfileImportOpen.Get() {
					m.LoginPasswordRef.Focus()
				}
			})
		})
	}()
}

func (m *AppModel) StartExportLoginProfile() {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	m.ResetIdleTimer()
	acct := m.Core.Account()
	server := m.Core.TrustedServerURL(acct.ID)
	if server == "" {
		server = strings.TrimSpace(m.Prefs.Get().ServerURL)
	}
	email := acct.Email
	if email == "" {
		email = strings.TrimSpace(m.Prefs.Get().Email)
	}
	m.clearProfileExportState()
	m.ProfileExportServer.Set(server)
	m.ProfileExportEmail.Set(email)
	m.ProfileExportOpen.Set(true)
}

func (m *AppModel) ConfirmProfileExport(cx *core.Scope) {
	if m.ProfileExportBusy.Get() || m.LockState.Get() != state.StatusUnlocked {
		return
	}
	server := strings.TrimSpace(m.ProfileExportServer.Get())
	email := strings.TrimSpace(m.ProfileExportEmail.Get())
	mode := m.ProfileExportMode.Get()
	clientID := strings.TrimSpace(m.ProfileExportClientID.Get())
	clientSecret := strings.TrimSpace(m.ProfileExportClientSecret.Get())
	pw := m.ProfileExportPW.Get()
	pw2 := m.ProfileExportPW2.Get()

	if server == "" || email == "" {
		m.ProfileExportError.Set("Server URL and email are required.")
		return
	}
	prof := loginprofile.Profile{
		ServerURL: server,
		Email:     email,
		AuthMode:  string(mode),
	}
	if mode == AuthModeAPIKey {
		if clientID == "" || clientSecret == "" {
			m.ProfileExportError.Set("Client ID and client secret are required for API Key profiles.")
			return
		}
		prof.ClientID = clientID
		prof.ClientSecret = clientSecret
	}
	if err := prof.Validate(); err != nil {
		m.ProfileExportError.Set(profileLoadError(err))
		return
	}
	if utf8.RuneCountInString(pw) < loginprofile.MinPassphraseRunes {
		m.ProfileExportError.Set(fmt.Sprintf("Use at least %d characters.", loginprofile.MinPassphraseRunes))
		return
	}
	if pw != pw2 {
		m.ProfileExportError.Set("The passphrases do not match.")
		return
	}

	m.ReleaseSecureInput()
	m.ProfileExportBusy.Set(true)
	m.ProfileExportError.Set("")
	gen := m.LockGeneration()
	m.profileExportOp++
	op := m.profileExportOp
	pwBytes := []byte(pw)

	go func() {
		defer crypto.ZeroBytes(pwBytes)
		data, err := loginprofile.Encrypt(prof, pwBytes, loginprofile.DefaultKDF)
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) || op != m.profileExportOp {
				crypto.ZeroBytes(data)
				return
			}
			m.ProfileExportBusy.Set(false)
			if err != nil {
				crypto.ZeroBytes(data)
				m.ProfileExportError.Set(err.Error())
				return
			}
			m.CloseProfileExportDialog()
			name := "govault-login-profile-" + time.Now().Format("20060102") + ".gvprofile"
			m.chooseSavePathWithTitle(cx, name, "Save Encrypted Login Profile", func(target saveTarget, err error) {
				if err != nil || target.dir == "" || !m.StillUnlocked(gen) {
					crypto.ZeroBytes(data)
					if err != nil {
						m.ShowToast(ui.ToastError, "Export failed", err.Error())
					}
					return
				}
				go func() {
					path, published, err := m.savePrivateFile(gen, target, data)
					m.Scope.Post(func() {
						switch {
						case err != nil:
							m.ShowToast(ui.ToastError, "Export failed", err.Error())
						case published:
							m.ShowToast(ui.ToastSuccess, "Login profile exported", filepath.Base(path))
						}
					})
				}()
			})
		})
	}()
}

func profileImportDialog(m *AppModel) core.Node {
	return ui.Dialog{
		TestID: "profile-import-dialog",
		Open:   m.ProfileImportOpen.Get,
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.CloseProfileImportDialog()
			}
		},
		OnConfirm: m.ConfirmProfileImport,
		Title:     "Import Encrypted Login Profile",
		DescriptionFunc: func() string {
			if name := m.ProfileImportName.Get(); name != "" {
				return "Enter the passphrase for " + name + "."
			}
			return "Enter the passphrase used to encrypt this login profile."
		},
		Children: []core.Node{
			ui.Input{
				TestID:        "profile-import-passphrase",
				OnBlur:        settleSecureInput,
				Placeholder:   "Profile passphrase",
				Masked:        true,
				AutoFocus:     true,
				NoAutoCorrect: true,
				Value:         m.ProfileImportPW.Get,
				OnChange:      m.ProfileImportPW.Set,
				OnSubmit:      func(string) { m.ConfirmProfileImport() },
				Disabled:      m.ProfileImportBusy.Get,
			},
			core.Show{
				When: func() bool { return m.ProfileImportError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{TestID: "profile-import-error", Class: "text-[12px] text-gv-danger", ContentFunc: m.ProfileImportError.Get}
				},
			},
		},
		Footer: []core.Node{
			ui.Button{
				TestID:   "profile-import-cancel",
				Text:     "Cancel",
				Variant:  ui.ButtonSecondary,
				Disabled: m.ProfileImportBusy.Get,
				OnPress:  m.CloseProfileImportDialog,
			},
			ui.Button{
				TestID:  "profile-import-confirm",
				Text:    "Unlock Profile",
				Variant: ui.ButtonPrimary,
				Busy:    m.ProfileImportBusy.Get,
				OnPress: m.ConfirmProfileImport,
			},
		},
	}
}

func profileExportDialog(cx *core.Scope, m *AppModel) core.Node {
	apiMode := func() bool { return m.ProfileExportMode.Get() == AuthModeAPIKey }
	busy := m.ProfileExportBusy.Get
	return ui.Dialog{
		TestID: "profile-export-dialog",
		Open:   m.ProfileExportOpen.Get,
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.CloseProfileExportDialog()
			}
		},
		OnConfirm:   func() { m.ConfirmProfileExport(cx) },
		Title:       "Export Encrypted Login Profile",
		Description: "Protect your sign-in metadata with a passphrase (min 8 characters). Your master password is never included.",
		Children: []core.Node{
			ui.Tabs[LoginAuthMode]{
				TestID: "profile-export-mode",
				Equal:  true,
				Label:  "Profile sign-in mode",
				Options: []ui.Option[LoginAuthMode]{
					{Value: AuthModePassword, Label: "Password", TestID: "profile-export-mode-password", Disabled: busy},
					{Value: AuthModeAPIKey, Label: "API Key", TestID: "profile-export-mode-apikey", Disabled: busy},
				},
				Value: m.ProfileExportMode.Get,
				OnChange: func(mode LoginAuthMode) {
					m.ProfileExportMode.Set(mode)
					m.ProfileExportError.Set("")
				},
			},
			formField("Server URL", authInput(base.Input{
				TestID:        "profile-export-server",
				Placeholder:   "https://vault.example.com",
				NoAutoCorrect: true,
				Value:         m.ProfileExportServer.Get,
				OnChange:      m.ProfileExportServer.Set,
				Disabled:      busy,
			})),
			formField("Email", authInput(base.Input{
				TestID:        "profile-export-email",
				Placeholder:   "name@example.com",
				NoAutoCorrect: true,
				Value:         m.ProfileExportEmail.Get,
				OnChange:      m.ProfileExportEmail.Set,
				Disabled:      busy,
			})),
			core.Show{
				When: apiMode,
				Then: func(cx *core.Scope) core.Node {
					return core.View{
						Class: "gap-3",
						Children: []core.Node{
							formField("Client ID", authInput(base.Input{
								TestID:        "profile-export-client-id",
								Placeholder:   "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
								NoAutoCorrect: true,
								Value:         m.ProfileExportClientID.Get,
								OnChange:      m.ProfileExportClientID.Set,
								Disabled:      busy,
							})),
							formField("Client Secret", authInput(base.Input{
								TestID:        "profile-export-client-secret",
								OnBlur:        settleSecureInput,
								Placeholder:   "API client secret",
								Masked:        true,
								NoAutoCorrect: true,
								Value:         m.ProfileExportClientSecret.Get,
								OnChange:      m.ProfileExportClientSecret.Set,
								Disabled:      busy,
							})),
						},
					}
				},
			},
			formField("Profile Passphrase", authInput(base.Input{
				TestID:        "profile-export-passphrase",
				OnBlur:        settleSecureInput,
				Placeholder:   "At least 8 characters",
				Masked:        true,
				AutoFocus:     true,
				NoAutoCorrect: true,
				Value:         m.ProfileExportPW.Get,
				OnChange:      m.ProfileExportPW.Set,
				Disabled:      busy,
			})),
			formField("Confirm Passphrase", authInput(base.Input{
				TestID:        "profile-export-passphrase-confirm",
				OnBlur:        settleSecureInput,
				Placeholder:   "Confirm passphrase",
				Masked:        true,
				NoAutoCorrect: true,
				Value:         m.ProfileExportPW2.Get,
				OnChange:      m.ProfileExportPW2.Set,
				OnSubmit:      func(string) { m.ConfirmProfileExport(cx) },
				Disabled:      busy,
			})),
			core.Show{
				When: func() bool { return m.ProfileExportError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{TestID: "profile-export-error", Class: "text-[12px] text-gv-danger", ContentFunc: m.ProfileExportError.Get}
				},
			},
		},
		Footer: []core.Node{
			ui.Button{
				TestID:   "profile-export-cancel",
				Text:     "Cancel",
				Variant:  ui.ButtonSecondary,
				Disabled: busy,
				OnPress:  m.CloseProfileExportDialog,
			},
			ui.Button{
				TestID:  "profile-export-confirm",
				Text:    "Export Profile",
				Variant: ui.ButtonPrimary,
				Busy:    busy,
				OnPress: func() { m.ConfirmProfileExport(cx) },
			},
		},
	}
}

func profileLoadError(err error) string {
	switch {
	case errors.Is(err, loginprofile.ErrProfileTooLarge):
		return "Login profile file is too large (maximum 64 KiB)."
	case errors.Is(err, loginprofile.ErrWrongPassphrase):
		return "Incorrect profile passphrase."
	case errors.Is(err, loginprofile.ErrPassphraseTooShort):
		return fmt.Sprintf("Use at least %d characters.", loginprofile.MinPassphraseRunes)
	case errors.Is(err, loginprofile.ErrInvalidProfile):
		return "Not a valid GoVault encrypted login profile."
	default:
		return err.Error()
	}
}

func sameServerOrigin(a, b string) bool {
	return normalizeServerOrigin(a) != "" && normalizeServerOrigin(a) == normalizeServerOrigin(b)
}

func normalizeServerOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}
