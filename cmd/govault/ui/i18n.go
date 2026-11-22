package ui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/export"
	"github.com/txchen/govault/internal/vaultcore/i18n"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func init() {
	core.SetLanguageMatch(i18n.NormalizeLocale)
}

func (m *AppModel) T(key string) string {
	return m.catalog.Get().T(key)
}

func (m *AppModel) Tf(key string, args ...any) string {
	return m.catalog.Get().Tf(key, args...)
}

func (m *AppModel) IsRTL() bool {
	return m.catalog.Get().RTL()
}

func (m *AppModel) SetLanguage(code string) {
	lang := ""
	if strings.TrimSpace(code) != "" {
		lang = i18n.NormalizeLocale(code)
	}
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.Language = lang
		return p
	})
}

func (m *AppModel) applyScopeLocale(tag string) {
	m.forcedLocale = tag
	m.Scope.SetLocale(tag)
	if m.windowScope != nil && m.windowScope != m.Scope {
		m.windowScope.SetLocale(tag)
	}
}

func languageSelect(cx *core.Scope, m *AppModel, testID string, width core.Points) core.Node {
	supported := i18n.SupportedLocales()
	opts := make([]ui.Option[string], 0, len(supported)+1)
	opts = append(opts, ui.Option[string]{Value: "", Label: m.T("settings.language.auto")})
	for _, loc := range supported {
		opts = append(opts, ui.Option[string]{Value: loc.Code, Label: loc.NativeName})
	}
	return ui.Select[string]{
		TestID:  testID,
		Label:   m.T("settings.language.label"),
		Style:   core.Style{Width: core.Pt(width)},
		Options: opts,
		Value: func() string {
			pref := m.Prefs.Get().Language
			if pref == "" {
				return ""
			}
			return i18n.NormalizeLocale(pref)
		},
		OnChange: m.SetLanguage,
	}
}

func rtlIcon(cx *core.Scope, ltr, rtl func() *core.SVG) func() *core.SVG {
	return func() *core.SVG {
		if cx.Env().RTL() {
			return rtl()
		}
		return ltr()
	}
}

func rtlSVG(cx *core.Scope, ltr, rtl *core.SVG) *core.SVG {
	if cx.Env().RTL() {
		return rtl
	}
	return ltr
}

func (m *AppModel) CipherTypeLabel(t api.CipherType) string {
	switch t {
	case api.CipherTypeLogin:
		return m.T("cipher.type.login")
	case api.CipherTypeSecureNote:
		return m.T("cipher.type.secure_note")
	case api.CipherTypeCard:
		return m.T("cipher.type.card")
	case api.CipherTypeIdentity:
		return m.T("cipher.type.identity")
	case api.CipherTypeSSHKey:
		return m.T("cipher.type.ssh_key")
	default:
		return m.T("cipher.type.item")
	}
}

func (m *AppModel) twoFactorProviderLabel(p api.TwoFactorProvider) string {
	switch p {
	case api.TwoFactorAuthenticator:
		return m.T("twofactor.provider.authenticator")
	case api.TwoFactorEmail:
		return m.T("twofactor.provider.email")
	case api.TwoFactorDuo:
		return m.T("twofactor.provider.duo")
	case api.TwoFactorYubiKey:
		return m.T("twofactor.provider.yubikey")
	case api.TwoFactorU2F:
		return m.T("twofactor.provider.u2f")
	case api.TwoFactorRemember:
		return m.T("twofactor.provider.remember")
	case api.TwoFactorOrganizationDuo:
		return m.T("twofactor.provider.organization_duo")
	case api.TwoFactorWebAuthn:
		return m.T("twofactor.provider.webauthn")
	default:
		return m.Tf("twofactor.provider.unknown", int(p))
	}
}

func (m *AppModel) friendlyError(err error) string {
	switch {
	case errors.Is(err, api.ErrTwoFactorRequired):
		return m.T("error.twofactor_required")
	case errors.Is(err, api.ErrUnauthorized):
		return m.T("error.invalid_credentials")
	case errors.Is(err, api.ErrNetworkOffline):
		return m.T("error.server_unreachable")
	case errors.Is(err, crypto.ErrInvalidMAC):
		return m.T("error.incorrect_master_password")
	case errors.Is(err, state.ErrArchiveUnsupported):
		return m.T("error.archive_unsupported")
	case errors.Is(err, state.ErrPremiumRequired):
		return m.T("error.premium_required")
	case errors.Is(err, state.ErrArchiveNotConfirmed):
		return m.T("error.archive_not_confirmed")
	case errors.Is(err, state.ErrCipherInTrash):
		return m.T("error.cipher_in_trash")
	default:
		return err.Error()
	}
}

func (m *AppModel) backupErrorText(err error) string {
	switch {
	case errors.Is(err, export.ErrNotBitwardenExport):
		return m.T("backup.error.not_bitwarden")
	case errors.Is(err, export.ErrAccountRestricted):
		return m.T("backup.error.account_restricted")
	}
	return m.friendlyError(err)
}

func (m *AppModel) healthDetailText(detail string) string {
	var n int
	if _, err := fmt.Sscanf(detail, "Used in %d items", &n); err == nil {
		return m.Tf("health.detail.reused", n)
	}
	if _, err := fmt.Sscanf(detail, "Shorter than %d characters", &n); err == nil {
		return m.Tf("health.detail.too_short", n)
	}
	if rest, ok := strings.CutPrefix(detail, "Expired "); ok {
		return m.Tf("health.detail.card_expired", rest)
	}
	if rest, ok := strings.CutPrefix(detail, "Expires "); ok {
		return m.Tf("health.detail.card_expiring", rest)
	}
	switch detail {
	case "Common password":
		return m.T("health.detail.common")
	case "Mostly a sequence or repeated characters":
		return m.T("health.detail.pattern")
	case "Uses only one type of character":
		return m.T("health.detail.single_class")
	case "Easy to guess":
		return m.T("health.detail.easy")
	default:
		return detail
	}
}

func (m *AppModel) translateImportDiff(diff []string) []string {
	if len(diff) == 0 {
		return nil
	}
	out := make([]string, len(diff))
	for i, d := range diff {
		switch d {
		case "Name":
			out[i] = m.T("field.name")
		case "Notes":
			out[i] = m.T("section.notes")
		case "Folder":
			out[i] = m.T("nav.folder_fallback")
		case "Favorite":
			out[i] = m.T("import.diff.favorite")
		case "Reprompt":
			out[i] = m.T("import.diff.reprompt")
		case "Username":
			out[i] = m.T("field.username")
		case "Password":
			out[i] = m.T("field.password")
		case "Verification Code":
			out[i] = m.T("common.verification_code")
		case "Websites":
			out[i] = m.T("section.websites")
		case "Passkey":
			out[i] = m.T("field.passkey")
		case "Card":
			out[i] = m.T("cipher.type.card")
		case "Identity":
			out[i] = m.T("cipher.type.identity")
		case "SSH Key":
			out[i] = m.T("cipher.type.ssh_key")
		case "Custom Fields":
			out[i] = m.T("section.custom_fields")
		default:
			out[i] = d
		}
	}
	return out
}

func (m *AppModel) translateImportBlocked(s string) string {
	switch s {
	case "the backup item is incomplete":
		return m.T("import.blocked.incomplete")
	case "its fields or websites cannot be matched safely":
		return m.T("import.blocked.unmatchable")
	default:
		return s
	}
}

func (m *AppModel) formatDateTime(t time.Time) string {
	return t.Local().Format(m.T("time.datetime_format"))
}

func (m *AppModel) formatDate(t time.Time) string {
	return t.Local().Format(m.T("time.date_format"))
}

func (m *AppModel) formatRelativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return m.T("time.just_now")
	case d < time.Hour:
		return m.Tf("time.minutes_ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return m.Tf("time.hours_ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return m.Tf("time.days_ago", int(d.Hours()/24))
	}
	return t.Local().Format(m.T("time.short_date_format"))
}
