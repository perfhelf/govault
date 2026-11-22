package ui

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/i18n"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/urlcheck"
)

func selectOption(t *testing.T, app *nsgotest.App, selectID string, index int) {
	t.Helper()
	app.Press("id:" + selectID)
	optSelector := fmt.Sprintf("id:%s-%d", selectID, index)
	app.WaitFor(optSelector, 2*time.Second)
	app.Press(optSelector)
}

func readScopeRTL(app *nsgotest.App, m *AppModel) (scopeRTL, windowRTL bool) {
	app.Post(func() {
		scopeRTL = m.Scope.Env().RTL()
		if m.windowScope != nil {
			windowRTL = m.windowScope.Env().RTL()
		}
	})
	app.Settle()
	return scopeRTL, windowRTL
}

func viewWindowX(v *nsgotest.View) float32 {
	var x float32
	for cur := v; cur != nil; cur = cur.Parent {
		x += float32(cur.Frame.Origin.X)
	}
	return x
}

func TestI18nLiveSwitchingAllSixLanguages(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{PrefsKey: "govault.i18n-all"})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 760))

	app.WaitFor("id:sidebar-all >> text:All Items", 2*time.Second)
	if got := model.Locale.Get(); got != "en" {
		t.Fatalf("initial Locale = %q, want en", got)
	}
	if sRTL, wRTL := readScopeRTL(app, model); sRTL || wRTL {
		t.Fatalf("initial RTL = (%v, %v), want false", sRTL, wRTL)
	}

	app.Press("id:sidebar-settings")
	app.WaitFor("id:settings-view", 2*time.Second)
	app.Find("id:settings-language")

	cases := []struct {
		index      int
		code       string
		nativeName string
		rtl        bool
		allItems   string
		settings   string
	}{
		{2, "zh-CN", "简体中文", false, "全部条目", "设置"},
		{3, "fr", "Français", false, "Tous les éléments", "Paramètres"},
		{4, "de", "Deutsch", false, "Alle Einträge", "Einstellungen"},
		{5, "es", "Español", false, "Todos los elementos", "Ajustes"},
		{6, "ar", "العربية", true, "جميع العناصر", "الإعدادات"},
		{1, "en", "English", false, "All Items", "Settings"},
	}

	for _, tc := range cases {
		selectOption(t, app, "settings-language", tc.index)
		app.WaitFor("id:sidebar-all >> text:"+tc.allItems, 2*time.Second)
		app.Find("id:sidebar-settings >> text:" + tc.settings)
		app.Find("id:settings-language >> text:" + tc.nativeName)

		if got := model.Locale.Get(); got != tc.code {
			t.Fatalf("after selecting %s: Locale = %q", tc.code, got)
		}
		if got := model.Prefs.Get().Language; got != tc.code {
			t.Fatalf("after selecting %s: Prefs.Language = %q", tc.code, got)
		}
		sRTL, wRTL := readScopeRTL(app, model)
		if sRTL != tc.rtl || wRTL != tc.rtl {
			t.Fatalf("locale %s: RTL = (scope=%v, win=%v), want %v", tc.code, sRTL, wRTL, tc.rtl)
		}
	}
}

func TestI18nRTLLayoutMirroringAndScreens(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-weak"] = &state.Cipher{
		ID:    "c-weak",
		Type:  api.CipherTypeLogin,
		Name:  "Weak One",
		Login: &state.Login{Username: "u@example.com", Password: "123", URIs: []state.LoginURI{{URI: "http://plain.example.com"}}},
	}
	svc.order = append(svc.order, "c-weak")

	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{PrefsKey: "govault.i18n-rtl"})
		model.UpdatePrefs(func(p UserPrefs) UserPrefs {
			p.Email = "alice@example.com"
			p.ServerURL = "https://vault.example.com"
			return p
		})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 760))

	app.WaitFor("id:vault-shell", 2*time.Second)
	ltrSidebarX := app.Find("id:vault-sidebar").Frame.Origin.X
	ltrResizeX := app.Find("id:sidebar-resize").Frame.Origin.X
	if ltrSidebarX != 0 || ltrResizeX <= ltrSidebarX {
		t.Fatalf("LTR layout unexpected: sidebarX=%v resizeX=%v", ltrSidebarX, ltrResizeX)
	}

	// Switch to Arabic RTL and confirm the shell columns mirror right-to-left.
	app.Post(func() { model.SetLanguage("ar") })
	app.WaitFor("id:sidebar-all >> text:جميع العناصر", 2*time.Second)
	if sRTL, wRTL := readScopeRTL(app, model); !sRTL || !wRTL {
		t.Fatalf("Arabic RTL = (%v, %v), want true", sRTL, wRTL)
	}

	rtlSidebarX := app.Find("id:vault-sidebar").Frame.Origin.X
	rtlResizeX := app.Find("id:sidebar-resize").Frame.Origin.X
	if rtlSidebarX <= rtlResizeX || rtlSidebarX < 700 {
		t.Fatalf("RTL sidebar did not mirror to right side: sidebarX=%v resizeX=%v", rtlSidebarX, rtlResizeX)
	}

	// Health view renders Arabic labels and chevron cleanly under RTL.
	app.Press("id:sidebar-health")
	app.WaitFor("id:health-view >> text:مكررة", 2*time.Second)
	app.Find("id:health-view >> text:أقصر من 10 أحرف")

	// Lock screen renders Arabic title, RTL lock badge, and non-overlapping password field inset.
	app.Post(model.Lock)
	app.WaitFor("id:lock-screen >> text:تم قفل GoVault", 2*time.Second)
	assertPasswordClearsToggleRTL(t, app, "lock-password", "lock-toggle-pw")

	// Switching back to English restores LTR layout cleanly.
	app.Post(func() { model.SetLanguage("en") })
	app.WaitFor("id:lock-screen >> text:GoVault is Locked", 2*time.Second)
	if sRTL, wRTL := readScopeRTL(app, model); sRTL || wRTL {
		t.Fatalf("English RTL = (%v, %v), want false", sRTL, wRTL)
	}
	assertPasswordClearsToggleLTR(t, app, "lock-password", "lock-toggle-pw")
	app.Type("id:lock-password", "master-password")
	app.Press("id:lock-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)
	if gotX := app.Find("id:vault-sidebar").Frame.Origin.X; gotX != 0 {
		t.Fatalf("after switching back to en: sidebarX=%v, want 0", gotX)
	}
}

func assertPasswordClearsToggleRTL(t *testing.T, app *nsgotest.App, inputID, toggleID string) {
	t.Helper()
	pw := app.Find("id:" + inputID)
	btn := app.Find("id:" + toggleID)
	if pw.Input.Padding.Left < 34 || pw.Input.Padding.Right != 10 {
		t.Fatalf("RTL %s padding = %+v, want Left>=34 Right==10", inputID, pw.Input.Padding)
	}
	contentLeft := viewWindowX(pw) + float32(pw.Input.Content.Origin.X)
	btnRight := viewWindowX(btn) + float32(btn.Frame.Size.Width)
	if contentLeft < btnRight {
		t.Fatalf("RTL %s contentLeft (%v) overlaps %s right (%v)", inputID, contentLeft, toggleID, btnRight)
	}
}

func assertPasswordClearsToggleLTR(t *testing.T, app *nsgotest.App, inputID, toggleID string) {
	t.Helper()
	pw := app.Find("id:" + inputID)
	btn := app.Find("id:" + toggleID)
	if pw.Input.Padding.Right < 34 || pw.Input.Padding.Left != 10 {
		t.Fatalf("LTR %s padding = %+v, want Left==10 Right>=34", inputID, pw.Input.Padding)
	}
	contentRight := viewWindowX(pw) + float32(pw.Input.Content.Origin.X+pw.Input.Content.Size.Width)
	btnLeft := viewWindowX(btn)
	if contentRight > btnLeft {
		t.Fatalf("LTR %s contentRight (%v) overlaps %s left (%v)", inputID, contentRight, toggleID, btnLeft)
	}
}

func TestI18nLoginLanguageSelectorAndPersistence(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{PrefsKey: "govault.i18n-login-persist"})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 760))

	app.WaitFor("id:login-screen >> text:Sign in to GoVault", 2*time.Second)
	assertPasswordClearsToggleLTR(t, app, "login-password", "login-toggle-pw")
	ltrLangX := viewWindowX(app.Find("id:login-language"))
	if ltrLangX < 550 {
		t.Fatalf("LTR login-language expected on right edge, got X=%v", ltrLangX)
	}

	selectOption(t, app, "login-language", 6)
	app.WaitFor("id:login-screen >> text:تسجيل الدخول إلى GoVault", 2*time.Second)
	if sRTL, wRTL := readScopeRTL(app, model); !sRTL || !wRTL {
		t.Fatalf("Arabic on login screen: RTL = (%v, %v), want true", sRTL, wRTL)
	}
	assertPasswordClearsToggleRTL(t, app, "login-password", "login-toggle-pw")
	rtlLangX := viewWindowX(app.Find("id:login-language"))
	if rtlLangX > 550 {
		t.Fatalf("RTL login-language expected on left edge, got X=%v", rtlLangX)
	}

	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")

	app.WaitFor("id:sidebar-all >> text:جميع العناصر", 2*time.Second)
	if got := model.Prefs.Get().Language; got != "ar" {
		t.Fatalf("persisted Language = %q, want ar", got)
	}
}

func TestI18nAutoSystemLocaleAndUnsupportedFallback(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{PrefsKey: "govault.i18n-auto"})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "fr-CA"}), nsgotest.Size(1100, 760))

	app.WaitFor("id:sidebar-all >> text:Tous les éléments", 2*time.Second)
	if got := model.Locale.Get(); got != "fr" {
		t.Fatalf("auto fr-CA Locale = %q, want fr", got)
	}
	if sRTL, _ := readScopeRTL(app, model); sRTL {
		t.Fatal("fr-CA reported RTL=true")
	}

	app.SetEnvironment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "ar-SA"})
	app.WaitFor("id:sidebar-all >> text:جميع العناصر", 2*time.Second)
	if got := model.Locale.Get(); got != "ar" {
		t.Fatalf("auto ar-SA Locale = %q, want ar", got)
	}
	if sRTL, wRTL := readScopeRTL(app, model); !sRTL || !wRTL {
		t.Fatalf("auto ar-SA RTL = (%v, %v), want true", sRTL, wRTL)
	}

	// Unsupported RTL locales must fall back cleanly to English LTR.
	app.SetEnvironment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "he-IL"})
	app.WaitFor("id:sidebar-all >> text:All Items", 2*time.Second)
	if got := model.Locale.Get(); got != "en" {
		t.Fatalf("auto he-IL Locale = %q, want en", got)
	}
	if sRTL, wRTL := readScopeRTL(app, model); sRTL || wRTL {
		t.Fatalf("auto he-IL RTL = (%v, %v), want false", sRTL, wRTL)
	}
}

func TestI18nDetectSystemLocaleNonEnglishNoLoop(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{
			PrefsKey:           "govault.i18n-detect-ar",
			DetectSystemLocale: func() string { return "ar" },
		})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: ""}), nsgotest.Size(1100, 760))

	app.WaitFor("id:sidebar-all >> text:جميع العناصر", 2*time.Second)
	if got := model.Locale.Get(); got != "ar" {
		t.Fatalf("initial detected Locale = %q, want ar", got)
	}
	if sRTL, wRTL := readScopeRTL(app, model); !sRTL || !wRTL {
		t.Fatalf("initial detected RTL = (%v, %v), want true", sRTL, wRTL)
	}

	app.Press("id:sidebar-settings")
	app.WaitFor("id:settings-view", 2*time.Second)

	// Explicit override to English works without fighting DetectSystemLocale.
	selectOption(t, app, "settings-language", 1)
	app.WaitFor("id:sidebar-all >> text:All Items", 2*time.Second)
	if sRTL, wRTL := readScopeRTL(app, model); sRTL || wRTL {
		t.Fatalf("en override RTL = (%v, %v), want false", sRTL, wRTL)
	}

	// Explicit override to Arabic stays clean.
	selectOption(t, app, "settings-language", 6)
	app.WaitFor("id:sidebar-all >> text:جميع العناصر", 2*time.Second)
	if sRTL, wRTL := readScopeRTL(app, model); !sRTL || !wRTL {
		t.Fatalf("ar override RTL = (%v, %v), want true", sRTL, wRTL)
	}

	// Switching from explicit en -> "" (System Default) resolves back to DetectSystemLocale ("ar") without looping.
	selectOption(t, app, "settings-language", 1)
	app.WaitFor("id:sidebar-all >> text:All Items", 2*time.Second)
	selectOption(t, app, "settings-language", 0)
	app.WaitFor("id:sidebar-all >> text:جميع العناصر", 2*time.Second)
	if got := model.Prefs.Get().Language; got != "" {
		t.Fatalf("after Auto: Prefs.Language = %q, want empty", got)
	}
	if got := model.Locale.Get(); got != "ar" {
		t.Fatalf("after Auto: Locale = %q, want ar", got)
	}
	if sRTL, wRTL := readScopeRTL(app, model); !sRTL || !wRTL {
		t.Fatalf("after Auto RTL = (%v, %v), want true", sRTL, wRTL)
	}
}

func TestAllReferencedI18nKeysExist(t *testing.T) {
	cat := i18n.NewCatalog(i18n.DefaultLocale)
	keyCall := regexp.MustCompile(`(?:\bm|tr|cat)\.Tf?\(\s*"([^"]+)"`)

	dirs := []string{".", ".."}
	checked := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", dir, err)
		}
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, ent.Name()))
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", ent.Name(), err)
			}
			for _, m := range keyCall.FindAllStringSubmatch(string(raw), -1) {
				checked++
				key := m[1]
				if got := cat.T(key); got == key {
					t.Errorf("%s references unknown i18n key %q", filepath.Join(dir, ent.Name()), key)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("found zero i18n lookup calls")
	}
}

func TestI18nNewPRSurfacesLocalizedAndRTL(t *testing.T) {
	zh := i18n.NewCatalog("zh-CN")
	ar := i18n.NewCatalog("ar")

	// 1. Logged-out screen: API Key auth mode & Login Profile dropzone localize cleanly and mirror in Arabic.
	loggedOutSvc := newMockVaultService(state.StatusLoggedOut)
	loginApp, loginModel, _ := startSecurityApp(t, loggedOutSvc, PlatformHooks{})

	loginApp.WaitFor("id:login-auth-mode", 2*time.Second)
	loginApp.Post(func() { loginModel.SetLanguage("zh-CN") })
	loginApp.WaitFor("id:login-mode-apikey >> text:"+zh.T("login.mode.apikey"), 2*time.Second)
	loginApp.Find("id:login-profile-dropzone >> text:" + zh.T("profile.dropzone_hint"))
	loginApp.Find("id:login-import-profile >> text:" + zh.T("profile.import.btn"))

	loginApp.Press("id:login-mode-apikey")
	loginApp.WaitFor("id:login-screen >> text:"+zh.T("login.apikey.local_note"), 2*time.Second)

	loginApp.Post(func() { loginModel.SetLanguage("ar") })
	loginApp.WaitFor("id:login-mode-apikey >> text:"+ar.T("login.mode.apikey"), 2*time.Second)
	loginApp.Find("id:login-screen >> text:" + ar.T("login.apikey.local_note"))
	scopeRTL, windowRTL := readScopeRTL(loginApp, loginModel)
	if !scopeRTL || !windowRTL {
		t.Fatalf("login Arabic RTL = (%v, %v), want (true, true)", scopeRTL, windowRTL)
	}

	// 2. Unlocked workspace: Login Profile export dialog, Batch Ops, Health Plus, Dedup, and Website Check.
	svc := newMockVaultService(state.StatusUnlocked)
	svc.folders = []state.Folder{{ID: "f-main", Name: "Main"}}
	svc.order = []string{"c-dup1", "c-dup2", "c-bad-url"}
	svc.ciphers = map[string]*state.Cipher{
		"c-dup1": {
			ID:   "c-dup1",
			Type: api.CipherTypeLogin,
			Name: "Shop Duplicate",
			Login: &state.Login{
				Username: "user@shop.example",
				Password: "weak",
				URIs:     []state.LoginURI{{URI: "https://shop.example"}},
			},
		},
		"c-dup2": {
			ID:   "c-dup2",
			Type: api.CipherTypeLogin,
			Name: "Shop Duplicate",
			Login: &state.Login{
				Username: "user@shop.example",
				Password: "weak",
				URIs:     []state.LoginURI{{URI: "https://shop.example"}},
			},
		},
		"c-bad-url": {
			ID:   "c-bad-url",
			Type: api.CipherTypeLogin,
			Name: "Broken Site",
			Login: &state.Login{
				Username: "bob",
				Password: "VeryStrongUnique!Password#2026",
				URIs:     []state.LoginURI{{URI: "https://[bad"}},
			},
		},
	}

	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.urlCheckOpts = func() urlcheck.Options {
			return urlcheck.Options{
				Concurrency: 2,
				Timeout:     time.Second,
				LookupHost: func(context.Context, string) ([]string, error) {
					return []string{"93.184.216.34"}, nil
				},
				HTTPClient: &http.Client{
					Transport: uiRoundTripFunc(func(r *http.Request) (*http.Response, error) {
						return uiResp(r, http.StatusOK), nil
					}),
				},
			}
		}
	})

	app.Press("id:sidebar-settings")
	app.WaitFor("id:settings-language", 2*time.Second)
	selectOption(t, app, "settings-language", 2) // zh-CN

	// Settings + Login Profile export dialog.
	app.WaitFor("id:settings-export-login-profile >> text:"+zh.T("settings.account.login_profile_btn"), 2*time.Second)
	app.Press("id:settings-export-login-profile")
	app.WaitFor("id:profile-export-dialog >> text:"+zh.T("profile.export.title"), 2*time.Second)
	app.Find("id:profile-export-confirm >> text:" + zh.T("profile.export.confirm_btn"))
	app.Press("id:profile-export-cancel")
	app.WaitUntil(2*time.Second, func() bool { return !m.ProfileExportOpen.Get() })

	// Batch Ops in vault list.
	app.Press("id:sidebar-all")
	app.WaitFor("id:batch-select-toggle", 2*time.Second)
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-action-bar >> text:"+zh.Tf("batch.selected_count", 0), 2*time.Second)
	app.Find("id:batch-move-folder-btn >> text:" + zh.T("batch.move_folder_btn"))
	app.Press("id:batch-select-toggle")

	// Health Plus.
	app.Press("id:sidebar-health")
	app.WaitFor("id:health-score-card >> text:"+zh.T("health.score.title"), 2*time.Second)
	app.Find("id:health-tiles >> text:" + zh.T("health.tile.weak"))
	app.Find("id:health-tiles >> text:" + zh.T("health.tile.unreadable"))

	// Dedup.
	app.Press("id:sidebar-dedup")
	app.WaitFor("id:dedup-count-exact >> text:"+zh.T("dedup.tile.exact"), 2*time.Second)
	app.Find("id:dedup-select-exact >> text:" + zh.T("dedup.select_exact"))
	app.Find("id:dedup-simplify-urls >> text:" + zh.T("dedup.simplify_urls"))
	app.Find("id:dedup-item-c-dup1 >> text:" + zh.T("dedup.badge.keep"))
	app.Find("id:dedup-view >> text:" + zh.T("dedup.footer"))

	// Website Check (idle + scan results + batch bar).
	app.Press("id:sidebar-urlcheck")
	app.WaitFor("id:urlcheck-idle >> text:"+zh.T("urlcheck.privacy_notice"), 2*time.Second)
	app.Press("id:urlcheck-scan-btn")
	app.WaitFor("id:urlcheck-batch-bar", 2*time.Second)
	app.Find("id:urlcheck-select-all >> text:" + zh.T("common.select_all"))
	app.Find("id:urlcheck-batch-move >> text:" + zh.T("batch.move_folder_btn"))
	app.Find("id:urlcheck-badge-c-bad-url >> text:" + zh.T("urlcheck.reason.invalid_url"))

	// Switch to Arabic and verify live localization + RTL across the new views.
	app.Post(func() { m.SetLanguage("ar") })
	app.WaitFor("id:urlcheck-results >> text:"+ar.T("urlcheck.section_title"), 2*time.Second)
	app.Find("id:urlcheck-badge-c-bad-url >> text:" + ar.T("urlcheck.reason.invalid_url"))
	app.Find("id:urlcheck-batch-trash >> text:" + ar.T("common.move_to_trash"))

	scopeRTL, windowRTL = readScopeRTL(app, m)
	if !scopeRTL || !windowRTL {
		t.Fatalf("urlcheck Arabic RTL = (%v, %v), want (true, true)", scopeRTL, windowRTL)
	}

	app.Press("id:sidebar-dedup")
	app.WaitFor("id:dedup-count-exact >> text:"+ar.T("dedup.tile.exact"), 2*time.Second)
	app.Find("id:dedup-item-c-dup1 >> text:" + ar.T("dedup.badge.keep"))
	app.Find("id:dedup-view >> text:" + ar.T("dedup.footer"))

	app.Press("id:sidebar-health")
	app.WaitFor("id:health-score-card >> text:"+ar.T("health.score.title"), 2*time.Second)
}
