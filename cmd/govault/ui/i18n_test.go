package ui

import (
	"fmt"
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

	// Lock screen renders Arabic title and RTL lock badge.
	app.Post(model.Lock)
	app.WaitFor("id:lock-screen >> text:تم قفل GoVault", 2*time.Second)

	// Switching back to English restores LTR layout cleanly.
	app.Post(func() { model.SetLanguage("en") })
	app.WaitFor("id:lock-screen >> text:GoVault is Locked", 2*time.Second)
	if sRTL, wRTL := readScopeRTL(app, model); sRTL || wRTL {
		t.Fatalf("English RTL = (%v, %v), want false", sRTL, wRTL)
	}
	app.Type("id:lock-password", "master-password")
	app.Press("id:lock-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)
	if gotX := app.Find("id:vault-sidebar").Frame.Origin.X; gotX != 0 {
		t.Fatalf("after switching back to en: sidebarX=%v, want 0", gotX)
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
	ltrLangX := viewWindowX(app.Find("id:login-language"))
	if ltrLangX < 550 {
		t.Fatalf("LTR login-language expected on right edge, got X=%v", ltrLangX)
	}

	selectOption(t, app, "login-language", 6)
	app.WaitFor("id:login-screen >> text:تسجيل الدخول إلى GoVault", 2*time.Second)
	if sRTL, wRTL := readScopeRTL(app, model); !sRTL || !wRTL {
		t.Fatalf("Arabic on login screen: RTL = (%v, %v), want true", sRTL, wRTL)
	}
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
