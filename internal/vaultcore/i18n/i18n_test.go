package i18n

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var printfVerbRE = regexp.MustCompile(`%(?:%|(?:\[\d+\])?(?:[+\-# 0]*(?:\*|\d+|\[\d+\]\*)?(?:\.(?:\*|\d+|\[\d+\]\*))?)?[vTtbcdoqxXUeEfFgGspq])`)

func extractPrintfVerbs(s string) []string {
	matches := printfVerbRE.FindAllString(s, -1)
	var verbs []string
	for _, m := range matches {
		if m == "%%" {
			continue
		}
		verbs = append(verbs, m)
	}
	return verbs
}

func TestAllLocalesParseAndMatchEnglishKeysAndFormatVerbs(t *testing.T) {
	locales := SupportedLocales()
	if len(locales) != 6 {
		t.Fatalf("SupportedLocales() len = %d, want 6", len(locales))
	}

	parsed := make(map[string]map[string]string, len(locales))
	for _, loc := range locales {
		raw, err := localeFS.ReadFile("locales/" + loc.Code + ".json")
		if err != nil {
			t.Fatalf("read locales/%s.json: %v", loc.Code, err)
		}
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal locales/%s.json: %v", loc.Code, err)
		}
		if len(m) == 0 {
			t.Fatalf("locales/%s.json is empty", loc.Code)
		}
		for k, v := range m {
			if strings.TrimSpace(k) == "" {
				t.Fatalf("locales/%s.json contains blank key", loc.Code)
			}
			if strings.TrimSpace(v) == "" {
				t.Fatalf("locales/%s.json key %q has empty value", loc.Code, k)
			}
		}
		parsed[loc.Code] = m
	}

	en := parsed[DefaultLocale]
	if en == nil {
		t.Fatalf("missing canonical %q catalog", DefaultLocale)
	}

	for _, loc := range locales {
		m := parsed[loc.Code]
		for k, enVal := range en {
			otherVal, ok := m[k]
			if !ok {
				t.Errorf("locale %s missing key %q", loc.Code, k)
				continue
			}
			enVerbs := extractPrintfVerbs(enVal)
			otherVerbs := extractPrintfVerbs(otherVal)
			if !slices.Equal(enVerbs, otherVerbs) {
				t.Errorf("locale %s key %q printf verbs = %v (%q), want %v (%q)",
					loc.Code, k, otherVerbs, otherVal, enVerbs, enVal)
			}
		}
		for k := range m {
			if _, ok := en[k]; !ok {
				t.Errorf("locale %s has extra orphan key %q not in %s.json", loc.Code, k, DefaultLocale)
			}
		}
	}
}

func TestSupportedLocalesMetadataAndRTL(t *testing.T) {
	locales := SupportedLocales()
	wantCodes := []string{"en", "zh-CN", "fr", "de", "es", "ar"}
	var gotCodes []string
	for _, l := range locales {
		gotCodes = append(gotCodes, l.Code)
		if l.NativeName == "" || l.EnglishName == "" {
			t.Errorf("locale %q missing NativeName/EnglishName: %+v", l.Code, l)
		}
		if l.Code == "ar" && !l.RTL {
			t.Errorf("expected ar to have RTL: true")
		}
		if l.Code != "ar" && l.RTL {
			t.Errorf("expected %s to have RTL: false", l.Code)
		}
	}
	if !slices.Equal(gotCodes, wantCodes) {
		t.Fatalf("SupportedLocales codes = %v, want %v", gotCodes, wantCodes)
	}

	// Mutating returned slice must not affect subsequent calls.
	locales[0].Code = "mutated"
	if SupportedLocales()[0].Code != "en" {
		t.Fatal("SupportedLocales() did not return a defensive copy")
	}
}

func TestNormalizeLocale(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "en"},
		{"C", "en"},
		{"C.UTF-8", "en"},
		{"POSIX", "en"},
		{"en", "en"},
		{"en-US", "en"},
		{"en_GB.UTF-8", "en"},
		{"zh", "zh-CN"},
		{"zh-CN", "zh-CN"},
		{"zh_CN.UTF-8", "zh-CN"},
		{"zh-Hans", "zh-CN"},
		{"zh-Hans-CN", "zh-CN"},
		{"zh-SG", "zh-CN"},
		{"fr", "fr"},
		{"fr_FR.UTF-8", "fr"},
		{"fr-CA", "fr"},
		{"de", "de"},
		{"de_DE.UTF-8@euro", "de"},
		{"de-CH", "de"},
		{"es", "es"},
		{"es-419", "es"},
		{"es_MX", "es"},
		{"ar", "ar"},
		{"ar-SA", "ar"},
		{"ar_EG.UTF-8", "ar"},
		{"ar-XB", "ar"},
		{"ja-JP", "en"},
		{"he-IL", "en"},
	}
	for _, tc := range cases {
		if got := NormalizeLocale(tc.in); got != tc.want {
			t.Errorf("NormalizeLocale(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDetectSystemLocaleEnvPrecedence(t *testing.T) {
	t.Setenv("LC_ALL", "fr_FR.UTF-8")
	t.Setenv("LC_MESSAGES", "de_DE.UTF-8")
	t.Setenv("LANG", "es_ES.UTF-8")
	if got := DetectSystemLocale(); got != "fr" {
		t.Fatalf("LC_ALL precedence: got %q, want fr", got)
	}

	t.Setenv("LC_ALL", "")
	if got := DetectSystemLocale(); got != "de" {
		t.Fatalf("LC_MESSAGES precedence: got %q, want de", got)
	}

	t.Setenv("LC_MESSAGES", "C.UTF-8")
	if got := DetectSystemLocale(); got != "es" {
		t.Fatalf("LANG fallback after POSIX LC_MESSAGES: got %q, want es", got)
	}

	t.Setenv("LANG", "ar_SA.UTF-8")
	if got := DetectSystemLocale(); got != "ar" {
		t.Fatalf("Arabic LANG: got %q, want ar", got)
	}

	t.Setenv("LANG", "zh_CN.UTF-8")
	if got := DetectSystemLocale(); got != "zh-CN" {
		t.Fatalf("zh_CN LANG: got %q, want zh-CN", got)
	}

	// When all env vars are cleared/POSIX, DetectSystemLocale falls back cleanly to a supported locale.
	t.Setenv("LC_ALL", "POSIX")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "C")
	got := DetectSystemLocale()
	if _, ok := LookupLocale(got); !ok {
		t.Fatalf("DetectSystemLocale() fallback = %q, not a supported locale", got)
	}
}

func TestParseAppleLanguages(t *testing.T) {
	raw := "(\n    \"ar-SA\",\n    \"en-US\"\n)\n"
	if got := parseAppleLanguages(raw); got != "ar-SA" {
		t.Fatalf("parseAppleLanguages = %q, want ar-SA", got)
	}
	if got := parseAppleLanguages(""); got != "" {
		t.Fatalf("parseAppleLanguages empty = %q, want empty", got)
	}
}

func TestCatalogTranslationAndFallback(t *testing.T) {
	ar := NewCatalog("ar-EG")
	if ar.Code() != "ar" || !ar.RTL() {
		t.Fatalf("ar catalog metadata = %+v", ar.Locale())
	}
	if got := ar.T("nav.trash"); got != "سلة المهملات" {
		t.Fatalf("ar nav.trash = %q", got)
	}
	if got := ar.Tf("toolbar.item_count_many", 5); got != "5 عناصر" {
		t.Fatalf("ar Tf = %q", got)
	}

	// Simulate partial catalog missing a key -> falls back to en, then to key itself.
	partial := &Catalog{
		locale:   Locale{Code: "fr"},
		messages: map[string]string{"common.save": "Enregistrer"},
		fallback: NewCatalog("en").messages,
	}
	if got := partial.T("common.save"); got != "Enregistrer" {
		t.Fatalf("partial hit = %q", got)
	}
	if got := partial.T("common.cancel"); got != "Cancel" {
		t.Fatalf("partial fallback to en = %q, want Cancel", got)
	}
	if got := partial.T("unknown.missing.key"); got != "unknown.missing.key" {
		t.Fatalf("unknown key = %q, want key name", got)
	}
}
