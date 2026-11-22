// Package i18n provides embedded localized string catalogs and locale helpers
// for GoVault with zero UI or CGO dependencies.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// DefaultLocale is the canonical fallback language code.
const DefaultLocale = "en"

// Locale describes a supported GoVault display language.
type Locale struct {
	Code        string
	NativeName  string
	EnglishName string
	RTL         bool
}

var supportedLocales = []Locale{
	{Code: "en", NativeName: "English", EnglishName: "English", RTL: false},
	{Code: "zh-CN", NativeName: "简体中文", EnglishName: "Simplified Chinese", RTL: false},
	{Code: "fr", NativeName: "Français", EnglishName: "French", RTL: false},
	{Code: "de", NativeName: "Deutsch", EnglishName: "German", RTL: false},
	{Code: "es", NativeName: "Español", EnglishName: "Spanish", RTL: false},
	{Code: "ar", NativeName: "العربية", EnglishName: "Arabic", RTL: true},
}

//go:embed locales/*.json
var localeFS embed.FS

var (
	catalogsOnce sync.Once
	catalogData  map[string]map[string]string
	catalogErr   error
)

func loadAllCatalogs() (map[string]map[string]string, error) {
	catalogsOnce.Do(func() {
		loaded := make(map[string]map[string]string, len(supportedLocales))
		for _, loc := range supportedLocales {
			raw, err := localeFS.ReadFile("locales/" + loc.Code + ".json")
			if err != nil {
				catalogErr = fmt.Errorf("i18n: read locale %s: %w", loc.Code, err)
				return
			}
			var msgs map[string]string
			if err := json.Unmarshal(raw, &msgs); err != nil {
				catalogErr = fmt.Errorf("i18n: parse locale %s: %w", loc.Code, err)
				return
			}
			loaded[loc.Code] = msgs
		}
		catalogData = loaded
	})
	return catalogData, catalogErr
}

// SupportedLocales returns a copy of the supported locales in display order.
func SupportedLocales() []Locale {
	return slices.Clone(supportedLocales)
}

// LookupLocale returns the metadata for an exact canonical locale code.
func LookupLocale(code string) (Locale, bool) {
	for _, loc := range supportedLocales {
		if loc.Code == code {
			return loc, true
		}
	}
	return Locale{}, false
}

// NormalizeLocale maps any BCP 47 tag or POSIX locale string to one of the
// supported canonical locale codes, defaulting to DefaultLocale ("en").
func NormalizeLocale(tag string) string {
	clean := stripLocaleSuffixes(tag)
	if clean == "" {
		return DefaultLocale
	}
	lower := strings.ToLower(strings.ReplaceAll(clean, "_", "-"))
	if lower == "c" || lower == "posix" {
		return DefaultLocale
	}
	primary, _, _ := strings.Cut(lower, "-")
	switch primary {
	case "en", "eng":
		return "en"
	case "zh", "zho", "chi":
		return "zh-CN"
	case "fr", "fra", "fre":
		return "fr"
	case "de", "deu", "ger":
		return "de"
	case "es", "spa":
		return "es"
	case "ar", "ara":
		return "ar"
	default:
		return DefaultLocale
	}
}

func stripLocaleSuffixes(tag string) string {
	s := strings.TrimSpace(tag)
	if i := strings.IndexAny(s, ".@"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// Catalog holds localized messages for one normalized locale with English fallback.
type Catalog struct {
	locale   Locale
	messages map[string]string
	fallback map[string]string
}

// NewCatalog returns a Catalog for code, falling back to English ("en") for
// unsupported locales or missing keys.
func NewCatalog(code string) *Catalog {
	norm := NormalizeLocale(code)
	loc, ok := LookupLocale(norm)
	if !ok {
		loc, _ = LookupLocale(DefaultLocale)
	}
	all, err := loadAllCatalogs()
	if err != nil {
		return &Catalog{locale: loc}
	}
	return &Catalog{
		locale:   loc,
		messages: all[loc.Code],
		fallback: all[DefaultLocale],
	}
}

// Locale returns the metadata of the catalog's active locale.
func (c *Catalog) Locale() Locale {
	if c == nil {
		loc, _ := LookupLocale(DefaultLocale)
		return loc
	}
	return c.locale
}

// Code returns the canonical locale code of the catalog.
func (c *Catalog) Code() string {
	return c.Locale().Code
}

// RTL reports whether the catalog's locale uses right-to-left layout.
func (c *Catalog) RTL() bool {
	return c.Locale().RTL
}

// T looks up key in the active locale, falling back to English ("en") and
// finally returning key itself if no translation exists.
func (c *Catalog) T(key string) string {
	if c == nil {
		all, err := loadAllCatalogs()
		if err == nil {
			if v := all[DefaultLocale][key]; v != "" {
				return v
			}
		}
		return key
	}
	if v := c.messages[key]; v != "" {
		return v
	}
	if v := c.fallback[key]; v != "" {
		return v
	}
	return key
}

// Tf looks up key and formats it with args using fmt.Sprintf.
func (c *Catalog) Tf(key string, args ...any) string {
	tmpl := c.T(key)
	if len(args) == 0 {
		return tmpl
	}
	return fmt.Sprintf(tmpl, args...)
}
