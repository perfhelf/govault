package i18n

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DetectSystemLocale inspects POSIX locale environment variables (LC_ALL,
// LC_MESSAGES, LANG) and falls back to the OS locale when unset or set to C/POSIX.
func DetectSystemLocale() string {
	for _, envVar := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.TrimSpace(os.Getenv(envVar))
		if v == "" || isPOSIXLocale(v) {
			continue
		}
		return NormalizeLocale(v)
	}
	return detectOSLocale()
}

func isPOSIXLocale(tag string) bool {
	clean := strings.ToLower(stripLocaleSuffixes(tag))
	return clean == "" || clean == "c" || clean == "posix"
}

func detectOSLocale() string {
	switch runtime.GOOS {
	case "darwin":
		if lang := detectDarwinLocale(); lang != "" {
			return NormalizeLocale(lang)
		}
	case "windows":
		if lang := detectWindowsLocale(); lang != "" {
			return NormalizeLocale(lang)
		}
	}
	return DefaultLocale
}

func detectDarwinLocale() string {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, "defaults", "read", "-g", "AppleLanguages").Output()
	if err != nil {
		return ""
	}
	return parseAppleLanguages(string(out))
}

func parseAppleLanguages(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		s = strings.TrimSuffix(s, ",")
		s = strings.TrimSpace(s)
		if s == "" || s == "(" || s == ")" {
			continue
		}
		s = strings.Trim(s, `"`)
		if s != "" {
			return s
		}
	}
	return ""
}
