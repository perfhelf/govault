// Package dedup analyzes decrypted login ciphers locally for exact and
// same-site duplicates and builds safe, recoverable merge/cleanup plans.
// It performs no UI or network calls directly.
package dedup

import (
	"net"
	"net/url"
	"strings"

	"github.com/txchen/govault/internal/vaultcore/state"
)

// multiPartTLDs lists known multi-part public suffixes so eTLD+1 extraction
// groups subdomains like "shop.example.co.uk" under "example.co.uk".
var multiPartTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "net.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true, "go.jp": true,
	"co.kr": true, "or.kr": true, "ne.kr": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"com.tw": true, "org.tw": true, "net.tw": true, "edu.tw": true,
	"com.hk": true, "org.hk": true, "net.hk": true, "edu.hk": true, "gov.hk": true,
	"co.nz": true, "net.nz": true, "org.nz": true,
	"com.br": true, "org.br": true, "net.br": true,
	"com.mx": true, "org.mx": true, "net.mx": true,
	"co.in": true, "net.in": true, "org.in": true,
	"com.sg": true, "org.sg": true, "net.sg": true, "edu.sg": true, "gov.sg": true,
	"co.za": true, "org.za": true, "net.za": true,
	"co.il": true, "org.il": true, "net.il": true,
	"com.tr": true, "org.tr": true, "net.tr": true,
	"co.th": true, "or.th": true, "ac.th": true,
	"com.vn": true, "net.vn": true, "org.vn": true,
	"com.ar": true, "org.ar": true, "net.ar": true,
}

// PrimaryURI returns the first non-empty URI on a login cipher, or "".
func PrimaryURI(c *state.Cipher) string {
	if c == nil || c.Login == nil {
		return ""
	}
	for _, u := range c.Login.URIs {
		if trimmed := strings.TrimSpace(u.URI); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// GetRegisteredDomain extracts the eTLD+1 registered domain from a hostname.
// IP literals and single/two-label hostnames are returned normalized without
// chopping labels.
func GetRegisteredDomain(hostname string) string {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	lastTwo := strings.Join(parts[len(parts)-2:], ".")
	if multiPartTLDs[lastTwo] && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return lastTwo
}

// NormalizeURI converts a Bitwarden login URI into a canonical site key:
// mobile app URIs (androidapp:// / iosapp://) normalize to the lowercased
// package/bundle identifier; web/host URIs normalize to the registered domain
// (eTLD+1) or IP address.
func NormalizeURI(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if scheme, rest, ok := parseMobileAppURI(s); ok {
		_ = scheme
		return rest
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err == nil && u.Hostname() != "" {
			return GetRegisteredDomain(u.Hostname())
		}
		return strings.ToLower(s)
	}
	u, err := url.Parse("https://" + s)
	if err == nil && u.Hostname() != "" {
		return GetRegisteredDomain(u.Hostname())
	}
	return strings.ToLower(s)
}

// SimplifyURL reduces a full URL to scheme://registered-domain (preserving
// non-default ports and mobile app scheme://bundle-id). Unparseable or
// scheme-less entries are returned trimmed.
func SimplifyURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if scheme, bundleID, ok := parseMobileAppURI(s); ok {
		return scheme + "://" + bundleID
	}
	if !strings.Contains(s, "://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return s
	}
	scheme := strings.ToLower(u.Scheme)
	host := GetRegisteredDomain(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port != "" && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		host += ":" + port
	}
	return scheme + "://" + host
}

func parseMobileAppURI(s string) (scheme, bundleID string, ok bool) {
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "androidapp://"):
		scheme = "androidapp"
		bundleID = s[len("androidapp://"):]
	case strings.HasPrefix(lower, "iosapp://"):
		scheme = "iosapp"
		bundleID = s[len("iosapp://"):]
	default:
		return "", "", false
	}
	if idx := strings.IndexAny(bundleID, "/?#"); idx >= 0 {
		bundleID = bundleID[:idx]
	}
	bundleID = strings.ToLower(strings.TrimSpace(bundleID))
	if bundleID == "" {
		return "", "", false
	}
	return scheme, bundleID, true
}
