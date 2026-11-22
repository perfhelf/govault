// Package health analyzes the decrypted vault locally for password, card,
// website, and metadata hygiene issues. It performs no network calls.
package health

import (
	"cmp"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

const (
	MinPasswordLength = 10
	ExpiringWindow    = 60 * 24 * time.Hour
	StaleWindow       = 365 * 24 * time.Hour
)

// Issue points at one flagged item. It never carries secret values.
type Issue struct {
	CipherID string
	Type     api.CipherType
	Name     string
	Subtitle string
	Detail   string
}

type ReusedGroup struct {
	Count int
	Items []Issue
}

type CardIssue struct {
	Issue
	Expired bool
}

type Report struct {
	Reused      []ReusedGroup
	Weak        []Issue
	Empty       []Issue
	Stale       []Issue
	Cards       []CardIssue
	Unsecured   []Issue
	MissingURI  []Issue
	MissingName []Issue
	Unreadable  []Issue
	ActiveItems int
	Score       int
}

func (r Report) ReusedItems() int {
	n := 0
	for _, g := range r.Reused {
		n += len(g.Items)
	}
	return n
}

func (r Report) HighRisk() int {
	n := len(r.Weak) + len(r.Empty) + len(r.Unreadable)
	for _, c := range r.Cards {
		if c.Expired {
			n++
		}
	}
	return n
}

func (r Report) MediumRisk() int {
	n := r.ReusedItems() + len(r.Stale) + len(r.Unsecured)
	for _, c := range r.Cards {
		if !c.Expired {
			n++
		}
	}
	return n
}

func (r Report) LowRisk() int {
	return len(r.MissingURI) + len(r.MissingName)
}

func (r Report) TotalIssues() int {
	return r.ReusedItems() + len(r.Weak) + len(r.Empty) + len(r.Stale) +
		len(r.Cards) + len(r.Unsecured) + len(r.MissingURI) + len(r.MissingName) + len(r.Unreadable)
}

// Analyze inspects active items. Items in Trash (DeletedDate != nil) are
// skipped, while archived items (ArchivedDate != nil) remain included. Logins
// whose password is hidden by an organization are left out of password checks.
func Analyze(ciphers []*state.Cipher, now time.Time) Report {
	return AnalyzeReport(ciphers, nil, now)
}

// AnalyzeReport inspects active items and records unreadable personal cipher
// IDs reported by the vault service. Items in Trash (DeletedDate != nil) are
// skipped, while archived items (ArchivedDate != nil) remain included. Logins
// whose password is hidden by an organization are left out of password checks.
func AnalyzeReport(ciphers []*state.Cipher, unreadableIDs []string, now time.Time) Report {
	var r Report
	byPassword := map[string][]*state.Cipher{}
	for _, c := range ciphers {
		if c == nil || c.DeletedDate != nil {
			continue
		}
		r.ActiveItems++
		if strings.TrimSpace(c.Name) == "" {
			r.MissingName = append(r.MissingName, missingNameIssue(c))
		}
		switch {
		case c.Login != nil && c.Type == api.CipherTypeLogin:
			if uri, ok := insecureURI(c.Login.URIs); ok {
				r.Unsecured = append(r.Unsecured, issue(c, uri))
			}
			if !hasNonEmptyURI(c.Login.URIs) {
				r.MissingURI = append(r.MissingURI, issue(c, "No website URI"))
			}
			if c.HidePassword {
				continue
			}
			if strings.TrimSpace(c.Login.Password) == "" {
				if len(c.Login.Fido2Credentials) == 0 {
					r.Empty = append(r.Empty, issue(c, "No password set"))
				}
				continue
			}
			byPassword[c.Login.Password] = append(byPassword[c.Login.Password], c)
			if reason := WeakReason(c.Login.Password); reason != "" {
				r.Weak = append(r.Weak, issue(c, reason))
			}
			if detail, stale := staleDetail(c, now); stale {
				r.Stale = append(r.Stale, issue(c, detail))
			}
		case c.Card != nil && c.Type == api.CipherTypeCard:
			if ci, ok := cardIssue(c, now); ok {
				r.Cards = append(r.Cards, ci)
			}
		}
	}
	seenUnreadable := map[string]bool{}
	for _, rawID := range unreadableIDs {
		id := strings.TrimSpace(rawID)
		if id == "" || seenUnreadable[id] {
			continue
		}
		seenUnreadable[id] = true
		r.ActiveItems++
		r.Unreadable = append(r.Unreadable, Issue{
			CipherID: id,
			Name:     "Unreadable item",
			Subtitle: "Item ID: " + id,
			Detail:   "Could not decrypt",
		})
	}
	for _, group := range byPassword {
		if len(group) < 2 {
			continue
		}
		g := ReusedGroup{Count: len(group)}
		for _, c := range group {
			g.Items = append(g.Items, issue(c, fmt.Sprintf("Used in %d items", len(group))))
		}
		sortIssues(g.Items)
		r.Reused = append(r.Reused, g)
	}
	slices.SortFunc(r.Reused, func(a, b ReusedGroup) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return compareIssue(a.Items[0], b.Items[0])
	})
	sortIssues(r.Weak)
	sortIssues(r.Empty)
	sortIssues(r.Stale)
	sortIssues(r.Unsecured)
	sortIssues(r.MissingURI)
	sortIssues(r.MissingName)
	sortIssues(r.Unreadable)
	slices.SortFunc(r.Cards, func(a, b CardIssue) int {
		if a.Expired != b.Expired {
			if a.Expired {
				return -1
			}
			return 1
		}
		return compareIssue(a.Issue, b.Issue)
	})
	r.Score = computeScore(r)
	return r
}

func computeScore(r Report) int {
	if r.TotalIssues() == 0 || r.ActiveItems <= 0 {
		return 100
	}
	weighted := float64(r.HighRisk())*3.0 + float64(r.MediumRisk())*1.5 + float64(r.LowRisk())*0.5
	penalty := (weighted / float64(r.ActiveItems)) * 25.0
	score := int(math.Round(100.0 - penalty))
	if score < 0 {
		return 0
	}
	if score > 99 {
		return 99
	}
	return score
}

func staleDetail(c *state.Cipher, now time.Time) (string, bool) {
	rev := c.Login.PasswordRevisionDate
	if rev == nil {
		rev = c.RevisionDate
	}
	if rev == nil || rev.IsZero() {
		return "", false
	}
	age := now.Sub(*rev)
	if age <= StaleWindow {
		return "", false
	}
	days := int(age / (24 * time.Hour))
	if days >= 730 {
		return fmt.Sprintf("Unchanged for %d years", days/365), true
	}
	return fmt.Sprintf("Unchanged for %d days", days), true
}

func hasNonEmptyURI(uris []state.LoginURI) bool {
	for _, u := range uris {
		if strings.TrimSpace(u.URI) != "" {
			return true
		}
	}
	return false
}

func issue(c *state.Cipher, detail string) Issue {
	sub := ""
	switch {
	case c.Login != nil:
		sub = c.Login.Username
	case c.Card != nil:
		sub = c.Card.Brand
		if sub == "" {
			sub = c.Card.CardholderName
		}
	case c.Identity != nil:
		sub = c.Identity.Email
		if sub == "" {
			sub = strings.TrimSpace(c.Identity.FirstName + " " + c.Identity.LastName)
		}
	case c.SSHKey != nil:
		sub = c.SSHKey.KeyFingerprint
	}
	return Issue{CipherID: c.ID, Type: c.Type, Name: c.Name, Subtitle: sub, Detail: detail}
}

func missingNameIssue(c *state.Cipher) Issue {
	it := issue(c, "Missing title")
	if strings.TrimSpace(it.Subtitle) == "" {
		it.Subtitle = cipherTypeName(c.Type)
	}
	return it
}

func cipherTypeName(t api.CipherType) string {
	switch t {
	case api.CipherTypeLogin:
		return "Login"
	case api.CipherTypeSecureNote:
		return "Secure Note"
	case api.CipherTypeCard:
		return "Card"
	case api.CipherTypeIdentity:
		return "Identity"
	case api.CipherTypeSSHKey:
		return "SSH Key"
	default:
		return "Item"
	}
}

func compareIssue(a, b Issue) int {
	return cmp.Or(
		strings.Compare(strings.ToLower(strings.TrimSpace(a.Name)), strings.ToLower(strings.TrimSpace(b.Name))),
		strings.Compare(a.CipherID, b.CipherID),
	)
}

func sortIssues(items []Issue) { slices.SortFunc(items, compareIssue) }

var commonPasswords = map[string]bool{
	"password": true, "passw0rd": true, "qwerty": true, "qwertyuiop": true, "asdfgh": true, "asdfghjkl": true,
	"zxcvbnm": true, "letmein": true, "welcome": true, "admin": true, "administrator": true, "login": true,
	"iloveyou": true, "monkey": true, "dragon": true, "football": true, "baseball": true, "master": true,
	"sunshine": true, "princess": true, "shadow": true, "superman": true, "trustno": true, "starwars": true,
	"secret": true, "changeme": true, "default": true, "abc": true, "test": true, "guest": true, "root": true,
	"summer": true, "winter": true, "spring": true, "autumn": true, "hello": true, "freedom": true,
}

// WeakReason returns why password is weak, or "" when it looks strong.
func WeakReason(password string) string {
	runes := []rune(password)
	if isCommon(password) {
		return "Common password"
	}
	if len(runes) < MinPasswordLength {
		return fmt.Sprintf("Shorter than %d characters", MinPasswordLength)
	}
	if patternRun(runes)*2 >= len(runes) {
		return "Mostly a sequence or repeated characters"
	}
	bits := entropyBits(runes)
	if classes(runes) == 1 && bits < 66 {
		return "Uses only one type of character"
	}
	if bits < 50 {
		return "Easy to guess"
	}
	return ""
}

var leet = strings.NewReplacer("@", "a", "4", "a", "0", "o", "1", "i", "3", "e", "$", "s", "5", "s", "7", "t")

func isCommon(password string) bool {
	p := strings.ToLower(password)
	for _, candidate := range []string{p, leet.Replace(p)} {
		if commonPasswords[candidate] {
			return true
		}
		base := strings.TrimFunc(candidate, func(r rune) bool { return !unicode.IsLetter(r) })
		if base != "" && commonPasswords[base] {
			return true
		}
	}
	return false
}

func patternRun(runes []rune) int {
	best, run, dir := 1, 1, 0
	if len(runes) == 0 {
		return 0
	}
	for i := 1; i < len(runes); i++ {
		d := int(runes[i]) - int(runes[i-1])
		if d >= -1 && d <= 1 && (run == 1 || d == dir) {
			dir = d
			run++
		} else if d >= -1 && d <= 1 {
			dir, run = d, 2
		} else {
			run = 1
		}
		best = max(best, run)
	}
	return best
}

func classes(runes []rune) int {
	var lower, upper, digit, other bool
	for _, r := range runes {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

func entropyBits(runes []rune) float64 {
	var lower, upper, digit, other bool
	distinct := map[rune]bool{}
	for _, r := range runes {
		distinct[r] = true
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	pool := 0
	if lower {
		pool += 26
	}
	if upper {
		pool += 26
	}
	if digit {
		pool += 10
	}
	if other {
		pool += 33
	}
	effective := min(float64(len(runes)), float64(len(distinct))*1.5)
	return effective * math.Log2(float64(max(pool, 1)))
}

func cardIssue(c *state.Cipher, now time.Time) (CardIssue, bool) {
	year, err := strconv.Atoi(strings.TrimSpace(c.Card.ExpYear))
	if err != nil || year <= 0 {
		return CardIssue{}, false
	}
	if year < 100 {
		year += 2000
	}
	month := 12
	if m := strings.TrimSpace(c.Card.ExpMonth); m != "" {
		if month, err = strconv.Atoi(m); err != nil || month < 1 || month > 12 {
			return CardIssue{}, false
		}
	}
	end := time.Date(year, time.Month(month)+1, 1, 0, 0, 0, 0, now.Location())
	label := fmt.Sprintf("%02d/%d", month, year)
	switch {
	case !now.Before(end):
		return CardIssue{Issue: issue(c, "Expired "+label), Expired: true}, true
	case end.Sub(now) <= ExpiringWindow:
		return CardIssue{Issue: issue(c, "Expires "+label)}, true
	}
	return CardIssue{}, false
}

func insecureURI(uris []state.LoginURI) (string, bool) {
	for _, u := range uris {
		raw := strings.TrimSpace(u.URI)
		if !strings.HasPrefix(strings.ToLower(raw), "http://") {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || isLocalHost(parsed.Hostname()) {
			continue
		}
		return raw, true
	}
	return "", false
}

func isLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
