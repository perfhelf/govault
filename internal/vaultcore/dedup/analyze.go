package dedup

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
)

type GroupType string

const (
	GroupExact    GroupType = "exact"
	GroupSameSite GroupType = "same_site"
)

type Group struct {
	ID             string
	Type           GroupType
	OrganizationID string
	Label          string
	MatchKey       string
	Items          []*state.Cipher
	PureDelete     bool
	NeedsMerge     bool
	DiffFields     []string
	BlockedReason  string
}

type Stats struct {
	TotalItems     int
	ActiveLogins   int
	ExactGroups    int
	SameSiteGroups int
	RedundantItems int
	BlockedGroups  int
}

type Report struct {
	Groups []Group
	Stats  Stats
}

func (r Report) ExactGroups() []Group {
	var out []Group
	for _, g := range r.Groups {
		if g.Type == GroupExact {
			out = append(out, g)
		}
	}
	return out
}

func (r Report) SameSiteGroups() []Group {
	var out []Group
	for _, g := range r.Groups {
		if g.Type == GroupSameSite {
			out = append(out, g)
		}
	}
	return out
}

func (r Report) RedundantItems() int {
	return r.Stats.RedundantItems
}

func (r Report) GroupByID(id string) (Group, bool) {
	for _, g := range r.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return Group{}, false
}

// Analyze inspects active (non-trashed, non-archived) Login ciphers for exact
// and same-site duplicates, strictly isolated by OrganizationID.
//
// Unsafe all-empty login items (empty primary URI, empty username, and empty
// password simultaneously) are skipped during exact duplicate grouping so
// unrelated blank or URI-less entries are never conflated.
func Analyze(ciphers []*state.Cipher) Report {
	var stats Stats
	var logins []*state.Cipher
	for _, c := range ciphers {
		if c == nil || c.DeletedDate != nil || c.ArchivedDate != nil {
			continue
		}
		stats.TotalItems++
		if c.Type == api.CipherTypeLogin && c.Login != nil {
			stats.ActiveLogins++
			logins = append(logins, cloneCipher(c))
		}
	}

	exactGroups := findExactDuplicates(logins)
	sameSiteGroups := findSameSiteDuplicates(logins, exactGroups)

	groups := make([]Group, 0, len(exactGroups)+len(sameSiteGroups))
	groups = append(groups, exactGroups...)
	groups = append(groups, sameSiteGroups...)

	redundant := map[string]bool{}
	for _, g := range groups {
		if g.BlockedReason != "" {
			stats.BlockedGroups++
		}
		for _, item := range g.Items[1:] {
			redundant[item.ID] = true
		}
	}
	stats.ExactGroups = len(exactGroups)
	stats.SameSiteGroups = len(sameSiteGroups)
	stats.RedundantItems = len(redundant)

	return Report{
		Groups: groups,
		Stats:  stats,
	}
}

type exactBucket struct {
	digest [32]byte
	items  []*state.Cipher
}

func findExactDuplicates(logins []*state.Cipher) []Group {
	buckets := map[[32]byte][]*exactBucket{}
	var order [][32]byte

	for _, c := range logins {
		org := orgBucket(c)
		normURI := NormalizeURI(PrimaryURI(c))
		lowerUser := strings.ToLower(c.Login.Username)
		pass := c.Login.Password

		// Skip unsafe all-empty URI + username + password items.
		if normURI == "" && lowerUser == "" && pass == "" {
			continue
		}

		digest := exactKeyDigest(org, normURI, lowerUser, pass)
		list := buckets[digest]
		var matched *exactBucket
		for _, b := range list {
			rep := b.items[0]
			if orgBucket(rep) == org &&
				NormalizeURI(PrimaryURI(rep)) == normURI &&
				strings.ToLower(rep.Login.Username) == lowerUser &&
				rep.Login.Password == pass {
				matched = b
				break
			}
		}
		if matched == nil {
			if len(list) == 0 {
				order = append(order, digest)
			}
			matched = &exactBucket{digest: digest}
			buckets[digest] = append(buckets[digest], matched)
		}
		matched.items = append(matched.items, c)
	}

	var groups []Group
	for _, digest := range order {
		for subIdx, b := range buckets[digest] {
			if len(b.items) < 2 {
				continue
			}
			sorted := SortByQuality(b.items)
			pureDelete, diffs := analyzeGroupDiffs(sorted)
			normURI := NormalizeURI(PrimaryURI(sorted[0]))
			matchKey := normURI
			if matchKey == "" {
				matchKey = sorted[0].Login.Username
			}
			if matchKey == "" {
				matchKey = "(no URL)"
			}
			label := strings.TrimSpace(sorted[0].Name)
			if label == "" {
				label = PrimaryURI(sorted[0])
			}
			if label == "" {
				label = sorted[0].Login.Username
			}
			if label == "" {
				label = "Untitled"
			}
			id := "exact:" + hex.EncodeToString(digest[:8])
			if subIdx > 0 {
				id = fmt.Sprintf("%s-%d", id, subIdx)
			}
			groups = append(groups, Group{
				ID:             id,
				Type:           GroupExact,
				OrganizationID: orgBucket(sorted[0]),
				Label:          label,
				MatchKey:       matchKey,
				Items:          sorted,
				PureDelete:     pureDelete,
				NeedsMerge:     !pureDelete,
				DiffFields:     diffs,
				BlockedReason:  groupBlockedReason(sorted),
			})
		}
	}

	slices.SortFunc(groups, compareGroups)
	return groups
}

type siteKey struct {
	org     string
	normURI string
}

func findSameSiteDuplicates(logins []*state.Cipher, exactGroups []Group) []Group {
	exactIDs := map[string]bool{}
	for _, g := range exactGroups {
		for _, item := range g.Items {
			exactIDs[item.ID] = true
		}
	}

	bySite := map[siteKey][]*state.Cipher{}
	var order []siteKey
	for _, c := range logins {
		normURI := NormalizeURI(PrimaryURI(c))
		if normURI == "" {
			continue
		}
		k := siteKey{org: orgBucket(c), normURI: normURI}
		if len(bySite[k]) == 0 {
			order = append(order, k)
		}
		bySite[k] = append(bySite[k], c)
	}

	var groups []Group
	for _, k := range order {
		items := bySite[k]
		if len(items) < 2 {
			continue
		}
		if !slices.ContainsFunc(items, func(c *state.Cipher) bool { return !exactIDs[c.ID] }) {
			continue
		}
		sorted := SortByQuality(items)
		pureDelete, diffs := analyzeGroupDiffs(sorted)
		sum := sha256.Sum256([]byte(k.org + "\x00" + k.normURI))
		groups = append(groups, Group{
			ID:             "site:" + hex.EncodeToString(sum[:8]),
			Type:           GroupSameSite,
			OrganizationID: k.org,
			Label:          k.normURI,
			MatchKey:       k.normURI,
			Items:          sorted,
			PureDelete:     pureDelete,
			NeedsMerge:     !pureDelete,
			DiffFields:     diffs,
			BlockedReason:  groupBlockedReason(sorted),
		})
	}

	slices.SortFunc(groups, compareGroups)
	return groups
}

func compareGroups(a, b Group) int {
	return cmp.Or(
		strings.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label)),
		strings.Compare(a.OrganizationID, b.OrganizationID),
		strings.Compare(a.ID, b.ID),
	)
}

func exactKeyDigest(org, normURI, lowerUser, password string) [32]byte {
	total := 4*4 + len(org) + len(normURI) + len(lowerUser) + len(password)
	buf := make([]byte, 0, total)
	defer crypto.ZeroBytes(buf[:cap(buf)])
	appendPart := func(s string) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, s...)
	}
	appendPart(org)
	appendPart(normURI)
	appendPart(lowerUser)
	appendPart(password)
	return sha256.Sum256(buf)
}

func orgBucket(c *state.Cipher) string {
	if c == nil || c.OrganizationID == nil {
		return ""
	}
	return *c.OrganizationID
}

func groupBlockedReason(items []*state.Cipher) string {
	hasReadOnly := false
	hasHidePassword := false
	for _, c := range items {
		if c.ReadOnly {
			hasReadOnly = true
		}
		if c.HidePassword {
			hasHidePassword = true
		}
	}
	switch {
	case hasReadOnly && hasHidePassword:
		return "Contains read-only items with hidden passwords"
	case hasReadOnly:
		return "Contains a read-only organization item"
	case hasHidePassword:
		return "Contains an item whose password is hidden by your organization"
	default:
		return ""
	}
}

// SortByQuality returns a copy of items ordered with the highest-quality item
// first: Passkeys > Attachments > TOTP > Custom fields > Notes length > Newest RevisionDate.
func SortByQuality(items []*state.Cipher) []*state.Cipher {
	out := slices.Clone(items)
	slices.SortStableFunc(out, func(a, b *state.Cipher) int {
		aPk, bPk := passkeyCount(a), passkeyCount(b)
		if aPk != bPk {
			return cmp.Compare(bPk, aPk)
		}
		aAtt, bAtt := len(a.Attachments), len(b.Attachments)
		if aAtt != bAtt {
			return cmp.Compare(bAtt, aAtt)
		}
		aTotp, bTotp := hasTOTP(a), hasTOTP(b)
		if aTotp != bTotp {
			if bTotp {
				return 1
			}
			return -1
		}
		aFields, bFields := len(a.Fields), len(b.Fields)
		if aFields != bFields {
			return cmp.Compare(bFields, aFields)
		}
		aNotes, bNotes := len(a.Notes), len(b.Notes)
		if aNotes != bNotes {
			return cmp.Compare(bNotes, aNotes)
		}
		if c := compareTimeDesc(a.RevisionDate, b.RevisionDate); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

func passkeyCount(c *state.Cipher) int {
	if c == nil || c.Login == nil {
		return 0
	}
	return len(c.Login.Fido2Credentials)
}

func hasTOTP(c *state.Cipher) bool {
	return c != nil && c.Login != nil && strings.TrimSpace(c.Login.TOTP) != ""
}

func compareTimeDesc(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	case b.After(*a):
		return 1
	case a.After(*b):
		return -1
	default:
		return 0
	}
}

// canonicalDiffOrder maintains deterministic diff label ordering.
var canonicalDiffOrder = []string{
	"Name",
	"Username",
	"Password",
	"TOTP",
	"Notes",
	"URIs",
	"Custom Fields",
	"Passkeys",
	"Attachments",
	"Favorite",
	"Reprompt",
	"Folder",
}

func analyzeGroupDiffs(items []*state.Cipher) (pureDelete bool, diffFields []string) {
	if len(items) < 2 {
		return true, nil
	}
	diffSet := map[string]bool{}
	base := items[0]
	for _, other := range items[1:] {
		for _, d := range findDiffFields(base, other) {
			diffSet[d] = true
		}
	}
	if len(diffSet) == 0 {
		return true, nil
	}
	for _, label := range canonicalDiffOrder {
		if diffSet[label] {
			diffFields = append(diffFields, label)
		}
	}
	return false, diffFields
}

func findDiffFields(a, b *state.Cipher) []string {
	var diffs []string
	var al, bl state.Login
	if a.Login != nil {
		al = *a.Login
	}
	if b.Login != nil {
		bl = *b.Login
	}
	if a.Name != b.Name {
		diffs = append(diffs, "Name")
	}
	if !strings.EqualFold(al.Username, bl.Username) {
		diffs = append(diffs, "Username")
	}
	if al.Password != bl.Password {
		diffs = append(diffs, "Password")
	}
	if al.TOTP != bl.TOTP {
		diffs = append(diffs, "TOTP")
	}
	if a.Notes != b.Notes {
		diffs = append(diffs, "Notes")
	}
	if !slices.Equal(sortedURISet(al.URIs), sortedURISet(bl.URIs)) {
		diffs = append(diffs, "URIs")
	}
	if !equalCustomFields(a.Fields, b.Fields) {
		diffs = append(diffs, "Custom Fields")
	}
	if !slices.Equal(sortedPasskeyKeys(al.Fido2Credentials), sortedPasskeyKeys(bl.Fido2Credentials)) {
		diffs = append(diffs, "Passkeys")
	}
	if !slices.Equal(sortedAttachmentKeys(a.Attachments), sortedAttachmentKeys(b.Attachments)) {
		diffs = append(diffs, "Attachments")
	}
	if a.Favorite != b.Favorite {
		diffs = append(diffs, "Favorite")
	}
	if a.Reprompt != b.Reprompt {
		diffs = append(diffs, "Reprompt")
	}
	if ptrString(a.FolderID) != ptrString(b.FolderID) {
		diffs = append(diffs, "Folder")
	}
	return diffs
}

func ptrString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func sortedURISet(uris []state.LoginURI) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range uris {
		val := strings.TrimSpace(u.URI)
		if val == "" || seen[val] {
			continue
		}
		seen[val] = true
		out = append(out, val)
	}
	slices.Sort(out)
	return out
}

type normField struct {
	name     string
	value    string
	typ      int
	hasLink  bool
	linkedID int
}

func equalCustomFields(a, b []state.CustomField) bool {
	if len(a) != len(b) {
		return false
	}
	na := normalizeFields(a)
	nb := normalizeFields(b)
	return slices.Equal(na, nb)
}

func normalizeFields(fields []state.CustomField) []normField {
	out := make([]normField, len(fields))
	for i, f := range fields {
		nf := normField{name: f.Name, value: f.Value, typ: f.Type}
		if f.LinkedID != nil {
			nf.hasLink = true
			nf.linkedID = *f.LinkedID
		}
		out[i] = nf
	}
	slices.SortFunc(out, func(x, y normField) int {
		return cmp.Or(
			strings.Compare(x.name, y.name),
			strings.Compare(x.value, y.value),
			cmp.Compare(x.typ, y.typ),
			cmp.Compare(boolInt(x.hasLink), boolInt(y.hasLink)),
			cmp.Compare(x.linkedID, y.linkedID),
		)
	})
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func passkeyIdentity(f state.Fido2Credential) string {
	if f.CredentialID != "" {
		return "id:" + f.CredentialID
	}
	if len(f.Sealed) > 0 {
		sum := sha256.Sum256(f.Sealed)
		return "sealed:" + hex.EncodeToString(sum[:])
	}
	return "meta:" + f.RpID + "\x00" + f.UserHandle + "\x00" + f.CreationDate
}

func sortedPasskeyKeys(creds []state.Fido2Credential) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range creds {
		k := passkeyIdentity(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func sortedAttachmentKeys(atts []state.Attachment) []string {
	out := make([]string, len(atts))
	for i, a := range atts {
		if a.ID != "" {
			out[i] = "id:" + a.ID
		} else {
			out[i] = fmt.Sprintf("file:%s:%d", a.FileName, a.Size)
		}
	}
	slices.Sort(out)
	return out
}

// ChooseBestTitle picks the best title among unique non-empty titles:
// CJK/non-ASCII titles have priority over ASCII-only titles; within the same
// tier, the shortest rune-length title wins (tie-breaking lexicographically).
func ChooseBestTitle(titles []string) (chosen string, discarded []string) {
	seen := map[string]bool{}
	var unique []string
	for _, raw := range titles {
		t := strings.TrimSpace(raw)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		unique = append(unique, t)
	}
	if len(unique) == 0 {
		return "", nil
	}
	if len(unique) == 1 {
		return unique[0], nil
	}

	var nonASCII, ascii []string
	for _, t := range unique {
		if hasCJKOrNonASCII(t) {
			nonASCII = append(nonASCII, t)
		} else {
			ascii = append(ascii, t)
		}
	}

	pool := ascii
	if len(nonASCII) > 0 {
		pool = nonASCII
	}
	slices.SortStableFunc(pool, func(a, b string) int {
		return cmp.Or(
			cmp.Compare(utf8.RuneCountInString(a), utf8.RuneCountInString(b)),
			strings.Compare(a, b),
		)
	})
	chosen = pool[0]
	for _, t := range unique {
		if t != chosen {
			discarded = append(discarded, t)
		}
	}
	return chosen, discarded
}

func hasCJKOrNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}
