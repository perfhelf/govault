package dedup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }

func makeLogin(id, name, user, pass string, uris ...string) *state.Cipher {
	loginURIs := make([]state.LoginURI, len(uris))
	for i, u := range uris {
		loginURIs[i] = state.LoginURI{URI: u}
	}
	return &state.Cipher{
		ID:   id,
		Type: api.CipherTypeLogin,
		Name: name,
		Login: &state.Login{
			Username: user,
			Password: pass,
			URIs:     loginURIs,
		},
	}
}

func TestNormalizeURI_MobileAndMultiPartTLDs(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"androidapp://com.Example.App", "com.example.app"},
		{"androidapp://com.example.app/login?foo=1", "com.example.app"},
		{"iosapp://COM.Example.App/auth", "com.example.app"},
		{"https://pan.baidu.com/disk/home", "baidu.com"},
		{"accounts.google.com/ServiceLogin", "google.com"},
		{"https://192.168.1.50:8443/admin", "192.168.1.50"},
		{"http://[::1]:8080/login", "::1"},
		{"http://localhost:3000/callback", "localhost"},
		{"https://www.Example.COM.", "example.com"},
		// 35+ multi-part eTLD+1 suffixes
		{"https://shop.acme.co.uk/cart", "acme.co.uk"},
		{"https://portal.charity.org.uk", "charity.org.uk"},
		{"https://uni.ox.ac.uk", "ox.ac.uk"},
		{"https://tax.hmrc.gov.uk", "hmrc.gov.uk"},
		{"https://blog.alice.me.uk", "alice.me.uk"},
		{"https://isp.core.net.uk", "core.net.uk"},
		{"https://bank.comm.com.au", "comm.com.au"},
		{"https://mail.telstra.net.au", "telstra.net.au"},
		{"https://help.redcross.org.au", "redcross.org.au"},
		{"https://portal.sydney.edu.au", "sydney.edu.au"},
		{"https://my.ato.gov.au", "ato.gov.au"},
		{"https://login.yahoo.co.jp", "yahoo.co.jp"},
		{"https://news.nhk.or.jp", "nhk.or.jp"},
		{"https://app.biglobe.ne.jp", "biglobe.ne.jp"},
		{"https://web.tokyo.ac.jp", "tokyo.ac.jp"},
		{"https://visa.mofa.go.jp", "mofa.go.jp"},
		{"https://mail.naver.co.kr", "naver.co.kr"},
		{"https://club.kbs.or.kr", "kbs.or.kr"},
		{"https://zone.hitel.ne.kr", "hitel.ne.kr"},
		{"https://sso.qq.com.cn", "qq.com.cn"},
		{"https://dns.chinanet.net.cn", "chinanet.net.cn"},
		{"https://dev.apache.org.cn", "apache.org.cn"},
		{"https://tax.beijing.gov.cn", "beijing.gov.cn"},
		{"https://lib.tsinghua.edu.cn", "tsinghua.edu.cn"},
		{"https://shop.pchome.com.tw", "pchome.com.tw"},
		{"https://wiki.open.org.tw", "open.org.tw"},
		{"https://isp.hinet.net.tw", "hinet.net.tw"},
		{"https://cs.ntu.edu.tw", "ntu.edu.tw"},
		{"https://pay.octopus.com.hk", "octopus.com.hk"},
		{"https://help.hk.org.hk", "hk.org.hk"},
		{"https://mail.netvigator.net.hk", "netvigator.net.hk"},
		{"https://lib.hku.edu.hk", "hku.edu.hk"},
		{"https://e.gov.hk", "e.gov.hk"},
		{"https://shop.trademe.co.nz", "trademe.co.nz"},
		{"https://app.uol.com.br", "uol.com.br"},
		{"https://pay.telmex.com.mx", "telmex.com.mx"},
		{"https://pay.flipkart.co.in", "flipkart.co.in"},
		{"https://login.dbs.com.sg", "dbs.com.sg"},
		{"https://bank.fnb.co.za", "fnb.co.za"},
		{"https://news.ynet.co.il", "ynet.co.il"},
		{"https://shop.hepsiburada.com.tr", "hepsiburada.com.tr"},
		{"https://mail.sanook.co.th", "sanook.co.th"},
		{"https://pay.viettel.com.vn", "viettel.com.vn"},
		{"https://shop.mercadolibre.com.ar", "mercadolibre.com.ar"},
	}
	for _, tc := range cases {
		if got := NormalizeURI(tc.raw); got != tc.want {
			t.Errorf("NormalizeURI(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestSimplifyURL(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://login.example.co.uk/oauth/authorize?client_id=1", "https://example.co.uk"},
		{"http://portal.example.com:80/login", "http://example.com"},
		{"https://nas.example.com:8443/app", "https://example.com:8443"},
		{"androidapp://com.Example.App/login", "androidapp://com.example.app"},
		{"iosapp://com.Example.App/auth", "iosapp://com.example.app"},
		{"https://192.168.1.5:8080/ui", "https://192.168.1.5:8080"},
		{"example.com", "example.com"},
	}
	for _, tc := range cases {
		if got := SimplifyURL(tc.raw); got != tc.want {
			t.Errorf("SimplifyURL(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestAnalyze_ExactSameSiteFilteringAndExclusions(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	trashedAt := now.Add(-time.Hour)
	archivedAt := now.Add(-2 * time.Hour)

	ciphers := []*state.Cipher{
		nil,
		// Non-login ignored
		{ID: "card-1", Type: api.CipherTypeCard, Name: "Card", Card: &state.Card{Brand: "Visa"}},
		// Trashed & archived ignored
		{ID: "trash-1", Type: api.CipherTypeLogin, Name: "GitHub", DeletedDate: &trashedAt, Login: &state.Login{Username: "alice", Password: "pw1", URIs: []state.LoginURI{{URI: "https://github.com"}}}},
		{ID: "arch-1", Type: api.CipherTypeLogin, Name: "GitHub", ArchivedDate: &archivedAt, Login: &state.Login{Username: "alice", Password: "pw1", URIs: []state.LoginURI{{URI: "https://github.com"}}}},
		// Unsafe all-empty URI + user + pass skipped
		makeLogin("empty-1", "Empty 1", "", ""),
		makeLogin("empty-2", "Empty 2", "", ""),
		// Exact duplicate pair across subdomains + case-insensitive username
		makeLogin("gh-1", "GitHub", "Alice@Example.com", "pw-github", "https://github.com/login"),
		makeLogin("gh-2", "GitHub", "alice@example.com", "pw-github", "https://gist.github.com/auth"),
		// Mobile app exact duplicate (androidapp + iosapp same bundle ID)
		makeLogin("mob-1", "Bank App", "user1", "pw-bank", "androidapp://com.bank.mobile/start"),
		makeLogin("mob-2", "Bank App", "user1", "pw-bank", "iosapp://com.bank.mobile"),
		// Site with exact pair + 3rd distinct credential -> appears in BOTH exact (pair) and same-site (all 3)
		makeLogin("ex-1", "Example A", "alice", "pw-a", "https://app.example.co.uk/login"),
		makeLogin("ex-2", "Example A", "alice", "pw-a", "https://shop.example.co.uk/home"),
		makeLogin("ex-3", "Example B", "bob", "pw-b", "https://example.co.uk"),
	}

	report := Analyze(ciphers)
	if report.Stats.ActiveLogins != 9 {
		t.Fatalf("ActiveLogins = %d, want 9", report.Stats.ActiveLogins)
	}
	exact := report.ExactGroups()
	same := report.SameSiteGroups()
	if len(exact) != 3 {
		t.Fatalf("ExactGroups = %d, want 3: %+v", len(exact), exact)
	}
	// github.com and com.bank.mobile are fully covered by exact duplicates, so
	// only example.co.uk remains in same-site.
	if len(same) != 1 || same[0].MatchKey != "example.co.uk" || len(same[0].Items) != 3 {
		t.Fatalf("SameSiteGroups = %+v, want 1 group (example.co.uk, 3 items)", same)
	}
	// Redundant items: gh-2, mob-2, ex-2, ex-3 -> 4 unique redundant items (not 5!)
	if report.RedundantItems() != 4 {
		t.Fatalf("RedundantItems = %d, want 4", report.RedundantItems())
	}
	// Never leak raw password into Label/MatchKey/DiffFields
	for _, g := range report.Groups {
		if strings.Contains(g.Label, "pw-") || strings.Contains(g.MatchKey, "pw-") {
			t.Fatalf("group leaked secret: %+v", g)
		}
	}
}

func TestAnalyze_OrgIsolationAndReadOnlyBlocking(t *testing.T) {
	org1 := "org-1"
	org2 := "org-2"
	cPersonal := makeLogin("p-1", "AWS", "ops", "pw", "https://aws.amazon.com")
	cOrg1A := makeLogin("o1-a", "AWS", "ops", "pw", "https://aws.amazon.com")
	cOrg1A.OrganizationID = &org1
	cOrg1B := makeLogin("o1-b", "AWS", "ops", "pw", "https://console.aws.amazon.com")
	cOrg1B.OrganizationID = &org1
	cOrg1B.ReadOnly = true
	cOrg2 := makeLogin("o2-a", "AWS", "ops", "pw", "https://aws.amazon.com")
	cOrg2.OrganizationID = &org2

	cHideA := makeLogin("h-a", "Hidden", "ops", "", "https://hidden.example.com")
	cHideA.OrganizationID = &org2
	cHideA.HidePassword = true
	cHideB := makeLogin("h-b", "Hidden", "ops", "", "https://hidden.example.com")
	cHideB.OrganizationID = &org2

	report := Analyze([]*state.Cipher{cPersonal, cOrg1A, cOrg1B, cOrg2, cHideA, cHideB})
	if len(report.Groups) != 2 {
		t.Fatalf("Groups = %d, want 2 (org-1 blocked, org-2 hidden blocked; personal & org2 AWS isolated)", len(report.Groups))
	}
	for _, g := range report.Groups {
		if g.BlockedReason == "" {
			t.Fatalf("expected group %q to have BlockedReason", g.ID)
		}
	}

	plan := BuildPlan([]GroupSelection{
		{Group: report.Groups[0]},
		{Group: report.Groups[1]},
	}, PlanOptions{})
	if len(plan.Groups) != 0 || len(plan.Errors) != 2 {
		t.Fatalf("blocked groups should produce 0 ops and 2 errors, got groups=%d errors=%+v", len(plan.Groups), plan.Errors)
	}
}

func TestAnalyze_DeepDiffAllFieldsAndSortByQuality(t *testing.T) {
	tOld := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	tNew := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f1 := "folder-1"

	base := makeLogin("1-base", "Alpha", "alice", "secret", "https://example.com")
	base.RevisionDate = &tOld

	newer := makeLogin("2-newer", "Alpha", "alice", "secret", "https://example.com")
	newer.RevisionDate = &tNew

	withNotes := makeLogin("3-notes", "Alpha", "alice", "secret", "https://example.com")
	withNotes.Notes = "some detailed notes"

	withFields := makeLogin("4-fields", "Alpha", "alice", "secret", "https://example.com")
	withFields.Fields = []state.CustomField{{Name: "PIN", Value: "1234"}}

	withTOTP := makeLogin("5-totp", "Alpha", "alice", "secret", "https://example.com")
	withTOTP.Login.TOTP = "JBSWY3DPEHPK3PXP"

	withAtt := makeLogin("6-att", "Alpha", "alice", "secret", "https://example.com")
	withAtt.Attachments = []state.Attachment{{ID: "att-1", FileName: "recovery.txt", Size: 12}}

	withPk := makeLogin("7-pk", "Alpha", "alice", "secret", "https://example.com")
	withPk.Login.Fido2Credentials = []state.Fido2Credential{{CredentialID: "cred-1", RpID: "example.com"}}

	sorted := SortByQuality([]*state.Cipher{base, newer, withNotes, withFields, withTOTP, withAtt, withPk})
	gotIDs := make([]string, len(sorted))
	for i, c := range sorted {
		gotIDs[i] = c.ID
	}
	wantIDs := []string{"7-pk", "6-att", "5-totp", "4-fields", "3-notes", "2-newer", "1-base"}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("SortByQuality order = %v, want %v", gotIDs, wantIDs)
	}

	// Verify all 12 diff fields trigger properly.
	a := makeLogin("a", "Title A", "alice", "pw1", "https://a.com", "https://b.com")
	b := makeLogin("b", "Title B", "bob", "pw2", "https://a.com")
	a.Login.TOTP = "SECRET1"
	a.Notes = "notes a"
	a.Fields = []state.CustomField{{Name: "k", Value: "v"}}
	a.Login.Fido2Credentials = []state.Fido2Credential{{CredentialID: "pk-1"}}
	a.Attachments = []state.Attachment{{ID: "att-1", FileName: "f.txt"}}
	a.Favorite = true
	a.Reprompt = 1
	a.FolderID = &f1

	diffs := findDiffFields(a, b)
	wantDiffs := []string{"Name", "Username", "Password", "TOTP", "Notes", "URIs", "Custom Fields", "Passkeys", "Attachments", "Favorite", "Reprompt", "Folder"}
	if !slices.Equal(diffs, wantDiffs) {
		t.Fatalf("findDiffFields = %v, want %v", diffs, wantDiffs)
	}

	// Identical items with same primary URI and reordered secondary URIs & Fields -> PureDelete == true.
	c1 := makeLogin("c1", "Same", "Alice", "pw", "https://a.com", "https://c.com", "https://b.com")
	c1.Fields = []state.CustomField{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}}
	c2 := makeLogin("c2", "Same", "alice", "pw", "https://a.com", "https://b.com", "https://c.com")
	c2.Fields = []state.CustomField{{Name: "B", Value: "2"}, {Name: "A", Value: "1"}}
	rep := Analyze([]*state.Cipher{c1, c2})
	if len(rep.Groups) != 1 || !rep.Groups[0].PureDelete || len(rep.Groups[0].DiffFields) != 0 {
		t.Fatalf("expected PureDelete for reordered identical items, got %+v", rep.Groups)
	}
}

func TestChooseBestTitle(t *testing.T) {
	chosen, discarded := ChooseBestTitle([]string{"GitHub Enterprise Portal", "GitHub", "GitHub 中文主站"})
	if chosen != "GitHub 中文主站" {
		t.Fatalf("chosen = %q, want CJK title", chosen)
	}
	if !slices.Equal(discarded, []string{"GitHub Enterprise Portal", "GitHub"}) {
		t.Fatalf("discarded = %v", discarded)
	}

	chosen, discarded = ChooseBestTitle([]string{"GitHub Enterprise", "GitHub"})
	if chosen != "GitHub" || !slices.Equal(discarded, []string{"GitHub Enterprise"}) {
		t.Fatalf("ASCII shortest = (%q, %v)", chosen, discarded)
	}
}

// memoryVaultStub implements state.VaultService methods needed by ExecutePlan tests.
type memoryVaultStub struct {
	state.VaultService
	mu         sync.Mutex
	ciphers    map[string]*state.Cipher
	nextID     int
	failSave   bool
	failDelete bool
	saveCalls  []*state.Cipher
	delCalls   []string
}

func newMemoryVaultStub(items ...*state.Cipher) *memoryVaultStub {
	m := &memoryVaultStub{ciphers: map[string]*state.Cipher{}}
	for _, c := range items {
		m.ciphers[c.ID] = cloneCipher(c)
	}
	return m
}

func (m *memoryVaultStub) SaveCipher(ctx context.Context, c *state.Cipher) (*state.Cipher, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveCalls = append(m.saveCalls, cloneCipher(c))
	if m.failSave {
		return nil, errors.New("server 500")
	}
	cp := cloneCipher(c)
	if cp.ID == "" {
		m.nextID++
		cp.ID = fmt.Sprintf("created-%d", m.nextID)
	}
	m.ciphers[cp.ID] = cp
	return cloneCipher(cp), nil
}

func (m *memoryVaultStub) SoftDeleteCipher(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delCalls = append(m.delCalls, id)
	if m.failDelete {
		return errors.New("delete failed")
	}
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	now := time.Now().UTC()
	c.DeletedDate = &now
	return nil
}

func TestBuildAndExecutePlan_PathA_PathB_CreateFailureAbort(t *testing.T) {
	// Path A: 100% identical except RevisionDate -> OpPureDelete
	a1 := makeLogin("a1", "Mail", "alice", "pw1", "https://mail.example.com")
	a2 := makeLogin("a2", "Mail", "alice", "pw1", "https://mail.example.com")
	repA := Analyze([]*state.Cipher{a1, a2})
	if len(repA.Groups) != 1 || !repA.Groups[0].PureDelete {
		t.Fatalf("expected PureDelete group, got %+v", repA.Groups)
	}
	planA := BuildPlan([]GroupSelection{{Group: repA.Groups[0], KeepCipherID: "a1"}}, PlanOptions{})
	if len(planA.Groups) != 1 || planA.Groups[0].Mode != OpPureDelete || !slices.Equal(planA.Groups[0].DeleteIDs, []string{"a2"}) {
		t.Fatalf("planA = %+v", planA)
	}
	stubA := newMemoryVaultStub(a1, a2)
	resA := ExecutePlan(context.Background(), stubA, planA, nil)
	if resA.SucceededGroups != 1 || resA.DeletedCount != 1 || len(stubA.saveCalls) != 0 {
		t.Fatalf("resA = %+v, saveCalls=%d", resA, len(stubA.saveCalls))
	}
	if stubA.ciphers["a1"].DeletedDate != nil || stubA.ciphers["a2"].DeletedDate == nil {
		t.Fatalf("a1 should stay active and a2 soft-deleted")
	}

	// Path B: merge notes, titles, TOTP, URIs (SimplifyURLs=true), fields, favorite, reprompt, history, org/collections
	orgID := "org-1"
	folderID := "f-work"
	t1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	b1 := makeLogin("b1", "GitHub Enterprise", "alice", "pw1", "https://gist.github.com/alice")
	b1.OrganizationID = &orgID
	b1.CollectionIDs = []string{"col-1"}
	b1.FolderID = &folderID
	b1.Notes = "short"
	b1.Favorite = true
	b1.Fields = []state.CustomField{{Name: "Env", Value: "prod"}}
	b1.PasswordHistory = []state.PasswordHistoryEntry{{Password: "old1", LastUsedDate: t1}}

	b2 := makeLogin("b2", "GitHub 中文", "alice", "pw1", "https://github.com/login")
	b2.OrganizationID = &orgID
	b2.CollectionIDs = []string{"col-1", "col-2"}
	b2.Login.TOTP = "JBSWY3DPEHPK3PXP"
	b2.Notes = "longer detailed note"
	b2.Reprompt = 1
	b2.Fields = []state.CustomField{{Name: "Env", Value: "staging"}, {Name: "Team", Value: "core"}}
	b2.PasswordHistory = []state.PasswordHistoryEntry{
		{Password: "old1", LastUsedDate: t1},
		{Password: "old2", LastUsedDate: t2},
	}

	repB := Analyze([]*state.Cipher{b1, b2})
	planB := BuildPlan([]GroupSelection{{Group: repB.Groups[0], KeepCipherID: "b2"}}, PlanOptions{SimplifyURLs: true})
	if len(planB.Groups) != 1 || planB.Groups[0].Mode != OpCreateThenDelete {
		t.Fatalf("planB = %+v", planB)
	}
	mc := planB.Groups[0].MergedCipher
	if mc.ID != "" || mc.Name != "GitHub 中文" || mc.Login.TOTP != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("merged header = %+v", mc)
	}
	if !strings.Contains(mc.Notes, "longer detailed note") || !strings.Contains(mc.Notes, "Previous titles before merge: GitHub Enterprise") {
		t.Fatalf("merged notes = %q", mc.Notes)
	}
	if len(mc.Login.URIs) != 1 || mc.Login.URIs[0].URI != "https://github.com" {
		t.Fatalf("expected simplified deduplicated URI, got %+v", mc.Login.URIs)
	}
	if !mc.Favorite || mc.Reprompt != 1 || len(mc.Fields) != 2 || len(mc.PasswordHistory) != 2 {
		t.Fatalf("merged attrs = fav:%v reprompt:%d fields:%+v hist:%+v", mc.Favorite, mc.Reprompt, mc.Fields, mc.PasswordHistory)
	}
	if mc.OrganizationID == nil || *mc.OrganizationID != orgID || !slices.Equal(mc.CollectionIDs, []string{"col-1", "col-2"}) {
		t.Fatalf("org/collections = %v %v", mc.OrganizationID, mc.CollectionIDs)
	}

	// Create-failure abort: originals MUST NOT be deleted!
	stubFail := newMemoryVaultStub(b1, b2)
	stubFail.failSave = true
	resFail := ExecutePlan(context.Background(), stubFail, planB, nil)
	if resFail.FailedGroups != 1 || len(stubFail.delCalls) != 0 {
		t.Fatalf("create failure should abort without deleting originals: res=%+v dels=%v", resFail, stubFail.delCalls)
	}
	if stubFail.ciphers["b1"].DeletedDate != nil || stubFail.ciphers["b2"].DeletedDate != nil {
		t.Fatal("originals were deleted after create failure")
	}

	// Normal create-then-delete success
	stubOK := newMemoryVaultStub(b1, b2)
	var phases []string
	resOK := ExecutePlan(context.Background(), stubOK, planB, func(p Progress) {
		phases = append(phases, p.Phase)
	})
	if resOK.SucceededGroups != 1 || resOK.CreatedCount != 1 || resOK.DeletedCount != 2 {
		t.Fatalf("resOK = %+v", resOK)
	}
	if !slices.Contains(phases, "creating") || !slices.Contains(phases, "deleting") || !slices.Contains(phases, "done") {
		t.Fatalf("unexpected progress phases: %v", phases)
	}
	if stubOK.ciphers["b1"].DeletedDate == nil || stubOK.ciphers["b2"].DeletedDate == nil {
		t.Fatal("originals were not soft-deleted after successful create")
	}
	if stubOK.ciphers["created-1"] == nil || stubOK.ciphers["created-1"].Name != "GitHub 中文" {
		t.Fatalf("created cipher missing: %+v", stubOK.ciphers)
	}
}

func TestBuildPlan_AttachmentSafety(t *testing.T) {
	withAtt := makeLogin("att-keep", "Bank", "alice", "pw", "https://bank.com")
	withAtt.Attachments = []state.Attachment{{ID: "att-1", FileName: "codes.pdf", Size: 512}}
	plain := makeLogin("plain-dup", "Bank", "alice", "pw", "https://bank.com")
	plain.Notes = "extra backup note"

	rep := Analyze([]*state.Cipher{plain, withAtt})
	if len(rep.Groups) != 1 || rep.Groups[0].Items[0].ID != "att-keep" {
		t.Fatalf("expected attachment-bearing item sorted first: %+v", rep.Groups)
	}

	// Keeping attachment item -> OpInPlace update on att-keep + soft-delete plain-dup.
	plan := BuildPlan([]GroupSelection{{Group: rep.Groups[0]}}, PlanOptions{})
	if len(plan.Errors) != 0 || len(plan.Groups) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	op := plan.Groups[0]
	if op.Mode != OpInPlace || op.KeepID != "att-keep" || op.MergedCipher.ID != "att-keep" {
		t.Fatalf("expected OpInPlace on att-keep, got %+v", op)
	}
	if !slices.Equal(op.DeleteIDs, []string{"plain-dup"}) || op.MergedCipher.Notes != "extra backup note" {
		t.Fatalf("op = %+v", op)
	}

	// Overriding KeepCipherID to plain-dup -> MUST refuse so att-keep's attachment isn't lost!
	unsafePlan := BuildPlan([]GroupSelection{{Group: rep.Groups[0], KeepCipherID: "plain-dup"}}, PlanOptions{})
	if len(unsafePlan.Groups) != 0 || len(unsafePlan.Errors) != 1 {
		t.Fatalf("expected error refusing to delete attachment item, got %+v", unsafePlan)
	}

	// Two items both with attachments -> MUST refuse!
	withAtt2 := makeLogin("att-2", "Bank", "alice", "pw", "https://bank.com")
	withAtt2.Attachments = []state.Attachment{{ID: "att-2", FileName: "other.pdf", Size: 256}}
	repBoth := Analyze([]*state.Cipher{withAtt, withAtt2})
	bothPlan := BuildPlan([]GroupSelection{{Group: repBoth.Groups[0]}}, PlanOptions{})
	if len(bothPlan.Groups) != 0 || len(bothPlan.Errors) != 1 {
		t.Fatalf("expected error when both items have attachments, got %+v", bothPlan)
	}
}

func TestExecutePlan_ContextCancellation(t *testing.T) {
	g1 := Analyze([]*state.Cipher{
		makeLogin("1a", "Site A", "u", "p", "https://a.com"),
		makeLogin("1b", "Site A", "u", "p", "https://a.com"),
	}).Groups[0]
	plan := BuildPlan([]GroupSelection{{Group: g1}}, PlanOptions{})
	stub := newMemoryVaultStub(g1.Items...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := ExecutePlan(ctx, stub, plan, nil)
	if !res.Cancelled || len(stub.delCalls) != 0 {
		t.Fatalf("expected cancelled report with 0 calls, got %+v", res)
	}
}

func mustEncString(t *testing.T, plain string, key *crypto.SymmetricKey) string {
	t.Helper()
	s, err := crypto.EncryptString(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustEncPtr(t *testing.T, plain string, key *crypto.SymmetricKey) *string {
	s := mustEncString(t, plain, key)
	return &s
}

func TestExecutePlan_RealStateServicePreservesPasskeyAndSealedFields(t *testing.T) {
	email := "alice@example.com"
	password := []byte("correct-horse-battery-staple")
	kdf := crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}
	masterKey, _ := crypto.DeriveMasterKey(password, email, kdf)
	stretched, _ := crypto.StretchMasterKey(masterKey)

	rawUser := bytes.Repeat([]byte{0x11}, 64)
	userKey, _ := crypto.SymmetricKeyFromBytes(rawUser)
	protectedUserKey, _ := crypto.EncryptBytes(rawUser, stretched)

	rawCipher := bytes.Repeat([]byte{0x22}, 64)
	cipherKey, _ := crypto.SymmetricKeyFromBytes(rawCipher)
	encCipherKey, _ := crypto.EncryptBytes(rawCipher, userKey)
	encCipherKeyStr := encCipherKey.String()

	sum := sha256.Sum256([]byte("https://github.com"))
	uriChecksum := mustEncString(t, base64.StdEncoding.EncodeToString(sum[:]), cipherKey)
	sealedTop := mustEncString(t, "top-secret-unknown", cipherKey)
	sealedLogin := mustEncString(t, "login-secret-unknown", cipherKey)
	passkeyJSON := json.RawMessage(fmt.Sprintf(
		`{"credentialId":%q,"keyType":%q,"keyAlgorithm":%q,"keyCurve":%q,"keyValue":%q,"rpId":%q,"userHandle":%q,"userName":%q,"counter":%q,"rpName":%q,"userDisplayName":%q,"discoverable":%q,"creationDate":"2026-03-14T10:22:00.000Z","futurePasskeyField":1}`,
		mustEncString(t, "cred-1", cipherKey),
		mustEncString(t, "public-key", cipherKey),
		mustEncString(t, "ECDSA", cipherKey),
		mustEncString(t, "P-256", cipherKey),
		mustEncString(t, "pk-priv", cipherKey),
		mustEncString(t, "github.com", cipherKey),
		mustEncString(t, "uh-1", cipherKey),
		mustEncString(t, "alice", cipherKey),
		mustEncString(t, "0", cipherKey),
		mustEncString(t, "GitHub", cipherKey),
		mustEncString(t, "Alice", cipherKey),
		mustEncString(t, "true", cipherKey),
	))

	rev := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	var login1 api.EncryptedLogin
	loginJSON := fmt.Sprintf(
		`{"username":%q,"password":%q,"totp":null,"uris":[{"uri":%q,"match":null,"uriChecksum":%q,"futureUriField":7}],"fido2Credentials":[%s],"autofillOnPageLoad":true,"sealedLoginField":%q}`,
		mustEncString(t, "alice", cipherKey),
		mustEncString(t, "pw-shared", cipherKey),
		mustEncString(t, "https://github.com", cipherKey),
		uriChecksum,
		passkeyJSON,
		sealedLogin,
	)
	if err := json.Unmarshal([]byte(loginJSON), &login1); err != nil {
		t.Fatal(err)
	}

	c1 := api.EncryptedCipher{
		ID: "c-passkey", Type: api.CipherTypeLogin, Key: &encCipherKeyStr,
		Name: mustEncString(t, "GitHub", cipherKey), RevisionDate: &rev,
		Login: &login1,
		Extra: map[string]json.RawMessage{"sealedCipherField": json.RawMessage(fmt.Sprintf("%q", sealedTop))},
	}
	c2 := api.EncryptedCipher{
		ID: "c-totp", Type: api.CipherTypeLogin,
		Name: mustEncString(t, "GitHub 中文", userKey), RevisionDate: &rev,
		Notes: mustEncPtr(t, "Recovery instructions", userKey),
		Login: &api.EncryptedLogin{
			Username: mustEncPtr(t, "alice", userKey),
			Password: mustEncPtr(t, "pw-shared", userKey),
			TOTP:     mustEncPtr(t, "JBSWY3DPEHPK3PXP", userKey),
			URIs:     []api.EncryptedLoginURI{{URI: mustEncPtr(t, "https://gist.github.com", userKey)}},
		},
	}

	var mu sync.Mutex
	ciphers := map[string]api.EncryptedCipher{"c-passkey": c1, "c-totp": c2}
	var lastCreate json.RawMessage
	var deletedIDs []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/identity/accounts/prelogin":
			_ = json.NewEncoder(w).Encode(kdf)
		case r.URL.Path == "/identity/connect/token":
			_ = json.NewEncoder(w).Encode(api.TokenResponse{AccessToken: "tok", RefreshToken: "ref", Key: protectedUserKey.String()})
		case r.URL.Path == "/api/accounts/revision-date":
			_ = json.NewEncoder(w).Encode(rev.UnixMilli())
		case r.URL.Path == "/api/sync":
			mu.Lock()
			list := make([]api.EncryptedCipher, 0, len(ciphers))
			for _, c := range ciphers {
				list = append(list, c)
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(api.SyncResponse{
				Profile: api.Profile{ID: "acct-1", Email: email, Key: protectedUserKey.String()},
				Ciphers: list,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/ciphers":
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r.Body)
			mu.Lock()
			lastCreate = bytes.Clone(buf.Bytes())
			var p api.CipherPayload
			_ = json.Unmarshal(buf.Bytes(), &p)
			created := api.EncryptedCipher{
				ID: "c-merged", Type: p.Type, Key: p.Key, Name: p.Name, Notes: p.Notes,
				Favorite: p.Favorite, Reprompt: p.Reprompt, RevisionDate: &rev,
				Login: p.Login, Fields: p.Fields, PasswordHistory: p.PasswordHistory, Extra: p.Extra,
			}
			ciphers[created.ID] = created
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(created)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/delete"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/ciphers/"), "/delete")
			mu.Lock()
			deletedIDs = append(deletedIDs, id)
			c := ciphers[id]
			now := time.Now().UTC()
			c.DeletedDate = &now
			ciphers[id] = c
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	svc, err := state.NewService(state.ServiceConfig{
		Store: store.NewFileStore(t.TempDir()), Secrets: newMemSecretStore(), DeviceID: "dev-1", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := svc.Login(ctx, state.LoginRequest{ServerURL: srv.URL, Email: email, MasterPassword: password}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	report := Analyze(svc.AllCiphers())
	if len(report.Groups) != 1 {
		t.Fatalf("Groups = %+v", report.Groups)
	}
	plan := BuildPlan([]GroupSelection{{Group: report.Groups[0]}}, PlanOptions{SimplifyURLs: false})
	if len(plan.Errors) != 0 || len(plan.Groups) != 1 || plan.Groups[0].Mode != OpCreateThenDelete {
		t.Fatalf("plan = %+v", plan)
	}

	execRes := ExecutePlan(ctx, svc, plan, nil)
	if execRes.SucceededGroups != 1 || execRes.CreatedCount != 1 || execRes.DeletedCount != 2 || execRes.Err != nil {
		t.Fatalf("execRes = %+v", execRes)
	}

	merged, err := svc.GetCipher("c-merged")
	if err != nil {
		t.Fatalf("GetCipher(c-merged): %v", err)
	}
	if merged.Name != "GitHub 中文" || merged.Login.TOTP != "JBSWY3DPEHPK3PXP" || len(merged.Login.URIs) != 2 {
		t.Fatalf("merged fields wrong: %+v", merged)
	}
	if len(merged.Login.Fido2Credentials) != 1 || merged.Login.Fido2Credentials[0].CredentialID != "cred-1" {
		t.Fatalf("passkey not preserved: %+v", merged.Login.Fido2Credentials)
	}
	if !bytes.Equal(merged.Login.Fido2Credentials[0].Sealed, passkeyJSON) {
		t.Fatalf("sealed passkey mutated: %s", merged.Login.Fido2Credentials[0].Sealed)
	}
	if merged.Key == nil || *merged.Key != encCipherKeyStr {
		t.Fatalf("per-cipher Key not preserved")
	}

	mu.Lock()
	var bodyMap map[string]json.RawMessage
	_ = json.Unmarshal(lastCreate, &bodyMap)
	mu.Unlock()
	if string(bodyMap["sealedCipherField"]) != fmt.Sprintf("%q", sealedTop) {
		t.Fatalf("sealedCipherField lost: %s", bodyMap["sealedCipherField"])
	}
	if len(deletedIDs) != 2 {
		t.Fatalf("deletedIDs = %v, want 2 originals soft-deleted", deletedIDs)
	}
}

func TestBuildPlan_TitleOverride_PasskeyFallback_And_ConflictingKeys(t *testing.T) {
	// Passkey-only item (empty username/password) merging with credential-bearing same-site item.
	pkOnly := makeLogin("pk-1", "GitHub Passkey", "", "", "https://github.com")
	pkOnly.Login.Fido2Credentials = []state.Fido2Credential{{CredentialID: "cred-a", Sealed: json.RawMessage(`{"credentialId":"a"}`)}}
	pkOnly.SealedKeyID = "key-a"
	pkOnly.Key = strPtr("2.key-a")

	pwItem := makeLogin("pw-1", "GitHub Login", "alice", "pw-secret", "https://github.com/login")
	pwItem.SealedKeyID = "key-user"

	rep := Analyze([]*state.Cipher{pkOnly, pwItem})
	if len(rep.SameSiteGroups()) != 1 {
		t.Fatalf("expected 1 same-site group, got %+v", rep.Groups)
	}
	plan := BuildPlan([]GroupSelection{{
		Group:         rep.SameSiteGroups()[0],
		TitleOverride: "My Custom GitHub",
	}}, PlanOptions{})
	if len(plan.Errors) != 0 || len(plan.Groups) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	mc := plan.Groups[0].MergedCipher
	if mc.Name != "My Custom GitHub" || mc.Login.Username != "alice" || mc.Login.Password != "pw-secret" {
		t.Fatalf("merged creds = %+v", mc)
	}
	if !strings.Contains(mc.Notes, "Previous titles before merge: GitHub Passkey, GitHub Login") {
		t.Fatalf("notes = %q", mc.Notes)
	}

	// Overriding KeepCipherID to pwItem still adopts pkOnly's key/passkey when pwItem has no sealed extras.
	adoptPlan := BuildPlan([]GroupSelection{{
		Group:        rep.SameSiteGroups()[0],
		KeepCipherID: "pw-1",
	}}, PlanOptions{})
	if len(adoptPlan.Errors) != 0 || len(adoptPlan.Groups) != 1 {
		t.Fatalf("adoptPlan = %+v", adoptPlan)
	}
	adopted := adoptPlan.Groups[0].MergedCipher
	if adopted.SealedKeyID != "key-a" || len(adopted.Login.Fido2Credentials) != 1 {
		t.Fatalf("adopted passkey/key missing: %+v", adopted)
	}

	// Conflicting sealed passkeys under two different per-cipher keys -> refused cleanly.
	pkOther := makeLogin("pk-2", "GitHub Passkey 2", "alice", "", "https://github.com")
	pkOther.Login.Fido2Credentials = []state.Fido2Credential{{CredentialID: "cred-b", Sealed: json.RawMessage(`{"credentialId":"b"}`)}}
	pkOther.SealedKeyID = "key-b"
	pkOther.Key = strPtr("2.key-b")
	conflictRep := Analyze([]*state.Cipher{pkOnly, pkOther})
	conflictPlan := BuildPlan([]GroupSelection{{Group: conflictRep.SameSiteGroups()[0]}}, PlanOptions{})
	if len(conflictPlan.Groups) != 0 || len(conflictPlan.Errors) != 1 {
		t.Fatalf("expected error for conflicting sealed passkey keys, got %+v", conflictPlan)
	}
}

func TestExecutePlan_InPlaceFailureAbort(t *testing.T) {
	withAtt := makeLogin("att-1", "Bank", "alice", "pw", "https://bank.com")
	withAtt.Attachments = []state.Attachment{{ID: "a-1", FileName: "doc.pdf"}}
	dup := makeLogin("dup-1", "Bank", "alice", "pw", "https://bank.com")
	dup.Notes = "extra"

	rep := Analyze([]*state.Cipher{withAtt, dup})
	plan := BuildPlan([]GroupSelection{{Group: rep.Groups[0]}}, PlanOptions{})
	stub := newMemoryVaultStub(withAtt, dup)
	stub.failSave = true
	res := ExecutePlan(context.Background(), stub, plan, nil)
	if res.FailedGroups != 1 || len(stub.delCalls) != 0 {
		t.Fatalf("in-place save failure should abort without deleting duplicate: %+v", res)
	}
}

type memSecretStore struct {
	mu sync.Mutex
	m  map[string]string
}

func newMemSecretStore() *memSecretStore { return &memSecretStore{m: map[string]string{}} }
func (s *memSecretStore) Get(k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *memSecretStore) Set(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}
func (s *memSecretStore) Delete(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
	return nil
}
