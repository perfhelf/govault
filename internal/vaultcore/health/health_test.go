package health

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func login(id, password string, uris ...string) *state.Cipher {
	l := &state.Login{Username: id + "@example.com", Password: password}
	for _, u := range uris {
		l.URIs = append(l.URIs, state.LoginURI{URI: u})
	}
	return &state.Cipher{ID: id, Name: id, Type: api.CipherTypeLogin, Login: l}
}

func card(id, month, year string) *state.Cipher {
	return &state.Cipher{ID: id, Name: id, Type: api.CipherTypeCard, Card: &state.Card{Brand: "Visa", ExpMonth: month, ExpYear: year}}
}

func ids(items []Issue) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.CipherID
	}
	return out
}

func TestWeakReason(t *testing.T) {
	weak := map[string]string{
		"P@ssw0rd":           "Common password",
		"Summer2024!":        "Common password",
		"Xk9#mQ":             "Shorter than 10 characters",
		"abcdefghij1":        "Mostly a sequence or repeated characters",
		"aaaaaaaaaaaaaa":     "Mostly a sequence or repeated characters",
		"9182736450":         "Uses only one type of character",
		"kitchenwindow":      "Uses only one type of character",
		"abababababababab12": "Easy to guess",
	}
	for pw, want := range weak {
		if got := WeakReason(pw); got != want {
			t.Errorf("WeakReason(%q) = %q, want %q", pw, got, want)
		}
	}
	for _, pw := range []string{"x7#Kq9!vLm2@Pz4w&Rt8", "Tr0ub4dor&3x", "correct horse battery staple", "lantern-orbit-meadow-42"} {
		if got := WeakReason(pw); got != "" {
			t.Errorf("WeakReason(%q) = %q, want strong", pw, got)
		}
	}
}

func TestAnalyze(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	deleted := now.Add(-time.Hour)
	const shared = "Shared-Secret-Value-99"

	trashed := login("trashed", shared)
	trashed.DeletedDate = &deleted
	hidden := login("hidden", "password")
	hidden.HidePassword = true

	report := Analyze([]*state.Cipher{
		login("a", shared, "https://a.example.com"),
		login("b", shared, "http://b.example.com/login"),
		login("c", shared),
		login("d", "Unique-Strong-Pass-123!"),
		login("e", "qwerty"),
		login("local", "Local-Dev-Strong-1!", "http://localhost:8080", "http://127.0.0.1", "http://[::1]:3000", "http://printer.local"),
		trashed,
		hidden,
		card("expired", "04", "2026"),
		card("soon", "6", "26"),
		card("valid", "12", "2027"),
		card("nodate", "", ""),
	}, now)

	if len(report.Reused) != 1 || report.Reused[0].Count != 3 || len(report.Reused[0].Items) != 3 || report.Reused[0].Items[0].Detail != "Used in 3 items" {
		t.Fatalf("Reused = %+v", report.Reused)
	}
	for _, it := range report.Reused[0].Items {
		if it.Detail == shared || it.Subtitle == shared {
			t.Fatalf("report leaks the password: %+v", it)
		}
	}
	if got := ids(report.Weak); len(got) != 1 || got[0] != "e" {
		t.Fatalf("Weak = %v", got)
	}
	if got := ids(report.Unsecured); len(got) != 1 || got[0] != "b" || report.Unsecured[0].Detail != "http://b.example.com/login" {
		t.Fatalf("Unsecured = %+v", report.Unsecured)
	}
	if len(report.Cards) != 2 || report.Cards[0].CipherID != "expired" || !report.Cards[0].Expired || report.Cards[0].Detail != "Expired 04/2026" ||
		report.Cards[1].CipherID != "soon" || report.Cards[1].Expired || report.Cards[1].Detail != "Expires 06/2026" {
		t.Fatalf("Cards = %+v", report.Cards)
	}
	if got := ids(report.MissingURI); !slices.Equal(got, []string{"c", "d", "e", "hidden"}) {
		t.Fatalf("MissingURI = %v", got)
	}
	if report.TotalIssues() != 3+1+1+2+4 {
		t.Fatalf("TotalIssues = %d", report.TotalIssues())
	}
	if report.Score < 0 || report.Score >= 100 {
		t.Fatalf("Score = %d, want in [0, 99]", report.Score)
	}
	if (Report{}).TotalIssues() != 0 {
		t.Fatal("empty report has issues")
	}
	if empty := Analyze(nil, now); empty.Score != 100 || empty.TotalIssues() != 0 {
		t.Fatalf("empty Analyze = %+v, want Score=100 TotalIssues=0", empty)
	}
}

func TestAnalyzeEmptyPasswordsAndPasskeyExclusion(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	deleted := now.Add(-time.Hour)

	passkeyLogin := login("passkey", "", "https://passkey.example.com")
	passkeyLogin.Login.Fido2Credentials = []state.Fido2Credential{{CredentialID: "cred-1", RpID: "passkey.example.com"}}

	passkeySpace := login("passkey-space", "   ", "https://passkey2.example.com")
	passkeySpace.Login.Fido2Credentials = []state.Fido2Credential{{CredentialID: "cred-2"}}

	hiddenEmpty := login("hidden-empty", "", "https://hidden.example.com")
	hiddenEmpty.HidePassword = true

	trashedEmpty := login("trashed-empty", "", "https://trash.example.com")
	trashedEmpty.DeletedDate = &deleted

	report := Analyze([]*state.Cipher{
		login("empty", "", "https://empty.example.com"),
		login("spaces", "  \t ", "https://spaces.example.com"),
		passkeyLogin,
		passkeySpace,
		hiddenEmpty,
		trashedEmpty,
	}, now)

	if got := ids(report.Empty); !slices.Equal(got, []string{"empty", "spaces"}) {
		t.Fatalf("Empty = %v, want [empty spaces]", got)
	}
	if len(report.Weak) != 0 || len(report.Reused) != 0 || len(report.Stale) != 0 {
		t.Fatalf("empty passwords leaked into weak/reused/stale: weak=%v reused=%v stale=%v", report.Weak, report.Reused, report.Stale)
	}
}

func TestAnalyzeStalePasswords(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	old400d := now.Add(-400 * 24 * time.Hour)
	old800d := now.Add(-800 * 24 * time.Hour)
	exact365d := now.Add(-StaleWindow)
	justOver := now.Add(-StaleWindow - time.Second)
	recent := now.Add(-30 * 24 * time.Hour)

	cExact := login("a-exact", "Strong-Unique-Pass-1!", "https://a.example.com")
	cExact.Login.PasswordRevisionDate = &exact365d

	cJustOver := login("b-over", "Strong-Unique-Pass-2!", "https://b.example.com")
	cJustOver.Login.PasswordRevisionDate = &justOver

	cPwRecentRevOld := login("c-pw-recent", "Strong-Unique-Pass-3!", "https://c.example.com")
	cPwRecentRevOld.Login.PasswordRevisionDate = &recent
	cPwRecentRevOld.RevisionDate = &old800d

	cPwOldRevRecent := login("d-pw-old", "Strong-Unique-Pass-4!", "https://d.example.com")
	cPwOldRevRecent.Login.PasswordRevisionDate = &old800d
	cPwOldRevRecent.RevisionDate = &recent

	cFallback := login("e-fallback", "Strong-Unique-Pass-5!", "https://e.example.com")
	cFallback.RevisionDate = &old400d

	cNoDate := login("f-nodate", "Strong-Unique-Pass-6!", "https://f.example.com")

	cHidden := login("g-hidden", "Strong-Unique-Pass-7!", "https://g.example.com")
	cHidden.HidePassword = true
	cHidden.RevisionDate = &old800d

	cEmptyOld := login("h-empty", "", "https://h.example.com")
	cEmptyOld.RevisionDate = &old800d

	report := Analyze([]*state.Cipher{
		cExact, cJustOver, cPwRecentRevOld, cPwOldRevRecent, cFallback, cNoDate, cHidden, cEmptyOld,
	}, now)

	if got := ids(report.Stale); !slices.Equal(got, []string{"b-over", "d-pw-old", "e-fallback"}) {
		t.Fatalf("Stale = %v, want [b-over d-pw-old e-fallback]", got)
	}
	if report.Stale[0].Detail != "Unchanged for 365 days" {
		t.Fatalf("b-over detail = %q", report.Stale[0].Detail)
	}
	if report.Stale[1].Detail != "Unchanged for 2 years" {
		t.Fatalf("d-pw-old detail = %q", report.Stale[1].Detail)
	}
}

func TestAnalyzeMissingURIAndMissingNameAndArchivedSemantics(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	archived := now.Add(-48 * time.Hour)
	deleted := now.Add(-24 * time.Hour)

	noURI := login("a-nouri", "Strong-Unique-Pass-1!")
	blankURI := login("b-blankuri", "Strong-Unique-Pass-2!", "   ", "\t")
	mixedURI := login("c-mixeduri", "Strong-Unique-Pass-3!", "", "https://ok.example.com")

	untitledLogin := &state.Cipher{ID: "d-untitled-login", Type: api.CipherTypeLogin, Name: "   ", Login: &state.Login{Username: "u@example.com", Password: "Strong-Unique-Pass-4!", URIs: []state.LoginURI{{URI: "https://u.example.com"}}}}
	untitledNote := &state.Cipher{ID: "e-untitled-note", Type: api.CipherTypeSecureNote, Name: "", SecureNote: &state.SecureNote{}}
	untitledCard := &state.Cipher{ID: "f-untitled-card", Type: api.CipherTypeCard, Name: "", Card: &state.Card{Brand: "Visa", ExpMonth: "12", ExpYear: "2030"}}
	untitledIdent := &state.Cipher{ID: "g-untitled-ident", Type: api.CipherTypeIdentity, Name: "", Identity: &state.Identity{Email: "id@example.com"}}
	untitledSSH := &state.Cipher{ID: "h-untitled-ssh", Type: api.CipherTypeSSHKey, Name: "", SSHKey: &state.SSHKey{KeyFingerprint: "SHA256:abc"}}

	archivedItem := login("i-archived", "weak", "http://archived.example.com")
	archivedItem.Name = ""
	archivedItem.ArchivedDate = &archived

	trashedItem := login("j-trashed", "weak")
	trashedItem.Name = ""
	trashedItem.DeletedDate = &deleted

	report := Analyze([]*state.Cipher{
		noURI, blankURI, mixedURI,
		untitledLogin, untitledNote, untitledCard, untitledIdent, untitledSSH,
		archivedItem, trashedItem,
	}, now)

	if got := ids(report.MissingURI); !slices.Equal(got, []string{"a-nouri", "b-blankuri"}) {
		t.Fatalf("MissingURI = %v", got)
	}
	wantUnnamed := []string{"d-untitled-login", "e-untitled-note", "f-untitled-card", "g-untitled-ident", "h-untitled-ssh", "i-archived"}
	if got := ids(report.MissingName); !slices.Equal(got, wantUnnamed) {
		t.Fatalf("MissingName = %v, want %v", got, wantUnnamed)
	}
	if !slices.Contains(ids(report.Weak), "i-archived") || !slices.Contains(ids(report.Unsecured), "i-archived") {
		t.Fatalf("archived item should remain analyzed consistently: weak=%v unsecured=%v", ids(report.Weak), ids(report.Unsecured))
	}
	if slices.Contains(ids(report.Weak), "j-trashed") || slices.Contains(ids(report.MissingURI), "j-trashed") {
		t.Fatalf("trashed item should be skipped")
	}
}

func TestAnalyzeReportUnreadableAndScoreBounds(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	deleted := now.Add(-time.Hour)

	trashedOnly := login("t", "weak")
	trashedOnly.DeletedDate = &deleted
	if r := AnalyzeReport([]*state.Cipher{trashedOnly}, nil, now); r.ActiveItems != 0 || r.TotalIssues() != 0 || r.Score != 100 {
		t.Fatalf("trashed-only report = %+v, want ActiveItems=0 TotalIssues=0 Score=100", r)
	}

	unreadableOnly := AnalyzeReport(nil, []string{"u-2", " u-1 ", "", "u-2"}, now)
	if got := ids(unreadableOnly.Unreadable); !slices.Equal(got, []string{"u-1", "u-2"}) {
		t.Fatalf("Unreadable = %v, want [u-1 u-2]", got)
	}
	if unreadableOnly.ActiveItems != 2 || unreadableOnly.TotalIssues() != 2 || unreadableOnly.Score >= 100 || unreadableOnly.Score < 0 {
		t.Fatalf("unreadableOnly = %+v", unreadableOnly)
	}

	// Healthy vault gives 100.
	healthy := []*state.Cipher{
		login("ok1", "X9#vLm2!pQ7@zR4w&Kt6", "https://ok1.example.com"),
		login("ok2", "M4$nB8*cV2^xZ9!qW5eR", "https://ok2.example.com"),
	}
	if r := AnalyzeReport(healthy, nil, now); r.Score != 100 || r.TotalIssues() != 0 {
		t.Fatalf("healthy score = %d total=%d", r.Score, r.TotalIssues())
	}

	// Large vault with a single low issue stays < 100 and >= 0.
	many := make([]*state.Cipher, 0, 120)
	for i := range 120 {
		id := string(rune('a'+i/26)) + string(rune('a'+i%26))
		pw := "Strong-Unique-Pass-" + id + "-99!"
		if i == 0 {
			many = append(many, login("missing-uri", pw))
		} else {
			many = append(many, login(id, pw, "https://"+id+".example.com"))
		}
	}
	rMany := AnalyzeReport(many, nil, now)
	if rMany.TotalIssues() != 1 || rMany.Score >= 100 || rMany.Score < 0 {
		t.Fatalf("large vault with 1 issue: score=%d total=%d", rMany.Score, rMany.TotalIssues())
	}

	// Heavily compromised vault clamps at 0.
	old := now.Add(-900 * 24 * time.Hour)
	bad1 := &state.Cipher{ID: "bad1", Type: api.CipherTypeLogin, RevisionDate: &old, Login: &state.Login{Password: "1234", URIs: []state.LoginURI{{URI: "http://bad1.example.com"}}}}
	bad2 := &state.Cipher{ID: "bad2", Type: api.CipherTypeLogin, RevisionDate: &old, Login: &state.Login{Password: "1234"}}
	rBad := AnalyzeReport([]*state.Cipher{bad1, bad2}, []string{"u1", "u2"}, now)
	if rBad.Score != 0 {
		t.Fatalf("heavily compromised Score = %d, want clamped 0", rBad.Score)
	}
	if rBad.HighRisk()+rBad.MediumRisk()+rBad.LowRisk() != rBad.TotalIssues() {
		t.Fatalf("risk sum %d+%d+%d != TotalIssues %d", rBad.HighRisk(), rBad.MediumRisk(), rBad.LowRisk(), rBad.TotalIssues())
	}
}

func TestNoNetworkOrGUIImportsInHealthPackage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range astFile.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(p, "net/http") || strings.HasPrefix(p, "net/rpc") ||
				strings.Contains(p, "nsgo") || strings.Contains(p, "/api") && p != "github.com/txchen/govault/internal/vaultcore/api" {
				t.Fatalf("disallowed import %q in %s", p, f)
			}
		}
	}
}
