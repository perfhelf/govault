package ui

import (
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestHealthViewCountsAndOpensFlaggedItem(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	add := func(c *state.Cipher) {
		svc.ciphers[c.ID] = c
		svc.order = append(svc.order, c.ID)
	}
	add(&state.Cipher{ID: "c-gitlab", Type: api.CipherTypeLogin, Name: "GitLab", Login: &state.Login{Password: "gh-secret-password"}})
	add(&state.Cipher{ID: "c-router", Type: api.CipherTypeLogin, Name: "Router", Login: &state.Login{Password: "admin", URIs: []state.LoginURI{{URI: "http://router.example.net"}}}})
	add(&state.Cipher{ID: "c-old-card", Type: api.CipherTypeCard, Name: "Old Card", Card: &state.Card{ExpMonth: "1", ExpYear: "2020"}})

	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 900))

	app.WaitFor("id:sidebar-health >> text:6", 2*time.Second)
	app.Press("id:sidebar-health")
	app.WaitFor("id:health-view", 2*time.Second)
	app.Find("id:health-score-card")
	app.Find("id:health-score-value")
	app.Find("id:health-score-tier")
	for id, want := range map[string]string{
		"reused":       "2",
		"weak":         "1",
		"empty":        "0",
		"stale":        "0",
		"cards":        "1",
		"unsecured":    "1",
		"missing-uri":  "1",
		"missing-name": "0",
		"unreadable":   "0",
	} {
		app.Find("id:health-count-" + id + " >> text:" + want)
	}
	app.Find("id:health-view >> text:Expired 01/2020")
	app.Find("id:health-view >> text:Checked on this device only. Nothing is sent to a server.")
	if app.Exists("id:health-view >> text:gh-secret-password") {
		t.Fatal("health view shows a raw password")
	}

	app.Press("id:health-view >> text:Router >> nth=0")
	app.WaitUntil(2*time.Second, func() bool { c := model.ActiveCipher.Get(); return c != nil && c.ID == "c-router" })
	app.WaitFor("id:detail-view >> text:Router", 2*time.Second)
	if model.Route.Get() != RouteVault || model.SelectedID.Get() != "c-router" {
		t.Fatalf("route=%v selected=%q", model.Route.Get(), model.SelectedID.Get())
	}

	app.Post(func() {
		svc.ciphers["c-router"].Login.Password = "x7#Kq9!vLm2@Pz4w&Rt8"
		svc.ciphers["c-router"].Login.URIs = []state.LoginURI{{URI: "https://router.example.net"}}
		svc.ciphers["c-gitlab"].Login.Password = "Unique-Strong-Pass-123!"
		svc.ciphers["c-gitlab"].Login.URIs = []state.LoginURI{{URI: "https://gitlab.example.com"}}
		svc.ciphers["c-old-card"].DeletedDate = &time.Time{}
		model.RefreshVaultData()
		model.Route.Set(RouteHealth)
	})
	app.WaitFor("id:health-all-clear", 2*time.Second)
	if got := app.Find("id:health-score-value").Text; got != "100" {
		t.Fatalf("health-score-value = %q, want 100", got)
	}
	if got := app.Find("id:health-score-tier").Text; got != "Strong" {
		t.Fatalf("health-score-tier = %q, want Strong", got)
	}
	if app.Exists("id:sidebar-health-badge") {
		t.Fatal("badge shown with no issues")
	}
}

func TestHealthExpandedCategoriesScoreAndUnreadableSync(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Login.Password = "Strong-Unique-GitHub-1!"
	old := time.Now().Add(-400 * 24 * time.Hour)
	svc.unreadable = []string{"u-item-1"}

	add := func(c *state.Cipher) {
		svc.ciphers[c.ID] = c
		svc.order = append(svc.order, c.ID)
	}
	add(&state.Cipher{
		ID:   "c-empty",
		Type: api.CipherTypeLogin,
		Name: "Empty Entry",
		Login: &state.Login{
			Username: "empty@example.com",
			URIs:     []state.LoginURI{{URI: "https://empty.example.com"}},
		},
	})
	add(&state.Cipher{
		ID:   "c-passkey",
		Type: api.CipherTypeLogin,
		Name: "Passkey Entry",
		Login: &state.Login{
			Username:         "pk@example.com",
			URIs:             []state.LoginURI{{URI: "https://passkey.example.com"}},
			Fido2Credentials: []state.Fido2Credential{{CredentialID: "cred-1", RpID: "passkey.example.com"}},
		},
	})
	add(&state.Cipher{
		ID:   "c-stale",
		Type: api.CipherTypeLogin,
		Name: "Stale Entry",
		Login: &state.Login{
			Username:             "stale@example.com",
			Password:             "Unique-Strong-Stale-1!",
			PasswordRevisionDate: &old,
			URIs:                 []state.LoginURI{{URI: "https://stale.example.com"}},
		},
	})
	add(&state.Cipher{
		ID:   "c-no-uri",
		Type: api.CipherTypeLogin,
		Name: "Missing URI Entry",
		Login: &state.Login{
			Username: "nouri@example.com",
			Password: "Unique-Strong-NoURI-1!",
		},
	})
	add(&state.Cipher{
		ID:         "c-no-title",
		Type:       api.CipherTypeSecureNote,
		Name:       "",
		SecureNote: &state.SecureNote{},
	})

	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 900))

	app.Press("id:sidebar-health")
	app.WaitFor("id:health-view", 2*time.Second)

	for id, want := range map[string]string{
		"empty":        "1",
		"stale":        "1",
		"missing-uri":  "1",
		"missing-name": "1",
		"unreadable":   "1",
	} {
		app.Find("id:health-count-" + id + " >> text:" + want + " >> nth=0")
	}
	app.Find("id:health-count-stale >> text:Stale (>1y)")
	if app.Exists("id:health-view >> text:Passkey Entry") {
		t.Fatal("passkey-only login should not appear as an empty password issue")
	}

	app.Find("id:health-score-card")
	if got := app.Find("id:health-score-value").Text; got != "73" {
		t.Fatalf("health-score-value = %q, want 73", got)
	}
	if got := app.Find("id:health-score-tier").Text; got != "Fair" {
		t.Fatalf("health-score-tier = %q, want Fair", got)
	}
	app.Find("id:health-breakdown-high >> text:High risk: 2")
	app.Find("id:health-breakdown-medium >> text:Medium risk: 1")
	app.Find("id:health-breakdown-low >> text:Low risk: 2")
	app.Find("id:health-unreadable-subtitle")
	app.Find("id:health-unreadable-sync")

	// Filter to Missing Title and check Untitled rendering.
	app.Press("id:health-count-missing-name")
	app.WaitForGone("id:health-view >> text:Stale Entry", 2*time.Second)
	app.Find("id:health-view >> text:Untitled")

	// Filter to Stale, open item, then use Back to verify HealthFilter restoration.
	app.Press("id:health-count-stale")
	app.WaitFor("id:health-view >> text:Stale Entry", 2*time.Second)
	app.WaitForGone("id:health-view >> text:Untitled", 2*time.Second)
	app.Press("id:health-view >> text:Stale Entry >> nth=0")
	app.WaitUntil(2*time.Second, func() bool {
		return model.Route.Get() == RouteVault && model.SelectedID.Get() == "c-stale"
	})
	app.Press("id:toolbar-back")
	app.WaitFor("id:health-view", 2*time.Second)
	if model.HealthFilter.Get() != HealthStale {
		t.Fatalf("HealthFilter after Back = %q, want %q", model.HealthFilter.Get(), HealthStale)
	}

	// Filter to Unreadable and trigger Sync Now.
	app.Press("id:health-count-unreadable")
	app.WaitFor("id:health-unreadable-item", 2*time.Second)
	app.Press("id:health-unreadable-sync")
	app.WaitUntil(2*time.Second, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		return svc.syncCalls == 1
	})
	app.WaitUntil(2*time.Second, func() bool { return model.SyncState.Get() == SyncIdle })
	app.Find("id:health-view >> text:Checked on this device only. Nothing is sent to a server.")
}
