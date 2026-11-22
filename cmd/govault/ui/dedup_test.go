package ui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/dedup"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func addMockCipher(svc *mockVaultService, c *state.Cipher) {
	svc.ciphers[c.ID] = c
	svc.order = append(svc.order, c.ID)
}

func newDedupTestService() *mockVaultService {
	svc := newMockVaultService(state.StatusUnlocked)
	// Remove default c-github so we control the exact dataset cleanly.
	delete(svc.ciphers, "c-github")
	svc.order = []string{"c-note"}

	// 1. Exact Path A (100% identical)
	addMockCipher(svc, &state.Cipher{
		ID:   "ex-a1",
		Type: api.CipherTypeLogin,
		Name: "Proton Mail",
		Login: &state.Login{
			Username: "alice@proton.me",
			Password: "secret-proton-password",
			URIs:     []state.LoginURI{{URI: "https://mail.proton.me"}},
		},
	})
	addMockCipher(svc, &state.Cipher{
		ID:   "ex-a2",
		Type: api.CipherTypeLogin,
		Name: "Proton Mail",
		Login: &state.Login{
			Username: "ALICE@proton.me",
			Password: "secret-proton-password",
			URIs:     []state.LoginURI{{URI: "https://mail.proton.me"}},
		},
	})

	// 2. Exact Path B (passkey + extra TOTP/notes)
	addMockCipher(svc, &state.Cipher{
		ID:   "ex-b1",
		Type: api.CipherTypeLogin,
		Name: "GitHub",
		Login: &state.Login{
			Username:         "alice",
			Password:         "secret-gh-password",
			URIs:             []state.LoginURI{{URI: "https://github.com/login"}},
			Fido2Credentials: []state.Fido2Credential{{CredentialID: "cred-gh-1", RpID: "github.com", Sealed: json.RawMessage(`{"credentialId":"2.pk"}`)}},
		},
	})
	addMockCipher(svc, &state.Cipher{
		ID:    "ex-b2",
		Type:  api.CipherTypeLogin,
		Name:  "GitHub 中文",
		Notes: "Backup recovery note",
		Login: &state.Login{
			Username: "alice",
			Password: "secret-gh-password",
			TOTP:     "SECRET-TOTP-KEY",
			URIs:     []state.LoginURI{{URI: "https://gist.github.com/auth"}},
		},
	})

	// 3. Same-site duplicate group
	addMockCipher(svc, &state.Cipher{
		ID:   "ss-1",
		Type: api.CipherTypeLogin,
		Name: "Portal Work",
		Login: &state.Login{
			Username: "work@example.co.uk",
			Password: "secret-work-password",
			URIs:     []state.LoginURI{{URI: "https://sso.example.co.uk"}},
		},
	})
	addMockCipher(svc, &state.Cipher{
		ID:   "ss-2",
		Type: api.CipherTypeLogin,
		Name: "Portal Personal",
		Login: &state.Login{
			Username: "personal@example.co.uk",
			Password: "secret-personal-password",
			URIs:     []state.LoginURI{{URI: "https://app.example.co.uk"}},
		},
	})

	// 4. Read-only organization duplicate group (blocked)
	orgID := "org-1"
	svc.organizations = []state.Organization{{ID: orgID, Name: "Acme", Enabled: true}}
	svc.collections = []state.Collection{{ID: "col-ro", OrganizationID: orgID, Name: "Shared", ReadOnly: true}}
	addMockCipher(svc, &state.Cipher{
		ID:             "ro-1",
		Type:           api.CipherTypeLogin,
		Name:           "Acme CI",
		OrganizationID: &orgID,
		CollectionIDs:  []string{"col-ro"},
		Login: &state.Login{
			Username: "ci-bot",
			Password: "secret-ci-password",
			URIs:     []state.LoginURI{{URI: "https://ci.acme.example"}},
		},
	})
	addMockCipher(svc, &state.Cipher{
		ID:             "ro-2",
		Type:           api.CipherTypeLogin,
		Name:           "Acme CI Copy",
		OrganizationID: &orgID,
		CollectionIDs:  []string{"col-ro"},
		Login: &state.Login{
			Username: "ci-bot",
			Password: "secret-ci-password",
			URIs:     []state.LoginURI{{URI: "https://ci.acme.example"}},
		},
	})

	return svc
}

func TestDedupView_SummaryTiles_Filters_And_NoRawSecrets(t *testing.T) {
	svc := newDedupTestService()
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1150, 900))

	// 3 exact groups (Proton, GitHub, Acme CI) + 1 same-site group (example.co.uk) -> 4 redundant items.
	app.WaitFor("id:sidebar-dedup >> text:4", 2*time.Second)
	app.Press("id:sidebar-dedup")
	app.WaitFor("id:dedup-view", 2*time.Second)

	app.Find("id:dedup-count-exact >> text:3")
	app.Find("id:dedup-count-samesite >> text:1")
	app.Find("id:dedup-count-redundant >> text:4")

	// Badges and blocked status are shown.
	app.Find("id:dedup-view >> text:Path A · Pure Delete >> nth=0")
	app.Find("id:dedup-view >> text:Path B · Merge >> nth=0")
	app.Find("id:dedup-view >> text:Read-Only >> nth=0")
	app.Find("id:dedup-view >> text:Contains a read-only organization item")
	app.Find("id:dedup-view >> text:TOTP >> nth=0")
	app.Find("id:dedup-view >> text:Notes >> nth=0")

	// Never expose raw passwords or TOTP secrets.
	for _, secret := range []string{"secret-proton-password", "secret-gh-password", "secret-work-password", "secret-ci-password", "SECRET-TOTP-KEY"} {
		if app.Exists("id:dedup-view >> text:" + secret) {
			t.Fatalf("dedup-view leaked secret %q", secret)
		}
	}

	// Tile filter toggles to Same-Site, hiding Exact groups, and navigates cleanly with Back/Forward.
	app.Press("id:dedup-count-samesite")
	app.WaitForGone("id:dedup-item-ex-a1", 2*time.Second)
	app.Find("id:dedup-view >> text:example.co.uk >> nth=0")

	// Inspecting an item jumps to Vault and Back restores Dedup + filter.
	app.Press("id:dedup-item-ss-1")
	app.WaitUntil(2*time.Second, func() bool {
		return model.Route.Get() == RouteVault && model.SelectedID.Get() == "ss-1"
	})
	app.Press("id:toolbar-back")
	app.WaitFor("id:dedup-view", 2*time.Second)
	if model.DedupFilter.Get() != DedupSameSite || app.Exists("id:dedup-item-ex-a1") {
		t.Fatalf("Back lost DedupFilter: %q", model.DedupFilter.Get())
	}

	// Toggle tile back to All.
	app.Press("id:dedup-count-samesite")
	app.WaitFor("id:dedup-item-ex-a1", 2*time.Second)
}

func TestDedupView_MergeSelected_ConfirmAlert_And_PasskeySafety(t *testing.T) {
	svc := newDedupTestService()
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1150, 900))

	alerts := []int{0, 1} // First cancel, then confirm.
	var seenMessages []string
	app.OnAlert = func(cfg core.AlertConfig) int {
		seenMessages = append(seenMessages, cfg.Message)
		a := alerts[0]
		alerts = alerts[1:]
		return a
	}

	app.Press("id:sidebar-dedup")
	app.WaitFor("id:dedup-view", 2*time.Second)

	// Uncheck Proton exact group so only GitHub Path B merges, toggle Simplify URLs on.
	var protonGroupID, githubGroupID string
	for _, g := range model.DedupReport.Get().Groups {
		if strings.Contains(g.Label, "Proton") {
			protonGroupID = g.ID
		}
		if g.MatchKey == "github.com" {
			githubGroupID = g.ID
		}
	}
	if protonGroupID == "" || githubGroupID == "" {
		t.Fatalf("missing expected groups: %+v", model.DedupReport.Get().Groups)
	}

	app.Press("id:dedup-group-check-" + protonGroupID)
	app.Press("id:dedup-simplify-urls")
	app.WaitUntil(2*time.Second, func() bool {
		return !model.DedupSelected.Get()[protonGroupID] && model.DedupSimplifyURLs.Get()
	})

	// First click: cancel confirm alert -> nothing changes.
	app.Press("id:dedup-merge-btn")
	app.WaitUntil(2*time.Second, func() bool { return len(seenMessages) == 1 })
	if svc.creates != 0 {
		t.Fatal("cancelling confirm alert triggered create")
	}

	// Second click: confirm -> executes merge!
	app.Press("id:dedup-merge-btn")
	app.WaitFor("id:dedup-result-summary", 3*time.Second)

	if svc.creates != 1 {
		t.Fatalf("creates = %d, want 1", svc.creates)
	}
	created, err := svc.GetCipher("c-new")
	if err != nil {
		t.Fatalf("created cipher missing: %v", err)
	}
	if created.Name != "GitHub 中文" || created.Login.TOTP != "SECRET-TOTP-KEY" {
		t.Fatalf("merged fields wrong: %+v", created)
	}
	if len(created.Login.Fido2Credentials) != 1 || created.Login.Fido2Credentials[0].CredentialID != "cred-gh-1" {
		t.Fatalf("passkey lost on merge: %+v", created.Login.Fido2Credentials)
	}
	if len(created.Login.URIs) != 1 || created.Login.URIs[0].URI != "https://github.com" {
		t.Fatalf("SimplifyURLs not applied: %+v", created.Login.URIs)
	}
	if !strings.Contains(created.Notes, "Backup recovery note") || !strings.Contains(created.Notes, "Previous titles before merge: GitHub") {
		t.Fatalf("notes not merged cleanly: %q", created.Notes)
	}
	if ex1, _ := svc.GetCipher("ex-b1"); ex1.DeletedDate == nil {
		t.Fatal("ex-b1 was not soft-deleted")
	}
	if ex2, _ := svc.GetCipher("ex-b2"); ex2.DeletedDate == nil {
		t.Fatal("ex-b2 was not soft-deleted")
	}
	// Proton remained untouched because it was unchecked.
	if p1, _ := svc.GetCipher("ex-a1"); p1.DeletedDate != nil {
		t.Fatal("unchecked Proton item was deleted")
	}

	// Dismiss result card.
	app.Press("id:dedup-result-dismiss")
	app.WaitForGone("id:dedup-result-summary", 2*time.Second)

	// Verify keep-item selector works on remaining Proton group.
	app.Press("id:dedup-group-check-" + protonGroupID)
	app.Press("id:dedup-keep-" + protonGroupID)
	app.WaitFor("id:dedup-keep-"+protonGroupID+"-1", 2*time.Second)
	app.Press("id:dedup-keep-" + protonGroupID + "-1")
	app.WaitUntil(2*time.Second, func() bool {
		return model.DedupKeepIDs.Get()[protonGroupID] == "ex-a2"
	})
}

func TestDedupView_OfflineAndLocalOnlyDisableMerge(t *testing.T) {
	svc := newDedupTestService()
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1150, 900))

	alerts := 0
	app.OnAlert = func(core.AlertConfig) int { alerts++; return 1 }

	app.Press("id:sidebar-dedup")
	app.WaitFor("id:dedup-view", 2*time.Second)
	if !app.Enabled("id:dedup-merge-btn") {
		t.Fatal("merge button disabled while online")
	}

	app.Post(func() { model.SyncState.Set(SyncOffline) })
	app.WaitFor("id:dedup-offline-banner >> text:Offline", 2*time.Second)
	app.Settle()
	if app.Enabled("id:dedup-merge-btn") || app.Enabled("id:dedup-simplify-urls") || app.Enabled("id:dedup-select-exact") {
		t.Fatal("merge actions enabled while offline")
	}

	app.Post(func() {
		model.SyncState.Set(SyncIdle)
		svc.localOnly = true
		model.RefreshVaultData()
	})
	app.WaitFor("id:dedup-offline-banner >> text:local-only", 2*time.Second)
	app.Settle()
	if app.Enabled("id:dedup-merge-btn") || app.Enabled("id:dedup-simplify-urls") || app.Enabled("id:dedup-select-exact") {
		t.Fatal("merge actions enabled while local-only")
	}
	_ = alerts
}

func TestDedupView_LockCancelsActiveMergeAndClearsState(t *testing.T) {
	svc := newDedupTestService()
	gate := make(chan struct{})
	svc.saveGate = gate

	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1150, 900))
	app.OnAlert = func(core.AlertConfig) int { return 1 }

	app.Press("id:sidebar-dedup")
	app.WaitFor("id:dedup-view", 2*time.Second)

	var githubGroup dedup.Group
	for _, g := range model.DedupReport.Get().Groups {
		if g.MatchKey == "github.com" {
			githubGroup = g
		}
	}

	app.Post(func() {
		model.executeDedupMerge([]dedup.GroupSelection{{Group: githubGroup}})
	})
	app.WaitFor("id:dedup-progress", 2*time.Second)

	gen := model.LockGeneration()
	app.Post(model.Lock)
	app.WaitFor("id:lock-screen", 2*time.Second)
	close(gate)
	time.Sleep(50 * time.Millisecond)
	app.Settle()

	if model.StillUnlocked(gen) {
		t.Fatal("generation remained unlocked after Lock")
	}
	if model.DedupBusy.Get() || len(model.DedupReport.Get().Groups) != 0 || model.DedupResult.Get() != nil || len(model.DedupSelected.Get()) != 0 {
		t.Fatalf("dedup state survived lock: busy=%v groups=%d res=%v sel=%v",
			model.DedupBusy.Get(), len(model.DedupReport.Get().Groups), model.DedupResult.Get(), model.DedupSelected.Get())
	}
	if model.Route.Get() != RouteVault {
		t.Fatalf("route = %v, want RouteVault after lock", model.Route.Get())
	}
}
