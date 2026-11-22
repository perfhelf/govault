package ui

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/urlcheck"
)

type uiRoundTripFunc func(*http.Request) (*http.Response, error)

func (f uiRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func uiResp(req *http.Request, code int) *http.Response {
	return &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}
}

func startURLCheckApp(t *testing.T, svc *mockVaultService, opts func() urlcheck.Options) (*nsgotest.App, *AppModel) {
	t.Helper()
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.urlCheckOpts = opts
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 860))
	return app, model
}

func TestURLCheckOptInPrivacyScanNavigateAndTrash(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	org := "org-1"
	svc.organizations = []state.Organization{{ID: org, Name: "Acme", Enabled: true}}
	svc.collections = []state.Collection{{ID: "col-ro", OrganizationID: org, Name: "Shared", ReadOnly: true}}
	svc.ciphers = map[string]*state.Cipher{
		"c-alive": {
			ID:   "c-alive",
			Type: api.CipherTypeLogin,
			Name: "Live App",
			Login: &state.Login{
				Username: "alive-user",
				Password: "super-secret-password-1",
				URIs:     []state.LoginURI{{URI: "https://alive.example.net/login?secret=1"}},
			},
		},
		"c-404": {
			ID:   "c-404",
			Type: api.CipherTypeLogin,
			Name: "Old Forum",
			Login: &state.Login{
				Username: "forum-user",
				Password: "super-secret-password-2",
				URIs:     []state.LoginURI{{URI: "https://forum.example.net/users/login?next=/home"}},
			},
		},
		"c-dns": {
			ID:   "c-dns",
			Type: api.CipherTypeLogin,
			Name: "Vanished Site",
			Login: &state.Login{
				Username: "vanished-user",
				Password: "super-secret-password-3",
				URIs:     []state.LoginURI{{URI: "https://user:pass@gone.example.net/account#tab"}},
			},
		},
		"c-ro": {
			ID:             "c-ro",
			Type:           api.CipherTypeLogin,
			Name:           "Shared Broken",
			OrganizationID: &org,
			CollectionIDs:  []string{"col-ro"},
			Login: &state.Login{
				Username: "shared-user",
				URIs:     []state.LoginURI{{URI: "https://tlsfail.example.net/"}},
			},
		},
	}
	svc.order = []string{"c-alive", "c-404", "c-dns", "c-ro"}

	var probeHits atomic.Int32
	var mu sync.Mutex
	var requestedURLs []string
	client := &http.Client{
		Transport: uiRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			probeHits.Add(1)
			mu.Lock()
			requestedURLs = append(requestedURLs, r.Method+" "+r.URL.String())
			mu.Unlock()
			switch r.URL.Host {
			case "alive.example.net":
				return uiResp(r, http.StatusOK), nil
			case "forum.example.net":
				return uiResp(r, http.StatusNotFound), nil
			case "gone.example.net":
				return nil, &net.DNSError{Err: "no such host", Name: r.URL.Host, IsNotFound: true}
			case "tlsfail.example.net":
				return nil, &tls.CertificateVerificationError{Err: errors.New("expired cert")}
			default:
				return uiResp(r, http.StatusOK), nil
			}
		}),
	}

	app, model := startURLCheckApp(t, svc, func() urlcheck.Options {
		return urlcheck.Options{HTTPClient: client, Timeout: time.Second}
	})

	// Strictly opt-in: unlocking and refreshing vault data must trigger 0 network probes.
	app.Settle()
	if probeHits.Load() != 0 {
		t.Fatalf("probed %d times before pressing Scan Websites", probeHits.Load())
	}

	app.Press("id:sidebar-urlcheck")
	app.WaitFor("id:urlcheck-idle", 2*time.Second)
	app.Find("id:urlcheck-privacy-notice")
	app.Find("text:" + urlCheckPrivacyNotice)
	app.Settle()
	if probeHits.Load() != 0 {
		t.Fatalf("probed %d times just by opening Website Check view", probeHits.Load())
	}

	// Start scan explicitly.
	app.Press("id:urlcheck-scan-btn")
	app.WaitFor("id:urlcheck-results", 2*time.Second)
	app.WaitFor("id:sidebar-urlcheck >> text:3", 2*time.Second)

	// Verify badges and privacy (only root URLs probed, no secrets displayed).
	app.Find("id:urlcheck-badge-c-404 >> text:HTTP 404")
	app.Find("id:urlcheck-badge-c-dns >> text:DNS not found")
	app.Find("id:urlcheck-badge-c-ro >> text:TLS error")
	if app.Exists("id:urlcheck-view >> text:Live App") {
		t.Fatal("alive item shown in dead list")
	}
	if app.Exists("id:urlcheck-view >> text:super-secret-password-2") {
		t.Fatal("password leaked in urlcheck view")
	}
	mu.Lock()
	for _, u := range requestedURLs {
		if strings.Contains(u, "secret") || strings.Contains(u, "users/login") || strings.Contains(u, "pass@") {
			t.Fatalf("privacy violation in probed URL: %q", u)
		}
	}
	mu.Unlock()

	// Read-only collection item's Move to Trash button must be disabled.
	if app.Enabled("id:urlcheck-trash-c-ro") {
		t.Fatal("Move to Trash enabled on read-only item")
	}
	if !app.Enabled("id:urlcheck-trash-c-404") {
		t.Fatal("Move to Trash disabled on writable online item")
	}

	// Offline guard disables Move to Trash.
	app.Post(func() { model.SyncState.Set(SyncOffline) })
	app.Settle()
	if app.Enabled("id:urlcheck-trash-c-404") {
		t.Fatal("Move to Trash enabled while offline")
	}
	app.Post(func() { model.SyncState.Set(SyncIdle) })
	app.Settle()
	if !app.Enabled("id:urlcheck-trash-c-404") {
		t.Fatal("Move to Trash stayed disabled after coming back online")
	}

	// Click item row to jump to item in Vault, then use Back to return.
	app.Press("id:urlcheck-open-c-404")
	app.WaitFor("id:detail-view >> text:Old Forum", 2*time.Second)
	if model.Route.Get() != RouteVault || model.SelectedID.Get() != "c-404" {
		t.Fatalf("route=%v selected=%q", model.Route.Get(), model.SelectedID.Get())
	}

	app.Press("id:toolbar-back")
	app.WaitFor("id:urlcheck-results", 2*time.Second)
	if !model.CanGoForward.Get() {
		t.Fatal("Forward unavailable after returning to Website Check")
	}
	app.Press("id:toolbar-forward")
	app.WaitFor("id:detail-view >> text:Old Forum", 2*time.Second)
	app.Press("id:toolbar-back")
	app.WaitFor("id:urlcheck-results", 2*time.Second)

	// LocalOnly guard also disables Move to Trash.
	app.Post(func() { model.LocalOnly.Set(true) })
	app.Settle()
	if app.Enabled("id:urlcheck-trash-c-404") {
		t.Fatal("Move to Trash enabled while LocalOnly")
	}
	app.Post(func() { model.LocalOnly.Set(false) })
	app.Settle()

	// Quick Move to Trash removes the item from results and moves it to Trash.
	app.Press("id:urlcheck-trash-c-404")
	app.WaitForGone("id:urlcheck-open-c-404", 2*time.Second)
	app.WaitFor("id:sidebar-urlcheck >> text:2", 2*time.Second)
	if c, _ := svc.GetCipher("c-404"); c == nil || c.DeletedDate == nil {
		t.Fatalf("c-404 not soft-deleted: %+v", c)
	}

	// Scan Again runs another check cleanly.
	prevHits := probeHits.Load()
	app.Press("id:urlcheck-rescan-btn")
	app.WaitUntil(2*time.Second, func() bool {
		return model.URLCheckPhase.Get() == URLCheckDone && probeHits.Load() > prevHits
	})
}

func TestURLCheckScanningProgressCancelAndAllClear(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers = map[string]*state.Cipher{
		"c-1": {ID: "c-1", Type: api.CipherTypeLogin, Name: "One", Login: &state.Login{URIs: []state.LoginURI{{URI: "https://one.example.net"}}}},
		"c-2": {ID: "c-2", Type: api.CipherTypeLogin, Name: "Two", Login: &state.Login{URIs: []state.LoginURI{{URI: "https://two.example.net"}}}},
	}
	svc.order = []string{"c-1", "c-2"}

	gate := make(chan struct{})
	var reqCount atomic.Int32
	client := &http.Client{
		Transport: uiRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if reqCount.Add(1) == 2 {
				select {
				case <-gate:
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}
			}
			return uiResp(r, http.StatusOK), nil
		}),
	}

	app, model := startURLCheckApp(t, svc, func() urlcheck.Options {
		return urlcheck.Options{Concurrency: 1, Timeout: 5 * time.Second, HTTPClient: client}
	})

	app.Press("id:sidebar-urlcheck")
	app.WaitFor("id:urlcheck-scan-btn", 2*time.Second)
	app.Press("id:urlcheck-scan-btn")

	app.WaitFor("id:urlcheck-scanning", 2*time.Second)
	app.WaitFor("id:urlcheck-scanning >> text:1 / 2", 2*time.Second)
	app.Find("id:urlcheck-progress-bar")

	// Cancel mid-scan returns to idle.
	app.Press("id:urlcheck-cancel-btn")
	app.WaitFor("id:urlcheck-idle", 2*time.Second)
	if model.URLCheckPhase.Get() != URLCheckIdle || len(model.URLCheckReport.Get().Dead) != 0 {
		t.Fatalf("after cancel: phase=%v dead=%d", model.URLCheckPhase.Get(), len(model.URLCheckReport.Get().Dead))
	}
	close(gate)

	// Re-scan and verify Escape key also cancels an active scan.
	gate2 := make(chan struct{})
	var reqCount2 atomic.Int32
	client2 := &http.Client{
		Transport: uiRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if reqCount2.Add(1) == 2 {
				select {
				case <-gate2:
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}
			}
			return uiResp(r, http.StatusOK), nil
		}),
	}
	app.Post(func() {
		model.urlCheckOpts = func() urlcheck.Options {
			return urlcheck.Options{Concurrency: 1, Timeout: 5 * time.Second, HTTPClient: client2}
		}
	})
	app.Settle()
	app.Press("id:urlcheck-scan-btn")
	app.WaitFor("id:urlcheck-scanning", 2*time.Second)
	app.Key("escape")
	app.WaitFor("id:urlcheck-idle", 2*time.Second)
	close(gate2)
	app.Post(func() {
		model.urlCheckOpts = func() urlcheck.Options {
			return urlcheck.Options{Concurrency: 1, Timeout: 5 * time.Second, HTTPClient: client}
		}
	})
	app.Settle()

	// Re-scan to completion -> All websites reachable.
	app.Press("id:urlcheck-scan-btn")
	app.WaitFor("id:urlcheck-all-clear", 2*time.Second)
	if app.Exists("id:sidebar-urlcheck-badge") {
		t.Fatal("badge shown when all websites are reachable")
	}
}

func TestURLCheckCancelsAndWipesOnLockLogoutAndSleep(t *testing.T) {
	for _, mode := range []string{"lock", "logout", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			svc := newMockVaultService(state.StatusUnlocked)
			svc.ciphers = map[string]*state.Cipher{
				"c-1": {ID: "c-1", Type: api.CipherTypeLogin, Name: "Held", Login: &state.Login{URIs: []state.LoginURI{{URI: "https://held.example.net"}}}},
			}
			svc.order = []string{"c-1"}

			ctxCanceled := make(chan struct{})
			release := make(chan struct{})
			client := &http.Client{
				Transport: uiRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					select {
					case <-r.Context().Done():
						close(ctxCanceled)
						return nil, r.Context().Err()
					case <-release:
						return uiResp(r, http.StatusNotFound), nil
					}
				}),
			}

			app, model := startURLCheckApp(t, svc, func() urlcheck.Options {
				return urlcheck.Options{Timeout: 5 * time.Second, HTTPClient: client}
			})

			app.Press("id:sidebar-urlcheck")
			app.WaitFor("id:urlcheck-scan-btn", 2*time.Second)
			app.Press("id:urlcheck-scan-btn")
			app.WaitFor("id:urlcheck-scanning", 2*time.Second)

			switch mode {
			case "lock":
				app.Post(model.Lock)
				app.WaitFor("id:lock-screen", 2*time.Second)
			case "logout":
				svc.mu.Lock()
				svc.status = state.StatusLoggedOut
				svc.mu.Unlock()
				app.Post(func() { model.ServiceLeftUnlocked(state.StatusLoggedOut) })
				app.WaitFor("id:login-screen", 2*time.Second)
			case "sleep":
				app.Post(func() {
					model.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
					model.LockOnSystemEvent()
				})
				app.WaitFor("id:lock-screen", 2*time.Second)
			}

			select {
			case <-ctxCanceled:
			case <-time.After(2 * time.Second):
				t.Fatal("active scan context was not canceled on " + mode)
			}
			close(release)
			app.Settle()

			if model.URLCheckPhase.Get() != URLCheckIdle || len(model.URLCheckReport.Get().Dead) != 0 {
				t.Fatalf("after %s: phase=%v dead=%d", mode, model.URLCheckPhase.Get(), len(model.URLCheckReport.Get().Dead))
			}
		})
	}
}

func TestURLCheckLiveServerOfflineIntegration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers = map[string]*state.Cipher{
		"c-srv": {
			ID:   "c-srv",
			Type: api.CipherTypeLogin,
			Name: "Local Test Server",
			Login: &state.Login{
				Username: "tester",
				URIs:     []state.LoginURI{{URI: srv.URL + "/secret?a=b"}},
			},
		},
	}
	svc.order = []string{"c-srv"}

	app, _ := startURLCheckApp(t, svc, func() urlcheck.Options {
		return urlcheck.Options{IncludePrivate: true, HTTPClient: srv.Client()}
	})

	app.Press("id:sidebar-urlcheck")
	app.WaitFor("id:urlcheck-scan-btn", 2*time.Second)
	app.Press("id:urlcheck-scan-btn")
	app.WaitFor("id:urlcheck-badge-c-srv >> text:HTTP 404", 2*time.Second)
}

func TestURLCheckInvalidURLBadgeAndArchivedJump(t *testing.T) {
	archivedAt := time.Now()
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers = map[string]*state.Cipher{
		"c-bad-arch": {
			ID:           "c-bad-arch",
			Type:         api.CipherTypeLogin,
			Name:         "Archived Bad URL",
			ArchivedDate: &archivedAt,
			Login: &state.Login{
				Username: "arch",
				URIs:     []state.LoginURI{{URI: "https://bad host.invalid/path"}},
			},
		},
	}
	svc.order = []string{"c-bad-arch"}

	app, model := startURLCheckApp(t, svc, func() urlcheck.Options {
		return urlcheck.Options{
			HTTPClient: &http.Client{
				Transport: uiRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					t.Fatalf("unexpected probe for invalid URL: %s", r.URL.String())
					return nil, errors.New("unexpected")
				}),
			},
		}
	})

	app.Press("id:sidebar-urlcheck")
	app.WaitFor("id:urlcheck-scan-btn", 2*time.Second)
	app.Press("id:urlcheck-scan-btn")
	app.WaitFor("id:urlcheck-badge-c-bad-arch >> text:Invalid URL", 2*time.Second)

	app.Press("id:urlcheck-open-c-bad-arch")
	app.WaitFor("id:detail-view >> text:Archived Bad URL", 2*time.Second)
	if model.SidebarFilter.Get().Category != state.FilterArchive {
		t.Fatalf("category = %v, want FilterArchive", model.SidebarFilter.Get().Category)
	}
}

func TestURLCheckBatchMoveToFolderAndTrashAndGuards(t *testing.T) {
	work := "f-work"
	archiveOld := "f-old"
	orgID := "org-1"

	svc := newMockVaultService(state.StatusUnlocked)
	svc.folders = []state.Folder{
		{ID: work, Name: "Work"},
		{ID: archiveOld, Name: "Old Sites"},
	}
	svc.organizations = []state.Organization{
		{ID: orgID, Name: "Acme", Enabled: true},
	}
	svc.order = []string{"c-dead-1", "c-dead-2", "c-dead-3", "c-dead-ro"}
	svc.ciphers = map[string]*state.Cipher{
		"c-dead-1": {
			ID:       "c-dead-1",
			Type:     api.CipherTypeLogin,
			Name:     "Dead One",
			FolderID: &work,
			Login: &state.Login{
				Username: "alice",
				Password: "pw1",
				URIs:     []state.LoginURI{{URI: "https://dead1.example.test"}},
			},
		},
		"c-dead-2": {
			ID:   "c-dead-2",
			Type: api.CipherTypeLogin,
			Name: "Dead Two",
			Login: &state.Login{
				Username: "bob",
				Password: "pw2",
				URIs:     []state.LoginURI{{URI: "https://dead2.example.test"}},
			},
		},
		"c-dead-3": {
			ID:   "c-dead-3",
			Type: api.CipherTypeLogin,
			Name: "Dead Three",
			Login: &state.Login{
				Username: "carol",
				Password: "pw3",
				URIs:     []state.LoginURI{{URI: "https://dead3.example.test"}},
			},
		},
		"c-dead-ro": {
			ID:             "c-dead-ro",
			Type:           api.CipherTypeLogin,
			Name:           "ReadOnly Dead",
			OrganizationID: &orgID,
			ReadOnly:       true,
			Login: &state.Login{
				Username: "shared",
				Password: "pw4",
				URIs:     []state.LoginURI{{URI: "https://dead-ro.example.test"}},
			},
		},
	}

	app, model := startURLCheckApp(t, svc, func() urlcheck.Options {
		return urlcheck.Options{
			Concurrency: 2,
			Timeout:     time.Second,
			LookupHost: func(context.Context, string) ([]string, error) {
				return []string{"93.184.216.34"}, nil
			},
			HTTPClient: &http.Client{
				Transport: uiRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					return uiResp(r, http.StatusNotFound), nil
				}),
			},
		}
	})

	var alerts []core.AlertConfig
	var alertAnswer int
	app.OnAlert = func(cfg core.AlertConfig) int {
		alerts = append(alerts, cfg)
		return alertAnswer
	}

	app.Press("id:sidebar-urlcheck")
	app.WaitFor("id:urlcheck-scan-btn", 2*time.Second)
	app.Press("id:urlcheck-scan-btn")
	app.WaitFor("id:urlcheck-batch-bar", 2*time.Second)
	app.WaitFor("id:urlcheck-check-c-dead-ro", 2*time.Second)

	// Read-only item checkbox is disabled; batch actions disabled at 0 selected; hint warns readonly omitted.
	app.Find("id:urlcheck-batch-bar >> text:0 selected")
	app.Find("id:urlcheck-batch-bar >> text:View-only omitted")
	if app.Enabled("id:urlcheck-check-c-dead-ro") {
		t.Fatal("read-only Dead URL checkbox unexpectedly enabled")
	}
	if app.Enabled("id:urlcheck-batch-move") || app.Enabled("id:urlcheck-batch-trash") {
		t.Fatal("Dead URL batch actions enabled with 0 selected")
	}

	// Select All selects all 3 editable dead items and skips the read-only item.
	app.Press("id:urlcheck-select-all")
	app.WaitFor("id:urlcheck-batch-bar >> text:3 selected", 2*time.Second)
	if !model.IsURLCheckSelected("c-dead-1") || !model.IsURLCheckSelected("c-dead-2") ||
		!model.IsURLCheckSelected("c-dead-3") || model.IsURLCheckSelected("c-dead-ro") {
		t.Fatalf("unexpected Select All set: %+v", model.URLCheckSelectedIDs.Get())
	}
	if !app.Enabled("id:urlcheck-batch-move") || !app.Enabled("id:urlcheck-batch-trash") {
		t.Fatal("Dead URL batch actions disabled despite editable selection")
	}

	// Clear resets selection cleanly.
	app.Press("id:urlcheck-clear-selection")
	app.WaitFor("id:urlcheck-batch-bar >> text:0 selected", 2*time.Second)

	// Offline and LocalOnly disable both single-row Trash and bulk Move/Trash.
	app.Press("id:urlcheck-check-c-dead-1")
	app.WaitFor("id:urlcheck-batch-bar >> text:1 selected", 2*time.Second)

	app.Post(func() { model.SyncState.Set(SyncOffline) })
	app.Settle()
	if app.Enabled("id:urlcheck-batch-move") || app.Enabled("id:urlcheck-batch-trash") || app.Enabled("id:urlcheck-trash-c-dead-1") {
		t.Fatal("Dead URL mutations enabled while Offline")
	}
	app.Find("id:urlcheck-batch-bar >> text:Offline · edits disabled")

	app.Post(func() { model.SyncState.Set(SyncIdle) })
	app.Settle()
	if !app.Enabled("id:urlcheck-batch-move") || !app.Enabled("id:urlcheck-batch-trash") {
		t.Fatal("Dead URL batch actions remained disabled after returning online")
	}

	svc.mu.Lock()
	svc.localOnly = true
	svc.mu.Unlock()
	app.Post(model.RefreshVaultData)
	app.Settle()
	if app.Enabled("id:urlcheck-batch-move") || app.Enabled("id:urlcheck-batch-trash") || app.Enabled("id:urlcheck-trash-c-dead-1") {
		t.Fatal("Dead URL mutations enabled while LocalOnly")
	}
	app.Find("id:urlcheck-batch-bar >> text:Sign in again to edit")

	svc.mu.Lock()
	svc.localOnly = false
	svc.mu.Unlock()
	app.Post(model.RefreshVaultData)
	app.Settle()

	// Bulk Move to Folder moves c-dead-1 and c-dead-2 into Old Sites while keeping all Dead rows visible.
	app.Press("id:urlcheck-check-c-dead-2")
	app.WaitFor("id:urlcheck-batch-bar >> text:2 selected", 2*time.Second)
	app.Press("id:urlcheck-batch-move")
	app.WaitFor("id:batch-folder-dialog", 2*time.Second)
	app.Find("id:batch-folder-none")
	app.Press("id:batch-folder-option-f-old")
	app.WaitUntil(2*time.Second, func() bool {
		c1, _ := svc.GetCipher("c-dead-1")
		c2, _ := svc.GetCipher("c-dead-2")
		return c1.FolderID != nil && *c1.FolderID == archiveOld &&
			c2.FolderID != nil && *c2.FolderID == archiveOld &&
			!model.URLCheckBatchBusy.Get() && model.URLCheckSelectedCount() == 0
	})
	if c3, _ := svc.GetCipher("c-dead-3"); c3.FolderID != nil {
		t.Fatalf("unselected c-dead-3 folder changed to %v", *c3.FolderID)
	}
	if len(model.URLCheckReport.Get().Dead) != 4 {
		t.Fatalf("Dead rows after folder move = %d, want 4", len(model.URLCheckReport.Get().Dead))
	}

	// Bulk Move to Trash: cancelling alert preserves items and selection; confirming trashes and prunes rows.
	app.Press("id:urlcheck-check-c-dead-2")
	app.Press("id:urlcheck-check-c-dead-3")
	app.WaitFor("id:urlcheck-batch-bar >> text:2 selected", 2*time.Second)

	alertAnswer = 0
	app.Press("id:urlcheck-batch-trash")
	app.Settle()
	if len(alerts) != 1 || alerts[0].Title != "Move 2 items to Trash?" {
		t.Fatalf("unexpected cancel alert: %+v", alerts)
	}
	if c2, _ := svc.GetCipher("c-dead-2"); c2.DeletedDate != nil {
		t.Fatal("c-dead-2 moved to Trash despite cancelling alert")
	}
	app.Find("id:urlcheck-batch-bar >> text:2 selected")

	alertAnswer = 1
	app.Press("id:urlcheck-batch-trash")
	app.WaitUntil(2*time.Second, func() bool {
		c2, _ := svc.GetCipher("c-dead-2")
		c3, _ := svc.GetCipher("c-dead-3")
		return c2.DeletedDate != nil && c3.DeletedDate != nil &&
			!model.URLCheckBatchBusy.Get() && model.URLCheckSelectedCount() == 0
	})
	if dead := model.URLCheckReport.Get().Dead; len(dead) != 2 {
		t.Fatalf("remaining Dead items = %d, want 2 (%+v)", len(dead), dead)
	}
	if ro, _ := svc.GetCipher("c-dead-ro"); ro.DeletedDate != nil {
		t.Fatal("read-only Dead URL item was deleted")
	}

	// Escape clears selection.
	app.Press("id:urlcheck-check-c-dead-1")
	app.WaitFor("id:urlcheck-batch-bar >> text:1 selected", 2*time.Second)
	app.Key("escape")
	app.WaitFor("id:urlcheck-batch-bar >> text:0 selected", 2*time.Second)

	// Switching route clears selection.
	app.Press("id:urlcheck-check-c-dead-1")
	app.WaitFor("id:urlcheck-batch-bar >> text:1 selected", 2*time.Second)
	app.Press("id:sidebar-all")
	app.WaitUntil(2*time.Second, func() bool {
		return model.Route.Get() == RouteVault && model.URLCheckSelectedCount() == 0
	})

	// Rescan clears selection, and Lock wipes scan + selection.
	app.Press("id:sidebar-urlcheck")
	app.WaitFor("id:urlcheck-check-c-dead-1", 2*time.Second)
	app.Press("id:urlcheck-check-c-dead-1")
	app.WaitFor("id:urlcheck-batch-bar >> text:1 selected", 2*time.Second)
	app.Press("id:urlcheck-rescan-btn")
	app.WaitFor("id:urlcheck-batch-bar", 2*time.Second)
	app.Find("id:urlcheck-batch-bar >> text:0 selected")

	app.Press("id:urlcheck-check-c-dead-1")
	app.WaitFor("id:urlcheck-batch-bar >> text:1 selected", 2*time.Second)
	app.Post(model.Lock)
	app.WaitUntil(2*time.Second, func() bool {
		return model.LockState.Get() == state.StatusLocked &&
			model.URLCheckSelectedCount() == 0 &&
			!model.URLCheckBatchBusy.Get() &&
			model.URLCheckPhase.Get() == URLCheckIdle
	})
}
