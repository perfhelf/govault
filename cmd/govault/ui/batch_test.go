package ui

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func seedBatchTestService(t *testing.T) *mockVaultService {
	t.Helper()
	svc := newMockVaultService(state.StatusUnlocked)
	svc.folders = []state.Folder{
		{ID: "f-work", Name: "Work"},
		{ID: "f-personal", Name: "Personal"},
	}
	work := "f-work"
	personal := "f-personal"
	deleted := time.Now().Add(-time.Hour)
	svc.ciphers["c-github"].FolderID = &work
	svc.ciphers["c-bank"] = &state.Cipher{
		ID:       "c-bank",
		Type:     api.CipherTypeLogin,
		Name:     "Bank",
		FolderID: &personal,
		Login:    &state.Login{Username: "alice", Password: "pw"},
	}
	svc.ciphers["c-ro"] = &state.Cipher{
		ID:         "c-ro",
		Type:       api.CipherTypeSecureNote,
		Name:       "Shared ReadOnly",
		ReadOnly:   true,
		SecureNote: &state.SecureNote{},
	}
	svc.collections = []state.Collection{
		{ID: "col-ro", OrganizationID: "org-1", Name: "RO Col", ReadOnly: true},
	}
	svc.organizations = []state.Organization{
		{ID: "org-1", Name: "Acme", Enabled: true},
	}
	orgID := "org-1"
	svc.ciphers["c-col-ro"] = &state.Cipher{
		ID:             "c-col-ro",
		Type:           api.CipherTypeSecureNote,
		Name:           "Collection ReadOnly",
		OrganizationID: &orgID,
		CollectionIDs:  []string{"col-ro"},
		SecureNote:     &state.SecureNote{},
	}
	svc.ciphers["c-tr1"] = &state.Cipher{
		ID:          "c-tr1",
		Type:        api.CipherTypeSecureNote,
		Name:        "Old Note 1",
		FolderID:    &work,
		DeletedDate: &deleted,
		SecureNote:  &state.SecureNote{},
	}
	svc.ciphers["c-tr2"] = &state.Cipher{
		ID:          "c-tr2",
		Type:        api.CipherTypeSecureNote,
		Name:        "Old Note 2",
		FolderID:    &work,
		DeletedDate: &deleted,
		SecureNote:  &state.SecureNote{},
	}
	svc.ciphers["c-tr-ro"] = &state.Cipher{
		ID:          "c-tr-ro",
		Type:        api.CipherTypeSecureNote,
		Name:        "Trashed ReadOnly",
		DeletedDate: &deleted,
		ReadOnly:    true,
		SecureNote:  &state.SecureNote{},
	}
	svc.order = []string{"c-github", "c-note", "c-bank", "c-ro", "c-col-ro", "c-tr1", "c-tr2", "c-tr-ro"}
	return svc
}

func TestBatchSelectAcrossViewsAndReadOnlyGuards(t *testing.T) {
	svc := seedBatchTestService(t)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})

	// Works in All Items: ReadOnly items have disabled checkboxes and are omitted from Select All.
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-action-bar", 2*time.Second)
	app.Find("id:batch-action-bar >> text:0 selected")
	app.Find("id:batch-checkbox-c-github")
	app.Find("id:batch-checkbox-c-note")
	app.Find("id:batch-checkbox-c-ro")
	if app.Enabled("id:batch-checkbox-c-ro") || app.Enabled("id:batch-checkbox-c-col-ro") {
		t.Fatal("read-only item checkbox is enabled in selection mode")
	}

	// Pressing a read-only row does not select it.
	app.Press("id:vault-row >> text:Shared ReadOnly")
	app.Settle()
	if m.BatchSelectedCount() != 0 {
		t.Fatalf("read-only row was selected: count=%d", m.BatchSelectedCount())
	}

	// Select All picks only the 3 editable items (c-github, c-note, c-bank).
	app.Press("id:batch-select-all")
	app.WaitFor("id:batch-action-bar >> text:3 selected", 2*time.Second)
	if m.IsBatchSelected("c-ro") || m.IsBatchSelected("c-col-ro") {
		t.Fatal("Select All included read-only items")
	}

	// Clear clears selection back to 0.
	app.Press("id:batch-clear")
	app.WaitFor("id:batch-action-bar >> text:0 selected", 2*time.Second)

	// Toggle individual items via checkbox and row.
	app.Press("id:batch-checkbox-c-github")
	app.WaitFor("id:batch-action-bar >> text:1 selected", 2*time.Second)
	app.Press("id:vault-row >> text:SSH Recovery Note")
	app.WaitFor("id:batch-action-bar >> text:2 selected", 2*time.Second)

	// Switching category clears selection mode & selected IDs: test Favorites, Folders, No Folder, Types, Trash.
	app.Press("id:sidebar-favorites")
	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() && m.BatchSelectedCount() == 0 })
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-github", 2*time.Second)

	app.Press("id:sidebar-no-folder")
	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() })
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-note", 2*time.Second)

	app.Press("id:sidebar-type-login")
	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() })
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-bank", 2*time.Second)

	app.Post(func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, FolderID: "f-work"}) })
	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() })
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-github", 2*time.Second)

	app.Press("id:sidebar-trash")
	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() })
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-restore-btn", 2*time.Second)
	app.Find("id:batch-hard-delete-btn")
}

func TestBatchMoveFolderAndSoftDeleteWorkflow(t *testing.T) {
	svc := seedBatchTestService(t)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})

	var alerts []core.AlertConfig
	var alertAnswer int
	app.OnAlert = func(cfg core.AlertConfig) int {
		alerts = append(alerts, cfg)
		return alertAnswer
	}

	// Move c-note (No Folder) and c-bank (Personal) to Work.
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-note", 2*time.Second)
	app.Press("id:batch-checkbox-c-note")
	app.Press("id:batch-checkbox-c-bank")
	app.WaitFor("id:batch-action-bar >> text:2 selected", 2*time.Second)

	app.Press("id:batch-move-folder-btn")
	app.WaitFor("id:batch-folder-dialog", 2*time.Second)
	app.Find("id:batch-folder-none")
	app.Press("id:batch-folder-option-f-work")

	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() })
	if c, _ := svc.GetCipher("c-note"); c.FolderID == nil || *c.FolderID != "f-work" {
		t.Fatalf("c-note folder = %v, want f-work", c.FolderID)
	}
	if c, _ := svc.GetCipher("c-bank"); c.FolderID == nil || *c.FolderID != "f-work" {
		t.Fatalf("c-bank folder = %v, want f-work", c.FolderID)
	}

	// Move c-github from Work to (No Folder) inside Folder view.
	app.Post(func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, FolderID: "f-work"}) })
	app.WaitFor("id:vault-item-list >> text:GitHub", 2*time.Second)
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-github", 2*time.Second)
	app.Press("id:batch-checkbox-c-github")
	app.Press("id:batch-move-folder-btn")
	app.WaitFor("id:batch-folder-none", 2*time.Second)
	app.Press("id:batch-folder-none")
	app.WaitForGone("id:vault-item-list >> text:GitHub", 2*time.Second)
	if c, _ := svc.GetCipher("c-github"); c.FolderID != nil {
		t.Fatalf("c-github folder after moving to No Folder = %v, want nil", *c.FolderID)
	}

	// Move to Trash requires confirmation: cancel leaves items intact, confirm moves to Trash.
	app.Press("id:sidebar-all")
	app.WaitFor("id:vault-item-list >> text:Bank", 2*time.Second)
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-bank", 2*time.Second)
	app.Press("id:batch-checkbox-c-bank")
	app.Press("id:batch-checkbox-c-note")

	alertAnswer = 0
	app.Press("id:batch-trash-btn")
	app.Settle()
	if len(alerts) != 1 {
		t.Fatalf("alerts shown = %d, want 1", len(alerts))
	}
	if c, _ := svc.GetCipher("c-bank"); c.DeletedDate != nil {
		t.Fatal("c-bank moved to trash despite cancelling confirm alert")
	}

	alertAnswer = 1
	app.Press("id:batch-trash-btn")
	app.WaitUntil(2*time.Second, func() bool {
		c1, _ := svc.GetCipher("c-bank")
		c2, _ := svc.GetCipher("c-note")
		return c1.DeletedDate != nil && c2.DeletedDate != nil && !m.BatchSelectMode.Get()
	})
}

func TestBatchTrashRestoreAndStrictPermanentDelete(t *testing.T) {
	svc := seedBatchTestService(t)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})

	var alerts []core.AlertConfig
	var alertAnswer int
	app.OnAlert = func(cfg core.AlertConfig) int {
		alerts = append(alerts, cfg)
		return alertAnswer
	}

	app.Press("id:sidebar-trash")
	app.WaitFor("id:vault-item-list >> text:Old Note 1", 2*time.Second)

	// Restore c-tr1 keeping its original folder (f-work).
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-tr1", 2*time.Second)
	app.Press("id:batch-checkbox-c-tr1")
	app.Press("id:batch-restore-btn")
	app.WaitFor("id:batch-folder-original", 2*time.Second)
	app.Find("id:batch-folder-none")
	app.Find("id:batch-folder-option-f-personal")
	app.Press("id:batch-folder-original")
	app.WaitUntil(2*time.Second, func() bool {
		c, _ := svc.GetCipher("c-tr1")
		return c.DeletedDate == nil && !m.BatchSelectMode.Get()
	})
	if c, _ := svc.GetCipher("c-tr1"); c.FolderID == nil || *c.FolderID != "f-work" {
		t.Fatalf("c-tr1 folder after original restore = %v, want f-work", c.FolderID)
	}

	// Restore c-tr2 into Personal folder.
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-tr2", 2*time.Second)
	app.Press("id:batch-checkbox-c-tr2")
	app.Press("id:batch-restore-btn")
	app.WaitFor("id:batch-folder-option-f-personal", 2*time.Second)
	app.Press("id:batch-folder-option-f-personal")
	app.WaitUntil(2*time.Second, func() bool {
		c, _ := svc.GetCipher("c-tr2")
		return c.DeletedDate == nil && c.FolderID != nil && *c.FolderID == "f-personal"
	})

	// Move c-tr1 and c-tr2 back to Trash for permanent delete test.
	svc.mu.Lock()
	now := time.Now()
	svc.ciphers["c-tr1"].DeletedDate = &now
	svc.ciphers["c-tr2"].DeletedDate = &now
	svc.mu.Unlock()
	app.Post(m.RefreshVaultData)
	app.WaitFor("id:vault-item-list >> text:Old Note 1", 2*time.Second)

	// Permanent delete requires strict destructive confirm alert; cancelling keeps items.
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-tr1", 2*time.Second)
	app.Press("id:batch-checkbox-c-tr1")
	app.Press("id:batch-checkbox-c-tr2")

	alertAnswer = 0
	app.Press("id:batch-hard-delete-btn")
	app.Settle()
	if len(alerts) != 1 || !strings.Contains(alerts[0].Message, "cannot be recovered") ||
		!slices.ContainsFunc(alerts[0].Actions, func(a core.AlertAction) bool { return a.Role == core.AlertDestructive }) {
		t.Fatalf("strict permanent delete alert missing expected copy/role: %+v", alerts)
	}
	if _, err := svc.GetCipher("c-tr1"); err != nil {
		t.Fatal("c-tr1 deleted after cancelling alert")
	}

	alertAnswer = 1
	app.Press("id:batch-hard-delete-btn")
	app.WaitUntil(2*time.Second, func() bool {
		_, e1 := svc.GetCipher("c-tr1")
		_, e2 := svc.GetCipher("c-tr2")
		return e1 != nil && e2 != nil && !m.BatchSelectMode.Get()
	})
	// Read-only item in Trash was untouched.
	if _, err := svc.GetCipher("c-tr-ro"); err != nil {
		t.Fatal("read-only trashed item was deleted")
	}
}

func TestBatchDisabledWhenOfflineOrLocalOnly(t *testing.T) {
	svc := seedBatchTestService(t)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})

	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-github", 2*time.Second)
	app.Press("id:batch-checkbox-c-github")
	app.WaitFor("id:batch-action-bar >> text:1 selected", 2*time.Second)
	if !app.Enabled("id:batch-move-folder-btn") || !app.Enabled("id:batch-trash-btn") {
		t.Fatal("batch buttons disabled when online")
	}

	// Offline disables batch mutations.
	app.Post(func() { m.SyncState.Set(SyncOffline) })
	app.Settle()
	if app.Enabled("id:batch-move-folder-btn") || app.Enabled("id:batch-trash-btn") {
		t.Fatal("batch mutations enabled while Offline")
	}
	app.Find("id:batch-action-bar >> text:Offline · edits disabled")

	// Back online enables them, then LocalOnly disables them again (including in Trash).
	app.Post(func() { m.SyncState.Set(SyncIdle) })
	app.Settle()
	if !app.Enabled("id:batch-move-folder-btn") {
		t.Fatal("batch buttons stayed disabled after coming back online")
	}

	svc.mu.Lock()
	svc.localOnly = true
	svc.mu.Unlock()
	app.Post(m.RefreshVaultData)
	app.Settle()
	if app.Enabled("id:batch-move-folder-btn") || app.Enabled("id:batch-trash-btn") {
		t.Fatal("batch mutations enabled while LocalOnly")
	}

	app.Press("id:sidebar-trash")
	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() })
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-tr1", 2*time.Second)
	app.Press("id:batch-checkbox-c-tr1")
	app.WaitFor("id:batch-action-bar >> text:1 selected", 2*time.Second)
	if app.Enabled("id:batch-restore-btn") || app.Enabled("id:batch-hard-delete-btn") {
		t.Fatal("trash batch mutations enabled while LocalOnly")
	}
}

func TestBatchSessionSafetyOnLockSleepLogoutRouteAndInFlight(t *testing.T) {
	svc := seedBatchTestService(t)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.OnAlert = func(core.AlertConfig) int { return 1 }

	// 1. Lock clears selection and open folder modal.
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-github", 2*time.Second)
	app.Press("id:batch-checkbox-c-github")
	app.Press("id:batch-move-folder-btn")
	app.WaitFor("id:batch-folder-dialog", 2*time.Second)
	app.Post(m.Lock)
	app.WaitFor("id:lock-screen", 2*time.Second)
	if m.BatchSelectMode.Get() || m.BatchSelectedCount() != 0 || m.BatchFolderDialog.Get().Open {
		t.Fatalf("batch state survived Lock: mode=%v count=%d dialog=%v", m.BatchSelectMode.Get(), m.BatchSelectedCount(), m.BatchFolderDialog.Get())
	}

	// Unlock again.
	app.Post(func() { m.LockPassword.Set("master-password"); m.UnlockWithPassword() })
	app.WaitFor("id:vault-shell", 2*time.Second)

	// 2. Sleep (LockOnSystemEvent) clears selection.
	app.Post(func() { m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p }) })
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-github", 2*time.Second)
	app.Press("id:batch-checkbox-c-github")
	app.Post(func() { m.LockOnSystemEvent() })
	app.WaitFor("id:lock-screen", 2*time.Second)
	if m.BatchSelectMode.Get() || m.BatchSelectedCount() != 0 {
		t.Fatal("batch state survived Sleep")
	}

	// Unlock again.
	app.Post(func() { m.LockPassword.Set("master-password"); m.UnlockWithPassword() })
	app.WaitFor("id:vault-shell", 2*time.Second)

	// 3. Switching route (to Settings) clears selection.
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-github", 2*time.Second)
	app.Press("id:batch-checkbox-c-github")
	app.Press("id:sidebar-settings")
	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() && m.BatchSelectedCount() == 0 })
	app.Press("id:sidebar-all")

	// 4. In-flight batch operation cancelled/ignored across Lock.
	gate := make(chan struct{})
	svc.mu.Lock()
	svc.batchGate = gate
	svc.mu.Unlock()

	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-note", 2*time.Second)
	app.Press("id:batch-checkbox-c-note")
	app.Press("id:batch-move-folder-btn")
	app.WaitFor("id:batch-folder-option-f-work", 2*time.Second)
	app.Press("id:batch-folder-option-f-work")
	app.WaitUntil(2*time.Second, func() bool { return m.BatchBusy.Get() })

	app.Post(m.Lock)
	app.WaitFor("id:lock-screen", 2*time.Second)
	close(gate)
	app.Settle()
	if m.BatchBusy.Get() || m.BatchSelectMode.Get() || m.BatchSelectedCount() != 0 {
		t.Fatal("in-flight lock did not clear batch busy/selection state")
	}
	svc.mu.Lock()
	svc.batchGate = nil
	svc.mu.Unlock()
	if c := svc.ciphers["c-note"]; c.FolderID != nil {
		t.Fatalf("locked in-flight batch move mutated c-note folder to %v", *c.FolderID)
	}

	// 5. Logout clears selection.
	app.Post(func() { m.LockPassword.Set("master-password"); m.UnlockWithPassword() })
	app.WaitFor("id:vault-shell", 2*time.Second)
	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-github", 2*time.Second)
	app.Press("id:batch-checkbox-c-github")
	app.WaitFor("id:batch-action-bar >> text:1 selected", 2*time.Second)
	app.Post(func() { m.Logout(root) })
	app.Settle()
	app.Answer(1)
	app.WaitFor("id:login-screen", 2*time.Second)
	if m.BatchSelectMode.Get() || m.BatchSelectedCount() != 0 {
		t.Fatal("batch state survived Logout")
	}
}

func TestBatchLocalCopyFailureUpdatesUIAndClearsSelection(t *testing.T) {
	svc := seedBatchTestService(t)
	svc.localCopyFails = true
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})

	app.Press("id:batch-select-toggle")
	app.WaitFor("id:batch-checkbox-c-note", 2*time.Second)
	app.Press("id:batch-checkbox-c-note")
	app.Press("id:batch-move-folder-btn")
	app.WaitFor("id:batch-folder-option-f-work", 2*time.Second)
	app.Press("id:batch-folder-option-f-work")
	app.WaitUntil(2*time.Second, func() bool { return !m.BatchSelectMode.Get() && !m.BatchBusy.Get() })

	if c, _ := svc.GetCipher("c-note"); c.FolderID == nil || *c.FolderID != "f-work" {
		t.Fatalf("c-note folder after LocalCopyError = %v, want f-work", c.FolderID)
	}
}
