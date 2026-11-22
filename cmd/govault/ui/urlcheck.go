package ui

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/urlcheck"
)

// URLCheckPhase tracks the opt-in website reachability scan lifecycle.
type URLCheckPhase int

const (
	URLCheckIdle URLCheckPhase = iota
	URLCheckScanning
	URLCheckDone
)

const urlCheckPrivacyNotice = "Checks whether login website domains are reachable directly from this device. Only hostnames are contacted; URL paths and vault secrets are never sent. Major sites and local/private addresses are skipped."

// StartURLCheck begins an opt-in website reachability scan for active Login
// items. It is bound to the current unlocked vault session and never starts
// automatically on login, unlock, or sync.
func (m *AppModel) StartURLCheck() {
	if m.LockState.Get() != state.StatusUnlocked || m.URLCheckPhase.Get() == URLCheckScanning {
		return
	}
	m.ResetIdleTimer()

	ctx, sessCancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	gen := m.LockGeneration()

	m.urlCheckMu.Lock()
	if m.urlCheckCancel != nil {
		m.urlCheckCancel()
	}
	m.urlCheckOp++
	op := m.urlCheckOp
	m.urlCheckCancel = sessCancel
	m.urlCheckMu.Unlock()

	ciphers := m.Core.AllCiphers()
	for _, c := range ciphers {
		c.ReadOnly = c.ReadOnly || m.CipherReadOnly(c)
	}

	var opts urlcheck.Options
	if m.urlCheckOpts != nil {
		opts = m.urlCheckOpts()
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = urlcheck.DefaultConcurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = urlcheck.DefaultTimeout
	}
	opts.OnProgress = func(p urlcheck.Progress) {
		if m.LockGeneration() != gen {
			return
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.urlCheckMu.Lock()
			active := m.urlCheckOp == op
			m.urlCheckMu.Unlock()
			if !active || m.URLCheckPhase.Get() != URLCheckScanning {
				return
			}
			m.URLCheckProgress.Set(p)
		})
	}

	m.clearURLCheckSelection()
	m.URLCheckReport.Set(urlcheck.Report{})
	m.URLCheckProgress.Set(urlcheck.Progress{})
	m.URLCheckPhase.Set(URLCheckScanning)

	go func() {
		defer sessCancel()
		report := urlcheck.Scan(ctx, ciphers, opts)
		if m.LockGeneration() != gen {
			return
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.urlCheckMu.Lock()
			active := m.urlCheckOp == op
			if active {
				m.urlCheckCancel = nil
			}
			m.urlCheckMu.Unlock()
			if !active || m.URLCheckPhase.Get() != URLCheckScanning {
				return
			}
			if report.Canceled {
				m.URLCheckProgress.Set(urlcheck.Progress{})
				m.URLCheckReport.Set(urlcheck.Report{})
				m.URLCheckPhase.Set(URLCheckIdle)
				return
			}
			m.URLCheckReport.Set(report)
			m.URLCheckPhase.Set(URLCheckDone)
		})
	}()
}

// CancelURLCheck stops any active website scan and returns to the idle screen.
func (m *AppModel) CancelURLCheck() {
	m.ResetIdleTimer()
	m.cancelURLCheck()
	m.clearURLCheckSelection()
	m.URLCheckProgress.Set(urlcheck.Progress{})
	m.URLCheckReport.Set(urlcheck.Report{})
	m.URLCheckPhase.Set(URLCheckIdle)
}

func (m *AppModel) cancelURLCheck() {
	m.urlCheckMu.Lock()
	m.urlCheckOp++
	cancel := m.urlCheckCancel
	m.urlCheckCancel = nil
	m.urlCheckMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// clearURLCheck cancels any in-flight scan and wipes all cached results on
// lock, logout, or system sleep.
func (m *AppModel) clearURLCheck() {
	m.cancelURLCheck()
	m.URLCheckBusyID.Set("")
	m.URLCheckBatchBusy.Set(false)
	m.clearURLCheckSelection()
	m.URLCheckProgress.Set(urlcheck.Progress{})
	m.URLCheckReport.Set(urlcheck.Report{})
	m.URLCheckPhase.Set(URLCheckIdle)
}

func (m *AppModel) IsURLCheckSelected(id string) bool {
	sel := m.URLCheckSelectedIDs.Get()
	return sel != nil && sel[id]
}

func (m *AppModel) URLCheckSelectedCount() int {
	return len(m.URLCheckSelectedIDs.Get())
}

func (m *AppModel) URLCheckSelectableCount() int {
	n := 0
	for _, it := range m.URLCheckReport.Get().Dead {
		if !it.ReadOnly {
			n++
		}
	}
	return n
}

func (m *AppModel) URLCheckHasReadOnly() bool {
	for _, it := range m.URLCheckReport.Get().Dead {
		if it.ReadOnly {
			return true
		}
	}
	return false
}

func (m *AppModel) SetURLCheckItemSelected(id string, selected bool) {
	if id == "" || m.LockState.Get() != state.StatusUnlocked || m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != "" {
		return
	}
	m.ResetIdleTimer()
	if selected {
		var found bool
		for _, it := range m.URLCheckReport.Get().Dead {
			if it.CipherID == id {
				if it.ReadOnly {
					return
				}
				found = true
				break
			}
		}
		if !found {
			return
		}
		if c, err := m.Core.GetCipher(id); err != nil || c.DeletedDate != nil || m.CipherReadOnly(c) {
			return
		}
	}
	cur := m.URLCheckSelectedIDs.Get()
	if (cur != nil && cur[id]) == selected {
		return
	}
	next := maps.Clone(cur)
	if next == nil {
		next = make(map[string]bool)
	}
	if selected {
		next[id] = true
	} else {
		delete(next, id)
	}
	if len(next) == 0 {
		next = nil
	}
	m.URLCheckSelectedIDs.Set(next)
}

func (m *AppModel) SelectAllURLCheck() {
	if m.LockState.Get() != state.StatusUnlocked || m.URLCheckPhase.Get() != URLCheckDone || m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != "" {
		return
	}
	m.ResetIdleTimer()
	next := make(map[string]bool)
	for _, it := range m.URLCheckReport.Get().Dead {
		if it.ReadOnly {
			continue
		}
		if c, err := m.Core.GetCipher(it.CipherID); err == nil && c.DeletedDate == nil && !m.CipherReadOnly(c) {
			next[it.CipherID] = true
		}
	}
	if len(next) == 0 {
		next = nil
	}
	m.URLCheckSelectedIDs.Set(next)
}

func (m *AppModel) ClearURLCheckSelection() {
	if m.URLCheckBatchBusy.Get() {
		return
	}
	m.ResetIdleTimer()
	m.clearURLCheckSelection()
}

func (m *AppModel) clearURLCheckSelection() {
	if len(m.URLCheckSelectedIDs.Get()) > 0 {
		m.URLCheckSelectedIDs.Set(nil)
	}
}

func (m *AppModel) selectedEditableURLCheckIDs() []string {
	sel := m.URLCheckSelectedIDs.Get()
	if len(sel) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(sel))
	var ids []string
	for _, it := range m.URLCheckReport.Get().Dead {
		if !sel[it.CipherID] || seen[it.CipherID] || it.ReadOnly {
			continue
		}
		seen[it.CipherID] = true
		if c, err := m.Core.GetCipher(it.CipherID); err == nil && c.DeletedDate == nil && !m.CipherReadOnly(c) {
			ids = append(ids, it.CipherID)
		}
	}
	return ids
}

func (m *AppModel) OpenURLCheckBatchMoveDialog() {
	if m.LockState.Get() != state.StatusUnlocked || m.URLCheckPhase.Get() != URLCheckDone ||
		m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != "" || m.BatchMutationsDisabled() {
		return
	}
	if len(m.selectedEditableURLCheckIDs()) == 0 {
		return
	}
	m.ResetIdleTimer()
	m.BatchFolderDialog.Set(BatchFolderModal{Open: true, Mode: BatchFolderURLCheckMove})
}

func (m *AppModel) ExecuteURLCheckBatchMoveFolder(folderID *string) {
	if m.LockState.Get() != state.StatusUnlocked || m.URLCheckBatchBusy.Get() || m.BatchMutationsDisabled() {
		return
	}
	ids := m.selectedEditableURLCheckIDs()
	if len(ids) == 0 {
		m.CloseBatchFolderDialog()
		return
	}
	var target *string
	if folderID != nil && *folderID != "" {
		v := *folderID
		target = &v
	}
	m.CloseBatchFolderDialog()
	n := len(ids)
	m.runURLCheckBatchMutation(
		ids,
		false,
		false,
		m.batchCountText("batch.moved_one", "batch.moved_many", n),
		m.T("batch.move_folder_failed"),
		func(ctx context.Context) error {
			return m.Core.BulkMoveFolder(ctx, ids, target)
		},
	)
}

func (m *AppModel) ConfirmURLCheckBatchSoftDelete(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked || m.URLCheckPhase.Get() != URLCheckDone ||
		m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != "" || m.BatchMutationsDisabled() {
		return
	}
	ids := m.selectedEditableURLCheckIDs()
	n := len(ids)
	if n == 0 {
		return
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   m.batchCountText("batch.trash_confirm_title_one", "batch.trash_confirm_title_many", n),
		Message: m.batchCountText("batch.trash_confirm_msg_one", "batch.trash_confirm_msg_many", n),
		Actions: []core.AlertAction{
			{Label: m.T("common.cancel"), Role: core.AlertCancel},
			{Label: m.T("common.move_to_trash"), Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 || m.LockState.Get() != state.StatusUnlocked {
			return
		}
		m.runURLCheckBatchMutation(
			ids,
			true,
			true,
			m.batchCountText("batch.moved_trash_one", "batch.moved_trash_many", n),
			m.T("toast.move_trash_failed"),
			func(ctx context.Context) error {
				return m.Core.BulkSoftDelete(ctx, ids)
			},
		)
	})
}

func (m *AppModel) runURLCheckBatchMutation(
	ids []string,
	removeFromReport bool,
	clearActiveIfAffected bool,
	successTitle string,
	failTitle string,
	fn func(ctx context.Context) error,
) {
	if len(ids) == 0 || m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != "" || m.BatchMutationsDisabled() {
		return
	}
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	m.ResetIdleTimer()
	m.URLCheckBatchBusy.Set(true)
	gen := m.LockGeneration()

	go func() {
		defer cancel()
		err := fn(ctx)
		if m.LockGeneration() != gen {
			return
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.URLCheckBatchBusy.Set(false)
			var lc *state.LocalCopyError
			localCopyFailed := errors.As(err, &lc)
			if err != nil && !localCopyFailed {
				m.RefreshVaultData()
				m.ShowToast(ui.ToastError, failTitle, m.friendlyError(err))
				return
			}
			if removeFromReport {
				m.removeURLCheckItems(ids)
			}
			if clearActiveIfAffected && slices.Contains(ids, m.SelectedID.Get()) {
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
			}
			m.clearURLCheckSelection()
			m.RefreshVaultData()
			if localCopyFailed {
				m.ShowLocalCopyWarning(successTitle)
				return
			}
			m.ShowToast(ui.ToastSuccess, successTitle, "")
		})
	}()
}

// OpenURLCheckItem jumps from a dead URL result row to the item in the Vault.
func (m *AppModel) OpenURLCheckItem(cx *core.Scope, id string) {
	m.GuardDirty(cx, func() {
		filter := state.SearchFilter{Category: state.FilterAll}
		if c, err := m.Core.GetCipher(id); err == nil && c.ArchivedDate != nil {
			filter = state.SearchFilter{Category: state.FilterArchive}
		}
		cx.Batch(func() {
			m.SearchQuery.Set("")
			m.SetSidebarFilter(filter)
			m.SelectCipher(cx, id)
		})
	})
}

// TrashURLCheckItem moves a dead Login item to Trash when online and writable.
func (m *AppModel) TrashURLCheckItem(id string) {
	if m.LockState.Get() != state.StatusUnlocked || m.SyncState.Get() == SyncOffline || m.LocalOnly.Get() ||
		m.URLCheckBusyID.Get() != "" || m.URLCheckBatchBusy.Get() {
		return
	}
	c, err := m.Core.GetCipher(id)
	if err != nil || c.DeletedDate != nil || m.CipherReadOnly(c) {
		return
	}
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	m.ResetIdleTimer()
	gen := m.LockGeneration()
	m.URLCheckBusyID.Set(id)

	go func() {
		defer cancel()
		err := m.Core.SoftDeleteCipher(ctx, id)
		if m.LockGeneration() != gen {
			return
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.URLCheckBusyID.Set("")
			var lc *state.LocalCopyError
			if err != nil && !errors.As(err, &lc) {
				m.ShowToast(ui.ToastError, m.T("toast.move_trash_failed"), m.friendlyError(err))
				return
			}
			m.removeURLCheckItems([]string{id})
			if m.SelectedID.Get() == id {
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
			}
			m.RefreshVaultData()
			if lc != nil {
				m.ShowLocalCopyWarning(m.T("toast.moved_to_trash"))
				return
			}
			m.ShowToast(ui.ToastInfo, m.T("toast.moved_to_trash"), "")
		})
	}()
}

func (m *AppModel) removeURLCheckItems(ids []string) {
	if len(ids) == 0 {
		return
	}
	remove := make(map[string]bool, len(ids))
	for _, id := range ids {
		remove[id] = true
	}
	if cur := m.URLCheckSelectedIDs.Get(); len(cur) > 0 {
		var next map[string]bool
		selChanged := false
		for id := range cur {
			if remove[id] {
				selChanged = true
				continue
			}
			if next == nil {
				next = make(map[string]bool, len(cur))
			}
			next[id] = true
		}
		if selChanged {
			m.URLCheckSelectedIDs.Set(next)
		}
	}
	r := m.URLCheckReport.Get()
	if len(r.Dead) == 0 {
		return
	}
	nextDead := slices.DeleteFunc(slices.Clone(r.Dead), func(it urlcheck.DeadItem) bool {
		return remove[it.CipherID]
	})
	if len(nextDead) != len(r.Dead) {
		r.Dead = nextDead
		m.URLCheckReport.Set(r)
	}
}

// pruneURLCheckResults removes items from the current scan report that were
// deleted or trashed elsewhere in the vault, without triggering any network scan.
func (m *AppModel) pruneURLCheckResults() {
	if m.URLCheckPhase.Get() != URLCheckDone {
		return
	}
	r := m.URLCheckReport.Get()
	if len(r.Dead) == 0 {
		m.clearURLCheckSelection()
		return
	}
	changed := false
	editable := make(map[string]bool, len(r.Dead))
	kept := make([]urlcheck.DeadItem, 0, len(r.Dead))
	for _, it := range r.Dead {
		c, err := m.Core.GetCipher(it.CipherID)
		if err != nil || c.DeletedDate != nil {
			changed = true
			continue
		}
		ro := c.ReadOnly || m.CipherReadOnly(c)
		if ro != it.ReadOnly || c.Name != it.Name {
			it.ReadOnly = ro
			it.Name = c.Name
			changed = true
		}
		if !ro {
			editable[it.CipherID] = true
		}
		kept = append(kept, it)
	}
	if cur := m.URLCheckSelectedIDs.Get(); len(cur) > 0 {
		var next map[string]bool
		selChanged := false
		for id := range cur {
			if editable[id] {
				if next == nil {
					next = make(map[string]bool, len(cur))
				}
				next[id] = true
			} else {
				selChanged = true
			}
		}
		if selChanged {
			m.URLCheckSelectedIDs.Set(next)
		}
	}
	if changed {
		r.Dead = kept
		m.URLCheckReport.Set(r)
	}
}

func urlCheckBadgeVariant(r urlcheck.Reason) ui.BadgeVariant {
	switch r {
	case urlcheck.ReasonDNSNotFound, urlcheck.ReasonRefused, urlcheck.ReasonNotFound, urlcheck.ReasonInvalidURL:
		return ui.BadgeDanger
	case urlcheck.ReasonTimeout, urlcheck.ReasonTLSError, urlcheck.ReasonServerError:
		return ui.BadgeWarn
	default:
		return ui.BadgeNeutral
	}
}

func URLCheckView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "urlcheck-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				var body core.Node
				switch m.URLCheckPhase.Get() {
				case URLCheckScanning:
					body = urlCheckScanningView(cx, m)
				case URLCheckDone:
					body = urlCheckResultsView(cx, m)
				default:
					body = urlCheckIdleView(cx, m)
				}
				return core.View{
					Class:    "w-full max-w-[680px] self-center px-7 pt-6 pb-10 gap-5",
					Children: []core.Node{body},
				}
			}),
		},
	}
}

func urlCheckIdleView(cx *core.Scope, m *AppModel) core.Node {
	return card(core.View{
		TestID: "urlcheck-idle",
		Class:  "px-6 py-7 items-center gap-4",
		Children: []core.Node{
			core.View{
				Class: "w-[44px] h-[44px] rounded-[12px] items-center justify-center bg-gv-accent-soft",
				Children: []core.Node{
					icon(lucide.GlobeCheck(), 22, "text-gv-accent"),
				},
			},
			core.View{
				Class: "items-center gap-1.5 max-w-[460px]",
				Children: []core.Node{
					core.Text{
						Class:   "text-[15px] font-semibold text-gv-fg text-center",
						Content: m.T("urlcheck.title"),
					},
					core.Text{
						TestID:  "urlcheck-privacy-notice",
						Class:   "text-[12.5px] leading-[18px] text-gv-fg2 text-center",
						Content: m.T("urlcheck.privacy_notice"),
					},
				},
			},
			ui.Button{
				TestID:  "urlcheck-scan-btn",
				Text:    m.T("urlcheck.scan_btn"),
				Icon:    lucide.GlobeCheck,
				Variant: ui.ButtonPrimary,
				OnPress: m.StartURLCheck,
			},
		},
	})
}

func urlCheckScanningView(cx *core.Scope, m *AppModel) core.Node {
	return card(core.View{
		TestID: "urlcheck-scanning",
		Class:  "px-6 py-6 gap-4",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-3",
				Children: []core.Node{
					icon(lucide.GlobeCheck(), 18, "text-gv-accent"),
					core.View{
						Class: "flex-1 gap-[2px]",
						Children: []core.Node{
							core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: m.T("urlcheck.scanning_title")},
							core.Text{
								TestID: "urlcheck-progress-text",
								Class:  "text-[12px] text-gv-fg2 tabular-nums",
								ContentFunc: func() string {
									p := m.URLCheckProgress.Get()
									if p.Total <= 0 {
										return m.T("urlcheck.progress.preparing")
									}
									if p.DeadCount > 0 {
										return m.Tf("urlcheck.progress.checked_dead", p.Checked, p.Total, p.DeadCount)
									}
									return m.Tf("urlcheck.progress.checked", p.Checked, p.Total)
								},
							},
						},
					},
					ui.Button{
						TestID:  "urlcheck-cancel-btn",
						Text:    m.T("common.cancel"),
						Variant: ui.ButtonSecondary,
						Size:    ui.SizeSmall,
						OnPress: m.CancelURLCheck,
					},
				},
			},
			ui.Progress{
				TestID: "urlcheck-progress-bar",
				Label:  m.T("urlcheck.progress.label"),
				Value: func() float32 {
					p := m.URLCheckProgress.Get()
					if p.Total <= 0 {
						return 0
					}
					return float32(p.Checked) * 100 / float32(p.Total)
				},
				Indeterminate: func() bool {
					return m.URLCheckProgress.Get().Total <= 0
				},
			},
			core.Text{
				Class:   "text-[11.5px] text-gv-fg3",
				Content: m.T("urlcheck.scanning_footnote"),
			},
		},
	})
}

func urlCheckResultsView(cx *core.Scope, m *AppModel) core.Node {
	r := m.URLCheckReport.Get()
	offline := func() bool { return m.SyncState.Get() == SyncOffline || m.LocalOnly.Get() }
	batchActionDisabled := func() bool {
		return m.URLCheckSelectedCount() == 0 || m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != "" || m.BatchMutationsDisabled()
	}

	summary := m.Tf("urlcheck.summary_checked", r.CheckedTargets, r.SkippedWhitelisted, r.SkippedPrivate)
	if len(r.Dead) > 0 {
		summary = m.Tf("urlcheck.summary_dead", len(r.Dead), summary)
	}

	header := core.View{
		TestID: "urlcheck-results-header",
		Class:  "flex-row items-center justify-between gap-3",
		Children: []core.Node{
			core.Text{
				TestID:  "urlcheck-summary",
				Class:   "flex-1 text-[12px] text-gv-fg2",
				Content: summary,
			},
			ui.Button{
				TestID:   "urlcheck-rescan-btn",
				Text:     m.T("urlcheck.rescan_btn"),
				Icon:     lucide.RefreshCw,
				Variant:  ui.ButtonSecondary,
				Size:     ui.SizeSmall,
				Disabled: func() bool { return m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != "" },
				OnPress:  m.StartURLCheck,
			},
		},
	}

	blocks := []core.Node{header}
	if len(r.Dead) == 0 {
		blocks = append(blocks, card(core.View{
			TestID: "urlcheck-all-clear",
			Class:  "flex-row items-center gap-3 px-4 py-4",
			Children: []core.Node{
				icon(lucide.CircleCheck(), 22, "text-gv-success"),
				core.View{
					Class: "flex-1 gap-[2px]",
					Children: []core.Node{
						core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: m.T("urlcheck.all_clear_title")},
						core.Text{Class: "text-[12px] text-gv-fg2", Content: m.T("urlcheck.all_clear_desc")},
					},
				},
			},
		}))
	} else {
		batchBar := card(core.View{
			TestID: "urlcheck-batch-bar",
			Class:  "px-3.5 py-2.5 gap-2",
			Children: []core.Node{
				core.View{
					Class: "flex-row flex-wrap items-center justify-between gap-2",
					Children: []core.Node{
						core.View{
							Class: "flex-row flex-wrap items-center gap-2",
							Children: []core.Node{
								ui.Button{
									TestID:  "urlcheck-select-all",
									Text:    m.T("common.select_all"),
									Variant: ui.ButtonSecondary,
									Size:    ui.SizeSmall,
									Disabled: func() bool {
										return m.URLCheckSelectableCount() == 0 || m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != ""
									},
									OnPress: m.SelectAllURLCheck,
								},
								ui.Button{
									TestID:   "urlcheck-clear-selection",
									Text:     m.T("common.clear"),
									Variant:  ui.ButtonGhost,
									Size:     ui.SizeSmall,
									Disabled: func() bool { return m.URLCheckSelectedCount() == 0 || m.URLCheckBatchBusy.Get() },
									OnPress:  m.ClearURLCheckSelection,
								},
								core.Text{
									TestID: "urlcheck-selected-count",
									Class:  "text-[12px] font-semibold text-gv-fg tabular-nums",
									ContentFunc: func() string {
										return m.Tf("batch.selected_count", m.URLCheckSelectedCount())
									},
								},
							},
						},
						core.Show{
							When: func() bool {
								return m.BatchMutationsDisabled() || m.URLCheckHasReadOnly()
							},
							Then: func(cx *core.Scope) core.Node {
								return core.Text{
									TestID: "urlcheck-batch-hint",
									ClassFunc: func() string {
										if m.BatchMutationsDisabled() {
											return "text-[11px] text-gv-warn"
										}
										return "text-[11px] text-gv-fg3"
									},
									ContentFunc: func() string {
										switch {
										case m.LocalOnly.Get():
											return m.T("batch.hint.local_only")
										case m.SyncState.Get() == SyncOffline:
											return m.T("batch.hint.offline")
										case m.URLCheckHasReadOnly():
											return m.T("batch.hint.readonly_omitted")
										default:
											return ""
										}
									},
								}
							},
						},
					},
				},
				core.View{
					Class: "flex-row flex-wrap items-center gap-2",
					Children: []core.Node{
						ui.Button{
							TestID:   "urlcheck-batch-move",
							Text:     m.T("batch.move_folder_btn"),
							Icon:     lucide.Folder,
							Variant:  ui.ButtonSecondary,
							Size:     ui.SizeSmall,
							Busy:     m.URLCheckBatchBusy.Get,
							Disabled: batchActionDisabled,
							OnPress:  m.OpenURLCheckBatchMoveDialog,
						},
						ui.Button{
							TestID:   "urlcheck-batch-trash",
							Text:     m.T("common.move_to_trash"),
							Icon:     lucide.Trash,
							Variant:  ui.ButtonSecondary,
							Size:     ui.SizeSmall,
							Color:    func() core.Color { return themeColor(cx, "gv-danger") },
							Tint:     func() core.Color { return themeColor(cx, "gv-danger") },
							Busy:     m.URLCheckBatchBusy.Get,
							Disabled: batchActionDisabled,
							OnPress:  func() { m.ConfirmURLCheckBatchSoftDelete(cx) },
						},
					},
				},
			},
		})
		blocks = append(blocks, batchBar)

		rows := make([]core.Node, 0, len(r.Dead))
		for _, item := range r.Dead {
			it := item
			name := strings.TrimSpace(it.Name)
			if name == "" {
				name = m.T("common.untitled")
			}
			sub := it.Domain
			if it.Username != "" {
				sub = it.Domain + " · " + it.Username
			}
			rows = append(rows, core.View{
				TestID: "urlcheck-item",
				Class:  "flex-row items-center gap-2 ps-3.5 pe-3 py-2 min-h-[52px]",
				Children: []core.Node{
					ui.Checkbox{
						TestID:  "urlcheck-check-" + it.CipherID,
						Label:   m.Tf("a11y.select_named", name),
						Style:   core.Style{FlexShrink: 0},
						Checked: func() bool { return m.IsURLCheckSelected(it.CipherID) },
						Disabled: func() bool {
							return it.ReadOnly || m.URLCheckBatchBusy.Get() || m.URLCheckBusyID.Get() != ""
						},
						OnChange: func(v bool) { m.SetURLCheckItemSelected(it.CipherID, v) },
					},
					core.View{
						TestID:  "urlcheck-open-" + it.CipherID,
						Role:    core.RoleButton,
						Label:   m.Tf("a11y.open_item", name),
						Class:   "flex-1 flex-row items-center gap-3 py-0.5 rounded-[6px] active:bg-gv-fill overflow-hidden",
						OnPress: func(core.PressEvent) { m.OpenURLCheckItem(cx, it.CipherID) },
						Children: []core.Node{
							itemEmblem(name, api.CipherTypeLogin, "", 28),
							core.View{
								Class: "flex-1 gap-[2px] overflow-hidden",
								Children: []core.Node{
									core.Text{MaxLines: 1, Class: "text-[13.5px] font-medium text-gv-fg", Content: name},
									core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: sub},
								},
							},
							core.View{
								TestID: "urlcheck-badge-" + it.CipherID,
								Children: []core.Node{
									ui.Badge{
										Text:    m.urlCheckReasonText(it),
										Variant: urlCheckBadgeVariant(it.Reason),
									},
								},
							},
						},
					},
					ui.Button{
						TestID:  "urlcheck-trash-" + it.CipherID,
						Text:    m.T("common.move_to_trash"),
						Icon:    lucide.Trash,
						Variant: ui.ButtonGhost,
						Size:    ui.SizeSmall,
						Tint:    func() core.Color { return themeColor(cx, "gv-danger") },
						Busy:    func() bool { return m.URLCheckBusyID.Get() == it.CipherID },
						Disabled: func() bool {
							return offline() || it.ReadOnly || m.URLCheckBusyID.Get() != "" || m.URLCheckBatchBusy.Get()
						},
						OnPress: func() { m.TrashURLCheckItem(it.CipherID) },
					},
				},
			})
		}
		blocks = append(blocks, section(m.T("urlcheck.section_title"), card(rows...)))
	}
	blocks = append(blocks, core.Text{
		Class:   "px-1 text-[11.5px] text-gv-fg3",
		Content: m.T("urlcheck.footer"),
	})

	return core.View{
		TestID:   "urlcheck-results",
		Class:    "gap-4",
		Children: blocks,
	}
}
