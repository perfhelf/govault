package ui

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

type BatchFolderMode int

const (
	BatchFolderNone BatchFolderMode = iota
	BatchFolderMove
	BatchFolderRestore
)

type BatchFolderModal struct {
	Open bool
	Mode BatchFolderMode
}

func (m *AppModel) clearBatchState() {
	m.BatchSelectMode.Set(false)
	m.BatchSelectedIDs.Set(nil)
	m.BatchBusy.Set(false)
	m.BatchFolderDialog.Set(BatchFolderModal{})
}

func (m *AppModel) SummaryReadOnly(it state.CipherSummary) bool {
	if it.ReadOnly {
		return true
	}
	if len(it.CollectionIDs) == 0 {
		return false
	}
	cols := m.Collections.Get()
	if len(cols) == 0 {
		return false
	}
	colMap := make(map[string]state.Collection, len(cols))
	for _, col := range cols {
		colMap[col.ID] = col
	}
	known := 0
	for _, id := range it.CollectionIDs {
		col, ok := colMap[id]
		if !ok {
			continue
		}
		if !col.ReadOnly {
			return false
		}
		known++
	}
	return known > 0
}

func (m *AppModel) IsBatchSelected(id string) bool {
	sel := m.BatchSelectedIDs.Get()
	return sel != nil && sel[id]
}

func (m *AppModel) BatchSelectedCount() int {
	return len(m.BatchSelectedIDs.Get())
}

func (m *AppModel) BatchSelectableCount() int {
	n := 0
	for i := range m.FilteredItems.Len() {
		if it, ok := m.FilteredItems.At(i); ok && !m.SummaryReadOnly(it) {
			n++
		}
	}
	return n
}

func (m *AppModel) BatchHasReadOnlyInView() bool {
	for i := range m.FilteredItems.Len() {
		if it, ok := m.FilteredItems.At(i); ok && m.SummaryReadOnly(it) {
			return true
		}
	}
	return false
}

func (m *AppModel) AllEditableSelected() bool {
	sel := m.BatchSelectedIDs.Get()
	editable := 0
	for i := range m.FilteredItems.Len() {
		it, ok := m.FilteredItems.At(i)
		if !ok || m.SummaryReadOnly(it) {
			continue
		}
		editable++
		if sel == nil || !sel[it.ID] {
			return false
		}
	}
	return editable > 0
}

func (m *AppModel) BatchMutationsDisabled() bool {
	return m.SyncState.Get() == SyncOffline || m.LocalOnly.Get()
}

func (m *AppModel) IsTrashView() bool {
	return m.EffectiveSearchFilter().Category == state.FilterTrash
}

func (m *AppModel) ToggleBatchSelectMode(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked || m.BatchBusy.Get() {
		return
	}
	if m.BatchSelectMode.Get() {
		m.clearBatchState()
		return
	}
	if m.FilteredItems.Len() == 0 {
		return
	}
	m.ResetIdleTimer()
	m.GuardDirty(cx, func() {
		if m.EditMode.Get() {
			m.EditMode.Set(false)
			m.EditDraft.Set(nil)
			m.EditDirty.Set(false)
			m.EditError.Set("")
		}
		m.BatchSelectedIDs.Set(nil)
		m.BatchFolderDialog.Set(BatchFolderModal{})
		m.BatchSelectMode.Set(true)
	})
}

func (m *AppModel) SetBatchItemSelected(id string, selected bool) {
	if !m.BatchSelectMode.Get() || m.BatchBusy.Get() || id == "" {
		return
	}
	m.ResetIdleTimer()
	if selected {
		for i := range m.FilteredItems.Len() {
			if it, ok := m.FilteredItems.At(i); ok && it.ID == id && m.SummaryReadOnly(it) {
				return
			}
		}
		if c, err := m.Core.GetCipher(id); err != nil || m.CipherReadOnly(c) {
			return
		}
	}
	cur := m.BatchSelectedIDs.Get()
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
	m.BatchSelectedIDs.Set(next)
}

func (m *AppModel) ToggleBatchItem(id string) {
	m.SetBatchItemSelected(id, !m.IsBatchSelected(id))
}

func (m *AppModel) SelectAllBatch() {
	if !m.BatchSelectMode.Get() || m.BatchBusy.Get() {
		return
	}
	m.ResetIdleTimer()
	next := make(map[string]bool)
	for i := range m.FilteredItems.Len() {
		it, ok := m.FilteredItems.At(i)
		if !ok || m.SummaryReadOnly(it) {
			continue
		}
		next[it.ID] = true
	}
	if len(next) == 0 {
		next = nil
	}
	m.BatchSelectedIDs.Set(next)
}

func (m *AppModel) ClearBatchSelection() {
	if m.BatchBusy.Get() {
		return
	}
	m.ResetIdleTimer()
	m.BatchSelectedIDs.Set(nil)
}

func (m *AppModel) pruneBatchSelection() {
	if !m.BatchSelectMode.Get() {
		return
	}
	cur := m.BatchSelectedIDs.Get()
	if len(cur) == 0 {
		return
	}
	items := m.Core.Search("", m.EffectiveSearchFilter())
	editable := make(map[string]bool, len(items))
	for _, it := range items {
		if !m.SummaryReadOnly(it) {
			editable[it.ID] = true
		}
	}
	changed := false
	next := make(map[string]bool, len(cur))
	for id := range cur {
		if editable[id] {
			next[id] = true
		} else {
			changed = true
		}
	}
	if !changed {
		return
	}
	if len(next) == 0 {
		next = nil
	}
	m.BatchSelectedIDs.Set(next)
}

func (m *AppModel) selectedEditableBatchIDs() []string {
	sel := m.BatchSelectedIDs.Get()
	if len(sel) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(sel))
	var ids []string
	appendIfEditable := func(id string) {
		if !sel[id] || seen[id] {
			return
		}
		seen[id] = true
		if c, err := m.Core.GetCipher(id); err == nil && !m.CipherReadOnly(c) {
			ids = append(ids, id)
		}
	}
	for i := range m.FilteredItems.Len() {
		if it, ok := m.FilteredItems.At(i); ok {
			appendIfEditable(it.ID)
		}
	}
	var rest []string
	for id := range sel {
		if !seen[id] {
			rest = append(rest, id)
		}
	}
	slices.Sort(rest)
	for _, id := range rest {
		appendIfEditable(id)
	}
	return ids
}

func (m *AppModel) OpenBatchMoveDialog() {
	if m.LockState.Get() != state.StatusUnlocked || m.BatchBusy.Get() || m.BatchMutationsDisabled() || m.IsTrashView() {
		return
	}
	if len(m.selectedEditableBatchIDs()) == 0 {
		return
	}
	m.ResetIdleTimer()
	m.BatchFolderDialog.Set(BatchFolderModal{Open: true, Mode: BatchFolderMove})
}

func (m *AppModel) OpenBatchRestoreDialog() {
	if m.LockState.Get() != state.StatusUnlocked || m.BatchBusy.Get() || m.BatchMutationsDisabled() || !m.IsTrashView() {
		return
	}
	if len(m.selectedEditableBatchIDs()) == 0 {
		return
	}
	m.ResetIdleTimer()
	m.BatchFolderDialog.Set(BatchFolderModal{Open: true, Mode: BatchFolderRestore})
}

func (m *AppModel) CloseBatchFolderDialog() {
	m.BatchFolderDialog.Set(BatchFolderModal{})
}

func batchItemNoun(n int) string {
	if n == 1 {
		return "item"
	}
	return "items"
}

func (m *AppModel) ExecuteBatchMoveFolder(folderID *string) {
	if m.LockState.Get() != state.StatusUnlocked || m.BatchBusy.Get() || m.BatchMutationsDisabled() {
		return
	}
	ids := m.selectedEditableBatchIDs()
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
	m.runBatchMutation(
		ids,
		false,
		fmt.Sprintf("Moved %d %s", n, batchItemNoun(n)),
		"Move to folder failed",
		func(ctx context.Context) error {
			return m.Core.BulkMoveFolder(ctx, ids, target)
		},
	)
}

func (m *AppModel) ExecuteBatchRestore(targetFolderID *string) {
	if m.LockState.Get() != state.StatusUnlocked || m.BatchBusy.Get() || m.BatchMutationsDisabled() {
		return
	}
	ids := m.selectedEditableBatchIDs()
	if len(ids) == 0 {
		m.CloseBatchFolderDialog()
		return
	}
	var target *string
	if targetFolderID != nil {
		v := *targetFolderID
		target = &v
	}
	m.CloseBatchFolderDialog()
	n := len(ids)
	m.runBatchMutation(
		ids,
		true,
		fmt.Sprintf("Restored %d %s", n, batchItemNoun(n)),
		"Restore failed",
		func(ctx context.Context) error {
			return m.Core.BulkRestore(ctx, ids, target)
		},
	)
}

func (m *AppModel) ConfirmBatchSoftDelete(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked || m.BatchBusy.Get() || m.BatchMutationsDisabled() || m.IsTrashView() {
		return
	}
	ids := m.selectedEditableBatchIDs()
	n := len(ids)
	if n == 0 {
		return
	}
	noun := batchItemNoun(n)
	cx.ShowAlert(core.AlertConfig{
		Title:   fmt.Sprintf("Move %d %s to Trash?", n, noun),
		Message: fmt.Sprintf("%d selected %s will be moved to Trash. You can restore them later from Trash.", n, noun),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Move to Trash", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 || m.LockState.Get() != state.StatusUnlocked {
			return
		}
		m.runBatchMutation(
			ids,
			true,
			fmt.Sprintf("Moved %d %s to Trash", n, noun),
			"Move to Trash failed",
			func(ctx context.Context) error {
				return m.Core.BulkSoftDelete(ctx, ids)
			},
		)
	})
}

func (m *AppModel) ConfirmBatchHardDelete(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked || m.BatchBusy.Get() || m.BatchMutationsDisabled() || !m.IsTrashView() {
		return
	}
	ids := m.selectedEditableBatchIDs()
	n := len(ids)
	if n == 0 {
		return
	}
	noun := batchItemNoun(n)
	cx.ShowAlert(core.AlertConfig{
		Title:   fmt.Sprintf("Permanently delete %d %s?", n, noun),
		Message: fmt.Sprintf("%d selected %s will be permanently deleted and cannot be recovered.", n, noun),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Delete Permanently", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 || m.LockState.Get() != state.StatusUnlocked {
			return
		}
		m.runBatchMutation(
			ids,
			true,
			fmt.Sprintf("Deleted %d %s permanently", n, noun),
			"Permanent delete failed",
			func(ctx context.Context) error {
				return m.Core.BulkHardDelete(ctx, ids)
			},
		)
	})
}

func (m *AppModel) runBatchMutation(
	ids []string,
	clearActiveIfAffected bool,
	successTitle string,
	failTitle string,
	fn func(ctx context.Context) error,
) {
	if len(ids) == 0 || m.BatchBusy.Get() || m.BatchMutationsDisabled() {
		return
	}
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	m.ResetIdleTimer()
	m.BatchBusy.Set(true)
	gen := m.LockGeneration()

	go func() {
		defer cancel()
		err := fn(ctx)
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.BatchBusy.Set(false)
			var lc *state.LocalCopyError
			localCopyFailed := errors.As(err, &lc)
			if err != nil && !localCopyFailed {
				m.RefreshVaultData()
				m.ShowToast(ui.ToastError, failTitle, friendlyError(err))
				return
			}
			if clearActiveIfAffected && slices.Contains(ids, m.SelectedID.Get()) {
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
			}
			m.clearBatchState()
			m.RefreshVaultData()
			if localCopyFailed {
				m.ShowLocalCopyWarning(successTitle)
				return
			}
			m.ShowToast(ui.ToastSuccess, successTitle, "")
		})
	}()
}
