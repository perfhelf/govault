package ui

import (
	"context"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// TrashDeletable counts the items in Trash the user may delete permanently.
func (m *AppModel) TrashDeletable() int {
	return len(m.Core.TrashSelection().Items)
}

func (m *AppModel) EmptyTrash(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked || m.SyncState.Get() == SyncOffline || m.TrashBusy.Get() {
		return
	}
	sel := m.Core.TrashSelection()
	n := len(sel.Items)
	if n == 0 {
		return
	}
	msgKey := "trash.empty_message_many"
	if n == 1 {
		msgKey = "trash.empty_message_one"
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   m.T("trash.empty_title"),
		Message: m.Tf(msgKey, n),
		Actions: []core.AlertAction{
			{Label: m.T("common.cancel"), Role: core.AlertCancel},
			{Label: m.T("trash.empty_action"), Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		m.TrashBusy.Set(true)
		gen := m.LockGeneration()
		go func() {
			res, err := m.Core.EmptyTrash(context.Background(), sel)
			m.Scope.Post(func() {
				m.TrashBusy.Set(false)
				if !m.StillUnlocked(gen) {
					return
				}
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
				m.RefreshVaultData()
				var notes []string
				if res.ReadOnly > 0 {
					notes = append(notes, m.Tf("trash.readonly_kept", res.ReadOnly))
				}
				if res.Skipped > 0 {
					notes = append(notes, m.Tf("trash.changed_kept", res.Skipped))
				}
				desc := strings.Join(notes, " ")
				switch {
				case err != nil && res.Deleted == 0:
					m.ShowToast(ui.ToastError, m.T("trash.empty_failed"), m.friendlyError(err))
				case err != nil:
					m.ShowToast(ui.ToastWarning, m.Tf("trash.deleted_partial", res.Deleted), m.Tf("trash.delete_partial_desc", m.friendlyError(err)))
				default:
					m.ShowToast(ui.ToastInfo, m.T("trash.emptied"), desc)
				}
			})
		}()
	})
}

// CanClone reports whether c may be copied into a new personal item: its
// secrets must be visible to the user.
func (m *AppModel) CanClone(c *state.Cipher) bool {
	return c != nil && c.DeletedDate == nil && !m.PasswordHidden(c) && m.SyncState.Get() != SyncOffline
}

// CloneActive opens the editor on a new personal copy of the selected item.
// Organization membership, attachments and history are not copied.
func (m *AppModel) CloneActive(cx *core.Scope) {
	c := m.ActiveCipher.Get()
	if !m.CanClone(c) || m.EditMode.Get() {
		return
	}
	m.ResetIdleTimer()
	m.GateReprompt(cx, c, m.T("reprompt.action.clone_item"), func() {
		if cur := m.ActiveCipher.Get(); cur == nil || cur.ID != c.ID {
			return
		}
		src := *c
		src.ID = ""
		src.OrganizationID = nil
		src.CollectionIDs = nil
		src.Attachments = nil
		src.PasswordHistory = nil
		src.RevisionDate = nil
		src.CreationDate = nil
		src.DeletedDate = nil
		src.ArchivedDate = nil
		src.Key = nil
		src.Data = nil
		src.EncryptedFor = nil
		src.EncryptedByKeyID = nil
		src.ReadOnly = false
		src.HidePassword = false
		src.Name = m.Tf("clone.copy_name", c.Name)
		// A passkey belongs to one item; Bitwarden does not copy it either.
		hadPasskey := false
		if c.Login != nil {
			login := *c.Login
			hadPasskey = len(login.Fido2Credentials) > 0
			login.Fido2Credentials = nil
			src.Login = &login
		}
		draft := draftFromCipher(&src)
		draft.IsNew = true
		draft.Revision = nil
		m.openDraft(draft)
		m.EditDirty.Set(true)
		m.EditError.Set("")
		m.EditMode.Set(true)
		if hadPasskey {
			m.ShowToast(ui.ToastInfo, m.T("clone.passkey_notice_title"), m.T("clone.passkey_notice_desc"))
		}
	})
}
