package ui

import (
	"fmt"
	"slices"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// passkeyText describes a passkey without any of its secret material: its
// relying party and when it was created.
func passkeyText(m *AppModel, f *state.Fido2Credential) string {
	site := f.RpID
	if site == "" {
		site = f.RpName
	}
	created := ""
	if t, err := time.Parse(time.RFC3339Nano, f.CreationDate); err == nil {
		created = m.Tf("metadata.created", m.formatDate(t))
	}
	switch {
	case site != "" && created != "":
		return site + " · " + created
	case site != "":
		return site
	case created != "":
		return created
	}
	return m.T("passkey.stored_in_item")
}

func passkeyTestID(base string, i int) string {
	if i == 0 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, i)
}

// detailPasskeyRows shows every passkey of a login, read-only.
func detailPasskeyRows(m *AppModel, c *state.Cipher) []core.Node {
	if c.Login == nil {
		return nil
	}
	var rows []core.Node
	for i := range c.Login.Fido2Credentials {
		rows = append(rows, fieldRow(m.T("field.passkey"), fieldOpts{
			testID: passkeyTestID("detail-passkey", i),
			value:  staticValue(passkeyText(m, &c.Login.Fido2Credentials[i])),
		}))
	}
	return rows
}

// ConfirmRemovePasskey asks before marking passkey i of the item being
// edited for removal. It goes only when the user saves.
func (m *AppModel) ConfirmRemovePasskey(cx *core.Scope, i int) {
	d := m.EditDraft.Get()
	if i < 0 || i >= len(d.DraftPasskeys()) || d.PasskeyRemoved(i) {
		return
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   m.T("passkey.remove_title"),
		Message: m.T("passkey.remove_message"),
		Actions: []core.AlertAction{
			{Label: m.T("common.cancel"), Role: core.AlertCancel},
			{Label: m.T("common.remove"), Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx == 1 {
			m.MutateDraft(func(d *EditDraft) {
				if !d.PasskeyRemoved(i) {
					d.RemovedPasskeys = append(d.RemovedPasskeys, i)
				}
			})
		}
	})
}

func hasDraftPasskeys(m *AppModel) bool {
	return len(m.EditDraft.Get().DraftPasskeys()) > 0
}

// editorPasskeyRows lists the passkeys of the item being edited, each with
// its own remove button, or Undo once removed.
func editorPasskeyRows(cx *core.Scope, m *AppModel) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		d := m.EditDraft.Get()
		passkeys := d.DraftPasskeys()
		var rows []core.Node
		for i := range passkeys {
			if d.PasskeyRemoved(i) {
				rows = append(rows, formRow(m.T("field.passkey"), core.View{
					Class: "flex-1 flex-row items-center gap-2",
					Children: []core.Node{
						core.Text{TestID: passkeyTestID("editor-passkey-removed", i), Class: "flex-1 text-[13px] text-gv-fg2", Content: m.T("passkey.removed_on_save")},
						ui.Button{
							Disabled: m.EditBusy.Get,
							TestID:   passkeyTestID("editor-passkey-undo", i),
							Text:     m.T("common.undo"),
							Variant:  ui.ButtonGhost,
							Size:     ui.SizeSmall,
							OnPress: func() {
								m.MutateDraft(func(d *EditDraft) {
									d.RemovedPasskeys = slices.DeleteFunc(d.RemovedPasskeys, func(x int) bool { return x == i })
								})
							},
						},
					},
				}))
				continue
			}
			rows = append(rows, formRow(m.T("field.passkey"), core.View{
				Class: "flex-1 flex-row items-center gap-2",
				Children: []core.Node{
					core.Text{TestID: passkeyTestID("editor-passkey", i), MaxLines: 1, Class: "flex-1 text-[13px] text-gv-fg", Content: passkeyText(m, &passkeys[i])},
					ui.Button{
						Disabled: m.EditBusy.Get,
						TestID:   passkeyTestID("editor-passkey-remove", i),
						Icon:     lucide.Trash,
						Label:    m.T("passkey.remove_label"),
						Variant:  ui.ButtonGhost,
						Side:     24,
						IconSize: 13,
						Tint:     func() core.Color { return themeColor(cx, "gv-danger") },
						OnPress:  func() { m.ConfirmRemovePasskey(cx, i) },
					},
				},
			}))
		}
		if len(rows) == 0 {
			return nil
		}
		return card(rows...)
	})
}
