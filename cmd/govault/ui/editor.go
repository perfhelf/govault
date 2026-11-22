package ui

import (
	"fmt"
	"strings"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/gen"
)

const editorFieldHeight core.Points = 28

func EditorPaneView(cx *core.Scope, m *AppModel) core.Node {
	showPW := core.NewSignal(cx, false)
	draftType := core.NewMemo(cx, func() api.CipherType {
		if d := m.EditDraft.Get(); d != nil {
			return d.Type
		}
		return api.CipherTypeLogin
	})

	return core.View{
		TestID: "editor-pane",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-3 px-7 h-[60px] border-b border-gv-line",
				Children: []core.Node{
					core.Dynamic(func(cx *core.Scope) core.Node {
						name := ""
						if d := m.EditDraft.Get(); d != nil {
							name = d.Name
						}
						if name == "" {
							name = m.CipherTypeLabel(draftType.Get())
						}
						return itemEmblem(name, draftType.Get(), "", 32)
					}),
					core.View{
						Class: "flex-1 gap-[1px]",
						Children: []core.Node{
							core.Text{
								Class: "text-[15px] font-semibold text-gv-fg",
								ContentFunc: func() string {
									d := m.EditDraft.Get()
									if d == nil {
										return ""
									}
									if d.IsNew {
										return m.Tf("editor.new_type", m.CipherTypeLabel(d.Type))
									}
									return m.Tf("editor.edit_type", m.CipherTypeLabel(d.Type))
								},
							},
							core.Text{
								Class: "text-[11.5px] text-gv-fg3",
								ContentFunc: func() string {
									if m.EditDirty.Get() {
										return m.T("editor.unsaved_changes")
									}
									return m.T("editor.no_changes")
								},
							},
						},
					},
					ui.Button{
						TestID:   "editor-cancel",
						Text:     m.T("common.cancel"),
						Variant:  ui.ButtonSecondary,
						Disabled: m.EditBusy.Get,
						OnPress:  func() { m.CancelEdit(cx) },
					},
					ui.Button{
						TestID:  "editor-save",
						Text:    m.T("common.save"),
						Variant: ui.ButtonPrimary,
						Busy:    m.EditBusy.Get,
						OnPress: func() { m.SaveDraft(cx) },
					},
				},
			},
			core.Scroll{
				Class: "flex-1",
				Children: []core.Node{
					core.View{
						Class: "w-full max-w-[680px] self-center px-7 pt-5 pb-10 gap-5",
						Children: []core.Node{
							core.Show{
								When: func() bool { return m.EditError.Get() != "" },
								Then: func(cx *core.Scope) core.Node { return errorBanner("editor-error", m.EditError.Get) },
							},
							section(m.T("cipher.type.item"), core.Dynamic(func(cx *core.Scope) core.Node {
								var rows []core.Node
								if d := m.EditDraft.GetUntracked(); d != nil && d.IsNew {
									rows = append(rows, formRow(m.T("editor.type"), ui.Select[api.CipherType]{
										Disabled: m.EditBusy.Get,
										TestID:   "editor-type",
										Style:    core.Style{Width: core.Pt(180)},
										Options: []ui.Option[api.CipherType]{
											{Value: api.CipherTypeLogin, Label: m.CipherTypeLabel(api.CipherTypeLogin)},
											{Value: api.CipherTypeSecureNote, Label: m.CipherTypeLabel(api.CipherTypeSecureNote)},
											{Value: api.CipherTypeCard, Label: m.CipherTypeLabel(api.CipherTypeCard)},
											{Value: api.CipherTypeIdentity, Label: m.CipherTypeLabel(api.CipherTypeIdentity)},
											{Value: api.CipherTypeSSHKey, Label: m.CipherTypeLabel(api.CipherTypeSSHKey)},
										},
										Value:    draftType.Get,
										OnChange: func(t api.CipherType) { m.MutateDraft(func(d *EditDraft) { d.Type = t }) },
									}))
								}
								rows = append(rows,
									formRow(m.T("field.name"), draftInput(m, "editor-name", m.T("common.required"), func(d *EditDraft) string { return d.Name }, func(d *EditDraft, v string) { d.Name = v })),
									formRow(m.T("nav.folder_fallback"), core.Dynamic(func(cx *core.Scope) core.Node {
										opts := []ui.Option[string]{{Value: "", Label: m.T("nav.no_folder")}}
										for _, f := range m.Folders.Get() {
											opts = append(opts, ui.Option[string]{Value: f.ID, Label: f.Name})
										}
										return ui.Select[string]{
											Disabled: m.EditBusy.Get,
											TestID:   "editor-folder",
											Style:    core.Style{Width: core.Pt(180)},
											Options:  opts,
											Value: func() string {
												if d := m.EditDraft.Get(); d != nil {
													return d.FolderID
												}
												return ""
											},
											OnChange: func(v string) { m.MutateDraft(func(d *EditDraft) { d.FolderID = v }) },
										}
									})),
									favoriteRow(m),
									switchRow(m.T("editor.reprompt"), "editor-reprompt", func(d *EditDraft) bool { return d.Reprompt }, func(d *EditDraft, v bool) { d.Reprompt = v }, m),
								)
								return card(rows...)
							})),
							core.Dynamic(func(cx *core.Scope) core.Node {
								switch draftType.Get() {
								case api.CipherTypeLogin:
									return editorLoginFields(cx, m, showPW)
								case api.CipherTypeCard:
									return editorCardFields(m)
								case api.CipherTypeIdentity:
									return editorIdentityFields(m)
								case api.CipherTypeSSHKey:
									return editorSSHKeyFields(m)
								default:
									return nil
								}
							}),
							editorCustomFieldsSection(cx, m),
							section(m.T("section.notes"), card(core.View{
								Class: "p-2",
								Children: []core.Node{
									ui.Input{
										Disabled:    m.EditBusy.Get,
										TestID:      "editor-notes",
										Placeholder: m.T("editor.notes_placeholder"),
										Multiline:   true,
										Style:       core.Style{MinHeight: core.Pt(96), BorderWidth: 0, Background: core.Transparent},
										Value: func() string {
											if d := m.EditDraft.Get(); d != nil {
												return d.Notes
											}
											return ""
										},
										OnChange: func(v string) { m.MutateDraft(func(d *EditDraft) { d.Notes = v }) },
									},
								},
							})),
						},
					},
				},
			},
		},
	}
}

func formRow(label string, control core.Node) core.Node {
	return core.View{
		Class: "flex-row items-center gap-3 px-4 py-2 min-h-[44px]",
		Children: []core.Node{
			core.Text{Class: "w-[124px] text-[12.5px] text-gv-fg2", Content: label},
			core.View{Class: "flex-1 flex-row items-center gap-2", Children: []core.Node{control}},
		},
	}
}

// favoriteRow is the editor's Favorite switch. An archived item keeps its
// favorite once the account can no longer archive, as Bitwarden does.
func favoriteRow(m *AppModel) core.Node {
	return core.View{
		Class: "flex-row items-center gap-3 px-4 py-2 min-h-[44px]",
		Children: []core.Node{
			core.Text{Class: "flex-1 text-[13px] text-gv-fg", Content: m.T("editor.favorite")},
			ui.Switch{
				Disabled: func() bool {
					d := m.EditDraft.Get()
					return m.EditBusy.Get() || d == nil || !m.CanFavorite(d.Source)
				},
				TestID: "editor-favorite",
				Label:  m.T("editor.favorite"),
				Checked: func() bool {
					d := m.EditDraft.Get()
					return d != nil && d.Favorite
				},
				OnChange: func(v bool) { m.MutateDraft(func(d *EditDraft) { d.Favorite = v }) },
			},
		},
	}
}

func switchRow(label, testID string, get func(*EditDraft) bool, set func(*EditDraft, bool), m *AppModel) core.Node {
	return core.View{
		Class: "flex-row items-center gap-3 px-4 py-2 min-h-[44px]",
		Children: []core.Node{
			core.Text{Class: "flex-1 text-[13px] text-gv-fg", Content: label},
			ui.Switch{
				Disabled: m.EditBusy.Get,
				TestID:   testID,
				Label:    label,
				Checked: func() bool {
					d := m.EditDraft.Get()
					return d != nil && get(d)
				},
				OnChange: func(v bool) { m.MutateDraft(func(d *EditDraft) { set(d, v) }) },
			},
		},
	}
}

func flexed(n core.Node) core.Node {
	return core.View{Class: "flex-1", Children: []core.Node{n}}
}

func draftCount(cx *core.Scope, m *AppModel, n func(*EditDraft) int) *core.Memo[int] {
	return core.NewMemo(cx, func() int {
		if d := m.EditDraft.Get(); d != nil {
			return n(d)
		}
		return 0
	})
}

func editorLoginFields(cx *core.Scope, m *AppModel, showPW *core.Signal[bool]) core.Node {
	uriCount := draftCount(cx, m, func(d *EditDraft) int { return len(d.URIs) })
	return core.View{
		Class: "gap-5",
		Children: []core.Node{
			section(m.T("section.credentials"), card(
				formRow(m.T("field.username"), draftInput(m, "editor-username", "name@example.com", func(d *EditDraft) string { return d.Username }, func(d *EditDraft, v string) { d.Username = v })),
				formRow(m.T("field.password"), flexed(passwordField(cx, m, base.Input{
					Disabled:      m.EditBusy.Get,
					TestID:        "editor-password",
					Placeholder:   m.T("field.password"),
					NoAutoCorrect: true,
					Class:         "font-mono",
					Value: func() string {
						if d := m.EditDraft.Get(); d != nil {
							return d.Password
						}
						return ""
					},
					OnChange: func(v string) { m.MutateDraft(func(d *EditDraft) { d.Password = v }) },
				}, editorFieldHeight, showPW, "editor-toggle-pw", ui.Button{
					Disabled: m.EditBusy.Get,
					TestID:   "editor-generate-pw",
					Icon:     lucide.WandSparkles,
					Label:    m.T("editor.generate_password"),
					Variant:  ui.ButtonGhost,
					Side:     editorFieldHeight - 8,
					IconSize: 13,
					Tint:     func() core.Color { return themeColor(cx, "gv-accent") },
					OnPress: func() {
						pw := m.GenerateInlinePassword()
						m.MutateDraft(func(d *EditDraft) { d.Password = pw })
					},
				}))),
				formRow(m.T("editor.authenticator"), flexed(sizedInput(base.Input{
					Disabled:      m.EditBusy.Get,
					TestID:        "editor-totp",
					Class:         "font-mono",
					Placeholder:   m.T("editor.totp_placeholder"),
					NoAutoCorrect: true,
					Value: func() string {
						if d := m.EditDraft.Get(); d != nil {
							return d.TOTP
						}
						return ""
					},
					OnChange: func(v string) { m.MutateDraft(func(d *EditDraft) { d.TOTP = v }) },
				}, editorFieldHeight))),
			)),
			core.Show{
				When: func() bool { return hasDraftPasskeys(m) },
				Then: func(cx *core.Scope) core.Node { return editorPasskeyRows(cx, m) },
			},
			section(m.T("section.websites"), core.Dynamic(func(cx *core.Scope) core.Node {
				n := uriCount.Get()
				rows := make([]core.Node, 0, n+1)
				for i := range n {
					idx := i
					rows = append(rows, core.View{
						Class: "flex-row items-center gap-2 ps-4 pe-2 py-2",
						Children: []core.Node{
							icon(lucide.Globe(), 14, "text-gv-fg3"),
							flexed(sizedInput(base.Input{
								Disabled:      m.EditBusy.Get,
								TestID:        fmt.Sprintf("editor-uri-%d", idx),
								Placeholder:   "https://example.com",
								NoAutoCorrect: true,
								Value: func() string {
									cur := m.EditDraft.Get()
									if cur == nil || idx >= len(cur.URIs) {
										return ""
									}
									return cur.URIs[idx].URI
								},
								OnChange: func(v string) {
									m.MutateDraft(func(d *EditDraft) {
										if idx < len(d.URIs) {
											d.URIs[idx].URI = v
										}
									})
								},
							}, editorFieldHeight)),
							removeButton(cx, m, m.T("editor.remove_website"), func() {
								m.MutateDraft(func(d *EditDraft) {
									if idx < len(d.URIs) {
										d.URIs = append(d.URIs[:idx], d.URIs[idx+1:]...)
									}
								})
							}),
						},
					})
				}
				rows = append(rows, addRow(m, "editor-add-uri", m.T("editor.add_website"), func() {
					m.MutateDraft(func(d *EditDraft) { d.URIs = append(d.URIs, EditURIDraft{}) })
				}))
				return card(rows...)
			})),
		},
	}
}

func removeButton(cx *core.Scope, m *AppModel, label string, onPress func()) core.Node {
	return ui.Button{
		Disabled: m.EditBusy.Get,
		Icon:     lucide.X,
		Label:    label,
		Variant:  ui.ButtonGhost,
		Side:     24,
		IconSize: 12,
		Tint:     func() core.Color { return themeColor(cx, "gv-fg3") },
		OnPress:  onPress,
	}
}

func addRow(m *AppModel, testID, label string, onPress func()) core.Node {
	return core.View{
		Disabled: m.EditBusy.Get,
		TestID:   testID,
		Role:     core.RoleButton,
		Label:    label,
		Class:    "flex-row items-center gap-2 px-4 h-[40px] active:bg-gv-fill",
		OnPress:  func(core.PressEvent) { onPress() },
		Children: []core.Node{
			core.View{
				Class:    "w-[16px] h-[16px] rounded-full items-center justify-center bg-gv-accent",
				Children: []core.Node{icon(lucide.Plus(), 11, "text-white")},
			},
			core.Text{Class: "text-[13px] font-medium text-gv-accent", Content: label},
		},
	}
}

func editorCardFields(m *AppModel) core.Node {
	return section(m.T("section.card_details"), card(
		formRow(m.T("field.cardholder"), draftInput(m, "editor-cardholder", m.T("editor.cardholder_placeholder"), func(d *EditDraft) string { return d.Cardholder }, func(d *EditDraft, v string) { d.Cardholder = v })),
		formRow(m.T("field.brand"), draftInput(m, "editor-brand", m.T("editor.brand_placeholder"), func(d *EditDraft) string { return d.Brand }, func(d *EditDraft, v string) { d.Brand = v })),
		formRow(m.T("editor.card_number_label"), draftInputMono(m, "editor-card-number", "1234 5678 9012 3456", func(d *EditDraft) string { return d.CardNumber }, func(d *EditDraft, v string) { d.CardNumber = v })),
		formRow(m.T("field.expiration"), core.View{
			Class: "flex-1 flex-row items-center gap-2",
			Children: []core.Node{
				flexed(draftInput(m, "editor-exp-month", m.T("editor.exp_month_placeholder"), func(d *EditDraft) string { return d.ExpMonth }, func(d *EditDraft, v string) { d.ExpMonth = v })),
				core.Text{Class: "text-[13px] text-gv-fg3", Content: "/"},
				flexed(draftInput(m, "editor-exp-year", m.T("editor.exp_year_placeholder"), func(d *EditDraft) string { return d.ExpYear }, func(d *EditDraft, v string) { d.ExpYear = v })),
			},
		}),
		formRow(m.T("field.security_code"), draftInputMono(m, "editor-card-code", m.T("editor.security_code_placeholder"), func(d *EditDraft) string { return d.CardCode }, func(d *EditDraft, v string) { d.CardCode = v })),
	))
}

func editorIdentityFields(m *AppModel) core.Node {
	pair := func(a, b core.Node) core.Node {
		return core.View{Class: "flex-1 flex-row items-center gap-2", Children: []core.Node{flexed(a), flexed(b)}}
	}
	return core.View{
		Class: "gap-5",
		Children: []core.Node{
			section(m.T("section.personal"), card(
				formRow(m.T("field.name"), pair(
					draftInput(m, "editor-first-name", m.T("editor.first_name_placeholder"), func(d *EditDraft) string { return d.FirstName }, func(d *EditDraft, v string) { d.FirstName = v }),
					draftInput(m, "editor-last-name", m.T("editor.last_name_placeholder"), func(d *EditDraft) string { return d.LastName }, func(d *EditDraft, v string) { d.LastName = v }),
				)),
				formRow(m.T("field.company"), draftInput(m, "editor-company", m.T("field.company"), func(d *EditDraft) string { return d.Company }, func(d *EditDraft, v string) { d.Company = v })),
				formRow(m.T("field.email"), draftInput(m, "editor-ident-email", "name@example.com", func(d *EditDraft) string { return d.Email }, func(d *EditDraft, v string) { d.Email = v })),
				formRow(m.T("field.phone"), draftInput(m, "editor-ident-phone", "+1 555 0100", func(d *EditDraft) string { return d.Phone }, func(d *EditDraft, v string) { d.Phone = v })),
			)),
			section(m.T("section.address"), card(
				formRow(m.T("editor.street_label"), draftInput(m, "editor-ident-addr", m.T("editor.street_placeholder"), func(d *EditDraft) string { return d.Address1 }, func(d *EditDraft, v string) { d.Address1 = v })),
				formRow(m.T("editor.city"), draftInput(m, "editor-ident-city", m.T("editor.city"), func(d *EditDraft) string { return d.City }, func(d *EditDraft, v string) { d.City = v })),
				formRow(m.T("editor.state_zip"), pair(
					draftInput(m, "editor-ident-state", m.T("editor.state_placeholder"), func(d *EditDraft) string { return d.State }, func(d *EditDraft, v string) { d.State = v }),
					draftInput(m, "editor-ident-postal", m.T("editor.postal_placeholder"), func(d *EditDraft) string { return d.PostalCode }, func(d *EditDraft, v string) { d.PostalCode = v }),
				)),
				formRow(m.T("editor.country"), draftInput(m, "editor-ident-country", m.T("editor.country"), func(d *EditDraft) string { return d.Country }, func(d *EditDraft, v string) { d.Country = v })),
			)),
		},
	}
}

func editorSSHKeyFields(m *AppModel) core.Node {
	keyInput := func(testID, placeholder string, multiline bool, get func(*EditDraft) string, set func(*EditDraft, string)) core.Node {
		in := ui.Input{
			Disabled:    m.EditBusy.Get,
			TestID:      testID,
			Placeholder: placeholder,
			Multiline:   multiline,
			Class:       "font-mono",
			Value: func() string {
				if d := m.EditDraft.Get(); d != nil {
					return get(d)
				}
				return ""
			},
			OnChange: func(v string) { m.MutateDraft(func(d *EditDraft) { set(d, v) }) },
		}
		if multiline {
			in.Style = core.Style{MinHeight: core.Pt(120)}
		}
		return flexed(in)
	}
	return section(m.T("section.ssh_key"), card(
		formRow(m.T("field.private_key"), keyInput("editor-ssh-private", "-----BEGIN OPENSSH PRIVATE KEY-----", true,
			func(d *EditDraft) string { return d.SSHPrivate },
			func(d *EditDraft, v string) {
				d.SSHPrivate = v
				if k, err := gen.InspectSSHPrivateKey(v, sshKeyComment(d)); err == nil {
					d.SSHPublic, d.SSHFinger = k.PublicKey, k.KeyFingerprint
				}
			})),
		formRow(m.T("field.public_key"), keyInput("editor-ssh-public", "ssh-ed25519 AAAA…", false,
			func(d *EditDraft) string { return d.SSHPublic }, func(d *EditDraft, v string) { d.SSHPublic = v })),
		formRow(m.T("field.fingerprint"), keyInput("editor-ssh-fingerprint", "SHA256:…", false,
			func(d *EditDraft) string { return d.SSHFinger }, func(d *EditDraft, v string) { d.SSHFinger = v })),
		core.View{
			Class: "flex-row items-center justify-end px-4 py-2",
			Children: []core.Node{
				ui.Button{
					Disabled: m.EditBusy.Get,
					TestID:   "editor-ssh-generate",
					Text:     m.T("editor.ssh_generate"),
					Icon:     lucide.WandSparkles,
					Variant:  ui.ButtonSecondary,
					OnPress:  m.GenerateDraftSSHKey,
				},
			},
		},
	))
}

func sshKeyComment(d *EditDraft) string {
	return strings.TrimSpace(d.Name)
}

func (m *AppModel) GenerateDraftSSHKey() {
	d := m.EditDraft.Get()
	if d == nil {
		return
	}
	k, err := gen.GenerateEd25519SSHKey(sshKeyComment(d))
	if err != nil {
		m.EditError.Set(m.Tf("editor.ssh_generate_failed", err.Error()))
		return
	}
	m.MutateDraft(func(d *EditDraft) {
		d.SSHPrivate, d.SSHPublic, d.SSHFinger = k.PrivateKey, k.PublicKey, k.KeyFingerprint
	})
}

func editorCustomFieldsSection(cx *core.Scope, m *AppModel) core.Node {
	fieldCount := draftCount(cx, m, func(d *EditDraft) int { return len(d.Fields) })
	return section(m.T("section.custom_fields"), core.Dynamic(func(cx *core.Scope) core.Node {
		n := fieldCount.Get()
		rows := make([]core.Node, 0, n+1)
		for i := range n {
			idx := i
			field := func(get func(EditFieldDraft) string, set func(*EditFieldDraft, string), placeholder string) core.Node {
				return flexed(sizedInput(base.Input{
					Disabled:      m.EditBusy.Get,
					Placeholder:   placeholder,
					NoAutoCorrect: true,
					Value: func() string {
						cur := m.EditDraft.Get()
						if cur == nil || idx >= len(cur.Fields) {
							return ""
						}
						return get(cur.Fields[idx])
					},
					OnChange: func(v string) {
						m.MutateDraft(func(d *EditDraft) {
							if idx < len(d.Fields) {
								set(&d.Fields[idx], v)
							}
						})
					},
				}, editorFieldHeight))
			}
			rows = append(rows, core.View{
				Class: "flex-row items-center gap-2 ps-4 pe-2 py-2",
				Children: []core.Node{
					ui.Select[int]{
						Disabled: m.EditBusy.Get,
						Style:    core.Style{Width: core.Pt(92)},
						Options: []ui.Option[int]{
							{Value: 0, Label: m.T("editor.field_type.text")},
							{Value: 1, Label: m.T("editor.field_type.hidden")},
						},
						Value: func() int {
							cur := m.EditDraft.Get()
							if cur == nil || idx >= len(cur.Fields) {
								return 0
							}
							return cur.Fields[idx].Type
						},
						OnChange: func(t int) {
							m.MutateDraft(func(d *EditDraft) {
								if idx < len(d.Fields) {
									d.Fields[idx].Type = t
								}
							})
						},
					},
					field(func(f EditFieldDraft) string { return f.Name }, func(f *EditFieldDraft, v string) { f.Name = v }, m.T("editor.field_name_placeholder")),
					field(func(f EditFieldDraft) string { return f.Value }, func(f *EditFieldDraft, v string) { f.Value = v }, m.T("editor.field_value_placeholder")),
					removeButton(cx, m, m.T("editor.remove_field"), func() {
						m.MutateDraft(func(d *EditDraft) {
							if idx < len(d.Fields) {
								d.Fields = append(d.Fields[:idx], d.Fields[idx+1:]...)
							}
						})
					}),
				},
			})
		}
		rows = append(rows, addRow(m, "editor-add-field", m.T("editor.add_field"), func() {
			m.MutateDraft(func(d *EditDraft) { d.Fields = append(d.Fields, EditFieldDraft{Type: 0}) })
		}))
		return card(rows...)
	}))
}

func draftInput(m *AppModel, testID, placeholder string, get func(*EditDraft) string, set func(*EditDraft, string)) core.Node {
	return draftInputClass(m, testID, placeholder, "", get, set)
}

func draftInputMono(m *AppModel, testID, placeholder string, get func(*EditDraft) string, set func(*EditDraft, string)) core.Node {
	return draftInputClass(m, testID, placeholder, "font-mono", get, set)
}

func draftInputClass(m *AppModel, testID, placeholder, class string, get func(*EditDraft) string, set func(*EditDraft, string)) core.Node {
	return flexed(sizedInput(base.Input{
		TestID:        testID,
		Class:         class,
		Placeholder:   placeholder,
		NoAutoCorrect: true,
		Value: func() string {
			if d := m.EditDraft.Get(); d != nil {
				return get(d)
			}
			return ""
		},
		OnChange: func(v string) {
			m.MutateDraft(func(d *EditDraft) { set(d, v) })
		},
		Disabled: m.EditBusy.Get,
	}, editorFieldHeight))
}
