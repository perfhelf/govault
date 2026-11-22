package ui

import (
	"strings"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func MainWindowView(cx *core.Scope, m *AppModel) core.Node {
	cx.SetTheme(GovaultTheme())
	if cx.Env().OS() == core.OSMacOS {
		desktop.SetTitleBar(cx, desktop.TitleBarHidden, titleBarHeight)
	}
	m.windowScope = cx
	if m.forcedLocale != "" {
		cx.SetLocale(m.forcedLocale)
	}
	cx.Cleanup(func() {
		if m.windowScope == cx {
			m.windowScope = nil
		}
	})
	bindMainWindowShortcuts(cx, m)

	return core.View{
		TestID: "main-window-root",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				_ = m.Locale.Get()
				switch m.LockState.Get() {
				case state.StatusUnlocked:
					return UnlockedShellView(cx, m)
				case state.StatusLocked:
					if m.ReSignIn.Get() {
						return LoginView(cx, m)
					}
					return LockView(cx, m)
				default:
					return LoginView(cx, m)
				}
			}),
			whenUnlocked(m, func(cx *core.Scope) core.Node {
				return core.Dynamic(func(cx *core.Scope) core.Node {
					_ = m.Locale.Get()
					return repromptDialog(m)
				})
			}),
			whenUnlocked(m, func(cx *core.Scope) core.Node {
				return core.Dynamic(func(cx *core.Scope) core.Node {
					_ = m.Locale.Get()
					return backupDialog(cx, m)
				})
			}),
			whenUnlocked(m, func(cx *core.Scope) core.Node {
				return core.Dynamic(func(cx *core.Scope) core.Node {
					_ = m.Locale.Get()
					return profileExportDialog(cx, m)
				})
			}),
			whenUnlocked(m, func(cx *core.Scope) core.Node {
				return core.Dynamic(func(cx *core.Scope) core.Node {
					_ = m.Locale.Get()
					return folderDialog(m)
				})
			}),
			whenUnlocked(m, func(cx *core.Scope) core.Node {
				return core.Dynamic(func(cx *core.Scope) core.Node {
					_ = m.Locale.Get()
					return batchFolderDialog(m)
				})
			}),
			core.Show{
				When: m.showingSignInScreen,
				Then: func(cx *core.Scope) core.Node {
					return core.Dynamic(func(cx *core.Scope) core.Node {
						_ = m.Locale.Get()
						return profileImportDialog(m)
					})
				},
			},
			ui.Toasts{
				Toaster:   m.Toaster,
				Placement: ui.ToastBottomEnd,
			},
		},
	}
}

func bindMainWindowShortcuts(cx *core.Scope, m *AppModel) {
	cx.OnKeyWith("mod+f", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked {
			return
		}
		m.ResetIdleTimer()
		m.Route.Set(RouteVault)
		m.SearchRef.Focus()
	})
	cx.OnKeyWith("mod+[", core.KeyOptions{When: core.KeyAlways}, func() { m.GoBack(cx) })
	cx.OnKeyWith("mod+]", core.KeyOptions{When: core.KeyAlways}, func() { m.GoForward(cx) })
	cx.OnKeyWith("mod+n", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.SyncState.Get() != SyncOffline {
			m.StartCreateCipher(cx)
		}
	})
	cx.OnKeyWith("mod+e", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.Route.Get() == RouteVault && !m.EditMode.Get() && m.SyncState.Get() != SyncOffline {
			m.StartEditCipher(cx)
		}
	})
	cx.OnKeyWith("mod+s", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.EditMode.Get() {
			m.SaveDraft(cx)
		}
	})
	cx.OnKeyWith("escape", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked {
			return
		}
		if m.EditMode.Get() {
			m.CancelEdit(cx)
		} else if m.BatchSelectMode.Get() && !m.BatchFolderDialog.Get().Open && !m.BatchBusy.Get() {
			m.clearBatchState()
		} else if m.Route.Get() == RouteURLCheck && m.URLCheckPhase.Get() == URLCheckScanning {
			m.CancelURLCheck()
		} else if m.Route.Get() == RouteURLCheck && m.URLCheckSelectedCount() > 0 && !m.BatchFolderDialog.Get().Open && !m.URLCheckBatchBusy.Get() {
			m.ClearURLCheckSelection()
		}
	})
	cx.OnKeyWith("mod+c", core.KeyOptions{When: core.KeyNotEditing}, func() {
		if m.LockState.Get() != state.StatusUnlocked || m.Route.Get() != RouteVault || m.EditMode.Get() {
			return
		}
		c := m.ActiveCipher.Get()
		if c == nil || c.Login == nil || c.Login.Password == "" || m.PasswordHidden(c) {
			return
		}
		m.GateReprompt(cx, c, m.T("reprompt.action.copy_password"), func() {
			m.CopySecretValue(m.T("field.password"), c.Login.Password)
		})
	})
	cx.OnKeyWith("mod+shift+u", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked || m.Route.Get() != RouteVault || m.EditMode.Get() {
			return
		}
		c := m.ActiveCipher.Get()
		if c != nil && c.Login != nil && c.Login.Username != "" {
			m.CopyPlainValue(m.T("field.username"), c.Login.Username)
		}
	})
	cx.OnKeyWith("mod+shift+t", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked || m.Route.Get() != RouteVault || m.EditMode.Get() {
			return
		}
		c := m.ActiveCipher.Get()
		if c == nil || c.Login == nil || strings.TrimSpace(c.Login.TOTP) == "" {
			return
		}
		m.GateReprompt(cx, c, m.T("reprompt.action.copy_totp"), func() {
			if code := m.TOTPCode.Get(); code != "" {
				m.CopySecretValue(m.T("field.totp_code"), code)
			}
		})
	})
	cx.OnKeyWith("mod+l", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			m.Lock()
		}
	})
	cx.OnKeyWith("mod+r", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			m.SyncNow(false)
		}
	})
	cx.OnKeyWith("mod+,", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			m.GuardDirty(cx, func() { m.Route.Set(RouteSettings) })
		}
	})
	cx.OnKeyWith("mod+shift+d", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			m.GuardDirty(cx, func() {
				m.ResetIdleTimer()
				m.Route.Set(RouteDedup)
			})
		}
	})
	cx.OnKeyWith("down", core.KeyOptions{When: core.KeyNotEditing}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.Route.Get() == RouteVault && !m.EditMode.Get() {
			m.MoveListSelection(cx, 1)
		}
	})
	cx.OnKeyWith("up", core.KeyOptions{When: core.KeyNotEditing}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.Route.Get() == RouteVault && !m.EditMode.Get() {
			m.MoveListSelection(cx, -1)
		}
	})
}

func repromptDialog(m *AppModel) core.Node {
	return ui.Dialog{
		TestID: "reprompt-dialog",
		Open:   func() bool { return m.Reprompt.Get().Open },
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.CloseReprompt()
			}
		},
		OnConfirm: m.SubmitReprompt,
		Title:     m.T("reprompt.title"),
		DescriptionFunc: func() string {
			act := m.Reprompt.Get().Action
			if act == "" {
				return m.T("reprompt.desc_default")
			}
			return m.Tf("reprompt.desc_action", act)
		},
		Children: []core.Node{
			ui.Input{
				TestID:        "reprompt-password",
				OnBlur:        settleSecureInput,
				Placeholder:   m.T("common.master_password"),
				Masked:        true,
				AutoFocus:     true,
				NoAutoCorrect: true,
				Value:         m.RepromptPW.Get,
				OnChange:      m.RepromptPW.Set,
				OnSubmit:      func(string) { m.SubmitReprompt() },
			},
			core.Show{
				When: func() bool { return m.RepromptError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{
						Class:       "text-[12px] text-gv-danger",
						ContentFunc: m.RepromptError.Get,
					}
				},
			},
		},
		Footer: []core.Node{
			ui.Button{
				Text:    m.T("common.cancel"),
				Variant: ui.ButtonSecondary,
				OnPress: m.CloseReprompt,
			},
			ui.Button{
				TestID:  "reprompt-confirm",
				Text:    m.T("common.verify"),
				Variant: ui.ButtonPrimary,
				Busy:    m.RepromptBusy.Get,
				OnPress: m.SubmitReprompt,
			},
		},
	}
}

func backupDialog(cx *core.Scope, m *AppModel) core.Node {
	input := func(testID, placeholder string, value *core.Signal[string], autoFocus bool) core.Node {
		return ui.Input{
			TestID:        testID,
			OnBlur:        settleSecureInput,
			Placeholder:   placeholder,
			Masked:        true,
			AutoFocus:     autoFocus,
			NoAutoCorrect: true,
			Value:         value.Get,
			OnChange:      value.Set,
			OnSubmit:      func(string) { m.ConfirmBackupDialog(cx) },
		}
	}
	return ui.Dialog{
		TestID: "backup-dialog",
		Open:   func() bool { return m.BackupDialog.Get() != BackupNone },
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.CloseBackupDialog()
			}
		},
		OnConfirm: func() { m.ConfirmBackupDialog(cx) },
		TitleFunc: func() string {
			if m.BackupDialog.Get() == BackupImport {
				return m.T("backup.dialog.import_title")
			}
			return m.T("backup.dialog.export_title")
		},
		DescriptionFunc: func() string {
			if m.BackupDialog.Get() == BackupImport {
				return m.T("backup.dialog.import_desc")
			}
			return m.T("backup.dialog.export_desc")
		},
		Children: []core.Node{
			input("backup-password", m.T("backup.dialog.password_placeholder"), m.BackupPW, true),
			core.Show{
				When: func() bool { return m.BackupDialog.Get() == BackupExport },
				Then: func(cx *core.Scope) core.Node {
					return input("backup-password-confirm", m.T("backup.dialog.confirm_placeholder"), m.BackupPW2, false)
				},
			},
			core.Show{
				When: func() bool { return m.BackupError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{TestID: "backup-error", Class: "text-[12px] text-gv-danger", ContentFunc: m.BackupError.Get}
				},
			},
		},
		Footer: []core.Node{
			ui.Button{Text: m.T("common.cancel"), Variant: ui.ButtonSecondary, OnPress: m.CloseBackupDialog},
			core.Dynamic(func(cx *core.Scope) core.Node {
				text := m.T("backup.dialog.export_btn")
				if m.BackupDialog.Get() == BackupImport {
					text = m.T("backup.dialog.decrypt_btn")
				}
				return ui.Button{
					TestID:  "backup-confirm",
					Text:    text,
					Variant: ui.ButtonPrimary,
					Busy:    m.BackupBusy.Get,
					OnPress: func() { m.ConfirmBackupDialog(cx) },
				}
			}),
		},
	}
}

func folderDialog(m *AppModel) core.Node {
	return ui.Dialog{
		TestID: "folder-dialog",
		Open:   func() bool { return m.FolderDialog.Get().Open },
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.FolderError.Set("")
				m.FolderDialog.Set(FolderModal{})
			}
		},
		OnConfirm: m.SaveFolderModal,
		TitleFunc: func() string {
			if m.FolderDialog.Get().FolderID == "" {
				return m.T("folder.new_title")
			}
			return m.T("folder.rename_title")
		},
		Children: []core.Node{
			ui.Input{
				TestID:      "folder-name-input",
				Placeholder: m.T("folder.name_placeholder"),
				AutoFocus:   true,
				Value:       func() string { return m.FolderDialog.Get().Name },
				OnChange: func(v string) {
					dlg := m.FolderDialog.Get()
					dlg.Name = v
					m.FolderDialog.Set(dlg)
				},
				OnSubmit: func(string) { m.SaveFolderModal() },
			},
			core.Show{
				When: func() bool { return m.FolderError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{
						Class:       "text-[12px] text-gv-danger",
						ContentFunc: m.FolderError.Get,
					}
				},
			},
		},
		Footer: []core.Node{
			ui.Button{
				Text:    m.T("common.cancel"),
				Variant: ui.ButtonSecondary,
				OnPress: func() {
					m.FolderError.Set("")
					m.FolderDialog.Set(FolderModal{})
				},
			},
			ui.Button{
				TestID:  "folder-save-btn",
				Text:    m.T("common.save"),
				Variant: ui.ButtonPrimary,
				Busy:    m.FolderBusy.Get,
				OnPress: m.SaveFolderModal,
			},
		},
	}
}

func batchFolderDialog(m *AppModel) core.Node {
	return ui.Dialog{
		TestID: "batch-folder-dialog",
		Open:   func() bool { return m.BatchFolderDialog.Get().Open },
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.CloseBatchFolderDialog()
			}
		},
		TitleFunc: func() string {
			if m.BatchFolderDialog.Get().Mode == BatchFolderRestore {
				return m.T("batch.folder.restore_title")
			}
			return m.T("batch.folder.move_title")
		},
		DescriptionFunc: func() string {
			dlg := m.BatchFolderDialog.Get()
			if dlg.Mode == BatchFolderURLCheckMove {
				n := m.URLCheckSelectedCount()
				if n == 1 {
					return m.Tf("batch.folder.choose_desc_one", n)
				}
				return m.Tf("batch.folder.choose_desc_many", n)
			}
			n := m.BatchSelectedCount()
			if dlg.Mode == BatchFolderRestore {
				if n == 1 {
					return m.Tf("batch.folder.restore_desc_one", n)
				}
				return m.Tf("batch.folder.restore_desc_many", n)
			}
			if n == 1 {
				return m.Tf("batch.folder.choose_desc_one", n)
			}
			return m.Tf("batch.folder.choose_desc_many", n)
		},
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				dlg := m.BatchFolderDialog.Get()
				folders := m.Folders.Get()
				disabled := func() bool { return m.BatchBusy.Get() || m.URLCheckBatchBusy.Get() || m.BatchMutationsDisabled() }
				optionBtn := func(testID, text string, icon func() *core.SVG, onPress func()) core.Node {
					return ui.Button{
						TestID:   testID,
						Text:     text,
						Icon:     icon,
						Variant:  ui.ButtonSecondary,
						Style:    core.Style{Width: core.Pct(100)},
						Disabled: disabled,
						OnPress:  onPress,
					}
				}

				var rows []core.Node
				if dlg.Mode == BatchFolderRestore {
					rows = append(rows, optionBtn("batch-folder-original", m.T("batch.folder.restore_original"), lucide.RotateCcw, func() {
						m.ExecuteBatchRestore(nil)
					}))
				}
				rows = append(rows, optionBtn("batch-folder-none", m.T("batch.folder.none"), lucide.Folder, func() {
					switch dlg.Mode {
					case BatchFolderRestore:
						empty := ""
						m.ExecuteBatchRestore(&empty)
					case BatchFolderURLCheckMove:
						m.ExecuteURLCheckBatchMoveFolder(nil)
					default:
						m.ExecuteBatchMoveFolder(nil)
					}
				}))
				for _, f := range folders {
					fid := f.ID
					rows = append(rows, optionBtn("batch-folder-option-"+fid, f.Name, lucide.Folder, func() {
						switch dlg.Mode {
						case BatchFolderRestore:
							m.ExecuteBatchRestore(&fid)
						case BatchFolderURLCheckMove:
							m.ExecuteURLCheckBatchMoveFolder(&fid)
						default:
							m.ExecuteBatchMoveFolder(&fid)
						}
					}))
				}
				return core.Scroll{
					Style:    core.Style{MaxHeight: core.Pt(260)},
					Children: []core.Node{core.View{Class: "gap-1.5", Children: rows}},
				}
			}),
		},
		Footer: []core.Node{
			ui.Button{
				TestID:   "batch-folder-cancel",
				Text:     m.T("common.cancel"),
				Variant:  ui.ButtonSecondary,
				Disabled: func() bool { return m.BatchBusy.Get() || m.URLCheckBatchBusy.Get() },
				OnPress:  m.CloseBatchFolderDialog,
			},
		},
	}
}

// whenUnlocked mounts a vault dialog only while the vault is unlocked, so
// none of its contents outlive the session.
func whenUnlocked(m *AppModel, node func(cx *core.Scope) core.Node) core.Node {
	return core.Show{
		When: func() bool { return m.LockState.Get() == state.StatusUnlocked },
		Then: node,
	}
}
