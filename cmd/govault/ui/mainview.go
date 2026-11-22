package ui

import (
	"fmt"
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
			whenUnlocked(m, func(*core.Scope) core.Node { return repromptDialog(m) }),
			whenUnlocked(m, func(cx *core.Scope) core.Node { return backupDialog(cx, m) }),
			whenUnlocked(m, func(cx *core.Scope) core.Node { return profileExportDialog(cx, m) }),
			whenUnlocked(m, func(*core.Scope) core.Node { return folderDialog(m) }),
			whenUnlocked(m, func(*core.Scope) core.Node { return batchFolderDialog(m) }),
			core.Show{
				When: m.showingSignInScreen,
				Then: func(cx *core.Scope) core.Node { return profileImportDialog(m) },
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
		m.GateReprompt(cx, c, "copy password", func() {
			m.CopySecretValue("Password", c.Login.Password)
		})
	})
	cx.OnKeyWith("mod+shift+u", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked || m.Route.Get() != RouteVault || m.EditMode.Get() {
			return
		}
		c := m.ActiveCipher.Get()
		if c != nil && c.Login != nil && c.Login.Username != "" {
			m.CopyPlainValue("Username", c.Login.Username)
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
		m.GateReprompt(cx, c, "copy TOTP code", func() {
			if code := m.TOTPCode.Get(); code != "" {
				m.CopySecretValue("TOTP code", code)
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
		Title:     "Master Password Verification",
		DescriptionFunc: func() string {
			act := m.Reprompt.Get().Action
			if act == "" {
				return "Enter your master password to continue."
			}
			return "Enter your master password to " + act + "."
		},
		Children: []core.Node{
			ui.Input{
				TestID:        "reprompt-password",
				OnBlur:        settleSecureInput,
				Placeholder:   "Master Password",
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
				Text:    "Cancel",
				Variant: ui.ButtonSecondary,
				OnPress: m.CloseReprompt,
			},
			ui.Button{
				TestID:  "reprompt-confirm",
				Text:    "Verify",
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
				return "Backup Password"
			}
			return "Protect Your Backup"
		},
		DescriptionFunc: func() string {
			if m.BackupDialog.Get() == BackupImport {
				return "Enter the password this backup was exported with."
			}
			return "Choose a password for the encrypted backup. It cannot be recovered if you forget it."
		},
		Children: []core.Node{
			input("backup-password", "Backup password", m.BackupPW, true),
			core.Show{
				When: func() bool { return m.BackupDialog.Get() == BackupExport },
				Then: func(cx *core.Scope) core.Node {
					return input("backup-password-confirm", "Confirm password", m.BackupPW2, false)
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
			ui.Button{Text: "Cancel", Variant: ui.ButtonSecondary, OnPress: m.CloseBackupDialog},
			core.Dynamic(func(cx *core.Scope) core.Node {
				text := "Export"
				if m.BackupDialog.Get() == BackupImport {
					text = "Decrypt"
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
				return "New Folder"
			}
			return "Rename Folder"
		},
		Children: []core.Node{
			ui.Input{
				TestID:      "folder-name-input",
				Placeholder: "Folder name",
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
				Text:    "Cancel",
				Variant: ui.ButtonSecondary,
				OnPress: func() {
					m.FolderError.Set("")
					m.FolderDialog.Set(FolderModal{})
				},
			},
			ui.Button{
				TestID:  "folder-save-btn",
				Text:    "Save",
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
				return "Restore Items"
			}
			return "Move to Folder"
		},
		DescriptionFunc: func() string {
			n := m.BatchSelectedCount()
			noun := batchItemNoun(n)
			if m.BatchFolderDialog.Get().Mode == BatchFolderRestore {
				return fmt.Sprintf("Restore %d selected %s to their original folders or choose a folder.", n, noun)
			}
			return fmt.Sprintf("Choose a folder for %d selected %s.", n, noun)
		},
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				dlg := m.BatchFolderDialog.Get()
				folders := m.Folders.Get()
				disabled := func() bool { return m.BatchBusy.Get() || m.BatchMutationsDisabled() }
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
					rows = append(rows, optionBtn("batch-folder-original", "Restore (Original Folders)", lucide.RotateCcw, func() {
						m.ExecuteBatchRestore(nil)
					}))
				}
				rows = append(rows, optionBtn("batch-folder-none", "(No Folder)", lucide.Folder, func() {
					if dlg.Mode == BatchFolderRestore {
						empty := ""
						m.ExecuteBatchRestore(&empty)
						return
					}
					m.ExecuteBatchMoveFolder(nil)
				}))
				for _, f := range folders {
					fid := f.ID
					rows = append(rows, optionBtn("batch-folder-option-"+fid, f.Name, lucide.Folder, func() {
						if dlg.Mode == BatchFolderRestore {
							m.ExecuteBatchRestore(&fid)
							return
						}
						m.ExecuteBatchMoveFolder(&fid)
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
				Text:     "Cancel",
				Variant:  ui.ButtonSecondary,
				Disabled: m.BatchBusy.Get,
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
