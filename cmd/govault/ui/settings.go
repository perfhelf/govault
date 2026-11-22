package ui

import (
	"runtime"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/nsgo-dev/nsgo/updater"
)

func SettingsView(cx *core.Scope, m *AppModel) core.Node {
	m.RefreshBiometricAvailability()
	m.RefreshBiometricProtection()
	showBio := runtime.GOOS == "darwin" || m.CanUseBiometric()
	canBio := core.NewMemo(cx, m.CanUseBiometric)
	bioOn := core.NewMemo(cx, func() bool { return m.Prefs.Get().BiometricEnabled })
	showTray := core.NewMemo(cx, func() bool { return m.Prefs.Get().ShowTrayIcon })

	return core.Scroll{
		TestID: "settings-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{
				Class: "w-full max-w-[620px] self-center px-7 pt-6 pb-10 gap-6",
				Children: []core.Node{
					section("Account", card(
						core.View{
							Class: "flex-row items-center gap-3 px-4 py-3.5",
							Children: []core.Node{
								avatar(func() string { return m.Prefs.Get().Email }, 40),
								core.View{
									Class: "flex-1 gap-[2px] overflow-hidden",
									Children: []core.Node{
										core.Text{MaxLines: 1, Class: "text-[14px] font-semibold text-gv-fg", ContentFunc: func() string { return m.Prefs.Get().Email }},
										core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2", ContentFunc: func() string { return m.Prefs.Get().ServerURL }},
									},
								},
								ui.Button{
									TestID:  "settings-sync-now",
									Text:    "Sync Now",
									Icon:    lucide.RefreshCw,
									Variant: ui.ButtonSecondary,
									Busy:    func() bool { return m.SyncState.Get() == SyncInProgress },
									OnPress: func() { m.SyncNow(false) },
								},
							},
						},
						settingsMetaRow("Key derivation", func() string {
							if s := m.Prefs.Get().KDFSummary; s != "" {
								return s
							}
							return "—"
						}),
						settingsMetaRow("Last sync", func() string {
							ts := m.LastSync.Get()
							if ts.IsZero() {
								return "Not yet synced"
							}
							return ts.Local().Format("Jan 2, 2006 at 3:04 PM")
						}),
						settingsRow(
							"Login profile",
							"Export server, email, and optional API key as an encrypted .gvprofile file (never includes your master password).",
							ui.Button{
								TestID:  "settings-export-login-profile",
								Text:    "Export Encrypted Login Profile…",
								Icon:    lucide.FileKey,
								Variant: ui.ButtonSecondary,
								OnPress: m.StartExportLoginProfile,
							},
						),
						core.View{
							Class: "flex-row items-center justify-between pl-4 pr-1.5 py-2",
							Children: []core.Node{
								core.Text{Class: "text-[12px] text-gv-fg3", Content: "Logging out removes the local vault cache."},
								core.View{
									TestID:  "settings-logout",
									Role:    core.RoleButton,
									Label:   "Log Out",
									Class:   "flex-row items-center gap-1.5 h-[26px] px-2.5 rounded-[6px] active:bg-gv-danger/10",
									OnPress: func(core.PressEvent) { m.Logout(cx) },
									Children: []core.Node{
										icon(lucide.LogOut(), 13, "text-gv-danger"),
										core.Text{Class: "text-[12.5px] font-medium text-gv-danger", Content: "Log Out"},
									},
								},
							},
						},
					)),
					section("Security", core.Dynamic(func(cx *core.Scope) core.Node {
						var rows []core.Node
						if showBio {
							rows = append(rows, biometricRows(cx, m, canBio.Get(), bioOn.Get())...)
						}
						rows = append(rows, settingsRow(
							"Auto-lock",
							"Lock the vault after a period of inactivity.",
							ui.Select[int]{
								TestID: "settings-autolock",
								Style:  core.Style{Width: core.Pt(172)},
								Options: []ui.Option[int]{
									{Value: 1, Label: "After 1 minute"},
									{Value: 5, Label: "After 5 minutes"},
									{Value: 15, Label: "After 15 minutes"},
									{Value: 60, Label: "After 1 hour"},
									{Value: 0, Label: "Never"},
								},
								Value: func() int { return m.Prefs.Get().AutoLockMinutes },
								OnChange: func(mins int) {
									m.UpdatePrefs(func(p UserPrefs) UserPrefs {
										p.AutoLockMinutes = mins
										return p
									})
									m.ResetIdleTimer()
								},
							},
						))
						if m.Hooks.SleepLockSupported {
							rows = append(rows, settingsRow(
								"Lock on sleep or screen lock",
								"Lock the vault when your Mac sleeps or the screen locks.",
								ui.Switch{
									TestID:  "settings-lock-on-sleep",
									Label:   "Lock on sleep or screen lock",
									Checked: func() bool { return m.Prefs.Get().LockOnSleep },
									OnChange: func(on bool) {
										m.UpdatePrefs(func(p UserPrefs) UserPrefs {
											p.LockOnSleep = on
											return p
										})
									},
								},
							))
						}
						return card(rows...)
					})),
					core.Show{
						When: func() bool { return m.Hooks.SSHAgent != nil },
						Then: func(cx *core.Scope) core.Node { return sshAgentSection(m) },
					},
					section("Backup", card(
						settingsRow(
							"Export encrypted backup",
							"A Bitwarden-compatible JSON file protected by a password you choose.",
							ui.Button{
								TestID:  "settings-export",
								Text:    "Export…",
								Icon:    lucide.FileOutput,
								Variant: ui.ButtonSecondary,
								OnPress: m.StartExport,
							},
						),
						settingsRow(
							"Import backup",
							"Bitwarden JSON, encrypted or plain. Review every item before anything changes.",
							ui.Button{
								TestID:   "settings-import",
								Text:     "Import…",
								Icon:     lucide.FileInput,
								Variant:  ui.ButtonSecondary,
								Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
								OnPress:  func() { m.StartImport(cx) },
							},
						),
					)),
					section("Privacy", card(
						settingsRow(
							"Show website icons",
							"Fetch site icons from your Vaultwarden server.",
							ui.Switch{
								TestID:   "settings-show-favicons",
								Label:    "Show website icons",
								Checked:  func() bool { return m.Prefs.Get().FaviconsEnabled() },
								OnChange: m.SetShowFavicons,
							},
						),
						settingsRow(
							"Icon cache",
							"Remove downloaded site icons from this device.",
							ui.Button{
								TestID:  "settings-clear-icon-cache",
								Text:    "Clear Icon Cache",
								Variant: ui.ButtonSecondary,
								OnPress: m.ClearIconCache,
							},
						),
					)),
					section("Clipboard", card(
						settingsRow(
							"Clear copied secrets",
							"Clears the clipboard if it still holds the copied value.",
							ui.Select[int]{
								TestID: "settings-clipboard-clear",
								Style:  core.Style{Width: core.Pt(172)},
								Options: []ui.Option[int]{
									{Value: 15, Label: "After 15 seconds"},
									{Value: 30, Label: "After 30 seconds"},
									{Value: 60, Label: "After 60 seconds"},
									{Value: 0, Label: "Never"},
								},
								Value: func() int { return m.Prefs.Get().ClipboardClearSeconds },
								OnChange: func(secs int) {
									m.UpdatePrefs(func(p UserPrefs) UserPrefs {
										p.ClipboardClearSeconds = secs
										return p
									})
								},
							},
						),
						settingsRow(
							"Concealed clipboard",
							"Marks secrets so clipboard managers skip them.",
							ui.Badge{
								TextFunc: func() string {
									if m.Hooks.IsClipboardConcealed != nil && m.Hooks.IsClipboardConcealed() {
										return "Active"
									}
									return "macOS only"
								},
								VariantFunc: func() ui.BadgeVariant {
									if m.Hooks.IsClipboardConcealed != nil && m.Hooks.IsClipboardConcealed() {
										return ui.BadgeUp
									}
									return ui.BadgeNeutral
								},
							},
						),
					)),
					section(trayLabel(), core.Dynamic(func(cx *core.Scope) core.Node {
						trayOn := showTray.Get()
						rows := []core.Node{settingsRow(
							"Show "+strings.ToLower(trayLabel())+" icon",
							"Open GoVault, sync or lock from the "+strings.ToLower(trayLabel())+".",
							ui.Switch{
								TestID:   "settings-show-tray",
								Label:    "Show " + strings.ToLower(trayLabel()) + " icon",
								Checked:  func() bool { return m.Prefs.Get().ShowTrayIcon },
								OnChange: m.SetShowTrayIcon,
							},
						)}
						rows = append(rows, settingsRow(
							"Launch at login",
							"Start GoVault automatically when you sign in.",
							ui.Switch{
								TestID:  "settings-launch-at-login",
								Label:   "Launch at login",
								Checked: func() bool { return m.Prefs.Get().LaunchAtLogin },
								OnChange: func(on bool) {
									m.UpdatePrefs(func(p UserPrefs) UserPrefs {
										p.LaunchAtLogin = on
										return p
									})
									if m.Hooks.SetLaunchAtLogin != nil {
										m.Hooks.SetLaunchAtLogin(on)
									}
								},
							},
						))
						if runtime.GOOS == "darwin" {
							desc := "Keep GoVault in the menu bar only."
							if !trayOn {
								desc = "Turn on the menu bar icon first, so GoVault stays reachable."
							}
							rows = append(rows, settingsRow(
								"Hide Dock icon",
								desc,
								ui.Switch{
									TestID:   "settings-hide-dock",
									Label:    "Hide Dock icon",
									Disabled: func() bool { return !m.Prefs.Get().ShowTrayIcon },
									Checked:  func() bool { return m.Prefs.Get().ShowTrayIcon && m.Prefs.Get().HideDockIcon },
									OnChange: func(on bool) {
										m.UpdatePrefs(func(p UserPrefs) UserPrefs {
											p.HideDockIcon = on
											return p
										})
										if m.Hooks.SetDockVisible != nil {
											m.Hooks.SetDockVisible(!on)
										}
									},
								},
							))
						}
						return card(rows...)
					})),
					section("About", card(
						settingsRow(
							"GoVault "+appVersionLabel(),
							"Updates are signed and installed automatically.",
							ui.Button{
								TestID:  "settings-check-updates",
								Text:    "Check for Updates",
								Icon:    lucide.RefreshCw,
								Variant: ui.ButtonSecondary,
								OnPress: func() { updater.Check(cx) },
							},
						),
					)),
				},
			},
		},
	}
}

func sshAgentSection(m *AppModel) core.Node {
	return section("SSH Agent", core.Dynamic(func(cx *core.Scope) core.Node {
		rows := []core.Node{settingsRow(
			"Enable SSH agent",
			"Serve SSH keys from the unlocked vault. Keys with master password reprompt are not served.",
			ui.Switch{
				TestID:   "settings-ssh-agent",
				Label:    "Enable SSH agent",
				Checked:  func() bool { return m.Prefs.Get().SSHAgentEnabled },
				OnChange: m.SetSSHAgentEnabled,
			},
		)}
		if !m.Prefs.Get().SSHAgentEnabled {
			return card(rows...)
		}
		rows = append(rows, core.View{
			Class: "flex-row items-center gap-3 pl-4 pr-2.5 py-2.5",
			Children: []core.Node{
				core.View{
					Class: "flex-1 gap-[3px] overflow-hidden",
					Children: []core.Node{
						core.Text{Class: "text-[13px] text-gv-fg", Content: "Socket"},
						core.Text{
							TestID:     "settings-ssh-agent-socket",
							Class:      "text-[12px] font-mono text-gv-fg2",
							Selectable: core.SelectableOn,
							Content:    m.SSHAgentSocketPath(),
						},
					},
				},
				ui.Button{
					TestID:  "settings-ssh-agent-copy",
					Text:    "Copy SSH_AUTH_SOCK",
					Icon:    lucide.Copy,
					Variant: ui.ButtonSecondary,
					OnPress: m.CopySSHAuthSock,
				},
			},
		})
		if msg := m.SSHAgentError.Get(); msg != "" {
			rows = append(rows, core.View{
				Class: "flex-row items-center gap-2 px-4 py-2.5",
				Children: []core.Node{
					icon(lucide.TriangleAlert(), 13, "text-gv-warn"),
					core.Text{TestID: "settings-ssh-agent-error", Class: "flex-1 text-[12px] text-gv-fg2", Content: "Agent unavailable: " + msg},
				},
			})
		}
		return card(rows...)
	}))
}

func appVersionLabel() string {
	info := core.App()
	if info.Version == "" {
		return "(development)"
	}
	if info.Development {
		return info.Version + " (development)"
	}
	return info.Version
}

func trayLabel() string {
	if runtime.GOOS == "darwin" {
		return "Menu Bar"
	}
	return "Tray"
}

func biometricRows(cx *core.Scope, m *AppModel, available, enabled bool) []core.Node {
	label := "Unlock with " + m.BiometricLabel()
	if !available {
		label = "Unlock with Touch ID"
		return []core.Node{settingsRow(
			label,
			"Touch ID unavailable on this Mac — pair a Touch ID keyboard or enroll in System Settings.",
			ui.Switch{
				TestID:   "settings-biometric-toggle",
				Label:    label,
				Disabled: func() bool { return true },
				Checked:  func() bool { return false },
			},
		)}
	}
	rows := []core.Node{settingsRow(
		label,
		"Keeps a wrapped key in the system keychain for fast unlock.",
		ui.Switch{
			TestID:   "settings-biometric-toggle",
			Label:    label,
			Checked:  func() bool { return m.Prefs.Get().BiometricEnabled },
			OnChange: func(on bool) { m.ToggleBiometric(cx, on) },
		},
	)}
	if enabled && runtime.GOOS == "darwin" {
		rows = append(rows, core.View{
			Class: "flex-row items-center gap-2 px-4 py-2.5",
			Children: []core.Node{
				iconFunc(func() *core.SVG {
					if m.BiometricHardware.Get() {
						return lucide.ShieldCheck()
					}
					return lucide.KeyRound()
				}, 13, func() string { return "text-gv-fg3" }),
				core.Text{
					TestID: "settings-biometric-protection",
					Class:  "flex-1 text-[12px] text-gv-fg2",
					ContentFunc: func() string {
						if m.BiometricHardware.Get() {
							return "Hardware-enforced: macOS releases the key only after Touch ID."
						}
						return "App-gated: the key is in your login keychain and GoVault asks for " + m.BiometricLabel() + " before reading it."
					},
				},
			},
		})
	}
	if enabled {
		rows = append(rows, settingsRow(
			"Prompt automatically",
			"Ask for "+m.BiometricLabel()+" as soon as the locked window opens.",
			ui.Switch{
				TestID:  "settings-biometric-autoprompt",
				Label:   "Prompt automatically",
				Checked: func() bool { return m.Prefs.Get().AutoPromptBiometric },
				OnChange: func(on bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs {
						p.AutoPromptBiometric = on
						return p
					})
				},
			},
		))
	}
	return rows
}

func settingsRow(title, desc string, control core.Node) core.Node {
	return optionRow(title, desc, control)
}

func settingsMetaRow(label string, value func() string) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between gap-4 px-4 py-2.5",
		Children: []core.Node{
			core.Text{Class: "text-[13px] text-gv-fg", Content: label},
			core.Text{MaxLines: 1, Class: "shrink text-[12.5px] text-gv-fg2 text-right", ContentFunc: value},
		},
	}
}
