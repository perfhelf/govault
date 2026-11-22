package ui

import (
	"runtime"

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

	trayTitleKey := "settings.tray.section_tray"
	showTrayKey := "settings.tray.show_tray"
	showTrayDescKey := "settings.tray.show_tray_desc"
	if runtime.GOOS == "darwin" {
		trayTitleKey = "settings.tray.section_menubar"
		showTrayKey = "settings.tray.show_menubar"
		showTrayDescKey = "settings.tray.show_menubar_desc"
	}

	return core.Scroll{
		TestID: "settings-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{
				Class: "w-full max-w-[620px] self-center px-7 pt-6 pb-10 gap-6",
				Children: []core.Node{
					section(m.T("settings.account.section"), card(
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
									Text:    m.T("common.sync_now"),
									Icon:    lucide.RefreshCw,
									Variant: ui.ButtonSecondary,
									Busy:    func() bool { return m.SyncState.Get() == SyncInProgress },
									OnPress: func() { m.SyncNow(false) },
								},
							},
						},
						settingsMetaRow(m.T("settings.account.kdf"), func() string {
							if s := m.Prefs.Get().KDFSummary; s != "" {
								return s
							}
							return "—"
						}),
						settingsMetaRow(m.T("settings.account.last_sync"), func() string {
							ts := m.LastSync.Get()
							if ts.IsZero() {
								return m.T("settings.account.never_synced")
							}
							return m.formatDateTime(ts)
						}),
						settingsRow(
							m.T("settings.account.login_profile"),
							m.T("settings.account.login_profile_desc"),
							ui.Button{
								TestID:  "settings-export-login-profile",
								Text:    m.T("settings.account.login_profile_btn"),
								Icon:    lucide.FileKey,
								Variant: ui.ButtonSecondary,
								OnPress: m.StartExportLoginProfile,
							},
						),
						core.View{
							Class: "flex-row items-center justify-between ps-4 pe-1.5 py-2",
							Children: []core.Node{
								core.Text{Class: "text-[12px] text-gv-fg3", Content: m.T("settings.account.logout_hint")},
								core.View{
									TestID:  "settings-logout",
									Role:    core.RoleButton,
									Label:   m.T("common.log_out"),
									Class:   "flex-row items-center gap-1.5 h-[26px] px-2.5 rounded-[6px] active:bg-gv-danger/10",
									OnPress: func(core.PressEvent) { m.Logout(cx) },
									Children: []core.Node{
										icon(lucide.LogOut(), 13, "text-gv-danger"),
										core.Text{Class: "text-[12.5px] font-medium text-gv-danger", Content: m.T("common.log_out")},
									},
								},
							},
						},
					)),
					section(m.T("settings.language.section"), card(
						settingsRow(
							m.T("settings.language.label"),
							m.T("settings.language.desc"),
							languageSelect(cx, m, "settings-language", 188),
						),
					)),
					section(m.T("settings.security.section"), core.Dynamic(func(cx *core.Scope) core.Node {
						var rows []core.Node
						if showBio {
							rows = append(rows, biometricRows(cx, m, canBio.Get(), bioOn.Get())...)
						}
						rows = append(rows, settingsRow(
							m.T("settings.autolock.label"),
							m.T("settings.autolock.desc"),
							ui.Select[int]{
								TestID: "settings-autolock",
								Style:  core.Style{Width: core.Pt(188)},
								Options: []ui.Option[int]{
									{Value: 1, Label: m.T("settings.autolock.1m")},
									{Value: 5, Label: m.T("settings.autolock.5m")},
									{Value: 15, Label: m.T("settings.autolock.15m")},
									{Value: 60, Label: m.T("settings.autolock.1h")},
									{Value: 0, Label: m.T("common.never")},
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
								m.T("settings.lock_on_sleep.label"),
								m.T("settings.lock_on_sleep.desc"),
								ui.Switch{
									TestID:  "settings-lock-on-sleep",
									Label:   m.T("settings.lock_on_sleep.label"),
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
					section(m.T("settings.backup.section"), card(
						settingsRow(
							m.T("settings.backup.export"),
							m.T("settings.backup.export_desc"),
							ui.Button{
								TestID:  "settings-export",
								Text:    m.T("settings.backup.export_btn"),
								Icon:    lucide.FileOutput,
								Variant: ui.ButtonSecondary,
								OnPress: m.StartExport,
							},
						),
						settingsRow(
							m.T("settings.backup.import"),
							m.T("settings.backup.import_desc"),
							ui.Button{
								TestID:   "settings-import",
								Text:     m.T("settings.backup.import_btn"),
								Icon:     lucide.FileInput,
								Variant:  ui.ButtonSecondary,
								Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
								OnPress:  func() { m.StartImport(cx) },
							},
						),
					)),
					section(m.T("settings.privacy.section"), card(
						settingsRow(
							m.T("settings.privacy.show_favicons"),
							m.T("settings.privacy.show_favicons_desc"),
							ui.Switch{
								TestID:   "settings-show-favicons",
								Label:    m.T("settings.privacy.show_favicons"),
								Checked:  func() bool { return m.Prefs.Get().FaviconsEnabled() },
								OnChange: m.SetShowFavicons,
							},
						),
						settingsRow(
							m.T("settings.privacy.icon_cache"),
							m.T("settings.privacy.icon_cache_desc"),
							ui.Button{
								TestID:  "settings-clear-icon-cache",
								Text:    m.T("settings.privacy.clear_icon_cache"),
								Variant: ui.ButtonSecondary,
								OnPress: m.ClearIconCache,
							},
						),
					)),
					section(m.T("settings.clipboard.section"), card(
						settingsRow(
							m.T("settings.clipboard.clear"),
							m.T("settings.clipboard.clear_desc"),
							ui.Select[int]{
								TestID: "settings-clipboard-clear",
								Style:  core.Style{Width: core.Pt(188)},
								Options: []ui.Option[int]{
									{Value: 15, Label: m.T("settings.clipboard.15s")},
									{Value: 30, Label: m.T("settings.clipboard.30s")},
									{Value: 60, Label: m.T("settings.clipboard.60s")},
									{Value: 0, Label: m.T("common.never")},
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
							m.T("settings.clipboard.concealed"),
							m.T("settings.clipboard.concealed_desc"),
							ui.Badge{
								TextFunc: func() string {
									if m.Hooks.IsClipboardConcealed != nil && m.Hooks.IsClipboardConcealed() {
										return m.T("settings.clipboard.active")
									}
									return m.T("settings.clipboard.macos_only")
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
					section(m.T(trayTitleKey), core.Dynamic(func(cx *core.Scope) core.Node {
						trayOn := showTray.Get()
						rows := []core.Node{settingsRow(
							m.T(showTrayKey),
							m.T(showTrayDescKey),
							ui.Switch{
								TestID:   "settings-show-tray",
								Label:    m.T(showTrayKey),
								Checked:  func() bool { return m.Prefs.Get().ShowTrayIcon },
								OnChange: m.SetShowTrayIcon,
							},
						)}
						rows = append(rows, settingsRow(
							m.T("settings.tray.launch_at_login"),
							m.T("settings.tray.launch_at_login_desc"),
							ui.Switch{
								TestID:  "settings-launch-at-login",
								Label:   m.T("settings.tray.launch_at_login"),
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
							desc := m.T("settings.tray.hide_dock_desc")
							if !trayOn {
								desc = m.T("settings.tray.hide_dock_need_menubar")
							}
							rows = append(rows, settingsRow(
								m.T("settings.tray.hide_dock"),
								desc,
								ui.Switch{
									TestID:   "settings-hide-dock",
									Label:    m.T("settings.tray.hide_dock"),
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
					section(m.T("settings.about.section"), card(
						settingsRow(
							m.Tf("settings.about.version_title", appVersionLabel(m)),
							m.T("settings.about.updates_desc"),
							ui.Button{
								TestID:  "settings-check-updates",
								Text:    m.T("settings.about.check_updates"),
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
	return section(m.T("settings.ssh.section"), core.Dynamic(func(cx *core.Scope) core.Node {
		rows := []core.Node{settingsRow(
			m.T("settings.ssh.enable"),
			m.T("settings.ssh.enable_desc"),
			ui.Switch{
				TestID:   "settings-ssh-agent",
				Label:    m.T("settings.ssh.enable"),
				Checked:  func() bool { return m.Prefs.Get().SSHAgentEnabled },
				OnChange: m.SetSSHAgentEnabled,
			},
		)}
		if !m.Prefs.Get().SSHAgentEnabled {
			return card(rows...)
		}
		rows = append(rows, core.View{
			Class: "flex-row items-center gap-3 ps-4 pe-2.5 py-2.5",
			Children: []core.Node{
				core.View{
					Class: "flex-1 gap-[3px] overflow-hidden",
					Children: []core.Node{
						core.Text{Class: "text-[13px] text-gv-fg", Content: m.T("settings.ssh.socket")},
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
					Text:    m.T("settings.ssh.copy_env"),
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
					core.Text{TestID: "settings-ssh-agent-error", Class: "flex-1 text-[12px] text-gv-fg2", Content: m.Tf("settings.ssh.unavailable", msg)},
				},
			})
		}
		return card(rows...)
	}))
}

func appVersionLabel(m *AppModel) string {
	info := core.App()
	if info.Version == "" {
		return m.T("settings.about.dev")
	}
	if info.Development {
		return m.Tf("settings.about.version_dev", info.Version)
	}
	return info.Version
}

func biometricRows(cx *core.Scope, m *AppModel, available, enabled bool) []core.Node {
	label := m.Tf("settings.biometric.unlock_with", m.BiometricLabel())
	if !available {
		label = m.T("settings.biometric.unlock_touch_id")
		return []core.Node{settingsRow(
			label,
			m.T("settings.biometric.unavailable_desc"),
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
		m.T("settings.biometric.enabled_desc"),
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
							return m.T("settings.biometric.hardware_enforced")
						}
						return m.Tf("settings.biometric.app_gated", m.BiometricLabel())
					},
				},
			},
		})
	}
	if enabled {
		rows = append(rows, settingsRow(
			m.T("settings.biometric.auto_prompt"),
			m.Tf("settings.biometric.auto_prompt_desc", m.BiometricLabel()),
			ui.Switch{
				TestID:  "settings-biometric-autoprompt",
				Label:   m.T("settings.biometric.auto_prompt"),
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
			core.Text{MaxLines: 1, Class: "shrink text-[12.5px] text-gv-fg2 text-end", ContentFunc: value},
		},
	}
}
