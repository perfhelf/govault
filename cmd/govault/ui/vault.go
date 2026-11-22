package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func UnlockedShellView(cx *core.Scope, m *AppModel) core.Node {
	shellW := core.NewSignal[float32](cx, 0)
	clamp := func() {
		sw, lw := ClampPaneWidths(m.SidebarW.Get(), m.ListW.Get(), shellW.Get())
		m.SidebarW.Set(sw)
		m.ListW.Set(lw)
	}
	return core.View{
		TestID: "vault-shell",
		Class:  "flex-1 flex-row bg-gv-list",
		OnLayout: func(b core.Bounds) {
			shellW.Set(float32(b.Size.Width))
			clamp()
		},
		Children: []core.Node{
			sidebarView(cx, m),
			paneHandle("sidebar-resize", m.SidebarW, func(w float32) (float32, float32) {
				sw, _ := ClampPaneWidths(w, m.ListW.Get(), shellW.Get())
				return sw, DefaultSidebarWidth
			}, m.PersistPaneWidths),
			core.View{
				Class: "flex-1 overflow-hidden",
				Children: []core.Node{
					topToolbar(cx, m),
					core.Show{
						When: func() bool { return m.SyncState.Get() == SyncAuthExpired || m.CredentialsNotSaved.Get() },
						Then: func(cx *core.Scope) core.Node {
							return core.View{
								Class: "flex-row items-center gap-3 px-4 py-2 bg-gv-warn-soft border-b border-gv-line",
								Children: []core.Node{
									icon(lucide.TriangleAlert(), 14, "text-gv-warn"),
									core.Text{
										TestID: "signin-banner",
										Class:  "flex-1 text-[12px] text-gv-fg",
										ContentFunc: func() string {
											switch {
											case m.LocalOnly.Get():
												return "Sign in again to sync. Your vault is available offline until then."
											case m.SyncState.Get() == SyncAuthExpired:
												return "Session expired — your cached vault is still readable. Sign in again to resume syncing."
											}
											return "Your sign-in could not be saved. Sign in again so GoVault can still sync after you lock."
										},
									},
									ui.Button{
										TestID:  "signin-banner-action",
										Text:    "Sign In Again",
										Variant: ui.ButtonSecondary,
										Size:    ui.SizeSmall,
										OnPress: m.SignInAgain,
									},
								},
							}
						},
					},
					core.Dynamic(func(cx *core.Scope) core.Node {
						switch m.Route.Get() {
						case RouteGenerator:
							return GeneratorView(cx, m)
						case RouteSettings:
							return SettingsView(cx, m)
						case RouteHealth:
							return HealthView(cx, m)
						case RouteImport:
							return ImportView(cx, m)
						default:
							return vaultSplitPanes(cx, m, shellW)
						}
					}),
				},
			},
		},
	}
}

func (m *AppModel) filterTitle() string {
	switch m.Route.Get() {
	case RouteGenerator:
		return "Generator"
	case RouteSettings:
		return "Settings"
	case RouteHealth:
		return "Vault Health"
	case RouteImport:
		return "Import"
	}
	if m.SearchIsGlobal() {
		return "All Items"
	}
	return m.sectionTitle()
}

func (m *AppModel) sectionTitle() string {
	f := m.SidebarFilter.Get()
	if f.Type != nil {
		switch *f.Type {
		case api.CipherTypeLogin:
			return "Logins"
		case api.CipherTypeCard:
			return "Cards"
		case api.CipherTypeIdentity:
			return "Identities"
		case api.CipherTypeSecureNote:
			return "Secure Notes"
		case api.CipherTypeSSHKey:
			return "SSH Keys"
		}
	}
	if f.CollectionID != "" {
		for _, col := range m.Collections.Get() {
			if col.ID == f.CollectionID {
				return col.Name
			}
		}
		return "Collection"
	}
	if f.FolderID != "" {
		for _, folder := range m.Folders.Get() {
			if folder.ID == f.FolderID {
				return folder.Name
			}
		}
		return "Folder"
	}
	switch f.Category {
	case state.FilterFavorites:
		return "Favorites"
	case state.FilterTrash:
		return "Trash"
	case state.FilterArchive:
		return "Archive"
	case state.FilterNoFolder:
		return "No Folder"
	}
	return "All Items"
}

func topToolbar(cx *core.Scope, m *AppModel) core.Node {
	toolIcon := func(testID, label string, glyph func() *core.SVG, busy func() bool, onPress func()) core.Node {
		return ui.Button{
			TestID:   testID,
			Icon:     glyph,
			Label:    label,
			Variant:  ui.ButtonGhost,
			Side:     30,
			IconSize: 16,
			Busy:     busy,
			Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
			OnPress:  onPress,
		}
	}
	navButton := func(testID, label string, glyph func() *core.SVG, enabled func() bool, onPress func()) core.Node {
		return ui.Button{
			TestID:   testID,
			Icon:     glyph,
			Label:    label,
			Variant:  ui.ButtonGhost,
			Side:     26,
			IconSize: 15,
			Disabled: func() bool { return !enabled() },
			Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
			OnPress:  onPress,
		}
	}
	return core.View{
		Class:   "flex-row items-center gap-3 pl-3 pr-3 border-b border-gv-line bg-gv-list",
		Style:   core.Style{Height: core.Pt(titleBarHeight)},
		Desktop: dragRegion(),
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-0.5",
				Children: []core.Node{
					navButton("toolbar-back", "Back", lucide.ChevronLeft, m.CanGoBack.Get, func() { m.GoBack(cx) }),
					navButton("toolbar-forward", "Forward", lucide.ChevronRight, m.CanGoForward.Get, func() { m.GoForward(cx) }),
				},
			},
			core.View{
				Class: "flex-row items-baseline gap-2 shrink",
				Children: []core.Node{
					core.Text{
						TestID:      "toolbar-title",
						MaxLines:    1,
						Class:       "text-[15px] font-semibold text-gv-fg",
						ContentFunc: m.filterTitle,
					},
					core.Text{
						Class: "text-[12px] text-gv-fg3 tabular-nums",
						ContentFunc: func() string {
							if m.Route.Get() != RouteVault {
								return ""
							}
							n := m.FilteredItems.Len()
							if n == 1 {
								return "1 item"
							}
							return fmt.Sprintf("%d items", n)
						},
					},
				},
			},
			core.View{Class: "flex-1"},
			core.View{
				Style: core.Style{FlexGrow: 1, FlexShrink: 1, MinWidth: core.Pt(260), MaxWidth: core.Pt(400)},
				Children: []core.Node{
					searchField(cx, base.Input{
						TestID:        "vault-search",
						Ref:           &m.SearchRef,
						Placeholder:   "Search vault",
						NoAutoCorrect: true,
						Role:          core.RoleSearchField,
						Value:         m.SearchQuery.Get,
						OnChange:      m.SetSearchQuery,
					}, cx.KeyLabel("mod+f"), func() { m.SetSearchQuery("") }),
				},
			},
			core.View{
				Class: "flex-row items-center gap-1",
				Children: []core.Node{
					core.Show{
						When: func() bool { return m.SyncState.Get() == SyncOffline },
						Then: func(cx *core.Scope) core.Node {
							return core.View{
								Class: "flex-row items-center gap-1.5 h-[22px] px-2 mr-1 rounded-full bg-gv-warn-soft",
								Children: []core.Node{
									icon(lucide.CloudOff(), 12, "text-gv-warn"),
									core.Text{Class: "text-[11.5px] font-medium text-gv-warn", Content: "Offline"},
								},
							}
						},
					},
					toolIcon("toolbar-sync", "Sync now", lucide.RefreshCw,
						func() bool { return m.SyncState.Get() == SyncInProgress },
						func() { m.SyncNow(false) }),
					toolIcon("toolbar-lock", "Lock vault", lucide.Lock, nil, m.Lock),
					core.View{Class: "w-px h-[18px] mx-1.5 bg-gv-line"},
					ui.Button{
						TestID:   "toolbar-new-item",
						Text:     "New Item",
						Icon:     lucide.Plus,
						Variant:  ui.ButtonPrimary,
						Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
						OnPress:  func() { m.StartCreateCipher(cx) },
					},
				},
			},
		},
	}
}

type sidebarEntry struct {
	testID string
	label  string
	glyph  func() *core.SVG
	tint   uint32
	count  func() int
	badge  bool
	active func() bool
	press  func()
}

func sidebarView(cx *core.Scope, m *AppModel) core.Node {
	vaultActive := func(match func(f state.SearchFilter) bool) func() bool {
		return func() bool { return m.Route.Get() == RouteVault && match(m.SidebarFilter.Get()) }
	}
	typeEntry := func(testID, label string, t api.CipherType, glyph func() *core.SVG, tint uint32, count func(VaultCounts) int) sidebarEntry {
		ct := t
		return sidebarEntry{
			testID: testID, label: label, glyph: glyph, tint: tint,
			count:  func() int { return count(m.AllCounts.Get()) },
			active: vaultActive(func(f state.SearchFilter) bool { return f.Type != nil && *f.Type == ct }),
			press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &ct}) },
		}
	}
	route := func(r MainRoute) func() {
		return func() {
			m.GuardDirty(cx, func() {
				m.ResetIdleTimer()
				m.Route.Set(r)
			})
		}
	}

	return core.View{
		TestID: "vault-sidebar",
		Class:  "bg-gv-sidebar",
		StyleFunc: func() core.Style {
			return core.Style{Width: core.Pt(core.Points(m.SidebarW.Get())), FlexShrink: 0}
		},
		Children: []core.Node{
			core.View{Style: core.Style{Height: core.Pt(titleBarHeight)}, Desktop: dragRegion()},
			core.View{
				Class: "px-2.5 pb-1.5 gap-px",
				Children: []core.Node{
					sidebarRow(sidebarEntry{
						testID: "sidebar-all", label: "All Items", glyph: lucide.LayoutGrid, tint: 0x2f6fe4,
						count:  func() int { return m.AllCounts.Get().All },
						active: vaultActive(IsAllItemsFilter),
						press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll}) },
					}),
					sidebarRow(sidebarEntry{
						testID: "sidebar-favorites", label: "Favorites", glyph: lucide.Star, tint: 0xf0a20b,
						count:  func() int { return m.AllCounts.Get().Favorites },
						active: vaultActive(func(f state.SearchFilter) bool { return f.Category == state.FilterFavorites }),
						press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterFavorites}) },
					}),
				},
			},
			core.Scroll{
				Class: "flex-1 px-2.5 pb-3",
				Children: []core.Node{
					sidebarHeader("Categories", nil),
					sidebarRow(typeEntry("sidebar-type-login", "Logins", api.CipherTypeLogin, lucide.Globe, 0x0a84ff, func(c VaultCounts) int { return c.Login })),
					sidebarRow(typeEntry("sidebar-type-card", "Cards", api.CipherTypeCard, lucide.CreditCard, 0x2fb35a, func(c VaultCounts) int { return c.Card })),
					sidebarRow(typeEntry("sidebar-type-identity", "Identities", api.CipherTypeIdentity, lucide.IdCard, 0xa25ddc, func(c VaultCounts) int { return c.Identity })),
					sidebarRow(typeEntry("sidebar-type-note", "Secure Notes", api.CipherTypeSecureNote, lucide.StickyNote, 0xf08a0a, func(c VaultCounts) int { return c.SecureNote })),
					sidebarRow(typeEntry("sidebar-type-ssh", "SSH Keys", api.CipherTypeSSHKey, lucide.KeyRound, 0x6b7a90, func(c VaultCounts) int { return c.SSHKey })),
					foldersHeader(m, ui.Button{
						TestID:   "sidebar-add-folder",
						Icon:     lucide.Plus,
						Label:    "New Folder",
						Variant:  ui.ButtonGhost,
						Side:     20,
						IconSize: 13,
						Tint:     func() core.Color { return themeColor(cx, "gv-fg3") },
						Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
						OnPress:  m.OpenNewFolderModal,
					}),
					core.Show{
						When: func() bool { return !m.Prefs.Get().FoldersCollapsed },
						Then: func(cx *core.Scope) core.Node {
							return foldersList(cx, m, vaultActive)
						},
					},
					core.Show{
						When: func() bool { return len(m.Collections.Get()) > 0 },
						Then: func(cx *core.Scope) core.Node {
							return core.View{Children: []core.Node{
								collapsibleHeader("sidebar-collections-toggle", "Collections",
									func() bool { return m.Prefs.Get().CollectionsCollapsed },
									func() {
										m.UpdatePrefs(func(p UserPrefs) UserPrefs {
											p.CollectionsCollapsed = !p.CollectionsCollapsed
											return p
										})
									},
									func() int { return len(m.Collections.Get()) }, nil),
								core.Show{
									When: func() bool { return !m.Prefs.Get().CollectionsCollapsed },
									Then: func(cx *core.Scope) core.Node { return collectionsList(m, vaultActive) },
								},
							}}
						},
					},
					sidebarHeader("Tools", nil),
					sidebarRow(sidebarEntry{
						testID: "sidebar-generator", label: "Generator", glyph: lucide.WandSparkles, tint: 0x14a3b8,
						active: func() bool { return m.Route.Get() == RouteGenerator },
						press:  route(RouteGenerator),
					}),
					sidebarRow(sidebarEntry{
						testID: "sidebar-health", label: "Vault Health", glyph: lucide.HeartPulse, tint: 0xe5484d,
						count:  func() int { return m.Health.Get().TotalIssues() },
						badge:  true,
						active: func() bool { return m.Route.Get() == RouteHealth },
						press:  route(RouteHealth),
					}),
					sidebarRow(sidebarEntry{
						testID: "sidebar-archive", label: "Archive", glyph: lucide.Archive, tint: 0x8e8e93,
						count:  func() int { return m.AllCounts.Get().Archive },
						active: vaultActive(func(f state.SearchFilter) bool { return f.Category == state.FilterArchive }),
						press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterArchive}) },
					}),
					sidebarRow(sidebarEntry{
						testID: "sidebar-trash", label: "Trash", glyph: lucide.Trash, tint: 0x8e8e93,
						count:  func() int { return m.AllCounts.Get().Trash },
						active: vaultActive(func(f state.SearchFilter) bool { return f.Category == state.FilterTrash }),
						press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterTrash}) },
					}),
					sidebarRow(sidebarEntry{
						testID: "sidebar-settings", label: "Settings", glyph: lucide.Settings, tint: 0x7c7c84,
						active: func() bool { return m.Route.Get() == RouteSettings },
						press:  route(RouteSettings),
					}),
				},
			},
			syncFooter(m),
		},
	}
}

func foldersList(cx *core.Scope, m *AppModel, vaultActive func(func(state.SearchFilter) bool) func() bool) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		folders := m.Folders.Get()
		rows := make([]core.Node, 0, len(folders)+1)
		for _, f := range folders {
			rows = append(rows, folderRow(cx, m, f))
		}
		rows = append(rows, sidebarRow(sidebarEntry{
			testID: "sidebar-no-folder", label: "No Folder", glyph: lucide.Folder,
			count:  func() int { return m.AllCounts.Get().NoFolder },
			active: vaultActive(func(f state.SearchFilter) bool { return f.Category == state.FilterNoFolder }),
			press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterNoFolder}) },
		}))
		return core.View{Class: "gap-px", Children: rows}
	})
}

func foldersHeader(m *AppModel, trailing core.Node) core.Node {
	return collapsibleHeader("sidebar-folders-toggle", "Folders",
		func() bool { return m.Prefs.Get().FoldersCollapsed },
		func() {
			m.UpdatePrefs(func(p UserPrefs) UserPrefs {
				p.FoldersCollapsed = !p.FoldersCollapsed
				return p
			})
		},
		func() int { return len(m.Folders.Get()) }, trailing)
}

func collapsibleHeader(testID, title string, collapsed func() bool, toggle func(), count func() int, trailing core.Node) core.Node {
	children := []core.Node{
		core.View{
			TestID:   testID,
			Role:     core.RoleButton,
			Label:    title,
			Expanded: func() bool { return !collapsed() },
			Class:    "flex-1 flex-row items-center gap-1 pl-2 h-full",
			OnPress:  func(core.PressEvent) { toggle() },
			Children: []core.Node{
				core.Text{Class: "text-[11px] font-semibold text-gv-fg3", Content: title},
				iconFunc(func() *core.SVG {
					if collapsed() {
						return lucide.ChevronRight()
					}
					return lucide.ChevronDown()
				}, 11, func() string { return "text-gv-fg3" }),
				core.Show{
					When: collapsed,
					Then: func(cx *core.Scope) core.Node {
						return core.Text{
							Class:       "text-[11px] text-gv-fg3 tabular-nums",
							ContentFunc: func() string { return fmt.Sprintf("%d", count()) },
						}
					},
				},
			},
		},
	}
	if trailing != nil {
		children = append(children, trailing)
	}
	return core.View{
		Class:    "flex-row items-center h-[22px] mt-3.5 mb-0.5 pr-1",
		Children: children,
	}
}

func collectionsList(m *AppModel, vaultActive func(func(state.SearchFilter) bool) func() bool) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		cols := m.Collections.Get()
		orgs := m.Organizations.Get()
		var rows []core.Node
		appendCols := func(orgID string) {
			for _, col := range cols {
				if orgID != "" && col.OrganizationID != orgID {
					continue
				}
				id := col.ID
				rows = append(rows, sidebarRow(sidebarEntry{
					testID: "sidebar-collection", label: col.Name, glyph: lucide.Library,
					count:  func() int { return m.AllCounts.Get().ByCollection[id] },
					active: vaultActive(func(f state.SearchFilter) bool { return f.CollectionID == id }),
					press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, CollectionID: id}) },
				}))
			}
		}
		if len(orgs) > 1 {
			for _, org := range orgs {
				rows = append(rows, core.Text{
					MaxLines: 1,
					Class:    "pl-2 pt-1.5 pb-0.5 text-[10.5px] font-medium text-gv-fg3",
					Content:  org.Name,
				})
				appendCols(org.ID)
			}
		} else {
			appendCols("")
		}
		return core.View{TestID: "sidebar-collections", Class: "gap-px", Children: rows}
	})
}

func sidebarHeader(title string, trailing core.Node) core.Node {
	children := []core.Node{core.Text{Class: "flex-1 text-[11px] font-semibold text-gv-fg3", Content: title}}
	if trailing != nil {
		children = append(children, trailing)
	}
	return core.View{
		Class:    "flex-row items-center h-[22px] mt-3.5 mb-0.5 pl-2 pr-1",
		Children: children,
	}
}

func sidebarRow(e sidebarEntry) core.Node {
	var lead core.Node
	if e.tint != 0 {
		lead = iconTile(e.glyph, e.tint)
	} else {
		lead = core.View{
			Class:    "w-[20px] items-center",
			Children: []core.Node{icon(e.glyph(), 15, "text-gv-accent")},
		}
	}
	children := []core.Node{
		lead,
		core.Text{
			MaxLines: 1,
			ClassFunc: func() string {
				if e.active() {
					return "flex-1 text-[13px] font-medium text-gv-fg"
				}
				return "flex-1 text-[13px] text-gv-fg"
			},
			Content: e.label,
		},
	}
	if e.count != nil && e.badge {
		children = append(children, core.Show{
			When: func() bool { return e.count() > 0 },
			Then: func(cx *core.Scope) core.Node {
				return core.View{
					Class: "h-[17px] min-w-[17px] px-1.5 rounded-full items-center justify-center bg-gv-warn-soft",
					Children: []core.Node{core.Text{
						TestID:      e.testID + "-badge",
						Class:       "text-[11px] font-semibold text-gv-warn tabular-nums",
						ContentFunc: func() string { return fmt.Sprintf("%d", e.count()) },
					}},
				}
			},
		})
	} else if e.count != nil {
		children = append(children, core.Text{
			Class:       "text-[12px] text-gv-fg3 tabular-nums",
			ContentFunc: func() string { return fmt.Sprintf("%d", e.count()) },
		})
	}
	return core.View{
		TestID: e.testID,
		ClassFunc: func() string {
			if e.active() {
				return "flex-row items-center gap-2 h-[28px] px-2 rounded-[6px] bg-gv-sel"
			}
			return "flex-row items-center gap-2 h-[28px] px-2 rounded-[6px]"
		},
		OnPress:  func(core.PressEvent) { e.press() },
		Children: children,
	}
}

func folderMenu(cx *core.Scope, m *AppModel, folder state.Folder, at core.Point) {
	offline := func() bool { return m.SyncState.Get() == SyncOffline }
	desktop.PopupMenu(cx, []desktop.MenuItem{
		{Label: "Rename Folder…", Disabled: offline(), OnSelect: func() { m.OpenRenameFolderModal(folder) }},
		{Separator: true},
		{Label: "Delete Folder", Disabled: offline(), OnSelect: func() { m.DeleteFolder(cx, folder) }},
	}, at, nil)
}

func folderRow(cx *core.Scope, m *AppModel, folder state.Folder) core.Node {
	active := func() bool {
		return m.Route.Get() == RouteVault && m.SidebarFilter.Get().FolderID == folder.ID
	}
	return core.View{
		TestID: "sidebar-folder",
		ClassFunc: func() string {
			if active() {
				return "flex-row items-center gap-2 h-[28px] pl-2 pr-1 rounded-[6px] bg-gv-sel"
			}
			return "flex-row items-center gap-2 h-[28px] pl-2 pr-1 rounded-[6px]"
		},
		OnPress: func(core.PressEvent) {
			m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, FolderID: folder.ID})
		},
		OnContextMenu: func(ev core.ContextMenuEvent) { folderMenu(cx, m, folder, ev.PagePosition) },
		Children: []core.Node{
			core.View{
				Class:    "w-[20px] items-center",
				Children: []core.Node{icon(lucide.Folder(), 15, "text-gv-accent")},
			},
			core.Text{
				MaxLines: 1,
				ClassFunc: func() string {
					if active() {
						return "flex-1 text-[13px] font-medium text-gv-fg"
					}
					return "flex-1 text-[13px] text-gv-fg"
				},
				Content: folder.Name,
			},
			core.Show{
				When: active,
				Then: func(cx *core.Scope) core.Node {
					return core.View{
						TestID:  "sidebar-folder-menu",
						Label:   "Folder actions",
						Class:   "w-[20px] h-[20px] items-center justify-center rounded-[5px] active:bg-gv-fill-strong",
						OnPress: func(ev core.PressEvent) { folderMenu(cx, m, folder, ev.PagePosition) },
						Children: []core.Node{
							icon(lucide.Ellipsis(), 14, "text-gv-fg2"),
						},
					}
				},
				Else: func(cx *core.Scope) core.Node {
					return core.Text{
						Class: "pr-1 text-[12px] text-gv-fg3 tabular-nums",
						ContentFunc: func() string {
							return fmt.Sprintf("%d", m.AllCounts.Get().ByFolder[folder.ID])
						},
					}
				},
			},
		},
	}
}

func syncFooter(m *AppModel) core.Node {
	return core.View{
		Class: "flex-row items-center gap-2.5 px-3.5 py-3 border-t border-gv-line",
		Children: []core.Node{
			avatar(func() string { return m.Prefs.Get().Email }, 28),
			core.View{
				Class: "flex-1 gap-[1px]",
				Children: []core.Node{
					core.Text{
						MaxLines:    1,
						Class:       "text-[12px] font-medium text-gv-fg",
						ContentFunc: func() string { return m.Prefs.Get().Email },
					},
					core.View{
						Class: "flex-row items-center gap-1.5",
						Children: []core.Node{
							core.View{
								ClassFunc: func() string {
									switch m.SyncState.Get() {
									case SyncInProgress, SyncPending:
										return "w-[6px] h-[6px] rounded-full bg-gv-accent"
									case SyncOffline, SyncAuthExpired:
										return "w-[6px] h-[6px] rounded-full bg-gv-warn"
									default:
										return "w-[6px] h-[6px] rounded-full bg-gv-success"
									}
								},
							},
							core.Text{
								TestID: "sync-status",
								Class:  "flex-1 text-[11px] text-gv-fg3",
								ContentFunc: func() string {
									switch m.SyncState.Get() {
									case SyncInProgress:
										return "Syncing…"
									case SyncPending:
										return "Sync pending"
									case SyncOffline:
										return "Offline · cached vault"
									case SyncAuthExpired:
										return "Session expired"
									default:
										ts := m.LastSync.Get()
										if ts.IsZero() {
											return "Synced"
										}
										return "Synced " + formatRelativeTime(ts)
									}
								},
							},
						},
					},
				},
			},
		},
	}
}

func paneHandle(testID string, width *core.Signal[float32], clamp func(float32) (float32, float32), persist func()) core.Node {
	var start float32
	return ui.ResizeHandle{
		TestID:      testID,
		Label:       "Resize pane",
		OnDragStart: func() { start = width.Get() },
		OnDragMove: func(offset core.Points) {
			w, _ := clamp(start + float32(offset))
			width.Set(w)
		},
		OnDragEnd: func(core.Points) { persist() },
		OnDoublePress: func() {
			_, def := clamp(0)
			w, _ := clamp(def)
			width.Set(w)
			persist()
		},
	}
}

func vaultSplitPanes(cx *core.Scope, m *AppModel, shellW *core.Signal[float32]) core.Node {
	return core.View{
		Class: "flex-1 flex-row overflow-hidden",
		Children: []core.Node{
			itemListPane(cx, m),
			paneHandle("list-resize", m.ListW, func(w float32) (float32, float32) {
				_, lw := ClampPaneWidths(m.SidebarW.Get(), w, shellW.Get())
				return lw, DefaultListWidth
			}, m.PersistPaneWidths),
			core.View{
				Class: "flex-1 bg-gv-canvas overflow-hidden",
				Children: []core.Node{
					core.Show{
						When: m.EditMode.Get,
						Then: func(cx *core.Scope) core.Node { return EditorPaneView(cx, m) },
						Else: func(cx *core.Scope) core.Node { return DetailPaneView(cx, m) },
					},
				},
			},
		},
	}
}

func searchField(cx *core.Scope, input base.Input, hint string, onClear func()) core.Node {
	focused := core.NewSignal(cx, false)
	input.Class = "flex-1 h-full text-[13px] text-gv-fg"
	input.StyleFunc = func() core.Style {
		return core.Style{PlaceholderColor: themeColor(cx, "gv-fg3"), CaretColor: themeColor(cx, "gv-accent"), Background: core.Transparent, BorderWidth: 0}
	}
	input.OnFocus = func() { focused.Set(true) }
	input.OnBlur = func() { focused.Set(false) }
	value := input.Value
	children := []core.Node{
		icon(lucide.Search(), 13, "text-gv-fg3"),
		input,
	}
	if hint != "" {
		children = append(children, core.Show{
			When: func() bool { return value == nil || value() == "" },
			Then: func(cx *core.Scope) core.Node { return keycap(hint) },
		})
	}
	if onClear != nil {
		children = append(children, core.Show{
			When: func() bool { return value != nil && value() != "" },
			Then: func(cx *core.Scope) core.Node {
				return ui.Button{
					TestID:   input.TestID + "-clear",
					Icon:     lucide.CircleX,
					Label:    "Clear search",
					Variant:  ui.ButtonGhost,
					Side:     20,
					IconSize: 13,
					Tint:     func() core.Color { return themeColor(cx, "gv-fg3") },
					OnPress:  onClear,
				}
			},
		})
	}
	return core.View{
		ClassFunc: func() string {
			if focused.Get() {
				return "flex-row items-center gap-1.5 h-[30px] pl-2.5 pr-1.5 rounded-[8px] bg-gv-card border border-gv-accent"
			}
			return "flex-row items-center gap-1.5 h-[30px] pl-2.5 pr-1.5 rounded-[8px] bg-gv-fill border border-transparent"
		},
		StyleFunc: func() core.Style {
			if focused.Get() {
				return core.Style{Shadows: []core.BoxShadow{core.Ring(3, cx.Palette().Selection)}}
			}
			return core.Style{}
		},
		Children: children,
	}
}

func rowMenu(cx *core.Scope, m *AppModel, id string, at core.Point) {
	m.SelectCipher(cx, id)
	c := m.ActiveCipher.Get()
	if c == nil || c.ID != id {
		return
	}
	offline := m.SyncState.Get() == SyncOffline
	var items []desktop.MenuItem
	if c.Login != nil {
		items = append(items,
			desktop.MenuItem{Label: "Copy Username", Disabled: c.Login.Username == "", OnSelect: func() { m.CopyPlainValue("Username", c.Login.Username) }},
			desktop.MenuItem{Label: "Copy Password", Disabled: c.Login.Password == "" || m.PasswordHidden(c), OnSelect: func() {
				m.GateReprompt(cx, c, "copy password", func() { m.CopySecretValue("Password", c.Login.Password) })
			}},
		)
		if strings.TrimSpace(c.Login.TOTP) != "" {
			items = append(items, desktop.MenuItem{Label: "Copy Verification Code", OnSelect: func() {
				m.GateReprompt(cx, c, "copy TOTP code", func() {
					if code := m.TOTPCode.Get(); code != "" {
						m.CopySecretValue("TOTP code", code)
					}
				})
			}})
		}
		items = append(items, desktop.MenuItem{Separator: true})
	}
	if c.SSHKey != nil {
		items = append(items,
			desktop.MenuItem{Label: "Copy Public Key", Disabled: c.SSHKey.PublicKey == "", OnSelect: func() { m.CopyPlainValue("Public key", c.SSHKey.PublicKey) }},
			desktop.MenuItem{Separator: true},
		)
	}
	if c.DeletedDate != nil {
		items = append(items,
			desktop.MenuItem{Label: "Restore", Disabled: offline || m.CipherReadOnly(c), OnSelect: m.RestoreActive},
			desktop.MenuItem{Label: "Delete Permanently…", Disabled: offline || m.CipherReadOnly(c), OnSelect: func() { m.HardDeleteActive(cx) }},
		)
	} else {
		fav := "Add to Favorites"
		if c.Favorite {
			fav = "Remove from Favorites"
		}
		readOnly := m.CipherReadOnly(c)
		items = append(items,
			desktop.MenuItem{Label: "Edit", Disabled: offline || readOnly || m.PasswordHidden(c), OnSelect: func() { m.StartEditCipher(cx) }},
			desktop.MenuItem{Label: "Clone", Disabled: !m.CanClone(c), OnSelect: func() { m.CloneActive(cx) }},
			desktop.MenuItem{Label: fav, Disabled: offline || readOnly || !m.CanFavorite(c), OnSelect: m.ToggleFavorite},
			desktop.MenuItem{Separator: true},
		)
		if c.ArchivedDate != nil {
			items = append(items, desktop.MenuItem{Label: "Unarchive", Disabled: !m.CanUnarchiveItem(c), OnSelect: func() { m.ArchiveActive(cx, false) }})
		} else {
			items = append(items, desktop.MenuItem{Label: "Archive", Disabled: !m.CanArchiveItem(c), OnSelect: func() { m.ArchiveActive(cx, true) }})
		}
		items = append(items, desktop.MenuItem{Label: "Move to Trash", Disabled: offline || readOnly, OnSelect: m.SoftDeleteActive})
	}
	desktop.PopupMenu(cx, items, at, nil)
}

func itemListPane(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		TestID: "vault-list-pane",
		Class:  "bg-gv-list",
		StyleFunc: func() core.Style {
			return core.Style{Width: core.Pt(core.Points(m.ListW.Get())), FlexShrink: 0}
		},
		Children: []core.Node{
			listHeader(cx, m),
			searchScope(cx, m),
			trashBar(cx, m),
			core.List{
				TestID:        "vault-item-list",
				Class:         "flex-1 pt-2 pb-2",
				EstimatedSize: 52,
				Gap:           2,
				Count:         m.FilteredItems.Len,
				Key:           func(i int) any { return m.FilteredItems.KeyAt(i) },
				Empty:         listEmptyState(m),
				Row: func(cx *core.Scope, row core.ListRow) core.Node {
					itemAt := func() (state.CipherSummary, bool) {
						return m.FilteredItems.At(row.Index())
					}
					selected := func() bool {
						if m.BatchSelectMode.Get() {
							return false
						}
						it, ok := itemAt()
						return ok && m.IsSelected(it.ID)
					}
					batchChecked := func() bool {
						if !m.BatchSelectMode.Get() {
							return false
						}
						it, ok := itemAt()
						return ok && m.IsBatchSelected(it.ID)
					}
					flag := func(pick func(state.CipherSummary) bool) func() bool {
						return func() bool {
							it, ok := itemAt()
							return ok && pick(it)
						}
					}
					indicator := func(when func() bool, glyph func() *core.SVG, size core.Points, normal string) core.Node {
						return core.Show{
							When: when,
							Then: func(cx *core.Scope) core.Node {
								return iconFunc(glyph, size, func() string {
									if selected() {
										return "text-white/90"
									}
									return normal
								})
							},
						}
					}
					return core.View{
						Class: "px-2",
						Children: []core.Node{
							core.View{
								TestID: "vault-row",
								ClassFunc: func() string {
									if selected() {
										return "flex-row items-center gap-2.5 h-[52px] px-2.5 rounded-[8px] bg-gv-accent"
									}
									if batchChecked() {
										return "flex-row items-center gap-2.5 h-[52px] px-2.5 rounded-[8px] bg-gv-accent-soft"
									}
									return "flex-row items-center gap-2.5 h-[52px] px-2.5 rounded-[8px]"
								},
								OnPress: func(core.PressEvent) {
									it, ok := itemAt()
									if !ok {
										return
									}
									if m.BatchSelectMode.Get() {
										if !m.SummaryReadOnly(it) {
											m.ToggleBatchItem(it.ID)
										}
										return
									}
									m.SelectCipher(cx, it.ID)
								},
								OnContextMenu: func(ev core.ContextMenuEvent) {
									if m.BatchSelectMode.Get() {
										return
									}
									if it, ok := itemAt(); ok {
										rowMenu(cx, m, it.ID, ev.PagePosition)
									}
								},
								Children: []core.Node{
									core.Show{
										When: m.BatchSelectMode.Get,
										Then: func(cx *core.Scope) core.Node {
											return core.Dynamic(func(cx *core.Scope) core.Node {
												it, ok := itemAt()
												if !ok {
													return core.View{}
												}
												return ui.Checkbox{
													TestID:  "batch-checkbox-" + it.ID,
													Label:   "Select " + it.Name,
													Style:   core.Style{FlexShrink: 0},
													Checked: batchChecked,
													Disabled: func() bool {
														cur, ok := itemAt()
														return !ok || m.BatchBusy.Get() || m.SummaryReadOnly(cur)
													},
													OnChange: func(checked bool) {
														if cur, ok := itemAt(); ok {
															m.SetBatchItemSelected(cur.ID, checked)
														}
													},
												}
											})
										},
									},
									core.Dynamic(func(cx *core.Scope) core.Node {
										it, ok := itemAt()
										if !ok {
											return core.View{Style: core.Style{Width: core.Pt(32), Height: core.Pt(32)}}
										}
										return siteEmblem(m, it.URIs, it.Name, it.Type, it.Subtitle, 32)
									}),
									core.View{
										Class: "flex-1 overflow-hidden gap-[2px]",
										Children: []core.Node{
											core.Text{
												MaxLines: 1,
												ClassFunc: func() string {
													if selected() {
														return "text-[13px] font-semibold text-white"
													}
													return "text-[13px] font-semibold text-gv-fg"
												},
												ContentFunc: func() string {
													it, _ := itemAt()
													return it.Name
												},
											},
											core.Text{
												MaxLines: 1,
												ClassFunc: func() string {
													if selected() {
														return "text-[12px] text-white/80"
													}
													return "text-[12px] text-gv-fg2"
												},
												ContentFunc: func() string {
													it, ok := itemAt()
													if !ok {
														return ""
													}
													if it.Subtitle != "" {
														return it.Subtitle
													}
													return CipherTypeLabel(it.Type)
												},
											},
										},
									},
									core.View{
										Class: "flex-row items-center gap-1.5",
										Children: []core.Node{
											core.Show{
												When: func() bool {
													it, ok := itemAt()
													return ok && m.BatchSelectMode.Get() && m.SummaryReadOnly(it)
												},
												Then: func(cx *core.Scope) core.Node {
													return core.Text{
														TestID:  "batch-row-readonly",
														Class:   "text-[10.5px] font-medium text-gv-fg3 px-1.5 py-0.5 rounded bg-gv-fill",
														Content: "View only",
													}
												},
											},
											indicator(flag(func(s state.CipherSummary) bool { return s.Reprompt == 1 }), lucide.LockKeyhole, 12, "text-gv-fg3"),
											indicator(flag(func(s state.CipherSummary) bool { return s.HasTOTP }), lucide.Timer, 12.5, "text-gv-fg3"),
											indicator(flag(func(s state.CipherSummary) bool { return s.Favorite }), FilledStar, 11.5, "text-gv-star"),
										},
									},
								},
							},
						},
					}
				},
			},
			batchActionBar(cx, m),
		},
	}
}

func listHeader(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		TestID: "vault-list-header",
		Class:  "flex-row items-center justify-between gap-2 h-[34px] px-3 border-b border-gv-line-soft",
		Children: []core.Node{
			core.Show{
				When: m.BatchSelectMode.Get,
				Then: func(cx *core.Scope) core.Node {
					return core.View{
						Class: "flex-1 flex-row items-center justify-between gap-1",
						Children: []core.Node{
							core.View{
								Class: "flex-row items-center gap-1",
								Children: []core.Node{
									ui.Button{
										TestID:  "batch-select-all",
										Text:    "Select All",
										Variant: ui.ButtonGhost,
										Size:    ui.SizeSmall,
										Disabled: func() bool {
											return m.BatchBusy.Get() || m.BatchSelectableCount() == 0 || m.AllEditableSelected()
										},
										OnPress: m.SelectAllBatch,
									},
									ui.Button{
										TestID:  "batch-clear",
										Text:    "Clear",
										Variant: ui.ButtonGhost,
										Size:    ui.SizeSmall,
										Disabled: func() bool {
											return m.BatchBusy.Get() || m.BatchSelectedCount() == 0
										},
										OnPress: m.ClearBatchSelection,
									},
								},
							},
							ui.Button{
								TestID:   "batch-select-toggle",
								Text:     "Cancel",
								Variant:  ui.ButtonGhost,
								Size:     ui.SizeSmall,
								Disabled: m.BatchBusy.Get,
								OnPress:  func() { m.ToggleBatchSelectMode(cx) },
							},
						},
					}
				},
				Else: func(cx *core.Scope) core.Node {
					return core.View{
						Class: "flex-1 flex-row items-center justify-between gap-2",
						Children: []core.Node{
							core.Text{
								TestID: "list-header-count",
								Class:  "text-[11.5px] font-medium text-gv-fg3 tabular-nums",
								ContentFunc: func() string {
									n := m.FilteredItems.Len()
									return fmt.Sprintf("%d %s", n, batchItemNoun(n))
								},
							},
							ui.Button{
								TestID:  "batch-select-toggle",
								Text:    "Select",
								Variant: ui.ButtonGhost,
								Size:    ui.SizeSmall,
								Disabled: func() bool {
									return m.FilteredItems.Len() == 0
								},
								OnPress: func() { m.ToggleBatchSelectMode(cx) },
							},
						},
					}
				},
			},
		},
	}
}

func batchActionBar(cx *core.Scope, m *AppModel) core.Node {
	return core.Show{
		When: m.BatchSelectMode.Get,
		Then: func(cx *core.Scope) core.Node {
			disabled := func() bool {
				return m.BatchSelectedCount() == 0 || m.BatchBusy.Get() || m.BatchMutationsDisabled()
			}
			return core.View{
				TestID: "batch-action-bar",
				Class:  "px-3 py-2.5 gap-2 border-t border-gv-line bg-gv-panel",
				Children: []core.Node{
					core.View{
						Class: "flex-row items-center justify-between gap-2",
						Children: []core.Node{
							core.Text{
								TestID: "batch-selected-count",
								Class:  "text-[12px] font-semibold text-gv-fg tabular-nums",
								ContentFunc: func() string {
									return fmt.Sprintf("%d selected", m.BatchSelectedCount())
								},
							},
							core.Show{
								When: func() bool {
									return m.BatchMutationsDisabled() || m.BatchHasReadOnlyInView()
								},
								Then: func(cx *core.Scope) core.Node {
									return core.Text{
										TestID: "batch-status-hint",
										ClassFunc: func() string {
											if m.BatchMutationsDisabled() {
												return "text-[11px] text-gv-warn"
											}
											return "text-[11px] text-gv-fg3"
										},
										ContentFunc: func() string {
											switch {
											case m.LocalOnly.Get():
												return "Sign in again to edit"
											case m.SyncState.Get() == SyncOffline:
												return "Offline · edits disabled"
											case m.BatchHasReadOnlyInView():
												return "View-only omitted"
											default:
												return ""
											}
										},
									}
								},
							},
						},
					},
					core.Dynamic(func(cx *core.Scope) core.Node {
						if m.IsTrashView() {
							return core.View{
								Class: "flex-row flex-wrap items-center gap-2",
								Children: []core.Node{
									ui.Button{
										TestID:   "batch-restore-btn",
										Text:     "Restore…",
										Variant:  ui.ButtonPrimary,
										Size:     ui.SizeSmall,
										Flex:     1,
										Busy:     m.BatchBusy.Get,
										Disabled: disabled,
										OnPress:  m.OpenBatchRestoreDialog,
									},
									ui.Button{
										TestID:   "batch-hard-delete-btn",
										Text:     "Delete Permanently",
										Variant:  ui.ButtonSecondary,
										Size:     ui.SizeSmall,
										Color:    func() core.Color { return themeColor(cx, "gv-danger") },
										Busy:     m.BatchBusy.Get,
										Disabled: disabled,
										OnPress:  func() { m.ConfirmBatchHardDelete(cx) },
									},
								},
							}
						}
						return core.View{
							Class: "flex-row flex-wrap items-center gap-2",
							Children: []core.Node{
								ui.Button{
									TestID:   "batch-move-folder-btn",
									Text:     "Move to Folder…",
									Variant:  ui.ButtonSecondary,
									Size:     ui.SizeSmall,
									Flex:     1,
									Busy:     m.BatchBusy.Get,
									Disabled: disabled,
									OnPress:  m.OpenBatchMoveDialog,
								},
								ui.Button{
									TestID:   "batch-trash-btn",
									Text:     "Move to Trash",
									Variant:  ui.ButtonSecondary,
									Size:     ui.SizeSmall,
									Color:    func() core.Color { return themeColor(cx, "gv-danger") },
									Busy:     m.BatchBusy.Get,
									Disabled: disabled,
									OnPress:  func() { m.ConfirmBatchSoftDelete(cx) },
								},
							},
						}
					}),
				},
			}
		},
	}
}

// trashBar offers Empty Trash while Trash holds items the user may delete.
func trashBar(cx *core.Scope, m *AppModel) core.Node {
	return core.Show{
		When: func() bool {
			m.AllCounts.Get()
			return m.SidebarFilter.Get().Category == state.FilterTrash && m.TrashDeletable() > 0
		},
		Then: func(cx *core.Scope) core.Node {
			return core.View{
				Class: "flex-row items-center gap-2 mx-3 mt-2.5 pl-2.5 pr-1 h-[30px] rounded-[8px] bg-gv-fill",
				Children: []core.Node{
					core.Text{Class: "flex-1 text-[12px] text-gv-fg2", Content: "Items in Trash can be restored."},
					ui.Button{
						TestID:   "trash-empty",
						Text:     "Empty Trash",
						Variant:  ui.ButtonGhost,
						Size:     ui.SizeSmall,
						Busy:     m.TrashBusy.Get,
						Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
						OnPress:  func() { m.EmptyTrash(cx) },
					},
				},
			}
		},
	}
}

// searchScope shows where a query typed in a section searches, with one
// click to widen it to every item or narrow it back.
func searchScope(cx *core.Scope, m *AppModel) core.Node {
	return core.Show{
		When: m.SearchScoped,
		Then: func(cx *core.Scope) core.Node {
			return core.View{
				TestID: "search-scope",
				Class:  "flex-row items-center gap-2 mx-3 mt-2.5 pl-2.5 pr-1 h-[30px] rounded-[8px] bg-gv-fill",
				Children: []core.Node{
					icon(lucide.Search(), 12, "text-gv-fg3"),
					core.Text{
						MaxLines: 1,
						Class:    "flex-1 text-[12px] text-gv-fg2",
						ContentFunc: func() string {
							if m.SearchIsGlobal() {
								return "In All Items"
							}
							return "In " + m.sectionTitle()
						},
					},
					core.Dynamic(func(cx *core.Scope) core.Node {
						if m.SearchIsGlobal() {
							return ui.Button{
								TestID:  "search-scope-section",
								Text:    "Only " + m.sectionTitle(),
								Variant: ui.ButtonGhost,
								Size:    ui.SizeSmall,
								OnPress: func() { m.SetSearchAll(false) },
							}
						}
						variant := ui.ButtonGhost
						if m.FilteredItems.Len() == 0 {
							variant = ui.ButtonPrimary
						}
						return ui.Button{
							TestID:  "search-scope-all",
							Text:    "Search All Items",
							Variant: variant,
							Size:    ui.SizeSmall,
							OnPress: func() { m.SetSearchAll(true) },
						}
					}),
				},
			}
		},
	}
}

func listEmptyState(m *AppModel) core.Node {
	return core.View{
		Class: "flex-1 items-center justify-center px-8 py-16 gap-2",
		Children: []core.Node{
			core.View{
				Class: "w-[44px] h-[44px] rounded-full items-center justify-center bg-gv-fill mb-1",
				Children: []core.Node{
					iconFunc(func() *core.SVG {
						if m.SearchQuery.Get() != "" {
							return lucide.Search()
						}
						if m.SidebarFilter.Get().Category == state.FilterTrash {
							return lucide.Trash()
						}
						return lucide.KeyRound()
					}, 20, func() string { return "text-gv-fg3" }),
				},
			},
			core.Text{
				Class: "text-[13px] font-semibold text-gv-fg",
				ContentFunc: func() string {
					if m.SearchQuery.Get() != "" {
						return "No Results"
					}
					if m.SidebarFilter.Get().Category == state.FilterTrash {
						return "Trash Is Empty"
					}
					return "No Items"
				},
			},
			core.Text{
				Class: "text-[12px] text-gv-fg2 text-center",
				ContentFunc: func() string {
					if q := m.SearchQuery.Get(); q != "" && m.SearchScoped() && !m.SearchIsGlobal() {
						return fmt.Sprintf("Nothing in %s matches “%s”.", m.sectionTitle(), q)
					}
					if q := m.SearchQuery.Get(); q != "" {
						return fmt.Sprintf("Nothing matches “%s”.", q)
					}
					if m.SidebarFilter.Get().Category == state.FilterTrash {
						return "Items you delete appear here."
					}
					return "Choose New Item to add your first entry."
				},
			},
			core.Show{
				When: func() bool { return m.SearchScoped() && !m.SearchIsGlobal() },
				Then: func(cx *core.Scope) core.Node {
					return core.View{
						Class: "pt-2",
						Children: []core.Node{ui.Button{
							TestID:  "search-empty-all",
							Text:    "Search All Items",
							Icon:    lucide.Search,
							Variant: ui.ButtonPrimary,
							OnPress: func() { m.SetSearchAll(true) },
						}},
					}
				},
			},
		},
	}
}

func detailEmptyState(cx *core.Scope) core.Node {
	return core.View{
		TestID: "detail-empty",
		Class:  "flex-1 items-center justify-center p-8 gap-3",
		Children: []core.Node{
			core.View{
				Class:    "opacity-90 mb-1",
				Children: []core.Node{brandEmblem(56)},
			},
			core.Text{Class: "text-[15px] font-semibold text-gv-fg", Content: "No Item Selected"},
			core.Text{Class: "text-[12.5px] text-gv-fg2", Content: "Choose an item from the list to see its details."},
			core.View{
				Class: "flex-row items-center gap-4 mt-2",
				Children: []core.Node{
					shortcutHint(cx, "mod+f", "Search"),
					shortcutHint(cx, "mod+n", "New Item"),
					shortcutHint(cx, "mod+l", "Lock"),
				},
			},
		},
	}
}

func shortcutHint(cx *core.Scope, keys, label string) core.Node {
	return core.View{
		Class: "flex-row items-center gap-1.5",
		Children: []core.Node{
			keycap(cx.KeyLabel(keys)),
			core.Text{Class: "text-[11.5px] text-gv-fg3", Content: label},
		},
	}
}

func actionIcon(cx *core.Scope, testID, label string, glyph func() *core.SVG, onPress func()) core.Node {
	return ui.Button{
		TestID:   testID,
		Icon:     glyph,
		Label:    label,
		Variant:  ui.ButtonGhost,
		Side:     28,
		IconSize: 14,
		Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
		OnPress:  onPress,
	}
}

type fieldOpts struct {
	testID  string
	mono    bool
	accent  bool
	value   func() string
	spans   func() []core.Span
	actions []core.Node
}

func fieldRow(label string, o fieldOpts) core.Node {
	valueClass := "text-[13.5px] text-gv-fg"
	if o.mono {
		valueClass = "text-[13.5px] font-mono text-gv-fg"
	}
	if o.accent {
		valueClass = "text-[13.5px] text-gv-accent"
	}
	value := core.Text{
		TestID:      o.testID,
		Class:       valueClass,
		Selectable:  core.SelectableOn,
		ContentFunc: o.value,
		SpansFunc:   o.spans,
	}
	return core.View{
		Class: "flex-row items-center gap-3 pl-4 pr-2.5 py-2.5 min-h-[52px]",
		Children: []core.Node{
			core.View{
				Class: "flex-1 gap-[3px] overflow-hidden",
				Children: []core.Node{
					core.Text{Class: "text-[11.5px] font-medium text-gv-fg2", Content: label},
					value,
				},
			},
			core.View{Class: "flex-row items-center gap-0.5", Children: o.actions},
		},
	}
}

func staticValue(v string) func() string { return func() string { return v } }

func secretRow(cx *core.Scope, m *AppModel, c *state.Cipher, label, value, testID, action string, mono bool, reveal *core.Signal[bool], copySecret func()) core.Node {
	return namedSecretRow(cx, m, c, label, strings.ToLower(label), value, testID, action, mono, reveal, copySecret)
}

func namedSecretRow(cx *core.Scope, m *AppModel, c *state.Cipher, label, name, value, testID, action string, mono bool, reveal *core.Signal[bool], copySecret func()) core.Node {
	if reveal == nil {
		reveal = core.NewSignal(cx, false)
	}
	return fieldRow(label, fieldOpts{
		testID: testID,
		mono:   true,
		spans: func() []core.Span {
			if !reveal.Get() {
				return []core.Span{{Content: maskedDots(len(value)), Class: "text-gv-fg2"}}
			}
			if mono {
				return passwordSpans(value)
			}
			return []core.Span{{Content: value}}
		},
		actions: []core.Node{
			ui.Button{
				TestID:   testID + "-reveal",
				Icon:     func() *core.SVG { return eyeIcon(reveal.Get()) },
				Label:    "Reveal " + name,
				Variant:  ui.ButtonGhost,
				Side:     28,
				IconSize: 14,
				Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
				OnPress: func() {
					if reveal.Get() {
						reveal.Set(false)
						return
					}
					m.GateReprompt(cx, c, "reveal "+action, func() { reveal.Set(true) })
				},
			},
			actionIcon(cx, testID+"-copy", "Copy "+name, lucide.Copy, copySecret),
		},
	})
}

func DetailPaneView(cx *core.Scope, m *AppModel) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		c := m.ActiveCipher.Get()
		if c == nil {
			return detailEmptyState(cx)
		}
		return detailContent(cx, m, c)
	})
}

func detailContent(cx *core.Scope, m *AppModel, c *state.Cipher) core.Node {
	isTrash := c.DeletedDate != nil
	offline := func() bool { return m.SyncState.Get() == SyncOffline }
	copyPlain := func(label, v string) func() { return func() { m.CopyPlainValue(label, v) } }

	var blocks []core.Node

	if c.Card != nil {
		blocks = append(blocks, cardVisual(m, c))
	}

	if c.Login != nil {
		var rows []core.Node
		if c.Login.Username != "" {
			rows = append(rows, fieldRow("Username", fieldOpts{
				value:   staticValue(c.Login.Username),
				actions: []core.Node{actionIcon(cx, "detail-copy-user", "Copy username", lucide.Copy, copyPlain("Username", c.Login.Username))},
			}))
		}
		if c.Login.Password != "" && m.PasswordHidden(c) {
			rows = append(rows, fieldRow("Password", fieldOpts{
				testID: "detail-password-value",
				value:  staticValue("Hidden by your organization"),
			}))
		} else if c.Login.Password != "" {
			rows = append(rows, fieldRow("Password", fieldOpts{
				testID: "detail-password-value",
				mono:   true,
				spans: func() []core.Span {
					if m.RevealPW.Get() {
						return passwordSpans(c.Login.Password)
					}
					return []core.Span{{Content: maskedDots(len(c.Login.Password)), Class: "text-gv-fg2"}}
				},
				actions: []core.Node{
					ui.Button{
						TestID:   "detail-reveal-pw",
						Icon:     func() *core.SVG { return eyeIcon(m.RevealPW.Get()) },
						Label:    "Reveal password",
						Variant:  ui.ButtonGhost,
						Side:     28,
						IconSize: 14,
						Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
						OnPress: func() {
							if m.RevealPW.Get() {
								m.RevealPW.Set(false)
								return
							}
							m.GateReprompt(cx, c, "reveal password", func() { m.RevealPW.Set(true) })
						},
					},
					actionIcon(cx, "detail-copy-pw", "Copy password", lucide.Copy, func() {
						m.GateReprompt(cx, c, "copy password", func() { m.CopySecretValue("Password", c.Login.Password) })
					}),
				},
			}))
		}
		if strings.TrimSpace(c.Login.TOTP) != "" {
			rows = append(rows, totpRow(cx, m, c))
		}
		rows = append(rows, detailPasskeyRows(c)...)
		if len(rows) > 0 {
			blocks = append(blocks, section("Credentials", card(rows...)))
		}

		if len(c.Login.URIs) > 0 {
			var uriRows []core.Node
			for i, u := range c.Login.URIs {
				uri := u.URI
				label := "Website"
				if len(c.Login.URIs) > 1 {
					label = fmt.Sprintf("Website %d", i+1)
				}
				uriRows = append(uriRows, fieldRow(label, fieldOpts{
					accent: true,
					value:  staticValue(uri),
					actions: []core.Node{
						actionIcon(cx, "", "Open website", lucide.ExternalLink, func() { cx.OpenURL(uri, nil) }),
						actionIcon(cx, "", "Copy website", lucide.Copy, copyPlain("URL", uri)),
					},
				}))
			}
			blocks = append(blocks, section("Websites", card(uriRows...)))
		}
	}

	if k := c.SSHKey; k != nil {
		blocks = append(blocks, sshKeySection(cx, m, c, k))
	}

	if c.Card != nil {
		var rows []core.Node
		if c.Card.CardholderName != "" {
			rows = append(rows, fieldRow("Cardholder Name", fieldOpts{
				value:   staticValue(c.Card.CardholderName),
				actions: []core.Node{actionIcon(cx, "", "Copy cardholder", lucide.Copy, copyPlain("Cardholder", c.Card.CardholderName))},
			}))
		}
		if c.Card.Number != "" {
			rows = append(rows, fieldRow("Card Number", fieldOpts{
				testID: "detail-card-number",
				mono:   true,
				value: func() string {
					if m.RevealCard.Get() {
						return c.Card.Number
					}
					return maskCardNumber(c.Card.Number)
				},
				actions: []core.Node{
					ui.Button{
						Icon:     func() *core.SVG { return eyeIcon(m.RevealCard.Get()) },
						Label:    "Reveal card number",
						Variant:  ui.ButtonGhost,
						Side:     28,
						IconSize: 14,
						Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
						OnPress: func() {
							if m.RevealCard.Get() {
								m.RevealCard.Set(false)
								return
							}
							m.GateReprompt(cx, c, "reveal card", func() { m.RevealCard.Set(true) })
						},
					},
					actionIcon(cx, "", "Copy card number", lucide.Copy, func() {
						m.GateReprompt(cx, c, "copy card number", func() { m.CopySecretValue("Card number", c.Card.Number) })
					}),
				},
			}))
		}
		if c.Card.ExpMonth != "" || c.Card.ExpYear != "" {
			exp := strings.Trim(c.Card.ExpMonth+" / "+c.Card.ExpYear, " /")
			rows = append(rows, fieldRow("Expiration", fieldOpts{
				mono:    true,
				value:   staticValue(exp),
				actions: []core.Node{actionIcon(cx, "", "Copy expiration", lucide.Copy, copyPlain("Expiration", exp))},
			}))
		}
		if c.Card.Code != "" {
			rows = append(rows, secretRow(cx, m, c, "Security Code", c.Card.Code, "detail-card-code", "security code", true, nil, func() {
				m.GateReprompt(cx, c, "copy security code", func() { m.CopySecretValue("Security code", c.Card.Code) })
			}))
		}
		if c.Card.Brand != "" {
			rows = append(rows, fieldRow("Brand", fieldOpts{value: staticValue(c.Card.Brand)}))
		}
		if len(rows) > 0 {
			blocks = append(blocks, section("Card Details", card(rows...)))
		}
	}

	if id := c.Identity; id != nil {
		plainRow := func(label, v string) core.Node {
			if strings.TrimSpace(v) == "" {
				return nil
			}
			return fieldRow(label, fieldOpts{
				value:   staticValue(v),
				actions: []core.Node{actionIcon(cx, "", "Copy "+strings.ToLower(label), lucide.Copy, copyPlain(label, v))},
			})
		}
		fullName := strings.Join(strings.Fields(strings.Join([]string{id.Title, id.FirstName, id.MiddleName, id.LastName}, " ")), " ")
		personal := nonNil(
			plainRow("Full Name", fullName),
			plainRow("Company", id.Company),
			plainRow("Email", id.Email),
			plainRow("Phone", id.Phone),
			plainRow("Username", id.Username),
		)
		if len(personal) > 0 {
			blocks = append(blocks, section("Personal", card(personal...)))
		}
		street := strings.TrimSpace(id.Address1)
		cityLine := strings.TrimSpace(strings.Join(strings.Fields(strings.Join([]string{id.City + ",", id.State, id.PostalCode}, " ")), " "))
		cityLine = strings.Trim(cityLine, ", ")
		addr := strings.Trim(strings.Join(nonEmpty(street, cityLine, id.Country), "\n"), "\n")
		if addr != "" {
			blocks = append(blocks, section("Address", card(fieldRow("Address", fieldOpts{
				value:   staticValue(addr),
				actions: []core.Node{actionIcon(cx, "", "Copy address", lucide.Copy, copyPlain("Address", strings.ReplaceAll(addr, "\n", ", ")))},
			}))))
		}
		var docs []core.Node
		if id.SSN != "" {
			docs = append(docs, secretRow(cx, m, c, "Social Security Number", id.SSN, "detail-ssn", "SSN", false, nil, func() {
				m.GateReprompt(cx, c, "copy SSN", func() { m.CopySecretValue("SSN", id.SSN) })
			}))
		}
		if id.PassportNumber != "" {
			docs = append(docs, fieldRow("Passport Number", fieldOpts{
				mono:    true,
				value:   staticValue(id.PassportNumber),
				actions: []core.Node{actionIcon(cx, "", "Copy passport number", lucide.Copy, func() { m.CopySecretValue("Passport", id.PassportNumber) })},
			}))
		}
		if id.LicenseNumber != "" {
			docs = append(docs, fieldRow("License Number", fieldOpts{
				mono:    true,
				value:   staticValue(id.LicenseNumber),
				actions: []core.Node{actionIcon(cx, "", "Copy license number", lucide.Copy, func() { m.CopySecretValue("License", id.LicenseNumber) })},
			}))
		}
		if len(docs) > 0 {
			blocks = append(blocks, section("Documents", card(docs...)))
		}
	}

	if len(c.Fields) > 0 {
		var rows []core.Node
		for i, f := range c.Fields {
			field := f
			testID := fmt.Sprintf("detail-field-%d", i)
			if field.Type == 1 && m.PasswordHidden(c) {
				rows = append(rows, fieldRow(field.Name, fieldOpts{testID: testID, value: staticValue("Hidden by your organization")}))
				continue
			}
			if field.Type == 1 {
				rows = append(rows, secretRow(cx, m, c, field.Name, field.Value, testID, "custom field", true, nil, func() {
					m.GateReprompt(cx, c, "copy custom field", func() { m.CopySecretValue(field.Name, field.Value) })
				}))
				continue
			}
			rows = append(rows, fieldRow(field.Name, fieldOpts{
				value:   staticValue(field.Value),
				actions: []core.Node{actionIcon(cx, "", "Copy "+field.Name, lucide.Copy, copyPlain(field.Name, field.Value))},
			}))
		}
		blocks = append(blocks, section("Custom Fields", card(rows...)))
	}

	if c.Login != nil && len(c.PasswordHistory) > 0 && !m.PasswordHidden(c) {
		blocks = append(blocks, passwordHistorySection(cx, m, c))
	}

	if strings.TrimSpace(c.Notes) != "" {
		blocks = append(blocks, section("Notes", card(core.View{
			Class: "px-4 py-3",
			Children: []core.Node{
				core.Text{
					Class:      "text-[13px] leading-[19px] text-gv-fg",
					Selectable: core.SelectableOn,
					Content:    c.Notes,
				},
			},
		})))
	}

	if n := attachmentsSection(cx, m, c); n != nil {
		blocks = append(blocks, n)
	}

	blocks = append(blocks, metadataFooter(cx, m, c, isTrash, offline))

	return core.View{
		TestID: "detail-view",
		Class:  "flex-1",
		Children: []core.Node{
			core.Scroll{
				Class: "flex-1",
				Children: []core.Node{
					core.View{
						Class: "w-full max-w-[680px] self-center px-7 pt-6 pb-8 gap-5",
						Children: append([]core.Node{
							detailHeader(cx, m, c, isTrash, offline),
						}, blocks...),
					},
				},
			},
		},
	}
}

func sshKeySection(cx *core.Scope, m *AppModel, c *state.Cipher, k *state.SSHKey) core.Node {
	var rows []core.Node
	if k.KeyFingerprint != "" {
		rows = append(rows, fieldRow("Fingerprint", fieldOpts{
			testID:  "detail-ssh-fingerprint",
			mono:    true,
			value:   staticValue(k.KeyFingerprint),
			actions: []core.Node{actionIcon(cx, "detail-ssh-fingerprint-copy", "Copy fingerprint", lucide.Copy, func() { m.CopyPlainValue("Fingerprint", k.KeyFingerprint) })},
		}))
	}
	if k.PublicKey != "" {
		rows = append(rows, fieldRow("Public Key", fieldOpts{
			testID:  "detail-ssh-public",
			mono:    true,
			value:   staticValue(k.PublicKey),
			actions: []core.Node{actionIcon(cx, "detail-ssh-public-copy", "Copy public key", lucide.Copy, func() { m.CopyPlainValue("Public key", k.PublicKey) })},
		}))
	}
	if k.PrivateKey != "" && m.PasswordHidden(c) {
		rows = append(rows, fieldRow("Private Key", fieldOpts{
			testID: "detail-ssh-private",
			value:  staticValue("Hidden by your organization"),
		}))
	} else if k.PrivateKey != "" {
		priv := strings.TrimSpace(k.PrivateKey)
		rows = append(rows, secretRow(cx, m, c, "Private Key", priv, "detail-ssh-private", "private key", false, nil, func() {
			m.GateReprompt(cx, c, "copy private key", func() { m.CopySecretValue("Private key", k.PrivateKey) })
		}))
	}
	return section("SSH Key", card(rows...))
}

func passwordHistorySection(cx *core.Scope, m *AppModel, c *state.Cipher) core.Node {
	open := core.NewSignal(cx, false)
	title := fmt.Sprintf("Password History (%d)", len(c.PasswordHistory))
	return core.View{
		Class: "gap-1.5",
		Children: []core.Node{
			core.View{
				TestID:   "detail-history-toggle",
				Role:     core.RoleButton,
				Label:    title,
				Expanded: open.Get,
				Class:    "flex-row items-center gap-1 px-1 self-start",
				OnPress:  func(core.PressEvent) { open.Set(!open.Get()) },
				Children: []core.Node{
					core.Text{Class: "text-[11.5px] font-semibold text-gv-fg2", Content: title},
					iconFunc(func() *core.SVG {
						if open.Get() {
							return lucide.ChevronDown()
						}
						return lucide.ChevronRight()
					}, 11, func() string { return "text-gv-fg2" }),
				},
			},
			core.Show{
				When: open.Get,
				Then: func(cx *core.Scope) core.Node {
					rows := make([]core.Node, 0, len(c.PasswordHistory))
					for i, h := range c.PasswordHistory {
						pw := h.Password
						label := "Used until " + h.LastUsedDate.Local().Format("Jan 2, 2006 at 3:04 PM")
						rows = append(rows, namedSecretRow(cx, m, c, label, "old password", pw, fmt.Sprintf("detail-history-%d", i), "old password", true, nil, func() {
							m.GateReprompt(cx, c, "copy old password", func() { m.CopySecretValue("Old password", pw) })
						}))
					}
					return card(rows...)
				},
			},
		},
	}
}

func nonNil(nodes ...core.Node) []core.Node {
	var out []core.Node
	for _, n := range nodes {
		if n != nil {
			out = append(out, n)
		}
	}
	return out
}

func nonEmpty(values ...string) []string {
	var out []string
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func cipherBrand(c *state.Cipher) string {
	if c.Card != nil {
		return c.Card.Brand
	}
	return ""
}

func detailHeader(cx *core.Scope, m *AppModel, c *state.Cipher, isTrash bool, offline func() bool) core.Node {
	pills := []core.Node{pill(typeGlyphOrGlobe(c.Type), CipherTypeLabel(c.Type))}
	if c.FolderID != nil && *c.FolderID != "" {
		for _, f := range m.Folders.Get() {
			if f.ID == *c.FolderID {
				pills = append(pills, pill(lucide.Folder, f.Name))
				break
			}
		}
	}
	if org := m.OrganizationName(c.OrganizationID); org != "" {
		pills = append(pills, pill(lucide.Building, org))
	}
	for _, col := range m.cipherCollections(c) {
		pills = append(pills, pill(lucide.Library, col.Name))
	}
	readOnly := m.CipherReadOnly(c)
	if readOnly {
		pills = append(pills, pill(lucide.Eye, "View only"))
	}
	if c.Reprompt == 1 {
		pills = append(pills, pill(lucide.ShieldCheck, "Password reprompt"))
	}
	editLocked := func() bool { return offline() || readOnly || m.PasswordHidden(c) }
	if isTrash {
		pills = append(pills, pill(lucide.Trash, "In Trash"))
	}
	if c.ArchivedDate != nil {
		pills = append(pills, pill(lucide.Archive, "Archived"))
	}

	var actions []core.Node
	if isTrash && readOnly {
		actions = nil
	} else if isTrash {
		actions = []core.Node{
			ui.Button{
				TestID:   "detail-hard-delete",
				Text:     "Delete Permanently",
				Variant:  ui.ButtonSecondary,
				Disabled: offline,
				OnPress:  func() { m.HardDeleteActive(cx) },
			},
			ui.Button{
				TestID:   "detail-restore",
				Text:     "Restore",
				Icon:     lucide.RotateCcw,
				Variant:  ui.ButtonPrimary,
				Disabled: offline,
				OnPress:  m.RestoreActive,
			},
		}
	} else {
		actions = []core.Node{
			ui.Button{
				TestID: "detail-favorite",
				Icon: func() *core.SVG {
					if c.Favorite {
						return FilledStar()
					}
					return lucide.Star()
				},
				Label:    "Toggle favorite",
				Variant:  ui.ButtonGhost,
				Side:     28,
				IconSize: 16,
				Tint: func() core.Color {
					if c.Favorite {
						return themeColor(cx, "gv-star")
					}
					return themeColor(cx, "gv-fg2")
				},
				Disabled: func() bool { return offline() || readOnly || !m.CanFavorite(c) },
				OnPress:  m.ToggleFavorite,
			},
			archiveButton(cx, m, c),
			ui.Button{
				TestID:   "detail-clone",
				Icon:     lucide.CopyPlus,
				Label:    "Clone item",
				Variant:  ui.ButtonGhost,
				Side:     28,
				IconSize: 15,
				Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
				Disabled: func() bool { return !m.CanClone(c) },
				OnPress:  func() { m.CloneActive(cx) },
			},
			ui.Button{
				TestID:   "detail-edit",
				Text:     "Edit",
				Icon:     lucide.Pencil,
				Variant:  ui.ButtonSecondary,
				Disabled: editLocked,
				OnPress:  func() { m.StartEditCipher(cx) },
			},
		}
	}

	return core.View{
		Class: "flex-row items-center gap-4 pb-1",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				return siteEmblem(m, cipherURIs(c), c.Name, c.Type, cipherBrand(c), 56)
			}),
			core.View{
				Class: "flex-1 gap-1.5 overflow-hidden",
				Children: []core.Node{
					core.Text{
						TestID:   "detail-title",
						MaxLines: 1,
						Class:    "text-[21px] font-semibold text-gv-fg",
						Content:  c.Name,
					},
					core.View{Class: "flex-row items-center gap-1.5 flex-wrap", Children: pills},
				},
			},
			core.View{Class: "flex-row items-center gap-2", Children: actions},
		},
	}
}

// archiveButton moves the item to the Archive or back, as Bitwarden's
// clients offer it for any item not in Trash.
func archiveButton(cx *core.Scope, m *AppModel, c *state.Cipher) core.Node {
	if c.ArchivedDate != nil {
		return ui.Button{
			TestID:   "detail-unarchive",
			Icon:     lucide.ArchiveRestore,
			Label:    "Unarchive",
			Variant:  ui.ButtonGhost,
			Side:     28,
			IconSize: 15,
			Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
			Disabled: func() bool { return !m.CanUnarchiveItem(c) },
			OnPress:  func() { m.ArchiveActive(cx, false) },
		}
	}
	return ui.Button{
		TestID:   "detail-archive",
		Icon:     lucide.Archive,
		Label:    "Archive",
		Variant:  ui.ButtonGhost,
		Side:     28,
		IconSize: 15,
		Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
		Disabled: func() bool { return !m.CanArchiveItem(c) },
		OnPress:  func() { m.ArchiveActive(cx, true) },
	}
}

func typeGlyphOrGlobe(t api.CipherType) func() *core.SVG {
	if g := typeGlyph(t); g != nil {
		return g
	}
	return lucide.Globe
}

func totpRow(cx *core.Scope, m *AppModel, c *state.Cipher) core.Node {
	urgent := func() bool {
		rem := m.TOTPRemaining.Get()
		return rem > 0 && rem <= 5
	}
	return core.View{
		TestID: "detail-totp-section",
		Class:  "flex-row items-center gap-3 pl-4 pr-2.5 py-2.5 min-h-[60px]",
		Children: []core.Node{
			core.View{
				Class: "flex-1 gap-[3px]",
				Children: []core.Node{
					core.Text{Class: "text-[11.5px] font-medium text-gv-fg2", Content: "Verification Code"},
					core.View{
						Class: "flex-row items-center gap-3",
						Children: []core.Node{
							core.Text{
								TestID: "detail-totp-code",
								ClassFunc: func() string {
									if urgent() {
										return "text-[22px] font-mono font-semibold tracking-[1px] text-gv-danger tabular-nums"
									}
									return "text-[22px] font-mono font-semibold tracking-[1px] text-gv-accent tabular-nums"
								},
								ContentFunc: func() string {
									code := m.TOTPCode.Get()
									if code == "" {
										return "––– –––"
									}
									if c.Reprompt == 1 && m.TOTPRevealedID.Get() != c.ID {
										return strings.Repeat("•", len(code)/2) + " " + strings.Repeat("•", len(code)-len(code)/2)
									}
									return FormatTOTPCode(code)
								},
							},
							core.View{
								Class: "flex-row items-center gap-1.5",
								Children: []core.Node{
									ui.ProgressRing{
										Size:  16,
										Label: "Time remaining",
										Value: func() float32 {
											period := m.TOTPPeriod.Get()
											if period <= 0 {
												return 0
											}
											return float32(m.TOTPRemaining.Get()) * 100 / float32(period)
										},
										Tint: func() core.Color {
											if urgent() {
												return themeColor(cx, "gv-danger")
											}
											return themeColor(cx, "gv-accent")
										},
									},
									core.Text{
										Class: "text-[12px] text-gv-fg2 tabular-nums",
										ContentFunc: func() string {
											rem := m.TOTPRemaining.Get()
											if rem <= 0 {
												return ""
											}
											return fmt.Sprintf("%ds", rem)
										},
									},
								},
							},
						},
					},
				},
			},
			core.Show{
				When: func() bool { return c.Reprompt == 1 },
				Then: func(cx *core.Scope) core.Node {
					return ui.Button{
						TestID:   "detail-reveal-totp",
						Icon:     func() *core.SVG { return eyeIcon(m.TOTPRevealedID.Get() == c.ID) },
						Label:    "Reveal verification code",
						Variant:  ui.ButtonGhost,
						Side:     28,
						IconSize: 14,
						Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
						OnPress: func() {
							if m.TOTPRevealedID.Get() == c.ID {
								m.TOTPRevealedID.Set("")
								return
							}
							id := c.ID
							m.GateReprompt(cx, c, "reveal verification code", func() {
								if cur := m.ActiveCipher.Get(); cur != nil && cur.ID == id {
									m.TOTPRevealedID.Set(id)
								}
							})
						},
					}
				},
			},
			actionIcon(cx, "detail-copy-totp", "Copy verification code", lucide.Copy, func() {
				m.GateReprompt(cx, c, "copy TOTP code", func() {
					if code := m.TOTPCode.Get(); code != "" {
						m.CopySecretValue("TOTP code", code)
					}
				})
			}),
		},
	}
}

func cardVisual(m *AppModel, c *state.Cipher) core.Node {
	p := paletteFor(c.Name, c.Type, c.Card.Brand)
	brand := strings.ToUpper(c.Card.Brand)
	if brand == "" {
		brand = "CARD"
	}
	exp := ""
	if c.Card.ExpMonth != "" || c.Card.ExpYear != "" {
		yr := c.Card.ExpYear
		if len(yr) == 4 {
			yr = yr[2:]
		}
		exp = c.Card.ExpMonth + "/" + yr
	}
	white := func(a float32) core.Color { return core.RGBA(0xffffff, a) }
	label := func(s string) core.Node {
		return core.Text{Content: s, Style: core.Style{FontSize: 9, FontWeight: core.FontWeightSemibold, Color: white(0.65), LetterSpacing: 0.8}}
	}
	return core.View{
		Class: "items-center py-1",
		Children: []core.Node{
			core.View{
				Style: core.Style{
					Width: core.Pt(320), Height: core.Pt(196), Padding: core.All(20),
					CornerRadius: 16, BorderCurve: core.BorderCurveContinuous,
					JustifyContent: core.JustifySpaceBetween,
					Gradients: []core.Gradient{
						core.LinearGradient(135, core.RGBA(0xffffff, 0.18), core.RGBA(0xffffff, 0)),
						core.LinearGradient(160, core.RGB(p.top), core.RGB(p.bottom)),
					},
					Shadows: []core.BoxShadow{
						ui.Shadow(0, 14, 30, -12, core.RGBA(p.bottom, 0.6)),
						core.Ring(0.5, core.RGBA(0x000000, 0.12)),
					},
				},
				Children: []core.Node{
					core.View{
						Class: "flex-row items-center justify-between",
						Children: []core.Node{
							core.View{
								Style: core.Style{
									Width: core.Pt(36), Height: core.Pt(27), CornerRadius: 5,
									Gradients: []core.Gradient{core.LinearGradient(135, core.RGB(0xf6dd9a), core.RGB(0xc79a3c))},
									Shadows:   []core.BoxShadow{core.Ring(0.5, core.RGBA(0x000000, 0.2))},
								},
							},
							core.Text{Content: brand, Style: core.Style{FontSize: 17, FontWeight: core.FontWeightBold, Color: core.RGB(0xffffff), LetterSpacing: 1.2}},
						},
					},
					core.Text{
						Class: "font-mono",
						ContentFunc: func() string {
							if m.RevealCard.Get() {
								return c.Card.Number
							}
							return maskCardNumber(c.Card.Number)
						},
						Style: core.Style{FontSize: 17, Color: core.RGB(0xffffff), LetterSpacing: 1},
					},
					core.View{
						Class: "flex-row items-end justify-between",
						Children: []core.Node{
							core.View{Class: "gap-0.5", Children: []core.Node{
								label("CARDHOLDER"),
								core.Text{Content: strings.ToUpper(c.Card.CardholderName), Style: core.Style{FontSize: 12.5, FontWeight: core.FontWeightMedium, Color: core.RGB(0xffffff), LetterSpacing: 0.6}},
							}},
							core.View{Class: "gap-0.5 items-end", Children: []core.Node{
								label("EXPIRES"),
								core.Text{Class: "font-mono", Content: exp, Style: core.Style{FontSize: 12.5, Color: core.RGB(0xffffff)}},
							}},
						},
					},
				},
			},
		},
	}
}

func metadataFooter(cx *core.Scope, m *AppModel, c *state.Cipher, isTrash bool, offline func() bool) core.Node {
	var lines []core.Node
	if c.RevisionDate != nil {
		lines = append(lines, core.Text{Class: "text-[11.5px] text-gv-fg3", Content: "Updated " + c.RevisionDate.Local().Format("Jan 2, 2006 at 3:04 PM")})
	}
	if c.CreationDate != nil {
		lines = append(lines, core.Text{Class: "text-[11.5px] text-gv-fg3", Content: "Created " + c.CreationDate.Local().Format("Jan 2, 2006")})
	}
	if isTrash && c.DeletedDate != nil {
		lines = append(lines, core.Text{Class: "text-[11.5px] text-gv-fg3", Content: "Deleted " + formatRelativeTime(*c.DeletedDate)})
	}
	children := []core.Node{core.View{Class: "flex-1 gap-0.5", Children: lines}}
	if !isTrash && !m.CipherReadOnly(c) {
		children = append(children, core.View{
			TestID:   "detail-trash",
			Label:    "Move to Trash",
			Role:     core.RoleButton,
			Disabled: offline,
			Class:    "flex-row items-center gap-1.5 h-[26px] px-2.5 rounded-[6px] active:bg-gv-danger/10 disabled:opacity-40",
			OnPress: func(core.PressEvent) {
				if !offline() {
					m.SoftDeleteActive()
				}
			},
			Children: []core.Node{
				icon(lucide.Trash(), 13, "text-gv-danger"),
				core.Text{Class: "text-[12px] font-medium text-gv-danger", Content: "Move to Trash"},
			},
		})
	}
	return core.View{
		Class:    "flex-row items-center pt-1 px-1",
		Children: children,
	}
}

func maskCardNumber(num string) string {
	digits := strings.ReplaceAll(num, " ", "")
	if len(digits) <= 4 {
		return "••••"
	}
	return "•••• •••• •••• " + digits[len(digits)-4:]
}

func formatRelativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
	return t.Local().Format("Jan 2")
}

func cipherURIs(c *state.Cipher) []string {
	if c == nil || c.Login == nil {
		return nil
	}
	out := make([]string, 0, len(c.Login.URIs))
	for _, u := range c.Login.URIs {
		out = append(out, u.URI)
	}
	return out
}
