package ui

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/dedup"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func (m *AppModel) cancelDedupMerge() {
	m.dedupMu.Lock()
	cancel := m.dedupCancel
	m.dedupCancel = nil
	m.dedupMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *AppModel) clearDedupState() {
	m.cancelDedupMerge()
	m.DedupReport.Set(dedup.Report{})
	m.DedupFilter.Set(DedupAll)
	m.DedupSelected.Set(nil)
	m.DedupKeepIDs.Set(nil)
	m.DedupTitles.Set(nil)
	m.DedupSimplifyURLs.Set(false)
	m.DedupBusy.Set(false)
	m.DedupProgress.Set(dedup.Progress{})
	m.DedupResult.Set(nil)
}

func (m *AppModel) recomputeDedup() {
	ciphers := m.Core.AllCiphers()
	for _, c := range ciphers {
		c.ReadOnly = c.ReadOnly || m.CipherReadOnly(c)
		c.HidePassword = c.HidePassword || m.PasswordHidden(c)
	}
	report := dedup.Analyze(ciphers)
	m.DedupReport.Set(report)
	m.reconcileDedupSelections(report)
}

func (m *AppModel) reconcileDedupSelections(report dedup.Report) {
	prevSel := m.DedupSelected.GetUntracked()
	prevKeep := m.DedupKeepIDs.GetUntracked()
	prevTitles := m.DedupTitles.GetUntracked()

	nextSel := make(map[string]bool, len(report.Groups))
	nextKeep := make(map[string]string, len(report.Groups))
	nextTitles := make(map[string]string)

	for _, g := range report.Groups {
		if len(g.Items) == 0 {
			continue
		}
		if g.BlockedReason != "" {
			nextSel[g.ID] = false
		} else if v, ok := prevSel[g.ID]; ok {
			nextSel[g.ID] = v
		} else {
			// Auto-select exact duplicate groups for quick cleanup; same-site groups
			// remain opt-in so distinct accounts are never merged unintentionally.
			nextSel[g.ID] = g.Type == dedup.GroupExact
		}

		keepID := g.Items[0].ID
		if prevID, ok := prevKeep[g.ID]; ok && slices.ContainsFunc(g.Items, func(c *state.Cipher) bool { return c.ID == prevID }) {
			keepID = prevID
		}
		nextKeep[g.ID] = keepID

		if t, ok := prevTitles[g.ID]; ok && t != "" {
			nextTitles[g.ID] = t
		}
	}

	m.DedupSelected.Set(nextSel)
	m.DedupKeepIDs.Set(nextKeep)
	m.DedupTitles.Set(nextTitles)
}

func (m *AppModel) SetDedupFilter(tab DedupFilterTab) {
	m.ResetIdleTimer()
	m.DedupFilter.Set(tab)
}

func (m *AppModel) ToggleDedupTileFilter(tab DedupFilterTab) {
	m.ResetIdleTimer()
	if m.DedupFilter.Get() == tab {
		m.DedupFilter.Set(DedupAll)
		return
	}
	m.DedupFilter.Set(tab)
}

func (m *AppModel) SetDedupGroupSelected(groupID string, checked bool) {
	if m.DedupMergeDisabled() {
		return
	}
	m.ResetIdleTimer()
	next := maps.Clone(m.DedupSelected.GetUntracked())
	if next == nil {
		next = map[string]bool{}
	}
	next[groupID] = checked
	m.DedupSelected.Set(next)
}

func (m *AppModel) SetDedupKeepItem(groupID, cipherID string) {
	if m.DedupMergeDisabled() {
		return
	}
	m.ResetIdleTimer()
	next := maps.Clone(m.DedupKeepIDs.GetUntracked())
	if next == nil {
		next = map[string]string{}
	}
	next[groupID] = cipherID
	m.DedupKeepIDs.Set(next)
}

func (m *AppModel) SelectAllExactDedup() {
	if m.DedupMergeDisabled() {
		return
	}
	m.ResetIdleTimer()
	next := maps.Clone(m.DedupSelected.GetUntracked())
	if next == nil {
		next = map[string]bool{}
	}
	for _, g := range m.DedupReport.GetUntracked().Groups {
		if g.Type == dedup.GroupExact && g.BlockedReason == "" {
			next[g.ID] = true
		}
	}
	m.DedupSelected.Set(next)
}

func (m *AppModel) ClearDedupSelection() {
	if m.DedupMergeDisabled() {
		return
	}
	m.ResetIdleTimer()
	next := make(map[string]bool, len(m.DedupReport.GetUntracked().Groups))
	for _, g := range m.DedupReport.GetUntracked().Groups {
		next[g.ID] = false
	}
	m.DedupSelected.Set(next)
}

func (m *AppModel) DismissDedupResult() {
	m.DedupResult.Set(nil)
}

func (m *AppModel) DedupMergeDisabled() bool {
	return m.DedupBusy.Get() || m.SyncState.Get() == SyncOffline || m.LocalOnly.Get()
}

type dedupSelectionSummary struct {
	selections   []dedup.GroupSelection
	anyReprompt  bool
	pureDeletes  int
	merges       int
	trashedItems int
}

func (m *AppModel) selectedDedupSummary() dedupSelectionSummary {
	rep := m.DedupReport.Get()
	selMap := m.DedupSelected.Get()
	keepMap := m.DedupKeepIDs.Get()
	titleMap := m.DedupTitles.Get()

	var sum dedupSelectionSummary
	for _, g := range rep.Groups {
		if g.BlockedReason != "" || !selMap[g.ID] || len(g.Items) < 2 {
			continue
		}
		keepID := keepMap[g.ID]
		if keepID == "" {
			keepID = g.Items[0].ID
		}
		sum.selections = append(sum.selections, dedup.GroupSelection{
			Group:         g,
			KeepCipherID:  keepID,
			TitleOverride: titleMap[g.ID],
		})
		if g.PureDelete {
			sum.pureDeletes++
		} else {
			sum.merges++
		}
		sum.trashedItems += len(g.Items) - 1
		for _, it := range g.Items {
			if it.Reprompt != 0 {
				sum.anyReprompt = true
			}
		}
	}
	return sum
}

func (m *AppModel) StartMergeSelected(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked || m.DedupMergeDisabled() {
		return
	}
	sum := m.selectedDedupSummary()
	if len(sum.selections) == 0 {
		return
	}
	m.ResetIdleTimer()

	var parts []string
	parts = append(parts, m.Tf("dedup.confirm.process_line", len(sum.selections)))
	if sum.pureDeletes > 0 {
		parts = append(parts, m.Tf("dedup.confirm.pure_delete_line", sum.pureDeletes))
	}
	if sum.merges > 0 {
		parts = append(parts, m.Tf("dedup.confirm.merge_line", sum.merges))
	}
	parts = append(parts, m.Tf("dedup.confirm.trash_line", sum.trashedItems))

	cx.ShowAlert(core.AlertConfig{
		Title:   m.T("dedup.confirm.title"),
		Message: strings.Join(parts, "\n"),
		Actions: []core.AlertAction{
			{Label: m.T("common.cancel"), Role: core.AlertCancel},
			{Label: m.T("dedup.merge_btn_action"), Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 || m.LockState.Get() != state.StatusUnlocked || m.DedupMergeDisabled() {
			return
		}
		run := func() { m.executeDedupMerge(sum.selections) }
		if sum.anyReprompt {
			m.GateReprompt(cx, &state.Cipher{Reprompt: 1}, m.T("reprompt.action.merge_dedup"), run)
			return
		}
		run()
	})
}

func (m *AppModel) executeDedupMerge(selections []dedup.GroupSelection) {
	if m.LockState.Get() != state.StatusUnlocked || m.DedupMergeDisabled() {
		return
	}
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}

	m.dedupMu.Lock()
	if m.dedupCancel != nil {
		m.dedupCancel()
	}
	m.dedupCancel = cancel
	m.dedupMu.Unlock()

	plan := dedup.BuildPlan(selections, dedup.PlanOptions{
		SimplifyURLs: m.DedupSimplifyURLs.Get(),
	})

	gen := m.LockGeneration()
	m.DedupBusy.Set(true)
	m.DedupResult.Set(nil)
	m.DedupProgress.Set(dedup.Progress{
		TotalGroups: len(plan.Groups),
		Phase:       "starting",
	})

	go func() {
		defer func() {
			cancel()
			m.dedupMu.Lock()
			m.dedupCancel = nil
			m.dedupMu.Unlock()
		}()

		execRes := dedup.ExecutePlan(ctx, m.Core, plan, func(p dedup.Progress) {
			m.Scope.Post(func() {
				if !m.StillUnlocked(gen) {
					return
				}
				m.DedupProgress.Set(p)
			})
		})

		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.DedupBusy.Set(false)
			m.DedupResult.Set(&execRes)
			m.RefreshVaultData()

			summaryTitle := m.Tf("dedup.toast.merged_title", execRes.SucceededGroups, execRes.TotalGroups)
			switch {
			case execRes.Cancelled:
				m.ShowToast(ui.ToastInfo, m.T("dedup.toast.cancelled"), "")
			case execRes.LocalCopyErr != nil && execRes.FailedGroups == 0:
				m.ShowLocalCopyWarning(summaryTitle)
			case execRes.FailedGroups > 0 && execRes.SucceededGroups == 0:
				m.ShowToast(ui.ToastError, m.T("dedup.toast.failed"), m.friendlyError(execRes.Err))
			case execRes.FailedGroups > 0:
				m.ShowToast(ui.ToastWarning, summaryTitle, m.Tf("dedup.toast.partial_failed_desc", execRes.FailedGroups))
			default:
				m.ShowToast(ui.ToastSuccess, summaryTitle, m.Tf("dedup.toast.trashed_desc", execRes.DeletedCount))
			}
		})
	}()
}

func DedupView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "dedup-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				r := m.DedupReport.Get()
				filter := m.DedupFilter.Get()
				offlineOrLocal := m.SyncState.Get() == SyncOffline || m.LocalOnly.Get()
				busy := m.DedupBusy.Get()
				sum := m.selectedDedupSummary()

				blocks := []core.Node{
					core.View{
						Class: "flex-row gap-3",
						Children: []core.Node{
							dedupTile(m, DedupExact, lucide.CopyCheck, 0x5856d6, r.Stats.ExactGroups, m.T("dedup.tile.exact"), filter == DedupExact, true),
							dedupTile(m, DedupSameSite, lucide.Layers, 0x0a84ff, r.Stats.SameSiteGroups, m.T("dedup.tile.samesite"), filter == DedupSameSite, true),
							dedupTile(m, DedupAll, lucide.Trash, 0xf08a0a, r.Stats.RedundantItems, m.T("dedup.tile.redundant"), false, false),
						},
					},
				}

				if offlineOrLocal {
					msg := m.T("dedup.offline_banner")
					if m.LocalOnly.Get() {
						msg = m.T("dedup.local_only_banner")
					}
					blocks = append(blocks, core.View{
						TestID: "dedup-offline-banner",
						Class:  "flex-row items-center gap-2.5 px-4 py-3 rounded-[10px] bg-gv-warn-soft border border-gv-line",
						Style:  core.Style{BorderCurve: core.BorderCurveContinuous},
						Children: []core.Node{
							icon(lucide.TriangleAlert(), 14, "text-gv-warn"),
							core.Text{Class: "flex-1 text-[12.5px] text-gv-fg", Content: msg},
						},
					})
				}

				if busy {
					blocks = append(blocks, dedupProgressCard(m))
				}

				if res := m.DedupResult.Get(); res != nil {
					blocks = append(blocks, dedupResultCard(m, res))
				}

				if len(r.Groups) == 0 {
					blocks = append(blocks, card(core.View{
						TestID: "dedup-all-clear",
						Class:  "flex-row items-center gap-3 px-4 py-4",
						Children: []core.Node{
							icon(lucide.CircleCheck(), 22, "text-gv-success"),
							core.View{
								Class: "flex-1 gap-[2px]",
								Children: []core.Node{
									core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: m.T("dedup.all_clear_title")},
									core.Text{Class: "text-[12px] text-gv-fg2", Content: m.T("dedup.all_clear_desc")},
								},
							},
						},
					}))
				} else {
					blocks = append(blocks,
						core.View{
							Class: "flex-row flex-wrap items-center justify-between gap-3",
							Children: []core.Node{
								ui.Tabs[DedupFilterTab]{
									TestID: "dedup-filter-tabs",
									Options: []ui.Option[DedupFilterTab]{
										{Value: DedupAll, Label: m.T("dedup.filter.all")},
										{Value: DedupExact, Label: m.T("dedup.filter.exact")},
										{Value: DedupSameSite, Label: m.T("dedup.filter.same_site")},
									},
									Value:    m.DedupFilter.Get,
									OnChange: m.SetDedupFilter,
								},
								core.View{
									Class: "flex-row flex-wrap items-center gap-2",
									Children: []core.Node{
										ui.Button{
											TestID:   "dedup-select-exact",
											Text:     m.T("dedup.select_exact"),
											Variant:  ui.ButtonSecondary,
											Size:     ui.SizeSmall,
											Disabled: m.DedupMergeDisabled,
											OnPress:  m.SelectAllExactDedup,
										},
										ui.Button{
											TestID:   "dedup-clear-selection",
											Text:     m.T("common.clear"),
											Variant:  ui.ButtonGhost,
											Size:     ui.SizeSmall,
											Disabled: m.DedupMergeDisabled,
											OnPress:  m.ClearDedupSelection,
										},
									},
								},
							},
						},
						card(core.View{
							Class: "flex-row flex-wrap items-center justify-between gap-3 px-4 py-2.5",
							Children: []core.Node{
								ui.Checkbox{
									TestID:   "dedup-simplify-urls",
									Text:     m.T("dedup.simplify_urls"),
									Label:    m.T("dedup.simplify_urls_a11y"),
									Checked:  m.DedupSimplifyURLs.Get,
									Disabled: m.DedupMergeDisabled,
									OnChange: func(v bool) {
										m.ResetIdleTimer()
										m.DedupSimplifyURLs.Set(v)
									},
								},
								ui.Button{
									TestID:   "dedup-merge-btn",
									Text:     m.Tf("dedup.merge_btn", len(sum.selections)),
									Icon:     lucide.Combine,
									Variant:  ui.ButtonPrimary,
									Busy:     m.DedupBusy.Get,
									Disabled: func() bool { return m.DedupMergeDisabled() || len(sum.selections) == 0 },
									OnPress:  func() { m.StartMergeSelected(cx) },
								},
							},
						}),
					)

					var visible []dedup.Group
					for _, g := range r.Groups {
						if filter == DedupAll || (filter == DedupExact && g.Type == dedup.GroupExact) || (filter == DedupSameSite && g.Type == dedup.GroupSameSite) {
							visible = append(visible, g)
						}
					}

					if len(visible) == 0 {
						blocks = append(blocks, core.Text{
							TestID:  "dedup-filter-empty",
							Class:   "px-1 text-[12.5px] text-gv-fg2",
							Content: m.T("dedup.filter.empty"),
						})
					} else {
						for _, g := range visible {
							blocks = append(blocks, dedupGroupCard(cx, m, g))
						}
					}
				}

				blocks = append(blocks, core.Text{
					Class:   "px-1 text-[11.5px] text-gv-fg3",
					Content: m.T("dedup.footer"),
				})

				return core.View{
					Class:    "w-full max-w-[760px] self-center px-7 pt-6 pb-10 gap-5",
					Children: blocks,
				}
			}),
		},
	}
}

func dedupTile(m *AppModel, tab DedupFilterTab, glyph func() *core.SVG, tint uint32, count int, label string, selected, clickable bool) core.Node {
	countClass := "text-[22px] font-semibold text-gv-fg tabular-nums"
	if count == 0 {
		countClass = "text-[22px] font-semibold text-gv-fg3 tabular-nums"
	}
	frame := "gap-1.5 px-3.5 py-3 rounded-[10px] bg-gv-card border border-gv-line"
	if selected {
		frame = "gap-1.5 px-3.5 py-3 rounded-[10px] bg-gv-accent-soft border border-gv-accent"
	}
	testID := "dedup-count-redundant"
	switch tab {
	case DedupExact:
		testID = "dedup-count-exact"
	case DedupSameSite:
		testID = "dedup-count-samesite"
	}
	v := core.View{
		TestID: testID,
		Label:  label,
		Class:  "flex-1",
		Children: []core.Node{core.View{
			Class: frame,
			Style: core.Style{BorderCurve: core.BorderCurveContinuous},
			Children: []core.Node{
				core.View{
					Class: "w-[24px] h-[24px] rounded-[6px] items-center justify-center",
					Style: core.Style{Background: core.RGB(tint)},
					Children: []core.Node{
						core.Icon{SVG: glyph(), Style: core.Style{Width: core.Pt(13), Height: core.Pt(13), Color: core.RGB(0xffffff)}},
					},
				},
				core.Text{Class: countClass, Content: fmt.Sprintf("%d", count)},
				core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2", Content: label},
			},
		}},
	}
	if clickable {
		v.Role = core.RoleButton
		v.Selected = func() bool { return selected }
		v.OnPress = func(core.PressEvent) { m.ToggleDedupTileFilter(tab) }
	}
	return v
}

func dedupProgressCard(m *AppModel) core.Node {
	return card(core.View{
		TestID: "dedup-progress-card",
		Class:  "px-4 py-3.5 gap-2.5",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center justify-between gap-2",
				Children: []core.Node{
					core.Text{
						Class: "text-[13px] font-semibold text-gv-fg",
						ContentFunc: func() string {
							p := m.DedupProgress.Get()
							if p.CurrentGroup != "" {
								return m.Tf("dedup.progress.merging_group", p.CurrentGroup)
							}
							return m.T("dedup.progress.merging")
						},
					},
					core.View{
						Class: "flex-row items-center gap-2",
						Children: []core.Node{
							core.Text{
								Class: "text-[12px] text-gv-fg2 tabular-nums",
								ContentFunc: func() string {
									p := m.DedupProgress.Get()
									return m.Tf("dedup.progress.count", p.CompletedGroups, p.TotalGroups)
								},
							},
							ui.Button{
								TestID:  "dedup-cancel-btn",
								Text:    m.T("common.cancel"),
								Variant: ui.ButtonGhost,
								Size:    ui.SizeSmall,
								OnPress: m.cancelDedupMerge,
							},
						},
					},
				},
			},
			ui.Progress{
				TestID: "dedup-progress",
				Label:  m.T("dedup.progress.label"),
				Value:  func() float32 { return m.DedupProgress.Get().Percent },
			},
		},
	})
}

func dedupResultCard(m *AppModel, res *dedup.ExecuteReport) core.Node {
	glyph := lucide.CircleCheck()
	tintClass := "text-gv-success"
	headline := m.Tf("dedup.result.merged", res.SucceededGroups, res.CreatedCount, res.UpdatedCount, res.DeletedCount)
	sub := m.T("dedup.result.merged_sub")

	if res.Cancelled {
		glyph = lucide.TriangleAlert()
		tintClass = "text-gv-warn"
		headline = m.Tf("dedup.result.cancelled", res.SucceededGroups, res.TotalGroups)
		sub = m.T("dedup.result.cancelled_sub")
	} else if res.FailedGroups > 0 {
		glyph = lucide.TriangleAlert()
		tintClass = "text-gv-warn"
		headline = m.Tf("dedup.result.failed", res.SucceededGroups, res.TotalGroups, res.FailedGroups)
		var reasons []string
		for _, r := range res.Results {
			if r.Err != nil {
				reasons = append(reasons, fmt.Sprintf("%s: %s", r.Label, m.friendlyError(r.Err)))
			}
		}
		if len(reasons) > 0 {
			sub = strings.Join(reasons, " · ")
		}
	} else if res.LocalCopyErr != nil {
		glyph = lucide.TriangleAlert()
		tintClass = "text-gv-warn"
		sub = m.T("dedup.result.local_copy_sub")
	}

	return card(core.View{
		TestID: "dedup-result-summary",
		Class:  "flex-row items-start gap-3 px-4 py-3.5",
		Children: []core.Node{
			icon(glyph, 18, tintClass+" mt-[2px]"),
			core.View{
				Class: "flex-1 gap-1",
				Children: []core.Node{
					core.Text{Class: "text-[13px] font-semibold text-gv-fg", Content: headline},
					core.Text{Class: "text-[12px] text-gv-fg2", Content: sub},
				},
			},
			ui.Button{
				TestID:  "dedup-result-dismiss",
				Text:    m.T("common.dismiss"),
				Variant: ui.ButtonGhost,
				Size:    ui.SizeSmall,
				OnPress: m.DismissDedupResult,
			},
		},
	})
}

func dedupGroupCard(cx *core.Scope, m *AppModel, g dedup.Group) core.Node {
	keepMap := m.DedupKeepIDs.Get()
	keepID := keepMap[g.ID]
	if keepID == "" && len(g.Items) > 0 {
		keepID = g.Items[0].ID
	}

	typeBadge := ui.Badge{Text: m.T("dedup.badge.exact"), Variant: ui.BadgeAccent}
	if g.Type == dedup.GroupSameSite {
		typeBadge = ui.Badge{Text: m.T("dedup.badge.same_site"), Variant: ui.BadgeInfo}
	}

	var pathBadge ui.Badge
	switch {
	case g.BlockedReason != "":
		pathBadge = ui.Badge{Text: m.T("dedup.badge.readonly"), Variant: ui.BadgeWarn}
	case g.PureDelete:
		pathBadge = ui.Badge{Text: m.T("dedup.badge.path_a"), Variant: ui.BadgeUp}
	default:
		pathBadge = ui.Badge{Text: m.T("dedup.badge.path_b"), Variant: ui.BadgeNeutral}
	}

	meta := m.Tf("dedup.group_meta", len(g.Items))
	if g.OrganizationID != "" {
		orgName := m.OrganizationName(&g.OrganizationID)
		if orgName == "" {
			orgName = m.T("dedup.org_fallback")
		}
		meta = m.Tf("dedup.group_meta_org", len(g.Items), orgName)
	}

	headerRow := core.View{
		Class: "flex-row flex-wrap items-center gap-2.5 px-4 py-3",
		Children: []core.Node{
			ui.Checkbox{
				TestID:  "dedup-group-check-" + g.ID,
				Label:   m.Tf("a11y.select_named", g.Label),
				Checked: func() bool { return m.DedupSelected.Get()[g.ID] },
				Disabled: func() bool {
					return g.BlockedReason != "" || m.DedupMergeDisabled()
				},
				OnChange: func(v bool) { m.SetDedupGroupSelected(g.ID, v) },
			},
			core.View{
				Class: "flex-1 min-w-[160px] gap-[2px]",
				Children: []core.Node{
					core.Text{MaxLines: 1, Class: "text-[13.5px] font-semibold text-gv-fg", Content: g.Label},
					core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: meta},
				},
			},
			core.View{
				Class:    "flex-row flex-wrap items-center gap-1.5",
				Children: []core.Node{typeBadge, pathBadge},
			},
		},
	}

	rows := []core.Node{headerRow}

	if g.BlockedReason != "" {
		rows = append(rows, core.View{
			TestID: "dedup-blocked-" + g.ID,
			Class:  "flex-row items-center gap-2 px-4 py-2 bg-gv-warn-soft",
			Children: []core.Node{
				icon(lucide.ShieldAlert(), 13, "text-gv-warn"),
				core.Text{Class: "flex-1 text-[12px] text-gv-warn", Content: m.translateDedupBlocked(g.BlockedReason)},
			},
		})
	}

	if len(g.DiffFields) > 0 {
		diffNodes := []core.Node{
			core.Text{Class: "text-[11.5px] font-medium text-gv-fg2", Content: m.T("dedup.diff.label")},
		}
		for _, d := range m.translateDedupDiff(g.DiffFields) {
			diffNodes = append(diffNodes, ui.Badge{Text: d, Variant: ui.BadgeWarn})
		}
		if g.Type == dedup.GroupSameSite && slices.Contains(g.DiffFields, "Username") {
			diffNodes = append(diffNodes, core.Text{
				Class:   "text-[11.5px] text-gv-warn",
				Content: m.T("dedup.diff.username_warning"),
			})
		}
		rows = append(rows, core.View{
			TestID:   "dedup-diffs-" + g.ID,
			Class:    "flex-row flex-wrap items-center gap-1.5 px-4 py-2",
			Children: diffNodes,
		})
	}

	keepOptions := make([]ui.Option[string], 0, len(g.Items))
	for _, it := range g.Items {
		keepOptions = append(keepOptions, ui.Option[string]{
			Value: it.ID,
			Label: dedupKeepOptionLabel(m, it),
		})
	}

	rows = append(rows, core.View{
		Class: "flex-row items-center justify-between gap-3 px-4 py-2",
		Children: []core.Node{
			core.Text{Class: "text-[12px] font-medium text-gv-fg2", Content: m.T("dedup.keep_item")},
			ui.Select[string]{
				TestID:  "dedup-keep-" + g.ID,
				Label:   m.Tf("dedup.keep_item_a11y", g.Label),
				Style:   core.Style{Width: core.Pt(260)},
				Options: keepOptions,
				Value: func() string {
					if id := m.DedupKeepIDs.Get()[g.ID]; id != "" {
						return id
					}
					if len(g.Items) > 0 {
						return g.Items[0].ID
					}
					return ""
				},
				Disabled: func() bool { return g.BlockedReason != "" || m.DedupMergeDisabled() },
				OnChange: func(id string) { m.SetDedupKeepItem(g.ID, id) },
			},
		},
	})

	folders := map[string]string{}
	for _, f := range m.Folders.Get() {
		folders[f.ID] = f.Name
	}

	for _, it := range g.Items {
		item := it
		isKeep := item.ID == keepID
		rows = append(rows, dedupItemRow(cx, m, item, folders, isKeep, g.PureDelete, g.BlockedReason != ""))
	}

	return core.View{
		TestID:   "dedup-group-" + g.ID,
		Children: []core.Node{card(rows...)},
	}
}

func dedupItemRow(cx *core.Scope, m *AppModel, c *state.Cipher, folders map[string]string, isKeep, pureDelete, blocked bool) core.Node {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		name = m.T("common.untitled")
	}
	user := m.T("dedup.no_username")
	if c.Login != nil && strings.TrimSpace(c.Login.Username) != "" {
		user = c.Login.Username
	}
	sub := user
	if uri := dedup.PrimaryURI(c); uri != "" {
		sub += " · " + uri
	}
	if c.FolderID != nil && *c.FolderID != "" {
		if fn := folders[*c.FolderID]; fn != "" {
			sub += " · " + fn
		}
	}

	var badges []core.Node
	if c.Login != nil && len(c.Login.Fido2Credentials) > 0 {
		badges = append(badges, ui.Badge{Text: m.Tf("dedup.badge.passkey", len(c.Login.Fido2Credentials)), Variant: ui.BadgeAccent})
	}
	if len(c.Attachments) > 0 {
		badges = append(badges, ui.Badge{Text: m.Tf("dedup.badge.files", len(c.Attachments)), Variant: ui.BadgeInfo})
	}
	if c.Login != nil && strings.TrimSpace(c.Login.TOTP) != "" {
		badges = append(badges, ui.Badge{Text: m.T("dedup.badge.totp"), Variant: ui.BadgeNeutral})
	}
	if len(c.Fields) > 0 {
		badges = append(badges, ui.Badge{Text: m.Tf("dedup.badge.fields_count", len(c.Fields)), Variant: ui.BadgeNeutral})
	}
	if c.Favorite {
		badges = append(badges, ui.Badge{Text: m.T("editor.favorite"), Variant: ui.BadgeNeutral})
	}
	if c.Reprompt != 0 {
		badges = append(badges, ui.Badge{Text: m.T("dedup.badge.reprompt"), Variant: ui.BadgeWarn})
	}

	switch {
	case blocked:
		badges = append(badges, ui.Badge{Text: m.T("dedup.badge.locked"), Variant: ui.BadgeOutline})
	case isKeep:
		badges = append(badges, ui.Badge{Text: m.T("dedup.badge.keep"), Variant: ui.BadgeUp})
	case pureDelete:
		badges = append(badges, ui.Badge{Text: m.T("dedup.badge.trash"), Variant: ui.BadgeDown})
	default:
		badges = append(badges, ui.Badge{Text: m.T("dedup.badge.merge_trash"), Variant: ui.BadgeWarn})
	}

	return core.View{
		TestID:  "dedup-item-" + c.ID,
		Role:    core.RoleButton,
		Label:   m.Tf("a11y.open_item", name),
		Class:   "flex-row items-center gap-3 ps-4 pe-3 py-2.5 min-h-[50px] active:bg-gv-fill",
		OnPress: func(core.PressEvent) { m.OpenHealthItem(cx, c.ID) },
		Children: []core.Node{
			itemEmblem(name, api.CipherTypeLogin, "", 26),
			core.View{
				Class: "flex-1 gap-[2px] overflow-hidden",
				Children: []core.Node{
					core.Text{MaxLines: 1, Class: "text-[13px] font-medium text-gv-fg", Content: name},
					core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: sub},
				},
			},
			core.View{
				Class:    "flex-row flex-wrap items-center justify-end gap-1",
				Children: badges,
			},
			icon(rtlSVG(cx, lucide.ChevronRight(), lucide.ChevronLeft()), 12, "text-gv-fg3"),
		},
	}
}

// dedupKeepOptionLabel formats a safe label for the keep-item selector.
// It never exposes passwords or TOTP secrets.
func dedupKeepOptionLabel(m *AppModel, c *state.Cipher) string {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		name = m.T("common.untitled")
	}
	user := m.T("dedup.no_username_short")
	if c.Login != nil && strings.TrimSpace(c.Login.Username) != "" {
		user = c.Login.Username
	}
	var tags []string
	if c.Login != nil && len(c.Login.Fido2Credentials) > 0 {
		tags = append(tags, m.T("dedup.keep_tag.passkey"))
	}
	if len(c.Attachments) > 0 {
		tags = append(tags, m.T("dedup.keep_tag.files"))
	}
	if c.Login != nil && strings.TrimSpace(c.Login.TOTP) != "" {
		tags = append(tags, m.T("dedup.keep_tag.2fa"))
	}
	if len(c.Fields) > 0 {
		tags = append(tags, m.Tf("dedup.keep_tag.fields", len(c.Fields)))
	}
	if len(tags) > 0 {
		return fmt.Sprintf("%s (%s) [%s]", name, user, strings.Join(tags, ", "))
	}
	return fmt.Sprintf("%s (%s)", name, user)
}
