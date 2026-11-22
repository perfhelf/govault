package ui

import (
	"fmt"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/health"
)

func HealthView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "health-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				r := m.Health.Get()
				filter := m.HealthFilter.Get()
				show := func(c HealthCategory) bool { return filter == HealthAll || filter == c }
				tile := func(c HealthCategory, glyph func() *core.SVG, tint uint32, count int, label string) core.Node {
					return healthTile(m, c, glyph, tint, count, label, filter == c)
				}
				blocks := []core.Node{
					healthScoreCard(m, r),
					core.View{
						TestID: "health-tiles",
						Class:  "grid grid-cols-2 sm:grid-cols-3 gap-2.5",
						Children: []core.Node{
							tile(HealthReused, lucide.Repeat, 0xf08a0a, r.ReusedItems(), m.T("health.tile.reused")),
							tile(HealthWeak, lucide.ShieldAlert, 0xe5484d, len(r.Weak), m.T("health.tile.weak")),
							tile(HealthEmpty, lucide.KeyRound, 0xe04f5f, len(r.Empty), m.T("health.tile.empty")),
							tile(HealthStale, lucide.Clock, 0xd97706, len(r.Stale), m.T("health.tile.stale")),
							tile(HealthCards, lucide.CalendarClock, 0xa25ddc, len(r.Cards), m.T("health.tile.cards")),
							tile(HealthUnsecured, lucide.LockOpen, 0x0a84ff, len(r.Unsecured), m.T("health.tile.unsecured")),
							tile(HealthMissingURI, lucide.Link2Off, 0x14a3b8, len(r.MissingURI), m.T("health.tile.missing_uri")),
							tile(HealthMissingName, lucide.Tag, 0x6b7a90, len(r.MissingName), m.T("health.tile.missing_name")),
							tile(HealthUnreadable, lucide.TriangleAlert, 0xd93025, len(r.Unreadable), m.T("health.tile.unreadable")),
						},
					},
				}
				if filter != HealthAll && healthCount(r, filter) == 0 && r.TotalIssues() > 0 {
					blocks = append(blocks, core.Text{
						TestID:  "health-filter-empty",
						Class:   "px-1 text-[12.5px] text-gv-fg2",
						Content: m.T("health.filter_empty"),
					})
				}
				if r.TotalIssues() == 0 {
					blocks = append(blocks, card(core.View{
						TestID: "health-all-clear",
						Class:  "flex-row items-center gap-3 px-4 py-4",
						Children: []core.Node{
							icon(lucide.CircleCheck(), 22, "text-gv-success"),
							core.View{
								Class: "flex-1 gap-[2px]",
								Children: []core.Node{
									core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: m.T("health.all_clear_title")},
									core.Text{Class: "text-[12px] text-gv-fg2", Content: m.T("health.all_clear_desc")},
								},
							},
						},
					}))
				}
				for i, g := range r.Reused {
					if !show(HealthReused) {
						break
					}
					title := ""
					if i == 0 {
						title = m.T("health.section.reused")
					}
					blocks = append(blocks, section(title, healthList(cx, m, g.Items)))
				}
				if len(r.Weak) > 0 && show(HealthWeak) {
					blocks = append(blocks, section(m.T("health.section.weak"), healthList(cx, m, r.Weak)))
				}
				if len(r.Empty) > 0 && show(HealthEmpty) {
					blocks = append(blocks, section(m.T("health.section.empty"), healthList(cx, m, r.Empty)))
				}
				if len(r.Stale) > 0 && show(HealthStale) {
					blocks = append(blocks, section(m.T("health.section.stale"), healthList(cx, m, r.Stale)))
				}
				if len(r.Cards) > 0 && show(HealthCards) {
					items := make([]health.Issue, len(r.Cards))
					for i, c := range r.Cards {
						items[i] = c.Issue
					}
					blocks = append(blocks, section(m.T("health.section.cards"), healthList(cx, m, items)))
				}
				if len(r.Unsecured) > 0 && show(HealthUnsecured) {
					blocks = append(blocks, section(m.T("health.section.unsecured"), healthList(cx, m, r.Unsecured)))
				}
				if len(r.MissingURI) > 0 && show(HealthMissingURI) {
					blocks = append(blocks, section(m.T("health.section.missing_uri"), healthList(cx, m, r.MissingURI)))
				}
				if len(r.MissingName) > 0 && show(HealthMissingName) {
					blocks = append(blocks, section(m.T("health.section.missing_name"), healthList(cx, m, r.MissingName)))
				}
				if len(r.Unreadable) > 0 && show(HealthUnreadable) {
					blocks = append(blocks, unreadableSection(m, r.Unreadable))
				}
				blocks = append(blocks, core.Text{
					Class:   "px-1 text-[11.5px] text-gv-fg3",
					Content: m.T("health.privacy_footer"),
				})
				return core.View{
					Class:    "w-full max-w-[680px] self-center px-7 pt-6 pb-10 gap-5",
					Children: blocks,
				}
			}),
		},
	}
}

func healthScoreTier(m *AppModel, score int) (tier, textClass, pillBgClass, barBgClass string) {
	switch {
	case score >= 90:
		return m.T("health.score.tier.strong"), "text-gv-success", "bg-gv-success/15", "bg-gv-success"
	case score >= 70:
		return m.T("health.score.tier.fair"), "text-gv-accent", "bg-gv-accent-soft", "bg-gv-accent"
	case score >= 40:
		return m.T("health.score.tier.needs_attention"), "text-gv-warn", "bg-gv-warn-soft", "bg-gv-warn"
	default:
		return m.T("health.score.tier.at_risk"), "text-gv-danger", "bg-gv-danger/15", "bg-gv-danger"
	}
}

func healthScoreCard(m *AppModel, r health.Report) core.Node {
	tier, textClass, pillBgClass, barBgClass := healthScoreTier(m, r.Score)
	summary := m.T("health.score.no_active")
	if r.ActiveItems > 0 {
		issuesText := m.Tf("health.issues_many", r.TotalIssues())
		if r.TotalIssues() == 1 {
			issuesText = m.T("health.issues_one")
		}
		itemsText := m.Tf("health.items_many", r.ActiveItems)
		if r.ActiveItems == 1 {
			itemsText = m.T("health.items_one")
		}
		summary = m.Tf("health.score.summary", issuesText, itemsText)
	}
	checkedText := m.Tf("health.breakdown.checked_many", r.ActiveItems)
	if r.ActiveItems == 1 {
		checkedText = m.T("health.breakdown.checked_one")
	}
	breakdownDot := func(testID, dotClass, text string) core.Node {
		return core.View{
			TestID: testID,
			Class:  "flex-row items-center gap-1.5",
			Children: []core.Node{
				core.View{Class: "w-[7px] h-[7px] rounded-full " + dotClass},
				core.Text{Class: "text-[11.5px] text-gv-fg2 tabular-nums", Content: text},
			},
		}
	}
	return core.View{
		TestID: "health-score-card",
		Children: []core.Node{
			card(
				core.View{
					Class: "flex-row items-center gap-4 px-4 py-4",
					Children: []core.Node{
						core.View{
							Class: "w-[64px] h-[64px] rounded-[14px] items-center justify-center " + pillBgClass,
							Style: core.Style{BorderCurve: core.BorderCurveContinuous},
							Children: []core.Node{
								core.Text{
									TestID:  "health-score-value",
									Class:   "text-[23px] font-bold tabular-nums leading-[1.05] " + textClass,
									Content: fmt.Sprintf("%d", r.Score),
								},
								core.Text{
									Class:   "text-[10px] font-medium text-gv-fg3 tabular-nums",
									Content: "/ 100",
								},
							},
						},
						core.View{
							Class: "flex-1 gap-1.5",
							Children: []core.Node{
								core.View{
									Class: "flex-row items-center justify-between gap-2",
									Children: []core.Node{
										core.Text{Class: "text-[14.5px] font-semibold text-gv-fg", Content: m.T("health.score.title")},
										core.View{
											Class: "px-2.5 py-[2px] rounded-full " + pillBgClass,
											Children: []core.Node{
												core.Text{
													TestID:  "health-score-tier",
													Class:   "text-[11.5px] font-semibold " + textClass,
													Content: tier,
												},
											},
										},
									},
								},
								core.Text{
									TestID:  "health-score-summary",
									Class:   "text-[12px] text-gv-fg2",
									Content: summary,
								},
								core.View{
									Class: "h-[6px] rounded-full bg-gv-fill overflow-hidden",
									Children: []core.Node{
										core.View{
											Class: "h-full rounded-full " + barBgClass,
											Style: core.Style{Width: core.Pct(float32(r.Score))},
										},
									},
								},
							},
						},
					},
				},
				core.View{
					Class: "flex-row flex-wrap items-center gap-4 px-4 py-2.5",
					Children: []core.Node{
						breakdownDot("health-breakdown-high", "bg-gv-danger", m.Tf("health.breakdown.high", r.HighRisk())),
						breakdownDot("health-breakdown-medium", "bg-gv-warn", m.Tf("health.breakdown.medium", r.MediumRisk())),
						breakdownDot("health-breakdown-low", "bg-gv-fg3", m.Tf("health.breakdown.low", r.LowRisk())),
						core.View{Class: "flex-1"},
						core.Text{
							TestID:  "health-breakdown-checked",
							Class:   "text-[11.5px] text-gv-fg3 tabular-nums",
							Content: checkedText,
						},
					},
				},
			),
		},
	}
}

func healthCount(r health.Report, c HealthCategory) int {
	switch c {
	case HealthReused:
		return r.ReusedItems()
	case HealthWeak:
		return len(r.Weak)
	case HealthEmpty:
		return len(r.Empty)
	case HealthStale:
		return len(r.Stale)
	case HealthCards:
		return len(r.Cards)
	case HealthUnsecured:
		return len(r.Unsecured)
	case HealthMissingURI:
		return len(r.MissingURI)
	case HealthMissingName:
		return len(r.MissingName)
	case HealthUnreadable:
		return len(r.Unreadable)
	}
	return r.TotalIssues()
}

// SetHealthFilter shows only category c, or every category when c is the
// active one.
func (m *AppModel) SetHealthFilter(c HealthCategory) {
	m.ResetIdleTimer()
	if m.HealthFilter.Get() == c {
		c = HealthAll
	}
	m.HealthFilter.Set(c)
}

func healthTile(m *AppModel, c HealthCategory, glyph func() *core.SVG, tint uint32, count int, label string, selected bool) core.Node {
	countClass := "text-[22px] font-semibold text-gv-fg tabular-nums"
	if count == 0 {
		countClass = "text-[22px] font-semibold text-gv-fg3 tabular-nums"
	}
	frame := "gap-1.5 px-3.5 py-3 rounded-[10px] bg-gv-card border border-gv-line"
	if selected {
		frame = "gap-1.5 px-3.5 py-3 rounded-[10px] bg-gv-accent-soft border border-gv-accent"
	}
	return core.View{
		TestID:   "health-count-" + string(c),
		Role:     core.RoleButton,
		Label:    label,
		Selected: func() bool { return selected },
		Class:    "w-full",
		OnPress:  func(core.PressEvent) { m.SetHealthFilter(c) },
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
}

func unreadableSection(m *AppModel, items []health.Issue) core.Node {
	rows := make([]core.Node, 0, len(items)+1)
	rows = append(rows, core.View{
		TestID: "health-unreadable-banner",
		Class:  "flex-row items-center gap-3 px-4 py-3",
		Children: []core.Node{
			icon(lucide.TriangleAlert(), 16, "text-gv-danger"),
			core.View{
				Class: "flex-1 gap-[2px]",
				Children: []core.Node{
					core.Text{Class: "text-[13px] font-medium text-gv-fg", Content: m.T("health.unreadable.title")},
					core.Text{
						TestID:  "health-unreadable-subtitle",
						Class:   "text-[11.5px] text-gv-fg2",
						Content: m.T("health.unreadable.subtitle"),
					},
				},
			},
			ui.Button{
				TestID:  "health-unreadable-sync",
				Text:    m.T("common.sync_now"),
				Icon:    lucide.RefreshCw,
				Variant: ui.ButtonSecondary,
				Size:    ui.SizeSmall,
				Busy:    func() bool { return m.SyncState.Get() == SyncInProgress },
				OnPress: func() { m.SyncNow(false) },
			},
		},
	})
	for _, it := range items {
		name := it.Name
		if name == "Unreadable item" {
			name = m.T("health.unreadable.item_name")
		}
		rows = append(rows, core.View{
			TestID: "health-unreadable-item",
			Class:  "flex-row items-center gap-3 ps-3.5 pe-3 py-2 min-h-[48px]",
			Children: []core.Node{
				core.View{
					Class: "w-[28px] h-[28px] rounded-[7px] items-center justify-center bg-gv-danger/10",
					Style: core.Style{BorderCurve: core.BorderCurveContinuous},
					Children: []core.Node{
						icon(lucide.FileQuestionMark(), 14, "text-gv-danger"),
					},
				},
				core.View{
					Class: "flex-1 gap-[2px] overflow-hidden",
					Children: []core.Node{
						core.Text{MaxLines: 1, Class: "text-[13.5px] text-gv-fg", Content: name},
						core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: m.healthSubtitleText(it)},
					},
				},
				core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2 text-end", Content: m.healthDetailText(it.Detail)},
			},
		})
	}
	return section(m.T("health.section.unreadable"), card(rows...))
}

func healthList(cx *core.Scope, m *AppModel, items []health.Issue) core.Node {
	rows := make([]core.Node, 0, len(items))
	for _, it := range items {
		issue := it
		title := strings.TrimSpace(issue.Name)
		if title == "" {
			title = m.T("common.untitled")
		}
		rows = append(rows, core.View{
			TestID:  "health-item",
			Role:    core.RoleButton,
			Label:   m.Tf("a11y.open_item", title),
			Class:   "flex-row items-center gap-3 ps-3.5 pe-3 py-2 min-h-[48px] active:bg-gv-fill",
			OnPress: func(core.PressEvent) { m.OpenHealthItem(cx, issue.CipherID) },
			Children: []core.Node{
				itemEmblem(title, issue.Type, "", 28),
				core.View{
					Class: "flex-1 gap-[2px] overflow-hidden",
					Children: []core.Node{
						core.Text{MaxLines: 1, Class: "text-[13.5px] text-gv-fg", Content: title},
						core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: m.healthSubtitleText(issue)},
					},
				},
				core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2 text-end", Content: m.healthDetailText(issue.Detail)},
				icon(rtlSVG(cx, lucide.ChevronRight(), lucide.ChevronLeft()), 12, "text-gv-fg3"),
			},
		})
	}
	return card(rows...)
}
