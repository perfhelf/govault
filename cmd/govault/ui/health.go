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
					healthScoreCard(r),
					core.View{
						TestID: "health-tiles",
						Class:  "grid grid-cols-2 sm:grid-cols-3 gap-2.5",
						Children: []core.Node{
							tile(HealthReused, lucide.Repeat, 0xf08a0a, r.ReusedItems(), m.T("health.tile.reused")),
							tile(HealthWeak, lucide.ShieldAlert, 0xe5484d, len(r.Weak), m.T("health.tile.weak")),
							tile(HealthEmpty, lucide.KeyRound, 0xe04f5f, len(r.Empty), "Empty"),
							tile(HealthStale, lucide.Clock, 0xd97706, len(r.Stale), "Stale (>1y)"),
							tile(HealthCards, lucide.CalendarClock, 0xa25ddc, len(r.Cards), m.T("health.tile.cards")),
							tile(HealthUnsecured, lucide.LockOpen, 0x0a84ff, len(r.Unsecured), m.T("health.tile.unsecured")),
							tile(HealthMissingURI, lucide.Link2Off, 0x14a3b8, len(r.MissingURI), "Missing URI"),
							tile(HealthMissingName, lucide.Tag, 0x6b7a90, len(r.MissingName), "Missing Title"),
							tile(HealthUnreadable, lucide.TriangleAlert, 0xd93025, len(r.Unreadable), "Unreadable"),
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
									core.Text{Class: "text-[12px] text-gv-fg2", Content: "No password, card, website, title, or unreadable item issues found."},
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
					blocks = append(blocks, section("Empty Passwords", healthList(cx, m, r.Empty)))
				}
				if len(r.Stale) > 0 && show(HealthStale) {
					blocks = append(blocks, section("Stale Passwords", healthList(cx, m, r.Stale)))
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
					blocks = append(blocks, section("Missing Website URI", healthList(cx, m, r.MissingURI)))
				}
				if len(r.MissingName) > 0 && show(HealthMissingName) {
					blocks = append(blocks, section("Missing Title", healthList(cx, m, r.MissingName)))
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

func healthScoreTier(score int) (tier, textClass, pillBgClass, barBgClass string) {
	switch {
	case score >= 90:
		return "Strong", "text-gv-success", "bg-gv-success/15", "bg-gv-success"
	case score >= 70:
		return "Fair", "text-gv-accent", "bg-gv-accent-soft", "bg-gv-accent"
	case score >= 40:
		return "Needs Attention", "text-gv-warn", "bg-gv-warn-soft", "bg-gv-warn"
	default:
		return "At Risk", "text-gv-danger", "bg-gv-danger/15", "bg-gv-danger"
	}
}

func healthCountPhrase(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func healthScoreCard(r health.Report) core.Node {
	tier, textClass, pillBgClass, barBgClass := healthScoreTier(r.Score)
	summary := "No active items to analyze."
	if r.ActiveItems > 0 {
		summary = fmt.Sprintf("%s across %s.",
			healthCountPhrase(r.TotalIssues(), "issue", "issues"),
			healthCountPhrase(r.ActiveItems, "item", "items"))
	}
	breakdownDot := func(testID, dotClass, label string, count int) core.Node {
		return core.View{
			TestID: testID,
			Class:  "flex-row items-center gap-1.5",
			Children: []core.Node{
				core.View{Class: "w-[7px] h-[7px] rounded-full " + dotClass},
				core.Text{Class: "text-[11.5px] text-gv-fg2 tabular-nums", Content: fmt.Sprintf("%s: %d", label, count)},
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
										core.Text{Class: "text-[14.5px] font-semibold text-gv-fg", Content: "Vault Health Score"},
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
						breakdownDot("health-breakdown-high", "bg-gv-danger", "High risk", r.HighRisk()),
						breakdownDot("health-breakdown-medium", "bg-gv-warn", "Medium risk", r.MediumRisk()),
						breakdownDot("health-breakdown-low", "bg-gv-fg3", "Low risk", r.LowRisk()),
						core.View{Class: "flex-1"},
						core.Text{
							TestID:  "health-breakdown-checked",
							Class:   "text-[11.5px] text-gv-fg3 tabular-nums",
							Content: healthCountPhrase(r.ActiveItems, "item checked", "items checked"),
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
					core.Text{Class: "text-[13px] font-medium text-gv-fg", Content: "Could not decrypt on this device"},
					core.Text{
						TestID:  "health-unreadable-subtitle",
						Class:   "text-[11.5px] text-gv-fg2",
						Content: "These personal items use a format GoVault cannot read yet. Update them in the web vault, then sync again.",
					},
				},
			},
			ui.Button{
				TestID:  "health-unreadable-sync",
				Text:    "Sync Now",
				Icon:    lucide.RefreshCw,
				Variant: ui.ButtonSecondary,
				Size:    ui.SizeSmall,
				Busy:    func() bool { return m.SyncState.Get() == SyncInProgress },
				OnPress: func() { m.SyncNow(false) },
			},
		},
	})
	for _, it := range items {
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
						core.Text{MaxLines: 1, Class: "text-[13.5px] text-gv-fg", Content: it.Name},
						core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: it.Subtitle},
					},
				},
				core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2 text-end", Content: it.Detail},
			},
		})
	}
	return section("Unreadable Items", card(rows...))
}

func healthList(cx *core.Scope, m *AppModel, items []health.Issue) core.Node {
	rows := make([]core.Node, 0, len(items))
	for _, it := range items {
		issue := it
		title := strings.TrimSpace(issue.Name)
		if title == "" {
			title = "Untitled"
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
						core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: issue.Subtitle},
					},
				},
				core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2 text-end", Content: m.healthDetailText(issue.Detail)},
				icon(rtlSVG(cx, lucide.ChevronRight(), lucide.ChevronLeft()), 12, "text-gv-fg3"),
			},
		})
	}
	return card(rows...)
}
