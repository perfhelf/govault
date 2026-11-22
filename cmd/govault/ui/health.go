package ui

import (
	"fmt"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
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
					core.View{
						Class: "flex-row gap-3",
						Children: []core.Node{
							tile(HealthReused, lucide.Repeat, 0xf08a0a, r.ReusedItems(), m.T("health.tile.reused")),
							tile(HealthWeak, lucide.ShieldAlert, 0xe5484d, len(r.Weak), m.T("health.tile.weak")),
							tile(HealthCards, lucide.CalendarClock, 0xa25ddc, len(r.Cards), m.T("health.tile.cards")),
							tile(HealthUnsecured, lucide.LockOpen, 0x0a84ff, len(r.Unsecured), m.T("health.tile.unsecured")),
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

func healthCount(r health.Report, c HealthCategory) int {
	switch c {
	case HealthReused:
		return r.ReusedItems()
	case HealthWeak:
		return len(r.Weak)
	case HealthCards:
		return len(r.Cards)
	case HealthUnsecured:
		return len(r.Unsecured)
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
		Class:    "flex-1",
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

func healthList(cx *core.Scope, m *AppModel, items []health.Issue) core.Node {
	rows := make([]core.Node, 0, len(items))
	for _, it := range items {
		issue := it
		rows = append(rows, core.View{
			TestID:  "health-item",
			Role:    core.RoleButton,
			Label:   m.Tf("a11y.open_item", issue.Name),
			Class:   "flex-row items-center gap-3 ps-3.5 pe-3 py-2 min-h-[48px] active:bg-gv-fill",
			OnPress: func(core.PressEvent) { m.OpenHealthItem(cx, issue.CipherID) },
			Children: []core.Node{
				itemEmblem(issue.Name, issue.Type, "", 28),
				core.View{
					Class: "flex-1 gap-[2px] overflow-hidden",
					Children: []core.Node{
						core.Text{MaxLines: 1, Class: "text-[13.5px] text-gv-fg", Content: issue.Name},
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
