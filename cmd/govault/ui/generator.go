package ui

import (
	"fmt"
	"github.com/txchen/govault/internal/vaultcore/gen"
	"math"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
)

func GeneratorView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "generator-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{
				Class: "w-full max-w-[600px] self-center px-7 pt-6 pb-10 gap-5",
				Children: []core.Node{
					generatorOutput(cx, m),
					ui.Tabs[string]{
						TestID: "generator-mode-tabs",
						Equal:  true,
						Options: []ui.Option[string]{
							{Value: "password", Label: m.T("field.password")},
							{Value: "passphrase", Label: m.T("generator.passphrase")},
						},
						Value: func() string {
							if m.Prefs.Get().GeneratorMode == "passphrase" {
								return "passphrase"
							}
							return "password"
						},
						OnChange: func(mode string) {
							m.UpdatePrefs(func(p UserPrefs) UserPrefs {
								p.GeneratorMode = mode
								return p
							})
							m.RegenerateSecret()
						},
					},
					core.Show{
						When: func() bool { return m.Prefs.Get().GeneratorMode == "passphrase" },
						Then: func(cx *core.Scope) core.Node { return passphraseOptionsView(m) },
						Else: func(cx *core.Scope) core.Node { return passwordOptionsView(m) },
					},
				},
			},
		},
	}
}

type strength struct {
	bits  float64
	label string
	level int
}

func (m *AppModel) generatorStrength() strength {
	p := m.Prefs.Get()
	var bits float64
	if p.GeneratorMode == "passphrase" {
		bits = gen.PassphraseBits(p.PassphraseOpts)
	} else {
		pool := 0
		o := p.PasswordOpts
		if o.Uppercase {
			pool += 26
		}
		if o.Lowercase {
			pool += 26
		}
		if o.Numbers {
			pool += 10
		}
		if o.Special {
			pool += 8
		}
		if o.AvoidAmbiguous && pool > 5 {
			pool -= 5
		}
		if pool > 1 {
			bits = float64(o.Length) * math.Log2(float64(pool))
		}
	}
	switch {
	case bits < 45:
		return strength{bits, m.T("generator.strength.weak"), 1}
	case bits < 64:
		return strength{bits, m.T("generator.strength.fair"), 2}
	case bits < 90:
		return strength{bits, m.T("generator.strength.strong"), 3}
	default:
		return strength{bits, m.T("generator.strength.very_strong"), 4}
	}
}

func generatorOutput(cx *core.Scope, m *AppModel) core.Node {
	levelColor := func(level int) string {
		switch level {
		case 1:
			return "bg-gv-danger"
		case 2:
			return "bg-gv-warn"
		default:
			return "bg-gv-success"
		}
	}
	segments := make([]core.Node, 4)
	for i := range segments {
		idx := i + 1
		segments[i] = core.View{
			ClassFunc: func() string {
				s := m.generatorStrength()
				if idx <= s.level {
					return "flex-1 h-[4px] rounded-full " + levelColor(s.level)
				}
				return "flex-1 h-[4px] rounded-full bg-gv-fill-strong"
			},
		}
	}
	return card(core.View{
		Class: "px-6 pt-7 pb-5 gap-5",
		Children: []core.Node{
			core.View{
				Class: "min-h-[56px] items-center justify-center",
				Children: []core.Node{
					core.Text{
						TestID:     "generator-output",
						Class:      "text-[20px] font-mono font-medium text-gv-fg text-center leading-[28px]",
						Selectable: core.SelectableOn,
						SpansFunc:  func() []core.Span { return passwordSpans(m.GenResult.Get()) },
					},
				},
			},
			core.View{
				Class: "gap-2",
				Children: []core.Node{
					core.View{Class: "flex-row gap-1", Children: segments},
					core.View{
						Class: "flex-row items-center justify-between",
						Children: []core.Node{
							core.Text{
								Class:       "text-[12px] font-semibold text-gv-fg",
								ContentFunc: func() string { return m.generatorStrength().label },
							},
							core.Text{
								Class: "text-[11.5px] text-gv-fg3 tabular-nums",
								ContentFunc: func() string {
									return m.Tf("generator.entropy_bits", int(math.Round(m.generatorStrength().bits)))
								},
							},
						},
					},
				},
			},
			core.View{
				Class: "flex-row gap-2",
				Children: []core.Node{
					ui.Button{
						TestID:  "generator-regenerate",
						Text:    m.T("generator.regenerate"),
						Icon:    lucide.RefreshCw,
						Variant: ui.ButtonSecondary,
						Flex:    1,
						OnPress: m.RegenerateSecret,
					},
					ui.Button{
						TestID:  "generator-copy",
						Text:    m.T("common.copy"),
						Icon:    lucide.Copy,
						Variant: ui.ButtonPrimary,
						Flex:    1,
						OnPress: func() { m.CopySecretValue(m.T("generator.generated_secret"), m.GenResult.Get()) },
					},
				},
			},
		},
	})
}

func optionRow(title, desc string, control core.Node) core.Node {
	text := []core.Node{core.Text{Class: "text-[13px] text-gv-fg", Content: title}}
	if desc != "" {
		text = append(text, core.Text{Class: "text-[11.5px] text-gv-fg3", Content: desc})
	}
	return core.View{
		Class: "flex-row items-center gap-4 px-4 py-2.5 min-h-[46px]",
		Children: []core.Node{
			core.View{Class: "flex-1 gap-[2px]", Children: text},
			control,
		},
	}
}

func sliderRow(title string, value func() int, lo, hi int, onChange func(int)) core.Node {
	return core.View{
		Class: "flex-row items-center gap-4 px-4 py-3 min-h-[50px]",
		Children: []core.Node{
			core.Text{Class: "w-[84px] text-[13px] text-gv-fg", Content: title},
			ui.Slider{
				Label: title,
				Min:   float64(lo),
				Max:   float64(hi),
				Step:  1,
				Value: func() float64 { return float64(value()) },
				OnChange: func(v float64) {
					if n := int(math.Round(v)); n != value() {
						onChange(n)
					}
				},
				Style: core.Style{FlexGrow: 1, FlexShrink: 1},
			},
			core.View{
				Class: "w-[40px] h-[24px] rounded-[6px] items-center justify-center bg-gv-fill",
				Children: []core.Node{
					core.Text{
						Class:       "text-[12.5px] font-semibold text-gv-fg tabular-nums",
						ContentFunc: func() string { return fmt.Sprintf("%d", value()) },
					},
				},
			},
		},
	}
}

func passwordOptionsView(m *AppModel) core.Node {
	toggle := func(testID, title, desc string, get func(p UserPrefs) bool, set func(p *UserPrefs, v bool)) core.Node {
		return optionRow(title, desc, ui.Switch{
			TestID:  testID,
			Label:   title,
			Checked: func() bool { return get(m.Prefs.Get()) },
			OnChange: func(v bool) {
				m.UpdatePrefs(func(p UserPrefs) UserPrefs { set(&p, v); return p })
				m.RegenerateSecret()
			},
		})
	}
	return core.View{
		Class: "gap-4",
		Children: []core.Node{
			card(sliderRow(m.T("generator.length"), func() int { return m.Prefs.Get().PasswordOpts.Length }, 8, 128, func(n int) {
				m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PasswordOpts.Length = n; return p })
				m.RegenerateSecret()
			})),
			section(m.T("generator.characters"), card(
				toggle("generator-upper", m.T("generator.uppercase"), "A–Z", func(p UserPrefs) bool { return p.PasswordOpts.Uppercase }, func(p *UserPrefs, v bool) { p.PasswordOpts.Uppercase = v }),
				toggle("generator-lower", m.T("generator.lowercase"), "a–z", func(p UserPrefs) bool { return p.PasswordOpts.Lowercase }, func(p *UserPrefs, v bool) { p.PasswordOpts.Lowercase = v }),
				toggle("generator-numbers", m.T("generator.numbers"), "0–9", func(p UserPrefs) bool { return p.PasswordOpts.Numbers }, func(p *UserPrefs, v bool) {
					p.PasswordOpts.Numbers = v
					if !v {
						p.PasswordOpts.MinNumbers = 0
					} else if p.PasswordOpts.MinNumbers == 0 {
						p.PasswordOpts.MinNumbers = 1
					}
				}),
				toggle("generator-special", m.T("generator.symbols"), "! @ # $ % ^ & *", func(p UserPrefs) bool { return p.PasswordOpts.Special }, func(p *UserPrefs, v bool) {
					p.PasswordOpts.Special = v
					if !v {
						p.PasswordOpts.MinSpecial = 0
					} else if p.PasswordOpts.MinSpecial == 0 {
						p.PasswordOpts.MinSpecial = 1
					}
				}),
				toggle("generator-ambiguous", m.T("generator.avoid_ambiguous"), m.T("generator.avoid_ambiguous_desc"), func(p UserPrefs) bool { return p.PasswordOpts.AvoidAmbiguous }, func(p *UserPrefs, v bool) { p.PasswordOpts.AvoidAmbiguous = v }),
			)),
		},
	}
}

func passphraseOptionsView(m *AppModel) core.Node {
	toggle := func(title, desc string, get func(p UserPrefs) bool, set func(p *UserPrefs, v bool)) core.Node {
		return optionRow(title, desc, ui.Switch{
			Label:   title,
			Checked: func() bool { return get(m.Prefs.Get()) },
			OnChange: func(v bool) {
				m.UpdatePrefs(func(p UserPrefs) UserPrefs { set(&p, v); return p })
				m.RegenerateSecret()
			},
		})
	}
	return core.View{
		Class: "gap-4",
		Children: []core.Node{
			card(sliderRow(m.T("generator.words"), func() int { return m.Prefs.Get().PassphraseOpts.NumWords }, 3, 12, func(n int) {
				m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PassphraseOpts.NumWords = n; return p })
				m.RegenerateSecret()
			})),
			section(m.T("generator.options"), card(
				optionRow(m.T("generator.word_separator"), m.T("generator.word_separator_desc"), sizedInput(base.Input{
					TestID:      "generator-separator",
					Placeholder: "-",
					Value:       func() string { return m.Prefs.Get().PassphraseOpts.Separator },
					OnChange: func(v string) {
						m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PassphraseOpts.Separator = v; return p })
						m.RegenerateSecret()
					},
					Style: core.Style{Width: core.Pt(64), TextAlign: core.TextAlignCenter},
				}, 28)),
				toggle(m.T("generator.capitalize_words"), m.T("generator.capitalize_words_desc"), func(p UserPrefs) bool { return p.PassphraseOpts.Capitalize }, func(p *UserPrefs, v bool) { p.PassphraseOpts.Capitalize = v }),
				toggle(m.T("generator.include_number"), m.T("generator.include_number_desc"), func(p UserPrefs) bool { return p.PassphraseOpts.IncludeNum }, func(p *UserPrefs, v bool) { p.PassphraseOpts.IncludeNum = v }),
			)),
		},
	}
}
