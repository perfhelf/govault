package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
)

const authFieldHeight core.Points = 34

func LoginView(cx *core.Scope, m *AppModel) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		if prompt := m.TwoFactor.Get(); prompt != nil {
			return TwoFactorView(cx, m, prompt)
		}
		return signInView(cx, m)
	})
}

func signInView(cx *core.Scope, m *AppModel) core.Node {
	return authScreen("login-screen", []core.Node{
		core.View{
			Class: "items-center gap-2.5 pb-1",
			Children: []core.Node{
				brandEmblem(56),
				core.Text{Class: "mt-1.5 text-[19px] font-semibold text-gv-fg", Content: m.T("login.title")},
				core.Text{
					Class:   "text-[12.5px] text-gv-fg2 text-center",
					Content: m.T("login.subtitle"),
				},
			},
		},
		core.View{
			Class: "gap-3.5",
			Children: []core.Node{
				formField(m.T("login.server_url"), authInput(base.Input{
					TestID:        "login-server",
					Placeholder:   "https://vault.example.com",
					NoAutoCorrect: true,
					Value:         m.LoginServer.Get,
					OnChange:      m.LoginServer.Set,
					Disabled:      func() bool { return m.LoginBusy.Get() || (m.CanReturnToUnlock() && m.ReSignInServer.Get() != "") },
				})),
				formField(m.T("login.email"), authInput(base.Input{
					TestID:        "login-email",
					Placeholder:   "name@example.com",
					NoAutoCorrect: true,
					Value:         m.LoginEmail.Get,
					OnChange:      m.LoginEmail.Set,
					Disabled:      func() bool { return m.LoginBusy.Get() || m.CanReturnToUnlock() },
				})),
				formField(m.T("common.master_password"), passwordField(cx, m, base.Input{
					TestID:        "login-password",
					Placeholder:   m.T("common.required"),
					NoAutoCorrect: true,
					Value:         m.LoginPassword.Get,
					OnChange:      m.LoginPassword.Set,
					OnSubmit:      func(string) { m.Login() },
					Disabled:      m.LoginBusy.Get,
				}, authFieldHeight, m.LoginShowPW, "login-toggle-pw")),
			},
		},
		core.Show{
			When: func() bool { return api.InsecureServer(m.LoginServer.Get()) },
			Then: func(cx *core.Scope) core.Node {
				return core.Text{
					TestID:  "login-insecure",
					Class:   "text-[12px] text-gv-warn",
					Content: m.T("login.insecure_warning"),
				}
			},
		},
		core.Show{
			When: func() bool { return m.LoginError.Get() != "" },
			Then: func(cx *core.Scope) core.Node { return errorBanner("login-error", m.LoginError.Get) },
		},
		ui.Button{
			TestID:  "login-submit",
			Text:    m.T("login.sign_in"),
			Variant: ui.ButtonPrimary,
			Size:    ui.SizeLarge,
			Busy:    m.LoginBusy.Get,
			Style:   core.Style{Width: core.Pct(100)},
			OnPress: m.Login,
		},
		core.Show{
			When: m.CanReturnToUnlock,
			Then: func(cx *core.Scope) core.Node {
				return ui.Button{
					TestID:  "login-back-to-unlock",
					Text:    m.T("login.back_to_unlock"),
					Variant: ui.ButtonGhost,
					Size:    ui.SizeLarge,
					Style:   core.Style{Width: core.Pct(100)},
					OnPress: m.BackToUnlock,
				}
			},
		},
	}, m.T("login.footnote"), languageSelect(cx, m, "login-language", 148))
}

func authScreen(testID string, body []core.Node, footnote string, topExtra ...core.Node) core.Node {
	children := []core.Node{
		core.View{Style: core.Style{Height: core.Pt(titleBarHeight)}, Desktop: dragRegion()},
		core.View{
			Class: "flex-1 items-center justify-center px-8 pb-[52px] gap-5",
			Children: []core.Node{
				core.View{
					Class: "w-[380px] px-8 pt-8 pb-7 gap-5 rounded-[16px] bg-gv-card border border-gv-line",
					Style: core.Style{
						BorderCurve: core.BorderCurveContinuous,
						Shadows: []core.BoxShadow{
							ui.Shadow(0, 1, 3, 0, core.RGBA(0x000000, 0.05)),
							ui.Shadow(0, 18, 40, -16, core.RGBA(0x000000, 0.22)),
						},
					},
					Children: body,
				},
				core.View{
					Class: "flex-row items-center gap-1.5",
					Children: []core.Node{
						icon(lucide.LockKeyhole(), 11, "text-gv-fg3"),
						core.Text{Class: "text-[11.5px] text-gv-fg3", Content: footnote},
					},
				},
			},
		},
	}
	if len(topExtra) > 0 {
		children = append(children, core.View{
			Class:    "absolute top-[56px] end-5 z-10",
			Children: topExtra,
		})
	}
	return core.View{
		TestID:   testID,
		Class:    "relative flex-1 bg-gv-canvas",
		Children: children,
	}
}

func formField(label string, field core.Node) core.Node {
	return core.View{
		Class: "gap-1.5",
		Children: []core.Node{
			core.Text{Class: "text-[12px] font-medium text-gv-fg2", Content: label},
			field,
		},
	}
}

func labeledField(label string, field core.Node) core.Node { return formField(label, field) }

func sizedInput(in base.Input, height core.Points) ui.Input {
	in.Style = core.Style{Height: core.Pt(height), FontSize: 13, CornerRadius: 7}.Merge(in.Style)
	return ui.Input(in)
}

func authInput(in base.Input) core.Node { return sizedInput(in, authFieldHeight) }

// passwordField is a masked input with a reveal toggle and optional trailing controls inside its rim.
func passwordField(cx *core.Scope, m *AppModel, in base.Input, height core.Points, show *core.Signal[bool], toggleTestID string, trailing ...core.Node) core.Node {
	inset := core.Points(34 + 28*len(trailing))
	controls := []core.Node{
		ui.Button{
			TestID:   toggleTestID,
			Variant:  ui.ButtonGhost,
			Icon:     func() *core.SVG { return eyeIcon(show.Get()) },
			Label:    m.T("common.toggle_password_visibility"),
			Side:     height - 8,
			IconSize: 14,
			Tint:     func() core.Color { return themeColor(cx, "gv-fg3") },
			Disabled: in.Disabled,
			OnPress:  func() { show.Set(!show.Get()) },
		},
	}
	controls = append(controls, trailing...)
	return core.View{
		Class: "relative",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				_ = m.Locale.Get()
				field := in
				field.Masked = !show.Get()
				field.OnBlur = settleSecureInput
				field.Style = core.Style{Padding: core.Edges{Left: 10, Right: inset}}.Merge(field.Style)
				return sizedInput(field, height)
			}),
			core.View{
				Class:    "absolute end-1 top-0 bottom-0 flex-row items-center gap-0.5",
				Children: controls,
			},
		},
	}
}

func eyeIcon(visible bool) *core.SVG {
	if visible {
		return lucide.EyeOff()
	}
	return lucide.Eye()
}
