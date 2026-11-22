package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
)

func TwoFactorView(cx *core.Scope, m *AppModel, prompt *TwoFactorPrompt) core.Node {
	emailSelected := func() bool { return m.TwoFactorProvider.Get() == api.TwoFactorEmail }
	busy := m.LoginBusy.Get

	body := []core.Node{
		core.View{
			Class: "items-center gap-2.5 pb-1",
			Children: []core.Node{
				twoFactorEmblem(),
				core.Text{Class: "mt-1.5 text-[19px] font-semibold text-gv-fg", Content: m.T("twofactor.title")},
				core.Text{
					Class: "text-[12.5px] text-gv-fg2 text-center",
					ContentFunc: func() string {
						if emailSelected() {
							if prompt.EmailHint != "" {
								return m.Tf("twofactor.subtitle.email_hint", prompt.EmailHint)
							}
							return m.T("twofactor.subtitle.email")
						}
						return m.T("twofactor.subtitle.authenticator")
					},
				},
			},
		},
	}

	if prompt.Has(api.TwoFactorAuthenticator) && prompt.Has(api.TwoFactorEmail) {
		body = append(body, core.View{
			Class: "items-center",
			Children: []core.Node{
				ui.ToggleGroup{
					TestID:   "twofactor-providers",
					Label:    m.T("twofactor.method_label"),
					Disabled: busy,
					Children: []core.Node{
						providerToggle(m, "twofactor-provider-authenticator", api.TwoFactorAuthenticator, lucide.Smartphone),
						providerToggle(m, "twofactor-provider-email", api.TwoFactorEmail, lucide.Mail),
					},
				},
			},
		})
	}

	body = append(body,
		core.View{
			Class: "gap-3",
			Children: []core.Node{
				formField(m.T("common.verification_code"), authInput(base.Input{
					TestID:        "twofactor-code",
					Class:         "font-mono",
					Placeholder:   "123456",
					NoAutoCorrect: true,
					AutoFocus:     true,
					MaxLength:     12,
					Value:         m.TwoFactorCode.Get,
					OnChange:      m.TwoFactorCode.Set,
					OnSubmit:      func(string) { m.VerifyTwoFactor() },
					Disabled:      busy,
					Style:         core.Style{FontSize: 15, LetterSpacing: 2},
				})),
				core.Show{
					When: emailSelected,
					Then: func(cx *core.Scope) core.Node { return emailCodeRow(m) },
				},
				ui.Checkbox{
					TestID:   "twofactor-remember",
					Text:     m.T("twofactor.remember_device"),
					Checked:  m.TwoFactorRemember.Get,
					OnChange: m.TwoFactorRemember.Set,
					Disabled: busy,
				},
			},
		},
		core.Show{
			When: func() bool { return m.LoginError.Get() != "" },
			Then: func(cx *core.Scope) core.Node { return errorBanner("twofactor-error", m.LoginError.Get) },
		},
		core.View{
			Class: "gap-2",
			Children: []core.Node{
				ui.Button{
					TestID:  "twofactor-verify",
					Text:    m.T("common.verify"),
					Variant: ui.ButtonPrimary,
					Size:    ui.SizeLarge,
					Busy:    busy,
					Style:   core.Style{Width: core.Pct(100)},
					OnPress: m.VerifyTwoFactor,
				},
				ui.Button{
					TestID:   "twofactor-back",
					Text:     m.T("twofactor.back_to_sign_in"),
					Variant:  ui.ButtonGhost,
					Disabled: busy,
					Style:    core.Style{Width: core.Pct(100)},
					OnPress:  m.CancelTwoFactor,
				},
			},
		},
	)
	return authScreen("twofactor-screen", body, m.T("twofactor.footnote"))
}

func providerToggle(m *AppModel, testID string, p api.TwoFactorProvider, glyph func() *core.SVG) core.Node {
	return ui.ToggleButton{
		TestID:   testID,
		Text:     m.twoFactorProviderLabel(p),
		Icon:     glyph,
		On:       func() bool { return m.TwoFactorProvider.Get() == p },
		OnChange: func(bool) { m.SelectTwoFactorProvider(p) },
	}
}

func emailCodeRow(m *AppModel) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between gap-2",
		Children: []core.Node{
			core.Text{
				Class:       "flex-1 text-[11.5px] text-gv-fg2",
				ContentFunc: func() string { return m.TwoFactorNotice.Get() },
			},
			core.Dynamic(func(cx *core.Scope) core.Node {
				text := m.T("twofactor.send_code")
				if m.TwoFactorNotice.Get() != "" {
					text = m.T("twofactor.resend_code")
				}
				return ui.Button{
					TestID:   "twofactor-send-email",
					Text:     text,
					Variant:  ui.ButtonOutline,
					Icon:     lucide.Send,
					Busy:     m.TwoFactorSending.Get,
					Disabled: m.LoginBusy.Get,
					OnPress:  m.SendTwoFactorEmail,
				}
			}),
		},
	}
}

func twoFactorEmblem() core.Node {
	const size core.Points = 56
	return core.View{
		Style: core.Style{
			Width: core.Pt(size), Height: core.Pt(size),
			CornerRadius: size * 0.28, BorderCurve: core.BorderCurveContinuous,
			AlignItems: core.AlignCenter, JustifyContent: core.JustifyCenter,
			Gradients: []core.Gradient{core.LinearGradient(160, core.RGB(0x3f7dff), core.RGB(0x1748b8))},
			Shadows: []core.BoxShadow{
				ui.Shadow(0, size*0.12, size*0.36, -size*0.12, core.RGBA(0x1748b8, 0.55)),
				core.Ring(0.5, core.RGBA(0x000000, 0.08)),
			},
		},
		Children: []core.Node{
			core.Icon{SVG: lucide.ShieldCheck(), Style: core.Style{Width: core.Pt(size * 0.5), Height: core.Pt(size * 0.5), Color: core.RGB(0xffffff)}},
		},
	}
}
