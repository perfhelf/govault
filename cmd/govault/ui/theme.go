package ui

import (
	"hash/fnv"
	"strings"
	"unicode"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
)

const (
	titleBarHeight core.Points = 52
)

var (
	accentLight = core.RGB(0x175ddc)
	accentDark  = core.RGB(0x4c8dff)
)

func GovaultTheme() *core.Theme {
	t := core.DefaultTheme()
	t.Radius = 8
	t.Mono = `"SF Mono", Menlo, monospace`

	light := map[string]core.Color{
		"gv-sidebar":     core.RGB(0xeeeef1),
		"gv-list":        core.RGB(0xffffff),
		"gv-canvas":      core.RGB(0xf5f5f7),
		"gv-card":        core.RGB(0xffffff),
		"gv-panel":       core.RGB(0xfbfbfc),
		"gv-line":        core.RGBA(0x000000, 0.09),
		"gv-line-soft":   core.RGBA(0x000000, 0.06),
		"gv-fg":          core.RGB(0x1d1d1f),
		"gv-fg2":         core.RGB(0x6e6e73),
		"gv-fg3":         core.RGB(0x9b9ba1),
		"gv-sel":         core.RGBA(0x000000, 0.075),
		"gv-accent":      accentLight,
		"gv-accent-soft": core.RGBA(0x175ddc, 0.10),
		"gv-fill":        core.RGBA(0x000000, 0.045),
		"gv-fill-strong": core.RGBA(0x000000, 0.075),
		"gv-digit":       core.RGB(0x175ddc),
		"gv-symbol":      core.RGB(0xc4420f),
		"gv-star":        core.RGB(0xf2a60c),
		"gv-danger":      core.RGB(0xd93025),
		"gv-success":     core.RGB(0x1e9e5a),
		"gv-warn":        core.RGB(0xb86e00),
		"gv-warn-soft":   core.RGBA(0xf2a60c, 0.14),
	}
	dark := map[string]core.Color{
		"gv-sidebar":     core.RGB(0x242427),
		"gv-list":        core.RGB(0x1c1c1e),
		"gv-canvas":      core.RGB(0x161618),
		"gv-card":        core.RGB(0x212124),
		"gv-panel":       core.RGB(0x1f1f22),
		"gv-line":        core.RGBA(0xffffff, 0.085),
		"gv-line-soft":   core.RGBA(0xffffff, 0.06),
		"gv-fg":          core.RGB(0xf2f2f4),
		"gv-fg2":         core.RGB(0xa1a1a8),
		"gv-fg3":         core.RGB(0x6f6f77),
		"gv-sel":         core.RGBA(0xffffff, 0.09),
		"gv-accent":      accentDark,
		"gv-accent-soft": core.RGBA(0x4c8dff, 0.17),
		"gv-fill":        core.RGBA(0xffffff, 0.06),
		"gv-fill-strong": core.RGBA(0xffffff, 0.10),
		"gv-digit":       core.RGB(0x74abff),
		"gv-symbol":      core.RGB(0xff9f5a),
		"gv-star":        core.RGB(0xffc23d),
		"gv-danger":      core.RGB(0xff6b5e),
		"gv-success":     core.RGB(0x3ccf82),
		"gv-warn":        core.RGB(0xffb547),
		"gv-warn-soft":   core.RGBA(0xffb547, 0.14),
	}
	for name, c := range light {
		t.Light.SetColor(name, c)
	}
	for name, c := range dark {
		t.Dark.SetColor(name, c)
	}

	t.Light.Background, t.Light.Surface = light["gv-list"], light["gv-card"]
	t.Light.Text, t.Light.TextMuted, t.Light.Border = light["gv-fg"], light["gv-fg2"], light["gv-line"]
	t.Light.Accent, t.Light.AccentHover, t.Light.AccentPressed = accentLight, core.RGB(0x1452c4), core.RGB(0x1046ab)
	t.Light.Selection, t.Light.Focus = core.RGBA(0x175ddc, 0.22), core.RGBA(0x175ddc, 0.5)
	t.Light.Danger, t.Light.Success, t.Light.Warning = light["gv-danger"], light["gv-success"], light["gv-warn"]
	t.Light.SetColor("accentFill", accentLight)
	t.Light.SetColor("field", core.RGB(0xffffff))
	t.Light.SetColor("fieldBorder", core.RGBA(0x000000, 0.14))
	t.Light.SetColor("inset", core.RGB(0xf0f0f3))
	t.Light.SetColor("line", light["gv-line"])

	t.Dark.Background, t.Dark.Surface = dark["gv-list"], dark["gv-card"]
	t.Dark.Text, t.Dark.TextMuted, t.Dark.Border = dark["gv-fg"], dark["gv-fg2"], dark["gv-line"]
	t.Dark.Accent, t.Dark.AccentHover, t.Dark.AccentPressed = accentDark, core.RGB(0x66a0ff), core.RGB(0x3b7cf0)
	t.Dark.Selection, t.Dark.Focus = core.RGBA(0x4c8dff, 0.28), core.RGBA(0x4c8dff, 0.65)
	t.Dark.Danger, t.Dark.Success, t.Dark.Warning = dark["gv-danger"], dark["gv-success"], dark["gv-warn"]
	t.Dark.SetColor("accentFill", accentDark)
	t.Dark.SetColor("field", core.RGB(0x2a2a2e))
	t.Dark.SetColor("fieldBorder", core.RGBA(0xffffff, 0.12))
	t.Dark.SetColor("inset", core.RGB(0x2a2a2e))
	t.Dark.SetColor("line", dark["gv-line"])
	return t
}

func themeColor(cx *core.Scope, name string) core.Color {
	return cx.Palette().Colors[name]
}

func dragRegion() core.DesktopViewProps {
	return core.DesktopViewProps{WindowDrag: core.WindowDragOn}
}

func icon(svg *core.SVG, size core.Points, class string) core.Node {
	return core.Icon{SVG: svg, Class: class, Style: core.Style{Width: core.Pt(size), Height: core.Pt(size)}}
}

func iconFunc(svg func() *core.SVG, size core.Points, classFunc func() string) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		return core.Icon{SVG: svg(), Class: classFunc(), Style: core.Style{Width: core.Pt(size), Height: core.Pt(size)}}
	})
}

var filledStar = core.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53.53 0 0 1-.771.56l-4.618-2.428a2.122 2.122 0 0 0-1.973 0L6.396 21.01a.53.53 0 0 1-.77-.56l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2.122 2.122 0 0 0 1.597-1.16z"/></svg>`))

func FilledStar() *core.SVG { return filledStar }

var shieldMark = core.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.6 4.6 5.4v5.8c0 4.7 3.1 8.6 7.4 10.2 4.3-1.6 7.4-5.5 7.4-10.2V5.4z" fill="currentColor" fill-opacity="0.18"/><circle cx="12" cy="10.6" r="2.3"/><path d="M12 12.9v3.4"/></svg>`))

func ShieldMark() *core.SVG { return shieldMark }

// brandEmblem renders the app's mark on a deep-blue squircle.
func brandEmblem(size core.Points) core.Node {
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
			core.Icon{SVG: shieldMark, Style: core.Style{Width: core.Pt(size * 0.56), Height: core.Pt(size * 0.56), Color: core.RGB(0xffffff)}},
		},
	}
}

type emblemPalette struct{ top, bottom uint32 }

var emblemPalettes = []emblemPalette{
	{0x4f8bff, 0x1f5fd6},
	{0x7a7cff, 0x4b44d6},
	{0xa77bff, 0x7440dd},
	{0xf26daa, 0xc93a7c},
	{0xff7a6b, 0xd9433a},
	{0xffa24d, 0xe0711b},
	{0x35c98a, 0x16955c},
	{0x2cc4c4, 0x128b9a},
	{0x6b8aa8, 0x3f5873},
}

var brandPalettes = map[string]emblemPalette{
	"github":     {0x3a4048, 0x171b21},
	"aws":        {0xffad33, 0xec7a00},
	"amazon":     {0xffad33, 0xec7a00},
	"cloudflare": {0xffa047, 0xf06d14},
	"stripe":     {0x8a82ff, 0x5a4fe8},
	"apple":      {0x7a7a80, 0x2c2c30},
	"google":     {0x5c9aff, 0x2a6ee8},
	"netflix":    {0xf2434d, 0xb8121d},
	"figma":      {0xb07cff, 0x7a3fe6},
	"linear":     {0x7b86f0, 0x4e59c9},
	"dropbox":    {0x4b8dff, 0x0b5be0},
	"visa":       {0x2f5fd0, 0x14307f},
	"amex":       {0x3aa6dd, 0x1771a8},
	"mastercard": {0xff8a3d, 0xe0471f},
}

func paletteFor(name string, t api.CipherType, brand string) emblemPalette {
	key := strings.ToLower(name + " " + brand)
	for b, p := range brandPalettes {
		if strings.Contains(key, b) {
			return p
		}
	}
	switch t {
	case api.CipherTypeCard:
		return emblemPalette{0x35c98a, 0x16955c}
	case api.CipherTypeIdentity:
		return emblemPalette{0xa77bff, 0x7440dd}
	case api.CipherTypeSecureNote:
		return emblemPalette{0xffc145, 0xe69400}
	case api.CipherTypeSSHKey:
		return emblemPalette{0x7d8a9c, 0x4a5568}
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(name)))
	return emblemPalettes[h.Sum32()%uint32(len(emblemPalettes))]
}

func monogram(name string) string {
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return strings.ToUpper(string(r))
		}
	}
	return "•"
}

func typeGlyph(t api.CipherType) func() *core.SVG {
	switch t {
	case api.CipherTypeCard:
		return lucide.CreditCard
	case api.CipherTypeIdentity:
		return lucide.IdCard
	case api.CipherTypeSecureNote:
		return lucide.StickyNote
	case api.CipherTypeSSHKey:
		return lucide.KeyRound
	}
	return nil
}

// itemEmblem is the colored badge that identifies an item at a glance.
func itemEmblem(name string, t api.CipherType, brand string, size core.Points) core.Node {
	p := paletteFor(name, t, brand)
	var content core.Node
	if glyph := typeGlyph(t); glyph != nil {
		content = core.Icon{SVG: glyph(), Style: core.Style{Width: core.Pt(size * 0.52), Height: core.Pt(size * 0.52), Color: core.RGB(0xffffff)}}
	} else {
		content = core.Text{
			Content: monogram(name),
			Style: core.Style{
				FontSize: size * 0.46, FontWeight: core.FontWeightSemibold, Color: core.RGB(0xffffff),
				TextAlign: core.TextAlignCenter,
			},
		}
	}
	return core.View{
		Style: core.Style{
			Width: core.Pt(size), Height: core.Pt(size), FlexShrink: 0,
			CornerRadius: size * 0.26, BorderCurve: core.BorderCurveContinuous,
			AlignItems: core.AlignCenter, JustifyContent: core.JustifyCenter,
			Gradients: []core.Gradient{core.LinearGradient(180, core.RGB(p.top), core.RGB(p.bottom))},
			Shadows:   []core.BoxShadow{core.Ring(0.5, core.RGBA(0x000000, 0.10))},
		},
		Children: []core.Node{content},
	}
}

// iconTile is a sidebar glyph on a small colored squircle.
func iconTile(glyph func() *core.SVG, color uint32) core.Node {
	return core.View{
		Style: core.Style{
			Width: core.Pt(20), Height: core.Pt(20), FlexShrink: 0,
			CornerRadius: 5.5, BorderCurve: core.BorderCurveContinuous,
			AlignItems: core.AlignCenter, JustifyContent: core.JustifyCenter,
			Background: core.RGB(color),
		},
		Children: []core.Node{
			core.Icon{SVG: glyph(), Style: core.Style{Width: core.Pt(12), Height: core.Pt(12), Color: core.RGB(0xffffff)}},
		},
	}
}

func keycap(label string) core.Node {
	return core.View{
		Class: "h-[18px] min-w-[18px] px-[5px] rounded-[4px] items-center justify-center bg-gv-fill-strong border border-gv-line",
		Children: []core.Node{
			core.Text{Class: "text-[10.5px] font-semibold text-gv-fg2", Content: label},
		},
	}
}

func pill(glyph func() *core.SVG, label string) core.Node {
	children := []core.Node{}
	if glyph != nil {
		children = append(children, icon(glyph(), 11, "text-gv-fg2"))
	}
	children = append(children, core.Text{Class: "text-[11.5px] font-medium text-gv-fg2", Content: label})
	return core.View{
		Class:    "flex-row items-center gap-1 h-[20px] px-2 rounded-full bg-gv-fill",
		Children: children,
	}
}

func card(children ...core.Node) core.Node {
	var rows []core.Node
	for i, c := range children {
		if c == nil {
			continue
		}
		if len(rows) > 0 && i > 0 {
			rows = append(rows, core.View{Class: "h-px ms-4 bg-gv-line-soft"})
		}
		rows = append(rows, c)
	}
	return core.View{
		Class: "rounded-[10px] bg-gv-card border border-gv-line overflow-hidden",
		Style: core.Style{
			BorderCurve: core.BorderCurveContinuous,
			Shadows:     []core.BoxShadow{ui.Shadow(0, 1, 2, 0, core.RGBA(0x000000, 0.04))},
		},
		Children: rows,
	}
}

func section(title string, body core.Node) core.Node {
	if title == "" {
		return body
	}
	return core.View{
		Class: "gap-1.5",
		Children: []core.Node{
			core.Text{Class: "px-1 text-[11.5px] font-semibold text-gv-fg2", Content: title},
			body,
		},
	}
}

func passwordSpans(secret string) []core.Span {
	var spans []core.Span
	var buf strings.Builder
	cls := ""
	flush := func() {
		if buf.Len() > 0 {
			spans = append(spans, core.Span{Content: buf.String(), Class: cls})
			buf.Reset()
		}
	}
	for _, r := range secret {
		next := ""
		switch {
		case unicode.IsDigit(r):
			next = "text-gv-digit"
		case !unicode.IsLetter(r):
			next = "text-gv-symbol"
		}
		if next != cls {
			flush()
			cls = next
		}
		buf.WriteRune(r)
	}
	flush()
	return spans
}

func maskedDots(n int) string {
	if n < 8 {
		n = 8
	}
	if n > 14 {
		n = 14
	}
	return strings.Repeat("•", n)
}

func initials(email string) string {
	local := strings.SplitN(email, "@", 2)[0]
	parts := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' || r == '+' })
	out := ""
	for _, p := range parts {
		if p != "" {
			out += strings.ToUpper(string([]rune(p)[0]))
		}
		if len(out) == 2 {
			break
		}
	}
	if out == "" {
		return "?"
	}
	return out
}

func avatar(email func() string, size core.Points) core.Node {
	return core.View{
		Style: core.Style{
			Width: core.Pt(size), Height: core.Pt(size), FlexShrink: 0, CornerRadius: size / 2,
			AlignItems: core.AlignCenter, JustifyContent: core.JustifyCenter,
			Gradients: []core.Gradient{core.LinearGradient(160, core.RGB(0x8e9bb0), core.RGB(0x5b6678))},
		},
		Children: []core.Node{
			core.Text{
				ContentFunc: func() string { return initials(email()) },
				Style:       core.Style{FontSize: size * 0.4, FontWeight: core.FontWeightSemibold, Color: core.RGB(0xffffff)},
			},
		},
	}
}

func errorBanner(testID string, msg func() string) core.Node {
	return core.View{
		TestID: testID,
		Class:  "flex-row items-start gap-2 px-3 py-2 rounded-lg bg-gv-danger/10 border border-gv-danger/25",
		Children: []core.Node{
			icon(lucide.TriangleAlert(), 13, "text-gv-danger mt-[1px]"),
			core.Text{Class: "flex-1 text-[12px] text-gv-danger", ContentFunc: msg},
		},
	}
}
