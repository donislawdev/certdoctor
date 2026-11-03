package look

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"

	"github.com/donislawdev/certdoctor/internal/gui/fonts"
)

// Size names of our own, for the parts that ask the theme by name - a rich
// text segment does. The toolkit's own names cover title, heading, body and
// caption already.
const (
	SizeLead fyne.ThemeSizeName = "text.lead"
	SizeMono fyne.ThemeSizeName = "text.mono"
)

// The window is set in Inter 4.1 (ADR122). Code - a command, a path, a
// fingerprint - keeps the toolkit's monospaced face.
var (
	interRegular = fyne.NewStaticResource("look-Inter-Regular.ttf", fonts.Regular)
	interBold    = fyne.NewStaticResource("look-Inter-Bold.ttf", fonts.Bold)
)

type ours struct{ base fyne.Theme }

// Theme is the window's theme: dark only, every colour and size from this
// package.
func Theme() fyne.Theme { return ours{base: theme.DefaultTheme()} }

// toolkitRoles is the role each of the toolkit's own colour names is drawn
// in. A table rather than a switch, so a name the toolkit adds is one line.
var toolkitRoles = map[fyne.ThemeColorName]Role{
	theme.ColorNameBackground:      Page,
	theme.ColorNameForeground:      Ink,
	theme.ColorNamePlaceHolder:     InkFaint,
	theme.ColorNameDisabled:        InkDisabled,
	theme.ColorNameInputBackground: Sunken,
	theme.ColorNameInputBorder:     EdgeControl,
	// The toolkit draws a box's edge in this colour while it holds the
	// keyboard, and its caret.
	theme.ColorNamePrimary:             Focus,
	theme.ColorNameSelection:           Selection,
	theme.ColorNameSeparator:           Divider,
	theme.ColorNameMenuBackground:      Raised,
	theme.ColorNameOverlayBackground:   Raised,
	theme.ColorNameButton:              Raised,
	theme.ColorNameHeaderBackground:    Raised,
	theme.ColorNameDisabledButton:      Surface,
	theme.ColorNameError:               StatusFail,
	theme.ColorNameSuccess:             StatusPass,
	theme.ColorNameWarning:             StatusWarn,
	theme.ColorNameHyperlink:           Ink,
	theme.ColorNameForegroundOnPrimary: OnAccent,
	theme.ColorNameForegroundOnError:   InkOnStatus,
	theme.ColorNameForegroundOnSuccess: InkOnStatus,
	theme.ColorNameForegroundOnWarning: InkOnStatus,
}

// shade is a role seen through: the toolkit lays these over what is under
// them, so they are the role at a share of opacity.
type shade struct {
	role  Role
	alpha uint8
}

// toolkitShades is the toolkit's colour names drawn as a shade.
var toolkitShades = map[fyne.ThemeColorName]shade{
	theme.ColorNameFocus:     {Focus, 0x40},
	theme.ColorNameHover:     {Ink, 0x10},
	theme.ColorNamePressed:   {Ink, 0x1c},
	theme.ColorNameScrollBar: {Ink, 0x55},
}

func (o ours) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	if r := Role(name); Known(r) {
		return Colour(r)
	}
	if r, ok := toolkitRoles[name]; ok {
		return Colour(r)
	}
	if s, ok := toolkitShades[name]; ok {
		return translucent(Colour(s.role), s.alpha)
	}
	switch name {
	case theme.ColorNameScrollBarBackground:
		return color.Transparent
	case theme.ColorNameShadow:
		return translucent(color.NRGBA{A: 0xff}, 0x66)
	}
	return o.base.Color(name, theme.VariantDark)
}

func (o ours) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return ThemePadding
	case theme.SizeNameInnerPadding:
		return ThemeInnerPadding
	case theme.SizeNameText:
		return TextBody
	case theme.SizeNameHeadingText:
		return TextTitle
	case theme.SizeNameSubHeadingText:
		return TextHeading
	case theme.SizeNameCaptionText:
		return TextCaption
	case SizeLead:
		return TextLead
	case SizeMono:
		return TextMono
	case theme.SizeNameInputBorder, theme.SizeNameSeparatorThickness:
		return Hairline
	case theme.SizeNameInputRadius, theme.SizeNameSelectionRadius:
		return RadiusControl
	case theme.SizeNameInlineIcon:
		return IconControl
	}
	return o.base.Size(name)
}

func (o ours) Font(style fyne.TextStyle) fyne.Resource {
	if !style.Monospace && !style.Italic && !style.Symbol {
		if style.Bold {
			return interBold
		}
		return interRegular
	}
	return o.base.Font(style)
}

func (o ours) Icon(name fyne.ThemeIconName) fyne.Resource { return o.base.Icon(name) }

func translucent(c color.Color, alpha uint8) color.NRGBA {
	r, g, b, _ := c.RGBA()
	return color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: alpha}
}
