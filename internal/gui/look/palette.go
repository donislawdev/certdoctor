package look

import (
	"image/color"
	"math"
)

// Role is the name of a colour by what it does. The same strings are the
// toolkit's colour names for the parts of the window that ask the theme by
// name (look/theme.go), so a rich text segment and a rectangle read one
// palette.
type Role string

// The ladder of surfaces, darkest at the bottom, and the edges on it.
const (
	Page    Role = "page"
	Sunken  Role = "sunken"
	Surface Role = "surface"
	Raised  Role = "raised"
	Hovered Role = "hovered"
	// EdgeCard is the outline of a card. Decorative: a card is told from the
	// page by its fill, so this line carries nothing that needs 3:1.
	EdgeCard Role = "edge.card"
	// EdgeControl is the outline of a box to type in, which IS how the box is
	// found, so it is held to 3:1 against what is round it.
	EdgeControl Role = "edge.control"
	Divider     Role = "divider"
)

// The inks.
const (
	Ink      Role = "ink"
	InkMuted Role = "ink.muted"
	InkFaint Role = "ink.faint"
	// InkDisabled is the word on a control that cannot be pressed. WCAG
	// exempts it from 4.5:1 and it is kept under it on purpose, so a disabled
	// button never reads as one that works.
	InkDisabled Role = "ink.disabled"
	// InkOnStatus is the glyph cut into a filled status mark.
	InkOnStatus Role = "ink.onstatus"
)

// The main action and the keyboard.
const (
	Accent        Role = "accent"
	AccentHovered Role = "accent.hovered"
	AccentPressed Role = "accent.pressed"
	OnAccent      Role = "accent.on"
	Focus         Role = "focus"
	Selection     Role = "selection"
	// Chosen is the bar beside the selected entry of a list.
	Chosen Role = "chosen"
)

// The four statuses. These hues carry a status and nothing else: no button,
// link or ring in the window is drawn in one of them.
const (
	StatusPass    Role = "status.pass"
	StatusWarn    Role = "status.warn"
	StatusFail    Role = "status.fail"
	StatusUnknown Role = "status.unknown"
)

// The surfaces and inks are the dark half of the HTML report's palette
// (internal/adapter/render/html.go, prefers-color-scheme: dark), so a report
// saved from the window and the window itself speak in one set of colours.
// The four status hues are that report's as they stand.
var common = map[Role]color.NRGBA{
	Page:        hex(0x16, 0x18, 0x1c),
	Sunken:      hex(0x11, 0x13, 0x17),
	Surface:     hex(0x1e, 0x21, 0x26),
	Raised:      hex(0x27, 0x2b, 0x32),
	Hovered:     hex(0x2e, 0x33, 0x3b),
	EdgeCard:    hex(0x2c, 0x31, 0x38),
	EdgeControl: hex(0x6b, 0x72, 0x80),
	Divider:     hex(0x2c, 0x31, 0x38),

	Ink:         hex(0xe6, 0xe8, 0xea),
	InkMuted:    hex(0xa0, 0xa6, 0xad),
	InkFaint:    hex(0x8f, 0x96, 0x9e),
	InkDisabled: hex(0x5f, 0x66, 0x6f),
	InkOnStatus: hex(0x16, 0x18, 0x1c),

	StatusPass:    hex(0x56, 0xd3, 0x64),
	StatusWarn:    hex(0xe3, 0xb3, 0x41),
	StatusFail:    hex(0xff, 0x8d, 0x8d),
	StatusUnknown: hex(0x7c, 0xb7, 0xff),

	// The main action is the blue of the shield in the program's icon -
	// decision of the owner against the recommendation of a light, neutral
	// face, because blue is also UNKNOWN (ADR122). Hovered and pressed go
	// darker, not lighter, so the white words stay above 4.5.
	Accent:        hex(0x35, 0x70, 0xd6),
	AccentHovered: hex(0x2f, 0x66, 0xc6),
	AccentPressed: hex(0x2a, 0x5b, 0xb2),
	OnAccent:      hex(0xff, 0xff, 0xff),
	Focus:         hex(0x8a, 0xb4, 0xf8),
	Selection:     hex(0x24, 0x3f, 0x6b),
	Chosen:        hex(0x5b, 0x93, 0xf0),
}

// Colour answers a role with the colour it is drawn in.
func Colour(r Role) color.NRGBA {
	if c, ok := common[r]; ok {
		return c
	}
	// A role nobody gave a colour. Magenta, so it cannot pass for a choice.
	return hex(0xff, 0x00, 0xff)
}

// Known says whether a role has a colour. The theme asks it before it
// answers a toolkit name that might be one of ours.
func Known(r Role) bool {
	_, ok := common[r]
	return ok
}

// Tone is what a status does to the colours of the thing that shows it.
type Tone int

const (
	ToneNeutral Tone = iota
	TonePass
	ToneWarn
	ToneFail
	ToneUnknown
)

// ToneRole is the hue of a tone.
func ToneRole(t Tone) Role {
	switch t {
	case TonePass:
		return StatusPass
	case ToneWarn:
		return StatusWarn
	case ToneFail:
		return StatusFail
	case ToneUnknown:
		return StatusUnknown
	}
	return InkMuted
}

// The share of a status hue in the fill and in the edge of a badge, over the
// surface it stands on. The fill is a tint and not the hue itself, so a
// column of red badges is a column of red words and not a red block - a
// filled red shape is a louder claim than the same word, and loudness is part
// of what a status says (docs/26 section 7.3).
const (
	tintShare = 0.14
	edgeShare = 0.42
)

// Tint is the fill of a badge of this tone over a surface.
func Tint(t Tone, over Role) color.NRGBA {
	if t == ToneNeutral {
		return Colour(Raised)
	}
	return Blend(Colour(over), Colour(ToneRole(t)), tintShare)
}

// TintEdge is the edge of a badge of this tone over a surface.
func TintEdge(t Tone, over Role) color.NRGBA {
	if t == ToneNeutral {
		return Colour(EdgeCard)
	}
	return Blend(Colour(over), Colour(ToneRole(t)), edgeShare)
}

// Blend paints over on under at the given share, the way a translucent fill
// lands on the screen.
func Blend(under, over color.NRGBA, share float64) color.NRGBA {
	mix := func(u, o uint8) uint8 {
		return uint8(math.Round(float64(o)*share + float64(u)*(1-share)))
	}
	return color.NRGBA{R: mix(under.R, over.R), G: mix(under.G, over.G), B: mix(under.B, over.B), A: 0xff}
}

// Contrast is the WCAG ratio between two colours, from 1 to 21 - 4.5 for
// anything read, 3.0 for anything that carries state or marks a control.
func Contrast(one, two color.NRGBA) float64 {
	a, b := luminance(one), luminance(two)
	if a < b {
		a, b = b, a
	}
	return (a + 0.05) / (b + 0.05)
}

func luminance(c color.NRGBA) float64 {
	straight := func(v uint8) float64 {
		f := float64(v) / 255
		if f <= 0.04045 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	return 0.2126*straight(c.R) + 0.7152*straight(c.G) + 0.0722*straight(c.B)
}

// Hex writes a colour the way a person compares it with another tool.
func Hex(c color.NRGBA) string {
	const digits = "0123456789abcdef"
	out := []byte{'#', 0, 0, 0, 0, 0, 0}
	for i, v := range []uint8{c.R, c.G, c.B} {
		out[1+2*i] = digits[v>>4]
		out[2+2*i] = digits[v&0x0f]
	}
	return string(out)
}

func hex(r, g, b uint8) color.NRGBA { return color.NRGBA{R: r, G: g, B: b, A: 0xff} }
