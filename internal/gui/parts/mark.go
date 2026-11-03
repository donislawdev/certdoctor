package parts

import (
	"fmt"
	"math"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// A status is told by its SHAPE before its colour (WCAG 1.4.1, and rule 20
// of this project): four silhouettes that differ at a glance - a circle, a
// triangle, an octagon and a rounded square - each with the glyph the
// terminal prints for that status cut into it. The glyph is drawn as a path,
// not set in a font, so it is the same in every typeface and never a box for
// a missing character.

// Mark is the filled shape of a status at a side of size.
func Mark(t look.Tone, size float32) fyne.CanvasObject {
	img := canvas.NewImageFromResource(markResource(t))
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSquareSize(size))
	return img
}

var markCache = map[string]fyne.Resource{}

func markResource(t look.Tone) fyne.Resource {
	fill := look.Hex(look.Colour(look.ToneRole(t)))
	cut := look.Hex(look.Colour(look.InkOnStatus))
	key := fmt.Sprintf("mark-%d-%s-%s.svg", t, fill, cut)
	if r, ok := markCache[key]; ok {
		return r
	}
	r := fyne.NewStaticResource(key, []byte(markSVG(t, fill, cut)))
	markCache[key] = r
	return r
}

// markSVG draws on a 20 by 20 grid. Every glyph stroke is 2.2 wide with
// round ends, which at the inline size of 14 is a line of about 1.5 px.
func markSVG(t look.Tone, fill, cut string) string {
	var shape, glyph string
	stroke := fmt.Sprintf(`fill="none" stroke="%s" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"`, cut)
	switch t {
	case look.TonePass:
		shape = fmt.Sprintf(`<circle cx="10" cy="10" r="9.2" fill="%s"/>`, fill)
		glyph = fmt.Sprintf(`<path d="M5.8 10.4 L8.7 13.2 L14.3 7.2" %s/>`, stroke)
	case look.ToneWarn:
		shape = fmt.Sprintf(`<path d="M10 2.4 L18.6 17.2 L1.4 17.2 Z" fill="%s" stroke="%s" stroke-width="1.6" stroke-linejoin="round"/>`, fill, fill)
		glyph = fmt.Sprintf(`<path d="M10 7.6 L10 11.6" %s/><circle cx="10" cy="14.4" r="1.25" fill="%s"/>`, stroke, cut)
	case look.ToneFail:
		shape = fmt.Sprintf(`<path d="%s" fill="%s" stroke="%s" stroke-width="1.2" stroke-linejoin="round"/>`, octagon(10, 10, 9.4), fill, fill)
		glyph = fmt.Sprintf(`<path d="M7 7 L13 13 M13 7 L7 13" %s/>`, stroke)
	case look.ToneUnknown:
		shape = fmt.Sprintf(`<rect x="1.4" y="1.4" width="17.2" height="17.2" rx="4.4" fill="%s"/>`, fill)
		glyph = fmt.Sprintf(`<path d="M7.5 7.7 C7.5 6.2 8.6 5.2 10 5.2 C11.5 5.2 12.5 6.2 12.5 7.6 C12.5 9.4 10 9.6 10 11.6" %s/><circle cx="10" cy="14.6" r="1.25" fill="%s"/>`, stroke, cut)
	default:
		shape = fmt.Sprintf(`<circle cx="10" cy="10" r="4" fill="%s"/>`, fill)
	}
	return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 20 20">` + shape + glyph + `</svg>`
}

// octagon is the path of a regular octagon with flat top and bottom.
func octagon(cx, cy, r float64) string {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		a := (22.5 + 45*float64(i)) * math.Pi / 180
		cmd := "L"
		if i == 0 {
			cmd = "M"
		}
		fmt.Fprintf(&b, "%s%.2f %.2f ", cmd, cx+r*math.Cos(a), cy+r*math.Sin(a))
	}
	b.WriteString("Z")
	return b.String()
}
