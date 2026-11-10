package look

import (
	"image/color"
	"math"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
)

// TestContrastIsTheWCAGRatio checks the measure every pair of colours in the
// window is held to against the two values WCAG defines it by: black on white
// is 21, a colour on itself is 1, and the order of the two does not matter.
func TestContrastIsTheWCAGRatio(t *testing.T) {
	black, white := hex(0, 0, 0), hex(0xff, 0xff, 0xff)
	if got := Contrast(black, white); math.Abs(got-21) > 1e-9 {
		t.Errorf("black on white is %.4f, want 21", got)
	}
	if got := Contrast(white, black); math.Abs(got-21) > 1e-9 {
		t.Errorf("white on black is %.4f, want 21", got)
	}
	if got := Contrast(Colour(Accent), Colour(Accent)); got != 1 {
		t.Errorf("a colour on itself is %.4f, want 1", got)
	}
	// The value written in ADR122 for the white words on the main action.
	if got := Contrast(Colour(OnAccent), Colour(Accent)); math.Abs(got-4.73) > 0.01 {
		t.Errorf("white on the accent is %.2f, and ADR122 records 4.73", got)
	}
}

// TestABadgeIsATintAndNotTheHue holds the fill and the edge of a status badge
// between the surface and the hue, and a neutral badge on the palette's own
// colours.
func TestABadgeIsATintAndNotTheHue(t *testing.T) {
	for _, tone := range []Tone{TonePass, ToneWarn, ToneFail, ToneUnknown} {
		hue := Colour(ToneRole(tone))
		fill, edge := Tint(tone, Surface), TintEdge(tone, Surface)
		if fill == hue || edge == hue || fill == edge {
			t.Errorf("tone %d: fill %s, edge %s, hue %s", tone, Hex(fill), Hex(edge), Hex(hue))
		}
	}
	if Tint(ToneNeutral, Surface) != Colour(Raised) || TintEdge(ToneNeutral, Surface) != Colour(EdgeCard) {
		t.Error("a neutral badge is not drawn in the palette's own colours")
	}
	if ToneRole(ToneNeutral) != InkMuted {
		t.Error("the neutral tone has a hue")
	}
	if Blend(Colour(Page), Colour(Ink), 0) != Colour(Page) || Blend(Colour(Page), Colour(Ink), 1) != Colour(Ink) {
		t.Error("a blend at the two ends is not the two colours")
	}
}

// TestARoleWithNoColourCannotPassForAChoice - a role nobody gave a colour is
// drawn magenta and is not known.
func TestARoleWithNoColourCannotPassForAChoice(t *testing.T) {
	const nobody Role = "nobody"
	if Known(nobody) || Colour(nobody) != hex(0xff, 0, 0xff) {
		t.Fatal("a role without a colour got one")
	}
	if got := Hex(Colour(Accent)); got != "#3570d6" {
		t.Errorf("the accent is written %s, want #3570d6", got)
	}
}

// TestTheThemeAnswersFromThisPackage asks the theme what the toolkit asks it
// and expects the palette's colours, the scale's sizes and Inter.
func TestTheThemeAnswersFromThisPackage(t *testing.T) {
	// The toolkit's own theme, which answers what this one leaves to it,
	// asks the running application for its settings.
	test.NewTempApp(t)
	th := Theme()
	for name, want := range map[fyne.ThemeColorName]color.Color{
		theme.ColorNameBackground:  Colour(Page),
		theme.ColorNameForeground:  Colour(Ink),
		theme.ColorNamePrimary:     Colour(Focus),
		theme.ColorNameError:       Colour(StatusFail),
		fyne.ThemeColorName(Ink):   Colour(Ink),
		theme.ColorNameButton:      Colour(Raised),
		theme.ColorNameSeparator:   Colour(Divider),
		theme.ColorNameInputBorder: Colour(EdgeControl),
	} {
		if got := th.Color(name, theme.VariantLight); !same(got, want) {
			t.Errorf("%s is %v, want %v", name, got, want)
		}
	}
	for _, name := range []fyne.ThemeColorName{
		theme.ColorNamePlaceHolder, theme.ColorNameDisabled, theme.ColorNameInputBackground,
		theme.ColorNameFocus, theme.ColorNameHover, theme.ColorNamePressed, theme.ColorNameSelection,
		theme.ColorNameScrollBar, theme.ColorNameScrollBarBackground, theme.ColorNameShadow,
		theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground, theme.ColorNameHeaderBackground,
		theme.ColorNameDisabledButton, theme.ColorNameSuccess, theme.ColorNameWarning,
		theme.ColorNameHyperlink, theme.ColorNameForegroundOnPrimary, theme.ColorNameForegroundOnError,
		theme.ColorNameHeaderBackground, "not.a.name",
	} {
		if th.Color(name, theme.VariantDark) == nil {
			t.Errorf("%s has no colour", name)
		}
	}
	for name, want := range map[fyne.ThemeSizeName]float32{
		theme.SizeNamePadding: ThemePadding, theme.SizeNameInnerPadding: ThemeInnerPadding,
		theme.SizeNameText: TextBody, theme.SizeNameHeadingText: TextTitle,
		theme.SizeNameSubHeadingText: TextHeading, theme.SizeNameCaptionText: TextCaption,
		SizeLead: TextLead, SizeMono: TextMono, theme.SizeNameInputBorder: Hairline,
		theme.SizeNameInputRadius: RadiusControl, theme.SizeNameInlineIcon: IconControl,
	} {
		if got := th.Size(name); got != want {
			t.Errorf("%s is %v, want %v", name, got, want)
		}
	}
	if th.Size(theme.SizeNameScrollBar) <= 0 {
		t.Error("a size the window does not set is not passed to the toolkit")
	}
	if th.Font(fyne.TextStyle{}) != interRegular || th.Font(fyne.TextStyle{Bold: true}) != interBold {
		t.Error("the words of the window are not set in Inter")
	}
	if th.Font(fyne.TextStyle{Monospace: true}) == interRegular {
		t.Error("code is set in Inter rather than the toolkit's monospaced face")
	}
	if th.Icon(theme.IconNameSearch) == nil {
		t.Error("the toolkit's icons do not come through")
	}
}

// TestWhatTheToolkitWritesOnItsOwnFacesCanBeRead holds the pairs the toolkit
// itself puts one over the other to the ratio for words, asked of the theme
// the way the toolkit asks. Its dialogs are drawn by none of the window's
// parts, so the pairs the catalogue measures do not reach them: the folder
// dialog's main button stood in white on light blue, at 2.1, until it was
// looked at on a screen.
func TestWhatTheToolkitWritesOnItsOwnFacesCanBeRead(t *testing.T) {
	test.NewTempApp(t)
	th := Theme()
	for _, p := range [][2]fyne.ThemeColorName{
		// The main, the destructive, the confirming and the warning button
		// (fyne v2.8.2, widget/button.go).
		{theme.ColorNameForegroundOnPrimary, theme.ColorNamePrimary},
		{theme.ColorNameForegroundOnError, theme.ColorNameError},
		{theme.ColorNameForegroundOnSuccess, theme.ColorNameSuccess},
		{theme.ColorNameForegroundOnWarning, theme.ColorNameWarning},
		// Words on the window, on a plain button, on a dialog, on a menu, in
		// a box to type in, on the head of a list, and on a chosen entry.
		{theme.ColorNameForeground, theme.ColorNameBackground},
		{theme.ColorNameForeground, theme.ColorNameButton},
		{theme.ColorNameForeground, theme.ColorNameOverlayBackground},
		{theme.ColorNameForeground, theme.ColorNameMenuBackground},
		{theme.ColorNameForeground, theme.ColorNameInputBackground},
		{theme.ColorNameForeground, theme.ColorNameHeaderBackground},
		{theme.ColorNameForeground, theme.ColorNameSelection},
		{theme.ColorNamePlaceHolder, theme.ColorNameInputBackground},
	} {
		front := color.NRGBAModel.Convert(th.Color(p[0], theme.VariantDark)).(color.NRGBA)
		back := color.NRGBAModel.Convert(th.Color(p[1], theme.VariantDark)).(color.NRGBA)
		if got := Contrast(front, back); got < 4.5 {
			t.Errorf("%s on %s is %.2f, and words need 4.5", p[0], p[1], got)
		}
	}
}

func same(a, b color.Color) bool {
	ar, ag, ab, aa := a.RGBA()
	br, bg, bb, ba := b.RGBA()
	return ar == br && ag == bg && ab == bb && aa == ba
}
