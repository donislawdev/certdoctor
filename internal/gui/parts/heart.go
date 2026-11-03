package parts

import "fyne.io/fyne/v2"

// Heart is the picture in front of Donate. The toolkit ships no heart among
// its icons, and one from an icon set would bring that set's licence along,
// so it is drawn here: two circles of radius 5 centred at (7.5, 9) and
// (16.5, 9) meeting at the notch (12, 6.821), and the lines from the tip at
// (12, 21) touching them at (3.874, 12.443) and (20.126, 12.443). The same
// drawing the owner's other window uses, on the toolkit's 24 by 24 grid.
//
// The path has no colour of its own, so the button tints it with its ink
// like any icon. Not red: in this window red is FAIL, a fact about the
// machine, and a heart in that hue beside a report would read as one.
func Heart() fyne.Resource { return heart }

var heart = fyne.NewStaticResource("heart.svg", []byte(
	`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">`+
		`<path d="M12,21L3.874,12.443A5,5 0 1 1 12,6.821A5,5 0 1 1 20.126,12.443Z"/></svg>`))
