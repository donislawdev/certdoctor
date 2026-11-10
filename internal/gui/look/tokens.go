// Package look holds every value that decides how the window looks: the
// scale of distances, the ladder of type, corners, strokes, the sizes of
// controls and of the window, and the palette. A view names a role and never
// a value, so a change of look is a change in this package and nowhere else.
package look

import "time"

// The scale of distances. Every gap in the window is one of these steps, and
// a distance that fits no role below gets a role here rather than a bare
// step at the call site.
const (
	step1 = 4
	step2 = 8
	step3 = 12
	step4 = 16
	step5 = 24
	step6 = 32
	step7 = 48
)

// Distances, named for what they separate. The steps are far enough apart to
// be told without counting: things that belong together sit one step apart,
// things that do not sit two.
const (
	// GapInline separates things on one line: a mark and its word, an icon
	// and its label.
	GapInline = step2
	// GapMark separates a status mark from the word beside it inside a
	// badge, where the pill already holds the two together.
	GapMark = step1 + 2
	// GapTight separates a line from the caption under it.
	GapTight = step1
	// GapRow separates two rows inside one card, and a card's head from its
	// body.
	GapRow = step3
	// GapField separates two fields of a form.
	GapField = step4
	// GapCard separates two cards.
	GapCard = step5
	// GapScreen separates a screen's title block from its first card.
	GapScreen = step6
	// GapButtons separates two buttons standing side by side.
	GapButtons = step3
	// InsetCard is the room a card keeps between its edge and its content.
	InsetCard = step5
	// InsetPage is the room between the window's edge and the cards.
	InsetPage = step6
	// InsetBar is the room the bars at the top and the foot keep round what
	// stands on them.
	InsetBar = step4
	// InsetControl is the room inside a button, left and right of its words.
	InsetControl = step4
	// InsetBadge is the room inside a status badge, left and right.
	InsetBadge = step2
	// InsetRow is the room above and below the words of a table row.
	InsetRow = step3
	// InsetCell is the room left and right of the words in a table cell.
	InsetCell = step3
	// ThemePadding is what the toolkit is told when a stock container asks
	// how far apart to put its children: the smallest step, so a stock
	// container lands on the scale rather than beside it.
	ThemePadding = step1
	// ThemeInnerPadding is the room the toolkit keeps inside a box to type in.
	ThemeInnerPadding = step2
	// FocusGap is the room between a control's face and the ring the
	// keyboard draws round it, so the ring reads on every face.
	FocusGap = 2
)

// The ladder of type: four sizes and the size of code, nothing between them.
const (
	// TextTitle is the one line that says what a screen is for.
	TextTitle = 22
	// TextHeading names a card, and TextLead is the verdict sentence - the
	// same size, because the verdict is read before anything else on the
	// screen and a heading is only a name.
	TextHeading = 16
	TextLead    = 16
	// TextBody is everything read at rest.
	TextBody = 14
	// TextCaption is a note under a line, a column's name, a badge's word.
	TextCaption = 12
	// TextMono is a command, a path, a fingerprint: text that is copied
	// rather than read. A step under the body, because a monospaced face sets
	// wider than a proportional one at the same size.
	TextMono = 13
)

// Corners.
const (
	RadiusControl = 6
	RadiusCard    = 10
)

// Strokes.
const (
	// Hairline is a line that separates and says nothing else.
	Hairline = 1
	// StrokeFocus is the ring round the control that holds the keyboard.
	// Twice a hairline, so the eye tells it from a resting edge by weight
	// before it reads the colour.
	StrokeFocus = 2
	// StrokeSelected is the bar beside the chosen item of a list.
	StrokeSelected = 3
	// StrokeVerdict is the bar of the status's hue down the verdict card.
	StrokeVerdict = 4
)

// Sizes of things that are not distances.
const (
	// ControlHeight is the height of a button and of a box to type in.
	ControlHeight = 36
	// BadgeHeight is the height of a status badge. Its corner is half of it.
	BadgeHeight = 22
	// MarkInline is the side of a status mark beside a word, MarkLarge the
	// side of the one beside the verdict.
	MarkInline = 14
	MarkRow    = 16
	MarkLarge  = 28
	// IconControl is the side of an icon inside a button.
	IconControl = 16
	// IconApp is the side of the program's icon in the bar at the top.
	IconApp = 28
	// RailWidth is how wide the list of layers on the report screen is.
	RailWidth = 264
	// RailItemHeight is how tall one entry of that list is.
	RailItemHeight = 52
	// PageWidth is as wide as the report gets on a large screen. Past it the
	// rows of the matrix are too long to follow with the eye.
	PageWidth = 1560
	// ColumnWidth is as wide as the start screen's column gets.
	ColumnWidth = 720
	// LabelWidth is the width of the column of names in a form.
	LabelWidth = 168
	// FieldWidthShort is the width of a box holding a number.
	FieldWidthShort = 120
	// ProseWidth is as wide as a paragraph gets: about 95 characters at the
	// lead size, the upper end of what reads easily.
	ProseWidth = 820
	// The columns of the trust matrix that do not stretch. The instance
	// column takes what is left.
	ColTrusts  = 148
	ColRuntime = 112
	ColAnchors = 80
	ColChosen  = 112
	ColToggle  = IconControl
	// TrackHeight is how tall the bar of time used is.
	TrackHeight = 6
	// MenuWidth is how wide a pop-up menu is.
	MenuWidth = 320
	// NoticeWidth is how wide a pop-up notice holding a line of code is,
	// such as the address a button could not open: room for about 50
	// characters of code beside Copy, where the longest address the window
	// shows has 41. A longer line wraps.
	NoticeWidth = 560
	// DialogWidth is how wide a dialog standing over the screen is, with its
	// edge: the width of the start screen's column, so a form in one reads
	// the same as the form in the other - its column of names, a folder with
	// Choose beside it, and room for the whole of a suggested file name.
	DialogWidth = ColumnWidth
	// ColInstanceMin is the narrowest the column naming where a store lives
	// may get before the least needed column gives up its room.
	ColInstanceMin = 160
	// SwatchSide is the side of a square of colour on the palette page.
	SwatchSide = step6
	// SheetColumn is the width of the narrow column of a catalogue page.
	SheetColumn = 440
)

// The window.
const (
	WindowWidth  = 1240
	WindowHeight = 820
	// WindowMinWidth stands above the narrowest width the report screen can
	// be laid out at, once the trust matrix has given up its least needed
	// column. A test in internal/gui/screens lays every screen out at this
	// width and fails when one asks for more, so a column that grows shows
	// there rather than as a cut right edge. It was 980 until that measure
	// found the report needing 988.
	WindowMinWidth  = 1000
	WindowMinHeight = 640
)

// Times the window shows something for.
const (
	// CopiedFor is how long Copy says Copied after a press: long enough to be
	// read at a glance, short enough that the next press is told again.
	CopiedFor = 2 * time.Second
)
