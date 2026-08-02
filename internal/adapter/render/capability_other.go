//go:build !windows

package render

// consoleRendersUnicode answers yes away from Windows.
//
// This is an ASSESSMENT, not a measurement. No terminal was tested for it. The
// reasoning is that a terminal on Linux or macOS is on UTF-8 in every ordinary
// case, and that the cost of being wrong is a marker that looks like a broken
// character rather than a wrong verdict about somebody's machine.
//
// WHAT WAS DELIBERATELY NOT DONE. Reading LC_ALL, LC_CTYPE or LANG would answer
// this more precisely. It is left alone because the rule about environment
// variables names NO_COLOR as the single exception, and widening a rule that is
// written as closed - for a glyph - is how closed rules stop being closed. If a
// terminal that cannot render the marker turns up in practice, that measurement
// is the argument for revisiting this, and a guess today is not.
func consoleRendersUnicode() bool { return true }
