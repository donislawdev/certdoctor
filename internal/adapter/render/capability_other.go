//go:build !windows

package render

import "os"

// consoleUnderstandsSequences answers yes away from Windows.
//
// This is an ASSESSMENT, not a measurement, and it is a much safer one than its
// Windows counterpart turned out to be. A terminal on Linux or macOS interprets
// escape sequences by definition - that is what the terminfo database describes
// and what every terminal emulator implements. Windows is the platform where a
// console can be a console and still print the sequence verbatim, which is why
// the question exists at all.
//
// What is NOT asked here is TERM=dumb, which is the one shape on these platforms
// that would answer no. That is a separate gap with its own entry, and closing
// it belongs with the other environment variable work rather than being smuggled
// in here.
func consoleUnderstandsSequences(*os.File) bool { return true }

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
