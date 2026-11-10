package main

// softwareFlag asks the window to draw with the software renderer shipped
// beside it instead of the graphics driver (ADR125 point 2). Public, and the
// same name TestingFilesGenerator gives it: it is the way to see the window as
// a machine without a driver sees it, and the way the window asks for itself
// when its first attempt gave no window.
const softwareFlag = "--software-gl"

// catalogueFlag opens the hidden catalogue of the window's parts instead of
// the window (GUI rule 4): every part in every state, drawn from the example
// report the window carries. For whoever looks after the window, so named in
// no help - the window has none - and in the README nowhere.
const catalogueFlag = "--catalogue"

// launch is what the launch line asked for.
//
// The arguments are kept as they were given, because a window that could not
// open starts this program again with them plus the flag, and the second
// process has to be asked for the same thing the first one was - the
// catalogue drawn by the software renderer is still the catalogue. Every
// other argument is ignored, as it was before the flags existed - a window
// started from a shortcut with odd arguments opens all the same.
type launch struct {
	softwareGL bool
	catalogue  bool
	args       []string
}

// readLaunch reads the two flags the window knows out of the launch line.
func readLaunch(args []string) launch {
	l := launch{args: args}
	for _, arg := range args {
		switch arg {
		case softwareFlag:
			l.softwareGL = true
		case catalogueFlag:
			l.catalogue = true
		}
	}
	return l
}
