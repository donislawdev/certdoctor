package main

// softwareFlag asks the window to draw with the software renderer shipped
// beside it instead of the graphics driver (ADR125 point 2). Public, and the
// same name TestingFilesGenerator gives it: it is the way to see the window as
// a machine without a driver sees it, and the way the window asks for itself
// when its first attempt gave no window.
const softwareFlag = "--software-gl"

// launch is what the launch line asked for.
//
// The arguments are kept as they were given, because a window that could not
// open starts this program again with them plus the flag, and the second
// process has to be asked for the same thing the first one was. Every other
// argument is ignored, as it was before the flag existed - a window started
// from a shortcut with odd arguments opens all the same.
type launch struct {
	softwareGL bool
	args       []string
}

// readLaunch reads the one flag the window knows out of the launch line.
func readLaunch(args []string) launch {
	l := launch{args: args}
	for _, arg := range args {
		if arg == softwareFlag {
			l.softwareGL = true
		}
	}
	return l
}
