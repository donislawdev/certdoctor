//go:build cgo && !windows

package main

// sayInADialog has nothing to add outside Windows: a program there keeps its
// standard error, so the sentence that the window could not open reaches the
// terminal it was started from. A person who started it from a file manager
// sees nothing - written down as not done rather than papered over, because
// the system dialog that would answer it differs by desktop.
func sayInADialog(string, string) {}
