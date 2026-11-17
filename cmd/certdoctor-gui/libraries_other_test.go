//go:build !windows

package main

// actAsLibraryLoader has nothing to ask for outside Windows, where the test
// that starts it does not run.
func actAsLibraryLoader(bool) int { return 1 }
