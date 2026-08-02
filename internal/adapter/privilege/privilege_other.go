//go:build !windows

package privilege

import "os"

// ask reports whether the process runs with an effective user id of zero.
//
// WHAT THIS DELIBERATELY DOES NOT ANSWER, written next to the code rather than
// left to be discovered. On Linux a process can hold the access that matters
// here - reading another account's trust store, listing a directory it does not
// own - through capabilities, with an effective user id that is not zero. This
// answers "user" for that case, so the level is a FLOOR rather than a
// measurement of what the process can actually reach.
//
// The narrowing is deliberate and it is the honest side of the trade. Deciding
// otherwise would mean parsing /proc/self/status, which is a second claim about
// somebody else's system in a field that is metadata rather than a diagnosis.
// Recorded as an observation instead of hidden here.
func ask() (bool, error) {
	return os.Geteuid() == 0, nil
}
