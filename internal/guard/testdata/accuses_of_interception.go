// This file is a fixture with a planted violation. It is under testdata, so the
// module walk never reaches it and no guard is red because of it. It exists so
// the guard below can be seen to FAIL, which is the only way to know it can.
package planted

import "fmt"

// The gap guard 30 named about itself when it was built: "a sentence about
// interception assembled into a plain string and printed". The judgement lives
// in one file and the contract refuses a finding that accuses while naming no
// product - but neither of those sees a renderer that words its own accusation
// and prints it. This fixture is that renderer.

// accuses plants the plain shape: the word in a literal, in a package with no
// business saying it.
func accuses() string {
	return "this connection is being intercepted"
}

// accusesInAFormat plants the second shape, because a guard that only looked at
// whole literals equal to a word would walk past every real sentence. The word
// here is a fragment of a longer string, which is how it would actually arrive.
func accusesInAFormat(who string) string {
	return fmt.Sprintf("%s is running a mitm proxy against you", who)
}
