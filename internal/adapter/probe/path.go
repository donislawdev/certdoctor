package probe

import (
	"path/filepath"
	"runtime"
	"strings"
)

// SameOrInside reports whether dir IS root or lies inside it.
//
// IT EXISTS SO THAT ONE RULE LIVES IN ONE PLACE - P3-2 and OBS50. Two probes ask
// "does this PATH entry point at this installation", and until this function
// they each answered it with their own copy. A rule with two homes is the shape
// this tree has measured four times: a mutation entry aimed at one of them stops
// proving anything about the other, and the two drift the first time one gains a
// case. This is that first time.
//
// IT COMPARES WHOLE SEGMENTS, which both copies already did and which is the
// older half of the rule: "C:\Program Files\Git2\cmd" begins with "C:\Program
// Files\Git" as TEXT, so a prefix comparison credits one installation with
// another one's presence on PATH.
//
// AND IT FOLDS CASE WHERE THE PLATFORM DOES, WHICH IS THE HALF THAT WAS MISSING.
// Windows path names are case insensitive, and this machine's own PATH carries
// system32 in two spellings - measured 2026-08-18, where it made the curl probe
// count one binary as two stores. The same spelling difference on the other side
// of this comparison makes selected_by say that NOTHING points at an install the
// console would in fact use, which reads as an idle installation and sends a
// person to fix the wrong one.
//
// THE COST, NAMED: on a case-sensitive filesystem two directories differing only
// by case would be treated as one. That is a pathology nobody ships, while mixed
// spellings in a Windows PATH are measured and here.
//
// THE FOLDING IS A PARAMETER ONE LEVEL DOWN, AND THAT IS ABOUT THE TEST RATHER
// THAN ABOUT THE RULE. An assertion that read runtime.GOOS would pass on one
// runner and fail on the other, and the mutation register would report ZLAPANE
// or PRZEZYLA depending on where somebody happened to run it - the trap OBS28
// names. Split like this, both answers are asserted everywhere and only the one
// line choosing between them belongs to the platform.
func SameOrInside(dir, root string) bool {
	return sameOrInside(dir, root, runtime.GOOS == "windows")
}

func sameOrInside(dir, root string, fold bool) bool {
	dir, root = filepath.Clean(dir), filepath.Clean(root)
	if fold {
		dir, root = strings.ToLower(dir), strings.ToLower(root)
	}
	return dir == root || strings.HasPrefix(dir, root+string(filepath.Separator))
}
