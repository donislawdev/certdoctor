package probe

import (
	"path/filepath"
	"testing"
)

// TestOnePathRuleAnsweredTheSameWayForEveryProbe is P3-2.
//
// BOTH ANSWERS ARE ASSERTED ON EVERY PLATFORM, which is why the folding is a
// parameter here rather than a call to runtime.GOOS: an assertion reading the
// platform would pass on one runner and fail on the other, and the mutation
// register would report a different result depending on where it ran - OBS28.
func TestOnePathRuleAnsweredTheSameWayForEveryProbe(t *testing.T) {
	root := filepath.Join("C:", "Program Files", "Git")
	inside := filepath.Join(root, "cmd")
	neighbour := filepath.Join("C:", "Program Files", "Git2", "cmd")
	shouted := filepath.Join("C:", "PROGRAM FILES", "GIT", "cmd")

	for _, c := range []struct {
		name string
		dir  string
		fold bool
		want bool
	}{
		{"the installation itself", root, false, true},
		{"a directory inside it", inside, false, true},
		// The older half of the rule: a neighbour whose name differs by one
		// character begins with this one's path as TEXT.
		{"a neighbouring installation", neighbour, false, false},
		{"a neighbouring installation, folded", neighbour, true, false},
		// The half that was missing, and the one this machine's own PATH
		// produces: system32 appears there in two spellings.
		{"the same directory in another case, not folded", shouted, false, false},
		{"the same directory in another case, folded", shouted, true, true},
		{"something else entirely", filepath.Join("C:", "Windows"), true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := sameOrInside(c.dir, root, c.fold); got != c.want {
				t.Errorf("%q against %q with folding=%v answered %v, want %v", c.dir, root, c.fold, got, c.want)
			}
		})
	}
}

// TestTheExportedRuleAgreesWithItselfOnEveryPlatform covers the one line that
// chooses whether to fold, without asserting which choice this platform made.
//
// An assertion about the platform's answer would pass on one runner and fail on
// the other - OBS28 - so what is asserted here is what is true everywhere: an
// installation is inside itself, a directory under it is inside it, and a
// neighbour whose name merely begins the same way is not.
func TestTheExportedRuleAgreesWithItselfOnEveryPlatform(t *testing.T) {
	root := filepath.Join("opt", "runtime")

	if !SameOrInside(root, root) {
		t.Error("an installation is not inside itself")
	}
	if !SameOrInside(filepath.Join(root, "bin"), root) {
		t.Error("a directory under the installation is not inside it")
	}
	if SameOrInside(filepath.Join("opt", "runtime2", "bin"), root) {
		t.Error("a neighbouring installation was credited with this one's place on PATH")
	}
}
