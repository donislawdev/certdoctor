package guard

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// The window's scrolling areas turn a notch of the wheel into three lines of
// text by dividing what the toolkit hands over by the toolkit's own step for a
// notch (internal/gui/parts/wheel_other.go). That step is a constant inside the
// toolkit, not a part of its API, so a toolkit that changed it would leave every
// notch moving another distance with every test green. This reads the step from
// the toolkit's source the module cache holds, and the window's copy of it from
// the window's source.
var (
	toolkitStep = regexp.MustCompile(`scrollSpeed\s*=\s*float32\((\d+)\)`)
	windowStep  = regexp.MustCompile(`const ToolkitNotch = (\d+)`)
)

// stepIn is the one number re finds in the file at path.
func stepIn(t *testing.T, path string, re *regexp.Regexp) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	all := re.FindAllSubmatch(b, -1)
	if len(all) != 1 {
		t.Fatalf("%s: %d matches of %s, want one", path, len(all), re)
	}
	return string(all[0][1])
}

func TestTheWheelStepIsTheToolkitsStep(t *testing.T) {
	root, _, err := findModuleRoot()
	if err != nil {
		t.Fatalf("finding the module root: %v", err)
	}
	cmd := exec.Command("go", "list", "-m", "-json", "fyne.io/fyne/v2")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -m fyne.io/fyne/v2: %v", err)
	}
	var m struct{ Dir string }
	if err := json.Unmarshal(out, &m); err != nil || m.Dir == "" {
		t.Fatalf("go list -m fyne.io/fyne/v2 answered no directory (%v) - is the module downloaded?", err)
	}
	toolkit := stepIn(t, filepath.Join(m.Dir, "internal", "driver", "glfw", "scroll_speed_default.go"), toolkitStep)
	window := stepIn(t, filepath.Join(root, "internal", "gui", "parts", "wheel_other.go"), windowStep)
	if toolkit != window {
		t.Errorf("the toolkit moves %s for a notch and the window divides by %s - set ToolkitNotch to the toolkit's step",
			toolkit, window)
	}
}
