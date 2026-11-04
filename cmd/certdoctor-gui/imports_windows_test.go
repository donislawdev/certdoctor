//go:build cgo

package main

import (
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheWindowDoesNotImportOpenGLAtLoadTime builds the window and reads the
// libraries its import table names (ADR125 point 9).
//
// The window starts again with a software renderer when the graphics driver
// gives it no window, and that renderer is loaded by path under the name
// opengl32.dll before the toolkit asks for OpenGL. Windows hands a library
// already loaded under a name to every later request for that name - so if the
// window imported opengl32.dll, the loader would have mapped the system's copy
// before any code of ours ran, and the renderer could never be the one the
// toolkit draws with. Measured 2026-11-04: the window built from the published
// OpenGL binding imports it, the one built from the copy in third_party does
// not. Nothing else would notice the import coming back - the window still
// opens on every machine with a driver, and only the second start stops
// helping.
//
// Built here rather than taken from a release, because the release does not
// build the window yet, and built without -trimpath so that the toolchain finds
// in its cache the packages it just compiled for this test.
func TestTheWindowDoesNotImportOpenGLAtLoadTime(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "certdoctor-gui.exe")
	build := exec.Command("go", "build", "-ldflags=-H=windowsgui", "-o", exe, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the window: %v\n%s", err, out)
	}
	libraries, err := loadTimeLibraries(exe)
	if err != nil {
		t.Fatalf("reading the import table of the window: %v", err)
	}
	if problem := openGLImportProblem(libraries); problem != "" {
		t.Error(problem)
	}
}

// TestTheImportGuardCanFail plants the two shapes the check above exists for:
// a table that names opengl32.dll, and a table read wrongly or not at all.
func TestTheImportGuardCanFail(t *testing.T) {
	if problem := openGLImportProblem(map[string]bool{"gdi32.dll": true, "opengl32.dll": true}); !strings.Contains(problem, "imports opengl32.dll") {
		t.Errorf("a table naming opengl32.dll gave %q", problem)
	}
	if problem := openGLImportProblem(map[string]bool{}); !strings.Contains(problem, "no gdi32.dll") {
		t.Errorf("an empty table gave %q", problem)
	}
	if problem := openGLImportProblem(map[string]bool{"gdi32.dll": true}); problem != "" {
		t.Errorf("a table without opengl32.dll gave %q", problem)
	}
}

// openGLImportProblem says what is wrong with a table of load time libraries,
// or nothing. gdi32.dll is the landmark: GLFW draws through it on Windows, so a
// table without it is a table this did not manage to read, and a check that
// read nothing must not pass for one that found nothing.
func openGLImportProblem(libraries map[string]bool) string {
	if !libraries["gdi32.dll"] {
		return "the window imports no gdi32.dll, which GLFW always links - the import table read is the wrong one or empty"
	}
	if libraries["opengl32.dll"] {
		return "the window imports opengl32.dll at load time, so the system's copy is mapped before a software renderer " +
			"can be loaded and the second start cannot help (ADR125) - go.mod has to replace github.com/go-gl/gl with " +
			"the copy in third_party/go-gl-gl, and no other linked C code may call an OpenGL function by its symbol"
	}
	return ""
}

// loadTimeLibraries answers the libraries an executable's import table names,
// in lower case. Read through ImportedSymbols, whose entries end in the name of
// the library, because ImportedLibraries answers an empty list for a binary the
// Go linker wrote - measured 2026-11-04 on this window: no library from it, 239
// symbols from the other. That is the reason the landmark above exists.
func loadTimeLibraries(path string) (map[string]bool, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	symbols, err := f.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	libraries := map[string]bool{}
	for _, symbol := range symbols {
		if _, library, ok := strings.Cut(symbol, ":"); ok {
			libraries[strings.ToLower(library)] = true
		}
	}
	return libraries, nil
}
