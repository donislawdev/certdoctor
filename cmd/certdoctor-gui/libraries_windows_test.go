//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// plantedLibrary is the library the test plants beside a copy of itself: the
// one OBS214 is named for, which GLFW asks for by name (wgl_context.c,
// _glfwInitWGL) and which is not a Known DLL. A copy of the system's own, so
// whatever copy is loaded does nothing harmful.
const plantedLibrary = "opengl32.dll"

// The exit codes of a child that asked for plantedLibrary by name: given the
// copy beside it, or another one. Neither is a code the window gives.
const (
	childLoadedBeside    = 9
	childLoadedElsewhere = 10
)

// TestALibraryBesideTheWindowIsNotTakenForTheSystemsOwn plants a copy of
// opengl32.dll beside a copy of the test binary and has a child ask for it by
// name the way GLFW does - once as it is, once after searchSystemOnly (OBS214,
// ADR152).
//
// Without the call the copy beside the program has to be the one loaded, and
// that is the canary: on a system whose loader did not look beside the program
// first, the half that matters would pass having proved nothing. Children
// rather than this process, because the search narrowed here would stay
// narrowed for every later test.
func TestALibraryBesideTheWindowIsNotTakenForTheSystemsOwn(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Fatal("SystemRoot is not set, so there is no system copy of opengl32.dll to plant")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	window := filepath.Join(dir, "window.exe")
	copyFile(t, exe, window)
	copyFile(t, filepath.Join(root, "System32", plantedLibrary), filepath.Join(dir, plantedLibrary))
	for _, c := range []struct {
		child, what string
		want        int
	}{
		{childLibrary, "without searchSystemOnly the copy beside the program has to be the one a name finds, " +
			"or this test proves nothing on this system", childLoadedBeside},
		{childLibrarySearched, "after searchSystemOnly a name still finds the copy beside the program", childLoadedElsewhere},
	} {
		cmd := exec.Command(window, "-test.run=^$")
		cmd.Env = append(os.Environ(), childVariable+"="+c.child)
		out, err := cmd.CombinedOutput()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("starting the child: %v", err)
		}
		if code != c.want {
			t.Errorf("%s - the child ended with %d, want %d:\n%s", c.what, code, c.want, out)
		}
	}
}

// actAsLibraryLoader is the child: it asks for plantedLibrary by name, after
// searchSystemOnly when searched, then for the copy beside this executable by
// its path, and answers whether the two are the same library.
func actAsLibraryLoader(searched bool) int {
	if searched {
		if err := searchSystemOnly(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	byName, err := syscall.LoadDLL(plantedLibrary)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dir, err := executableDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	beside, err := syscall.LoadDLL(filepath.Join(dir, plantedLibrary))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if byName.Handle == beside.Handle {
		return childLoadedBeside
	}
	return childLoadedElsewhere
}
