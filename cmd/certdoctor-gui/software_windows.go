//go:build windows

package main

import (
	"os"
	"syscall"
)

// loadFailed: the renderer was asked for and the variable it reads could not
// be set - which variable, and what the system said. A file that does not load
// is reported by the toolchain's own error, which already names the file. Here
// rather than beside the other reasons because only this file raises it, and a
// type nothing raises on Linux is a type staticcheck there calls unused.
type loadFailed struct {
	name string
	err  error
}

func (e loadFailed) Error() string { return e.name + ": " + e.err.Error() }
func (e loadFailed) Unwrap() error { return e.err }

// loadRendererBeside loads the software renderer from beside this executable.
func loadRendererBeside() error {
	dir, err := executableDir()
	if err != nil {
		return err
	}
	return loadSoftwareRenderer(dir)
}

// loadSoftwareRenderer loads the renderer's files from under exeDir, so that
// the toolkit's later request for OpenGL by name is answered by them.
//
// Called before the toolkit exists, because the loader hands a library already
// mapped under a name to every later request for that name - and the window no
// longer imports opengl32.dll when it starts (third_party/go-gl-gl/PATCH.md),
// so at this point nothing of that name is mapped and the first request is this
// one. The search order puts the loaded module list ahead of the system's own
// libraries: https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order
// (read 2026-11-04).
//
// By absolute path worked out from where the executable is, which is the same
// trust the executable already has (ADR125 point 8). syscall.LoadDLL goes
// through LoadLibrary, which for a full path loads that file and nothing else.
// The renderer's own dependency is then found by name, which is why the
// renderer goes first - softwareFiles says so and every caller takes the order
// from it.
//
// The driver variable is set in this process before the first file, because
// the renderer reads it when it initialises. The first process sets it for the
// second too, in the environment it hands over - see startAgain - and both are
// needed, because a person can ask for the flag by hand.
func loadSoftwareRenderer(exeDir string) error {
	if err := os.Setenv(softwareDriver, softwareLLVMPipe); err != nil {
		return loadFailed{softwareDriver, err}
	}
	for _, path := range softwareFiles(exeDir) {
		// The toolchain's error names the file and repeats what the system
		// said, so it goes on as it is rather than wrapped in a second copy of
		// the path.
		if _, err := syscall.LoadDLL(path); err != nil {
			return err
		}
	}
	return nil
}
