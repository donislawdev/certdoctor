package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// The software renderer shipped beside the window on Windows (ADR125 points 2
// and 4): two files of Mesa's llvmpipe in a folder of their own beside the
// executable - the renderer, which carries llvmpipe and LLVM, and the thin
// loader Windows programs ask for OpenGL by name.
//
// The order is not a preference. The loader imports the renderer BY NAME -
// read off its import table, Mesa 26.2.5 from pal1000/mesa-dist-win, measured
// 2026-11-04 - and a dependency of a library loaded by path is searched for the
// ordinary way rather than beside that library (the search order, read
// 2026-11-04: https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order),
// so loaded second the loader fails with "module not found". Loaded first, the
// renderer is already mapped under its name when the loader asks.
//
// The driver is named rather than left to the renderer, which otherwise picks
// one itself: measured in TestingFilesGenerator on a machine with a graphics
// card, the renderer chose the one that needs dxil.dll and the process died
// within three seconds, two times out of two, with no word on standard error.
//
// In a folder of their own rather than beside the executable, because a file
// called opengl32.dll beside a program is the classic shape of a library
// hijack, and the only reason it works here is that the program asks for these
// two by absolute path - see software_windows.go.
const (
	softwareDir      = "opengl"
	softwareRenderer = "libgallium_wgl.dll"
	softwareLoader   = "opengl32.dll"
	softwareDriver   = "GALLIUM_DRIVER"
	softwareLLVMPipe = "llvmpipe"
)

// softwareFiles names the renderer's files beside the executable, in the order
// they have to be loaded. Every caller takes the order from here.
func softwareFiles(exeDir string) []string {
	return []string{
		filepath.Join(exeDir, softwareDir, softwareRenderer),
		filepath.Join(exeDir, softwareDir, softwareLoader),
	}
}

// softwareBeside looks for the renderer's files beside the executable.
func softwareBeside(exeDir string) (missing string, err error) {
	return rendererBeside(exeDir, os.Stat)
}

// rendererBeside answers with the first of the renderer's files that is
// missing, or with what stood in the way of looking. A file that cannot be
// looked at is not a file that is missing - the advice for the two differs
// (put the folder back, against look at who may read it), which an outside
// review of TestingFilesGenerator's version of this pointed out. The question
// to the file system is handed in so a test can answer it with a permission
// error, which no disk arranges the same way on every system.
func rendererBeside(exeDir string, stat func(string) (fs.FileInfo, error)) (missing string, err error) {
	for _, path := range softwareFiles(exeDir) {
		_, err := stat(path)
		if err == nil {
			continue
		}
		if errors.Is(err, fs.ErrNotExist) {
			return path, nil
		}
		return "", err
	}
	return "", nil
}

// executableDir is the directory the running program was started from.
func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// secondAttempt is the second attempt at a window, taken when the toolkit gave
// none: this program started again with the same arguments plus the flag, so
// that the second process loads the software renderer before the toolkit asks
// the driver for anything (ADR125 point 2). A second process rather than a
// second try in this one, because the toolkit's state after a failed window is
// not something its public API can reset.
//
// The pieces that touch the world are fields, so the decision can be pressed
// by a test on any system without a window, a renderer or a second process -
// which is also why the system's name is a field rather than read.
type secondAttempt struct {
	launch launch
	goos   string
	// executableDir is where the executable lives, or what stood in the way of
	// knowing.
	executableDir func() (string, error)
	// beside names the first of the renderer's files that is not beside the
	// executable, or nothing when both are - or what stood in the way of
	// looking, which is a different answer with different advice.
	beside func(exeDir string) (missing string, err error)
	// start starts this program again with args and answers its exit code.
	start  func(args []string) (code int, err error)
	errOut io.Writer
}

// The reasons the second attempt was not taken. Each becomes a sentence of the
// refusal through rendererSentence, apart from the one that becomes none: on a
// system the renderer does not ship for there is nothing missing to name. Their
// Error strings carry the fact and no words, because the words a person reads
// come from the catalogue and nowhere else.
type (
	// alreadySoftware: this IS the second process, and it does not start a
	// third. The refusal it shows says the renderer was tried.
	alreadySoftware struct{}
	// notShipped: no renderer ships for this system.
	notShipped struct{ goos string }
	// notBeside: a file of the renderer is not where the archive put it.
	notBeside struct{ path string }
	// notReadable: a file of the renderer could not be looked at - the
	// system's answer, which names the file.
	notReadable struct{ err error }
	// startFailed: the second process could not be started at all.
	startFailed struct{ err error }
)

func (alreadySoftware) Error() string { return softwareFlag }
func (e notShipped) Error() string    { return e.goos }
func (e notBeside) Error() string     { return e.path }
func (e notReadable) Error() string   { return e.err.Error() }
func (e notReadable) Unwrap() error   { return e.err }
func (e startFailed) Error() string   { return e.err.Error() }
func (e startFailed) Unwrap() error   { return e.err }

// secondAttemptFor is the attempt the real window takes: this executable, this
// system, a real second process.
func secondAttemptFor(l launch, errOut io.Writer) secondAttempt {
	return secondAttempt{
		launch:        l,
		goos:          runtime.GOOS,
		executableDir: executableDir,
		beside:        softwareBeside,
		start:         startAgain,
		errOut:        errOut,
	}
}

// try tries the window a second time, in a second process, and answers that
// process's exit code. When it does not try, it answers why, and the refusal
// carries the reason - see rendererSentence.
//
// The second process never starts a third: a process started with the flag is
// the attempt, and when the toolkit refuses there too the answer is the
// refusal, not a chain of processes each waiting for the next.
func (a secondAttempt) try() (int, error) {
	if a.launch.softwareGL {
		return 0, alreadySoftware{}
	}
	if a.goos != "windows" {
		return 0, notShipped{a.goos}
	}
	dir, err := a.executableDir()
	if err != nil {
		return 0, startFailed{err}
	}
	missing, err := a.beside(dir)
	if err != nil {
		return 0, notReadable{err}
	}
	if missing != "" {
		return 0, notBeside{missing}
	}
	// Said before the second process starts, on the stream whatever started
	// this one reads - as a note rather than a finding, because the program has
	// checked one thing only: the first attempt gave no window.
	fmt.Fprintln(a.errOut, words.T(words.SoftwareAgain))
	code, err := a.start(append(append([]string{}, a.launch.args...), softwareFlag))
	if err != nil {
		return 0, startFailed{err}
	}
	return code, nil
}

// rendererSentence is what the refusal adds about the software renderer: why
// it was not tried, or that it was and did not help. Nothing on a system the
// renderer does not ship for, where a sentence about a missing file would be
// about a file nobody promised (ADR125 point 2).
//
// why is what try answered. loaded is what this process found when it loaded
// the renderer: nil when it loaded, the error when it did not - and nil as well
// in a first process, which never tried.
func rendererSentence(why, loaded error) string {
	var beside notBeside
	var unreadable notReadable
	var failed startFailed
	var shipsNot notShipped
	switch {
	case errors.As(why, &beside):
		return fmt.Sprintf(words.T(words.SoftwareNotBeside), beside.path)
	case errors.As(why, &unreadable):
		return fmt.Sprintf(words.T(words.SoftwareNotReadable), withoutFullStop(unreadable.err))
	case errors.As(why, &failed):
		return fmt.Sprintf(words.T(words.SoftwareStartFailed), withoutFullStop(failed.err))
	case errors.Is(why, alreadySoftware{}) && errors.As(loaded, &shipsNot):
		// Asked for by flag on a system nothing ships for, and refused by the
		// driver: the same silence as without the flag.
		return ""
	case errors.Is(why, alreadySoftware{}) && loaded != nil:
		return fmt.Sprintf(words.T(words.SoftwareNotLoaded), withoutFullStop(loaded))
	case errors.Is(why, alreadySoftware{}):
		return words.T(words.SoftwareDidNotHelp)
	default:
		return ""
	}
}

// loadingSentence is what a window asked for the renderer says on standard
// error about loading it: that it draws with the renderer, that none ships for
// this system, or what stood in the way.
func loadingSentence(loaded error) string {
	var shipsNot notShipped
	switch {
	case errors.As(loaded, &shipsNot):
		return words.T(words.SoftwareNotShipped)
	case loaded != nil:
		return fmt.Sprintf(words.T(words.SoftwareNotLoaded), withoutFullStop(loaded))
	default:
		return words.T(words.SoftwareDrawing)
	}
}

// withoutFullStop is an error's words without the full stop Windows ends its
// own with, for a sentence that supplies its own - "The specified module could
// not be found." arrives with one (measured in TestingFilesGenerator).
func withoutFullStop(err error) string {
	return strings.TrimRight(strings.TrimSpace(err.Error()), ".")
}
