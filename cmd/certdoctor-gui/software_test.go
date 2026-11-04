package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestTheSecondAttemptIsTakenOnlyWhereTheRendererCanBe presses the decision
// between refusing and starting again (ADR125 points 2 and 9) without a window,
// a renderer or a second process: every piece that touches the world is a field
// of secondAttempt, and each case sets them to what a machine in that state
// answers.
//
// Two things matter more than the rest. The second process never starts a
// third - the flag it was started with is what says so - because on a machine
// where the renderer does not help either the window would otherwise start
// processes until something else stopped it. And the refusal says what became
// of the renderer: which file is missing, that a file could not be read, that
// starting again failed, or that it was tried and did not help. On a system the
// renderer does not ship for it says nothing.
func TestTheSecondAttemptIsTakenOnlyWhereTheRendererCanBe(t *testing.T) {
	for _, c := range attemptCases {
		t.Run(c.name, func(t *testing.T) { pressTheAttempt(t, c) })
	}
}

// attemptCase is one machine state the second attempt is asked in, and what it
// has to do there.
type attemptCase struct {
	name       string
	launch     launch
	goos       string
	dirErr     error
	missing    string
	besideErr  error
	startCode  int
	startErr   error
	loaded     error
	wantCode   int
	wantTried  bool   // start was called
	wantSaid   bool   // the note before starting reached standard error
	wantAdd    string // what the refusal adds, when there was no second process
	wantWorked bool   // try answered a code and no reason
}

// The errors the cases answer with, two of them ending in the full stop the
// system's own words carry, so a sentence that adds its own is seen to drop it.
var (
	attemptMissing    = filepath.Join("C:", "somewhere", "opengl", "libgallium_wgl.dll")
	attemptNoDir      = errors.New("no executable path")
	attemptNoStart    = errors.New("access denied.")
	attemptNoLoad     = errors.New("the renderer did not load.")
	attemptUnreadable = errors.New("CreateFile C:/somewhere/opengl/opengl32.dll: Access is denied.")
)

var attemptCases = []attemptCase{
	{name: "windows, renderer beside, the second process opened the window",
		launch: readLaunch([]string{"--some-argument"}), goos: "windows", startCode: 0,
		wantTried: true, wantSaid: true, wantWorked: true},
	{name: "windows, renderer beside, the second process refused too",
		launch: readLaunch(nil), goos: "windows", startCode: 1,
		wantCode: 1, wantTried: true, wantSaid: true, wantWorked: true},
	{name: "windows, renderer beside, the second process could not be started",
		launch: readLaunch(nil), goos: "windows", startErr: attemptNoStart,
		wantTried: true, wantSaid: true, wantAdd: "starting the window again did not work (access denied)."},
	{name: "windows, renderer not beside",
		launch: readLaunch(nil), goos: "windows", missing: attemptMissing,
		wantAdd: attemptMissing + " is missing."},
	{name: "windows, renderer beside but not readable",
		launch: readLaunch(nil), goos: "windows", besideErr: attemptUnreadable,
		wantAdd: "could not be read (CreateFile C:/somewhere/opengl/opengl32.dll: Access is denied)."},
	{name: "windows, the executable's directory unknown",
		launch: readLaunch(nil), goos: "windows", dirErr: attemptNoDir,
		wantAdd: "starting the window again did not work (no executable path)."},
	{name: "linux, nothing ships", launch: readLaunch(nil), goos: "linux"},
	{name: "darwin, nothing ships", launch: readLaunch(nil), goos: "darwin"},
	{name: "already the second process, the renderer loaded and did not help",
		launch: readLaunch([]string{softwareFlag}), goos: "windows",
		wantAdd: words.T(words.SoftwareDidNotHelp)},
	{name: "already the second process, the renderer did not load",
		launch: readLaunch([]string{softwareFlag}), goos: "windows", loaded: attemptNoLoad,
		wantAdd: "could not be loaded: the renderer did not load."},
	{name: "asked for by flag on a system nothing ships for, and refused by the driver",
		launch: readLaunch([]string{softwareFlag}), goos: "linux", loaded: notShipped{"linux"}},
}

// pressTheAttempt asks the second attempt in the state c describes and holds
// what it did to what c wants.
func pressTheAttempt(t *testing.T, c attemptCase) {
	var said bytes.Buffer
	var startedWith []string
	tried := false
	a := secondAttempt{
		launch:        c.launch,
		goos:          c.goos,
		executableDir: func() (string, error) { return "somewhere", c.dirErr },
		beside:        func(string) (string, error) { return c.missing, c.besideErr },
		start: func(args []string) (int, error) {
			tried, startedWith = true, args
			return c.startCode, c.startErr
		},
		errOut: &said,
	}
	code, why := a.try()

	if tried != c.wantTried {
		t.Fatalf("a second process was started: %v, and in this state it has to be %v", tried, c.wantTried)
	}
	if want := append(append([]string{}, c.launch.args...), softwareFlag); tried && strings.Join(startedWith, " ") != strings.Join(want, " ") {
		t.Errorf("the second process was started with %q and has to get %q - the same arguments plus the one flag, "+
			"so it opens what the first was asked for", startedWith, want)
	}
	if got := strings.Contains(said.String(), words.T(words.SoftwareAgain)); got != c.wantSaid {
		t.Errorf("standard error got %q, and the note before the second start has to be there: %v", said.String(), c.wantSaid)
	}
	if c.wantWorked {
		if why != nil || code != c.wantCode {
			t.Errorf("try answered code %d, reason %v - it has to answer the second process's code %d and no reason",
				code, why, c.wantCode)
		}
		return
	}
	if why == nil {
		t.Fatal("try answered no reason, and in this state there is no second process to answer for")
	}
	requireTheRendererSentence(t, rendererSentence(why, c.loaded), c.wantAdd)
}

// requireTheRendererSentence holds what the refusal adds about the renderer:
// nothing when nothing is wanted, and otherwise the wanted words whole, with no
// verb left unfilled and no full stop doubled.
func requireTheRendererSentence(t *testing.T, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("the refusal adds %q about the renderer and has to add nothing", got)
		}
		return
	}
	if !strings.Contains(got, want) || strings.Contains(got, "%") || strings.Contains(got, "..") {
		t.Errorf("the refusal adds %q about the renderer, and it has to carry %q whole, once punctuated", got, want)
	}
}

// TestAWindowAskedForTheRendererSaysWhatBecameOfIt - that it draws with the
// renderer, that none ships for this system without naming the system as if it
// were the error, and what stood in the way, with the system's full stop
// dropped so the sentence does not end on two.
func TestAWindowAskedForTheRendererSaysWhatBecameOfIt(t *testing.T) {
	if got := loadingSentence(nil); got != words.T(words.SoftwareDrawing) {
		t.Errorf("a renderer that loaded is announced as %q", got)
	}
	if got := loadingSentence(notShipped{"darwin"}); got != words.T(words.SoftwareNotShipped) || strings.Contains(got, "darwin") {
		t.Errorf("a system nothing ships for is announced as %q", got)
	}
	failed := errors.New("The specified module could not be found.")
	if got := loadingSentence(failed); !strings.Contains(got, "could not be found.") || strings.Contains(got, "..") {
		t.Errorf("a renderer that did not load is announced as %q", got)
	}
}

// TestARendererFileThatCannotBeReadIsNotReportedAsMissing - the renderer is
// looked for file by file, and a file that cannot be looked at is not a file
// that is missing, because the advice for the two differs.
func TestARendererFileThatCannotBeReadIsNotReportedAsMissing(t *testing.T) {
	files := softwareFiles("here")
	present := func(string) (fs.FileInfo, error) { return nil, nil }
	if missing, err := rendererBeside("here", present); missing != "" || err != nil {
		t.Errorf("with every file present the answer is %q, %v", missing, err)
	}
	gone := func(path string) (fs.FileInfo, error) {
		if path == files[1] {
			return nil, fs.ErrNotExist
		}
		return nil, nil
	}
	if missing, err := rendererBeside("here", gone); missing != files[1] || err != nil {
		t.Errorf("with the loader gone the answer is %q, %v - it has to name %s", missing, err, files[1])
	}
	denied := &fs.PathError{Op: "stat", Path: files[0], Err: fs.ErrPermission}
	unreadable := func(string) (fs.FileInfo, error) { return nil, denied }
	if missing, err := rendererBeside("here", unreadable); missing != "" || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("with a file that cannot be read the answer is %q, %v - a permission error is not a missing file", missing, err)
	}
	empty := t.TempDir()
	if missing, err := softwareBeside(empty); missing != softwareFiles(empty)[0] || err != nil {
		t.Errorf("an empty directory read as %q, %v - it has to name the renderer, the first file", missing, err)
	}
}

// TestTheLaunchLineIsReadAndKeptWhole - the one flag is read off the launch
// line, and the arguments are kept as given for the second process.
func TestTheLaunchLineIsReadAndKeptWhole(t *testing.T) {
	args := []string{"something", softwareFlag, "something-else"}
	l := readLaunch(args)
	if !l.softwareGL || strings.Join(l.args, " ") != strings.Join(args, " ") {
		t.Errorf("%q read as software %v, arguments %q - the flag is there and the arguments stay as given",
			args, l.softwareGL, l.args)
	}
	if plain := readLaunch([]string{"--software", "software-gl"}); plain.softwareGL {
		t.Error("an argument that is not the flag read as the flag")
	}
}

// TestTheRendererIsLoadedRendererFirstFromBesideTheProgram - the files are
// named in the order the loader needs, under the folder the archive puts them
// in, and a load names the file it failed on.
//
// Measured 2026-11-04 on Mesa 26.2.5's files: the loader opengl32.dll imports
// libgallium_wgl.dll by name, and a dependency of a library loaded by path is
// searched for by its name alone, so the renderer has to be mapped first.
func TestTheRendererIsLoadedRendererFirstFromBesideTheProgram(t *testing.T) {
	files := softwareFiles("here")
	want := []string{
		filepath.Join("here", "opengl", "libgallium_wgl.dll"),
		filepath.Join("here", "opengl", "opengl32.dll"),
	}
	if strings.Join(files, "|") != strings.Join(want, "|") {
		t.Fatalf("the renderer's files are %q and have to be %q, in that order - the renderer first, because the "+
			"loader imports it by name and finds it only if it is already mapped", files, want)
	}
	assertTheRendererLoads(t, want)
}

// TestTheSecondStartSpeaksAsANoteNotAFinding - the program has checked one
// thing when it writes the line before the second start: the first attempt
// gave no window. So the line says that, and names the driver as the usual
// cause rather than as a fact (ADR125 point 2). The table above takes the
// expected words from the catalogue and would stay green after a change of
// wording, so this one holds the words that make it a note.
func TestTheSecondStartSpeaksAsANoteNotAFinding(t *testing.T) {
	line := words.T(words.SoftwareAgain)
	for _, needed := range []string{"first attempt", "usually"} {
		if !strings.Contains(line, needed) {
			t.Errorf("the line before the second start does not say %q:\n  %s", needed, line)
		}
	}
	if strings.Contains(line, "offers no OpenGL") || strings.Contains(line, "does not support") {
		t.Errorf("the line before the second start states as a fact what the program never checked:\n  %s", line)
	}
}

// executableIsHere is where the test binary runs from, for the cases that ask
// the real executableDir.
func executableIsHere(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir, err := executableDir()
	if err != nil || dir != filepath.Dir(exe) {
		t.Fatalf("executableDir answered %q, %v - want %q", dir, err, filepath.Dir(exe))
	}
	return dir
}

// assertTheRendererLoads is the load on the system the test runs on: on
// Windows from an empty directory, which stands for a program with no renderer
// beside it - the load has to refuse naming the FIRST file, and the driver has
// to have been named in the environment before that, because the renderer
// reads it when it initialises and a load that set it afterwards would be too
// late. Anywhere else the load says nothing ships for this system.
func assertTheRendererLoads(t *testing.T, want []string) {
	t.Helper()
	executableIsHere(t)
	if runtime.GOOS != "windows" {
		if err := loadRendererBeside(); !errors.As(err, new(notShipped)) {
			t.Errorf("on %s the load answered %v, and nothing ships for this system to have loaded", runtime.GOOS, err)
		}
		return
	}
	t.Setenv(softwareDriver, "")
	err := loadRendererBeside()
	if err == nil {
		t.Fatal("loading a renderer from beside the test binary answered nil, and nothing is there")
	}
	if !strings.Contains(err.Error(), want[0][len("here")+1:]) {
		t.Errorf("the load failed with %q and has to name the renderer's file, the first one it tried", err)
	}
	if got := os.Getenv(softwareDriver); got != softwareLLVMPipe {
		t.Errorf("after the load %s is %q and has to be %s - named before the first file, because without it the "+
			"renderer picks a driver itself", softwareDriver, got, softwareLLVMPipe)
	}
}
