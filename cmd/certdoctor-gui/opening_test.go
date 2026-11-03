//go:build cgo

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"
	"fyne.io/fyne/v2/test"

	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// childVariable asks the test binary to be the window instead of running the
// tests - see TestAWindowWithNoDisplayIsRefusedRatherThanLeftWaiting.
const childVariable = "CERTDOCTOR_GUI_TEST_CHILD"

// TestMain is the window itself when the variable asks for it. Run from here
// rather than from a test because the toolkit's loop belongs to the main
// goroutine, and TestMain is the only code of a test binary that runs there.
func TestMain(m *testing.M) {
	if os.Getenv(childVariable) == "1" {
		os.Exit(run(nil, os.Stderr))
	}
	os.Exit(m.Run())
}

// native is a window that answers with a handle in one of the toolkit's
// contexts. Everything but showing it and asking for its handle is left to the
// embedded interface, which nothing here calls.
type native struct {
	fyne.Window
	context any
	showed  *bool
	panics  any
}

func (n native) Show() {
	*n.showed = true
	if n.panics != nil {
		panic(n.panics)
	}
}

func (n native) RunNative(f func(any)) { f(n.context) }

// TestAWindowTheToolkitDidNotGiveIsRefused - the loop is never run, the refusal
// is said, and the code is 1. Then the same with a window the toolkit gave, which
// runs and is not refused.
func TestAWindowTheToolkitDidNotGiveIsRefused(t *testing.T) {
	showed, ran, refused := false, false, false
	var handedOver any = "untouched"
	refuse := func(panicked any) { refused, handedOver = true, panicked }
	absent := native{context: driver.X11WindowContext{}, showed: &showed}
	if code := openOrRefuse(absent, func() { ran = true }, refuse); code != 1 {
		t.Errorf("a window with no handle gave code %d, want 1", code)
	}
	if !showed || ran || !refused || handedOver != nil {
		t.Errorf("a window with no handle: showed %v, ran %v, refused %v with %v - want it shown, refused with "+
			"no panic and never run", showed, ran, refused, handedOver)
	}

	showed, ran, refused = false, false, false
	present := native{context: driver.X11WindowContext{WindowHandle: 1}, showed: &showed}
	if code := openOrRefuse(present, func() { ran = true }, refuse); code != 0 {
		t.Errorf("a window with a handle gave code %d, want 0", code)
	}
	if !showed || !ran || refused {
		t.Errorf("a window with a handle: showed %v, ran %v, refused %v - want it shown and run, never refused",
			showed, ran, refused)
	}
}

// TestAPanicThatLeftNoWindowIsARefusal - the shape a machine with no display
// gives: Show panics before the window exists, and the panic is handed to the
// refusal rather than ending the process. A panic with a window standing is
// not the toolkit failing to give one, so it goes on as the panic it was.
func TestAPanicThatLeftNoWindowIsARefusal(t *testing.T) {
	showed, ran := false, false
	var handedOver any
	absent := native{context: driver.X11WindowContext{}, showed: &showed, panics: "NotInitialized"}
	if code := openOrRefuse(absent, func() { ran = true }, func(p any) { handedOver = p }); code != 1 {
		t.Errorf("a panic with no window gave code %d, want 1", code)
	}
	if ran || handedOver != "NotInitialized" {
		t.Errorf("a panic with no window: ran %v, the refusal was handed %v - want it never run and handed the panic",
			ran, handedOver)
	}

	present := native{context: driver.X11WindowContext{WindowHandle: 1}, showed: &showed, panics: "ours"}
	defer func() {
		if got := recover(); got != "ours" {
			t.Errorf("a panic with a window standing came out as %v, want the panic itself", got)
		}
	}()
	openOrRefuse(present, func() { ran = true }, func(any) { t.Error("a panic with a window standing was refused") })
	t.Error("a panic with a window standing was swallowed")
}

// TestEveryPlatformsHandleIsRead - each desktop context with no handle is a
// window that did not open and with one is a window that did, and a window that
// cannot answer, or answers in a context nobody knows, is taken as shown.
func TestEveryPlatformsHandleIsRead(t *testing.T) {
	cases := []struct {
		name          string
		empty, filled any
	}{
		{"Windows", driver.WindowsWindowContext{}, driver.WindowsWindowContext{HWND: 1}},
		{"macOS", driver.MacWindowContext{}, driver.MacWindowContext{NSWindow: 1}},
		{"X11", driver.X11WindowContext{}, driver.X11WindowContext{WindowHandle: 1}},
		{"Wayland", driver.WaylandWindowContext{}, driver.WaylandWindowContext{WaylandSurface: 1}},
	}
	showed := false
	for _, c := range cases {
		if shown(native{context: c.empty, showed: &showed}) {
			t.Errorf("%s with no handle reads as shown", c.name)
		}
		if !shown(native{context: c.filled, showed: &showed}) {
			t.Errorf("%s with a handle reads as not shown", c.name)
		}
	}
	if !shown(native{context: struct{}{}, showed: &showed}) {
		t.Error("a context nobody knows reads as not shown")
	}
	test.NewTempApp(t)
	if !shown(test.NewTempWindow(t, nil)) {
		t.Error("the test driver's window, which has no native handle at all, reads as not shown")
	}
}

// TestTheCauseIsTheToolkitsOwnSentence - read off the last line the toolkit's
// logger marks, ahead of a panic, and the panic when nothing is marked. Nothing
// when there is neither. The sentence quotes it, and says the rest without it.
//
// The log is the shape measured on Linux with no display, shortened: a cause
// about the cache directory first, and the one about the graphics library last.
func TestTheCauseIsTheToolkitsOwnSentence(t *testing.T) {
	logged := "2026/11/03 Fyne error:  Failed to create fyne cache space\n" +
		"2026/11/03   Cause: mkdir /home/jdoe/.cache/fyne/: no such file or directory\n" +
		"2026/11/03   At: app/cache.go:28\n" +
		"2026/11/03 Fyne error:  failed to initialise GLFW\n" +
		"2026/11/03   Cause: PlatformUnavailable: Failed to detect any supported platform\n" +
		"2026/11/03   At: internal/driver/glfw/loop_desktop.go:29\n"
	cause := causeFrom(logged, "NotInitialized")
	if cause != "PlatformUnavailable: Failed to detect any supported platform" {
		t.Errorf("the cause read %q", cause)
	}
	if got := causeFrom("nothing marked\n", errors.New("NotInitialized")); got != "NotInitialized" {
		t.Errorf("an unmarked log with a panic gave the cause %q", got)
	}
	if got := causeFrom("nothing marked\n", nil); got != "" {
		t.Errorf("an unmarked log gave the cause %q", got)
	}
	if got := refusal(cause); !strings.Contains(got, cause) || strings.Contains(got, "%") {
		t.Errorf("the sentence with a cause does not quote it whole: %q", got)
	}
	if got := refusal(""); got != words.T(words.WindowRefused) {
		t.Errorf("the sentence without a cause reads %q", got)
	}
}

// TestAWindowWithNoDisplayIsRefusedRatherThanLeftWaiting starts the window for
// real, with no display to put it on, and requires the refusal: code 1, the
// sentence on standard error, and a process that ends. Without the question
// openOrRefuse asks, this process would wait in the toolkit's loop until it was
// killed - the failure ADR125 point 1 exists for.
//
// Linux only, because only there is a desktop something a process can be
// started without: on Windows and macOS the window would open. The variables
// of both display servers are taken away, and with them the runtime directory
// Wayland would find its default socket in, and the configuration directories
// point into a directory of the test's own, so the toolkit's preferences are
// not left behind on whatever machine runs this.
func TestAWindowWithNoDisplayIsRefusedRatherThanLeftWaiting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("on %s a desktop is there, so the window would open rather than be refused", runtime.GOOS)
	}
	home := t.TempDir()
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", childVariable:
			continue
		}
		env = append(env, kv)
	}
	env = append(env, childVariable+"=1", "HOME="+home, "XDG_CONFIG_HOME="+home, "XDG_CACHE_HOME="+home)

	const limit = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	child.Env = env
	var stderr bytes.Buffer
	child.Stderr = &stderr
	err := child.Run()
	if ctx.Err() != nil {
		t.Fatalf("the window was still running after %v with no display to open on - it waits instead of refusing:\n%s",
			limit, stderr.String())
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("the window with no display ended with %v, want exit code 1:\n%s", err, stderr.String())
	}
	lead, _, _ := strings.Cut(words.T(words.WindowRefusedCause), " The toolkit said")
	if !strings.Contains(stderr.String(), lead) {
		t.Fatalf("the window with no display did not say why on standard error:\n%s", stderr.String())
	}
	t.Logf("what the refused window said:\n%s", stderr.String())
}
