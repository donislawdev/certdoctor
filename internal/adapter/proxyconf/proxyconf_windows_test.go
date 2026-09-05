//go:build windows

package proxyconf

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// TestThisMachineAnswersForBothWindowsProxyStacks runs the real calls against
// the machine the test is on.
//
// IT ASSERTS THE SHAPE AND NEVER THE CONTENT, and the difference is the point.
// What this machine holds is not something a test may pin - a runner has
// different settings from a desktop, and a test that expected either would be
// green on one and red on the other for no reason anybody could act on. What can
// be pinned is that both stacks were asked, that each answer says which call it
// came from, and that nothing came back as a lens nobody asked for.
func TestThisMachineAnswersForBothWindowsProxyStacks(t *testing.T) {
	lenses := Read(context.Background(), nil)

	if len(lenses) != 2 {
		t.Fatalf("Windows keeps proxy configuration in two places and %d lenses came back: %+v", len(lenses), lenses)
	}
	want := []struct {
		stack  proxy.Stack
		source string
	}{
		{proxy.StackWinINET, proxy.SourceIEProxyConfig},
		{proxy.StackWinHTTP, proxy.SourceWinHTTPProxyConfig},
	}
	for i, w := range want {
		if lenses[i].Stack != w.stack {
			t.Errorf("lens %d is about %q, want %q", i, lenses[i].Stack, w.stack)
		}
		if lenses[i].Source != w.source {
			t.Errorf("lens %d says it came from %q, want %q", i, lenses[i].Source, w.source)
		}
		// A lens that was read must not be the zero value wearing a stack name,
		// and one that was not must say why - Lens.Read calls the silent case a
		// defect on our side.
		if !lenses[i].Read && lenses[i].Detail == "" {
			t.Errorf("lens %d could not be read and says nothing about why", i)
		}
		if lenses[i].Read && lenses[i].Servers == nil {
			t.Errorf("lens %d says it was read and left Servers nil, which means nobody looked", i)
		}
	}
}

func TestWideReadsAStringSomebodyElseAllocated(t *testing.T) {
	units, err := syscall.UTF16FromString("http=p.corp:8080;https=q.corp:8443")
	if err != nil {
		t.Fatalf("building the fixture: %v", err)
	}
	got, whole := wide(&units[0])
	if !whole || got != "http=p.corp:8080;https=q.corp:8443" {
		t.Errorf("wide read %q (whole %v), want the string it was given", got, whole)
	}

	// A NULL pointer is the vendor's way of saying "there is nothing here", and
	// it is not a string that failed to read.
	if got, whole := wide(nil); got != "" || !whole {
		t.Errorf("a NULL pointer read as %q (whole %v), want an empty string that was read fine", got, whole)
	}
}

// TestWideRefusesAStringWithNoTerminator is the ceiling doing the one job it
// exists for. Without it this loop walks to the first unmapped page.
func TestWideRefusesAStringWithNoTerminator(t *testing.T) {
	units := make([]uint16, stringCeiling+1)
	for i := range units {
		units[i] = 'a'
	}

	got, whole := wide(&units[0])
	if whole {
		t.Error("a string with no terminator inside the ceiling was reported as one that was read whole")
	}
	if got != "" {
		t.Errorf("wide returned %d characters of a string it could not finish, and a partial value looks like a whole one", len(got))
	}
}

// TestTheLibraryIsLoadedFromTheSystemDirectory checks the security rule this
// file carries a second copy of: winhttp.dll is not a KnownDLL, so a bare name
// would go through a search order whose first entry is the directory holding
// certdoctor.exe.
func TestTheLibraryIsLoadedFromTheSystemDirectory(t *testing.T) {
	library, err := systemLibrary("winhttp.dll")
	if err != nil {
		t.Fatalf("winhttp.dll could not be located on a Windows machine: %v", err)
	}
	if !filepath.IsAbs(library.Name) {
		t.Errorf("the library is named %q, and anything but an absolute path is resolved by the loader's search order", library.Name)
	}
	if !strings.EqualFold(filepath.Base(library.Name), "winhttp.dll") {
		t.Errorf("the library is named %q, which is not the one that was asked for", library.Name)
	}
}

func TestErrnoOfTakesTheNumberAndNotTheWording(t *testing.T) {
	if got := errnoOf(syscall.Errno(errorFileNotFound)); got != errorFileNotFound {
		t.Errorf("errnoOf gave %d, want %d", got, errorFileNotFound)
	}
	// Anything that is not a Windows error number carries no number to read, and
	// zero is the value that means no code rather than a code that means
	// something.
	if got := errnoOf(errors.New("something that is not an errno")); got != 0 {
		t.Errorf("errnoOf invented %d out of an error carrying no code", got)
	}
}
