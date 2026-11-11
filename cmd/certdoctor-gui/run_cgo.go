//go:build cgo

package main

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/donislawdev/certdoctor"
	"github.com/donislawdev/certdoctor/assets/icon"
	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// appID names the directory the toolkit keeps this window's preferences in -
// the one place on disk the window may write besides a report (D21: its size
// and the last folder, never a target). It is not the identifier of the macOS
// bundle, which the release names on its own, the same split
// TestingFilesGenerator has - decided by the owner (ADR127). Changing it after
// a release leaves every saved preference behind under the old name.
const appID = "dev.donislaw.certdoctor"

// run opens the window and returns the exit code of the process: 0 when the
// window was closed, 1 when the toolkit gave no window (ADR125 point 1), and
// on Windows, when the first attempt gave none, the code of the second process
// that tried with the software renderer (ADR125 point 2). The one flag read is
// --software-gl, and every other argument is passed on to that second process
// as it came - see readLaunch.
func run(args []string, errOut io.Writer) int {
	// The toolkit's own words in English before anything of it is drawn
	// (OBS206). A failure costs those words their language and not the
	// window, so it is said and the window opens.
	if err := speakEnglish(); err != nil {
		fmt.Fprintf(errOut, words.T(words.ToolkitNotEnglish)+"\n", err)
	}
	l := readLaunch(args)
	// The software renderer, when asked for, before anything below asks the
	// driver for anything: the toolkit's first request for OpenGL by name has to
	// find it already mapped. A renderer that does not load is said out loud and
	// the window goes on to the toolkit - which on the machine this exists for
	// refuses, and the refusal then says the renderer was tried and why it
	// could not be. On a machine with a driver the window opens drawn by the
	// driver.
	var loaded error
	if l.softwareGL {
		loaded = loadRendererBeside()
		fmt.Fprintln(errOut, loadingSentence(loaded))
	}

	// The toolkit says why a window failed through the standard logger, so a
	// copy is kept for the sentence of the refusal. The copy comes first, so a
	// standard error that is not there - a program built for the windows
	// subsystem has none - cannot stop it. Our own code never logs, so where
	// the window opens the copy stays empty.
	var said bytes.Buffer
	log.SetOutput(io.MultiWriter(&said, log.Writer()))

	a := app.NewWithID(appID)
	// The toolkit has just put its own reader of web addresses behind http
	// and https - see offline.
	refuseAddresses()
	picture := fyne.NewStaticResource("certdoctor.png", icon.PNG)
	// The picture the desktop shows for this program, which the toolkit also
	// gives every window it opens - without it the toolkit's own logo stands
	// in the task bar under our name.
	a.SetIcon(picture)
	a.Settings().SetTheme(look.Theme())
	w := a.NewWindow(words.T(words.AppName))
	// Drawn by the software renderer when it was asked for and it loaded -
	// which the start screen says (ADR125 point 2). Under --catalogue the
	// catalogue of the window's parts instead (GUI rule 4).
	if err := fill(w, picture, l, certdoctor.Version, l.softwareGL && loaded == nil, commandLinePort{}); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	w.Resize(fyne.NewSize(look.WindowWidth, look.WindowHeight))
	w.CenterOnScreen()

	// When the toolkit gave no window, tried again in a second process with the
	// software renderer where one ships, and only then refused out loud. The
	// refusal goes to standard error for whatever started this, and to a
	// system dialog for the person, because the window that would have carried
	// it is what failed - and it says what became of the renderer, when there
	// is something to say. One dialog in all: a second process that refuses
	// shows its own and this one only passes its code on.
	// The title bar dark, as the window under it is (ADR122): once the
	// window is shown and so has a title bar, and after every change of
	// settings, which the toolkit answers by setting it from the system.
	keepDark(a.Settings(), w, darkTitleBar)
	darkThenRun := func() {
		darkTitleBar(w)
		a.Run()
	}
	return openOrRefuse(w, darkThenRun, secondAttemptFor(l, errOut).try, func(why error, panicked any) {
		sentence := refusal(causeFrom(said.String(), panicked))
		fmt.Fprintln(errOut, sentence)
		body := sentence
		if renderer := rendererSentence(why, loaded); renderer != "" {
			fmt.Fprintln(errOut, renderer)
			body += "\n\n" + renderer
		}
		sayInADialog(words.T(words.WindowRefusedTitle), body)
	})
}
