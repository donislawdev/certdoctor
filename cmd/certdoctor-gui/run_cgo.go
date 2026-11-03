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
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/screens"
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
// window was closed, 1 when the toolkit gave no window (ADR125 point 1).
// Arguments are not read yet - the flags of the window arrive with the code
// that needs them, and a window started from a shortcut with odd arguments
// opens all the same.
func run(_ []string, errOut io.Writer) int {
	// The toolkit says why a window failed through the standard logger, so a
	// copy is kept for the sentence of the refusal. The copy comes first, so a
	// standard error that is not there - a program built for the windows
	// subsystem has none - cannot stop it. Our own code never logs, so where
	// the window opens the copy stays empty.
	var said bytes.Buffer
	log.SetOutput(io.MultiWriter(&said, log.Writer()))

	a := app.NewWithID(appID)
	picture := fyne.NewStaticResource("certdoctor.png", icon.PNG)
	// The picture the desktop shows for this program, which the toolkit also
	// gives every window it opens - without it the toolkit's own logo stands
	// in the task bar under our name.
	a.SetIcon(picture)
	a.Settings().SetTheme(look.Theme())
	w := a.NewWindow(words.T(words.AppName))
	start, _ := screens.Start(picture, certdoctor.Version, false)
	// The smallest the window may be made (GUI rule 21): the toolkit keeps a
	// window no smaller than what it holds, so what it holds says so.
	w.SetContent(parts.AtLeast(look.WindowMinWidth, look.WindowMinHeight, start))
	w.Resize(fyne.NewSize(look.WindowWidth, look.WindowHeight))
	w.CenterOnScreen()

	// The refusal goes to standard error for whatever started this, and to a
	// system dialog for the person, because the window that would have
	// carried it is what failed.
	return openOrRefuse(w, a.Run, func(panicked any) {
		sentence := refusal(causeFrom(said.String(), panicked))
		fmt.Fprintln(errOut, sentence)
		sayInADialog(words.T(words.WindowRefusedTitle), sentence)
	})
}
