//go:build cgo

package main

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
	"github.com/donislawdev/certdoctor/internal/gui/screens"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// toolAnswer is what certdoctor tool jwt --json writes, as the window reads
// it - written out here rather than made, because the window's program sees
// the window's packages and nothing of the tools but their words.
const toolAnswer = `{"schema_version":"1.0","program":{"name":"certdoctor","version":"0.1.0"},"tool":"jwt",` +
	`"evaluated_at":"2026-11-12T12:00:00Z","notes":[],` +
	`"checks":[{"id":"expiry","status":"PASS","summary":"Valid for 50 minutes more."}],"data":{},` +
	`"view":[{"kind":"code","title":"Header","language":"json","body":"{}"}]}`

// TestADiagnosisThatEndsWhileToolsIsShownWaitsOnDiagnose - the window is not
// taken from under the person: the report lands on Diagnose, and is there
// when they go back to it.
func TestADiagnosisThatEndsWhileToolsIsShownWaitsOnDiagnose(t *testing.T) {
	win, h, _ := testWindow(t)
	win.form.Address.SetText("https://example.com")
	win.diagnose()
	// Pressed as a person presses them: the tab of the screen shown.
	win.diagnosis.tabs.Choose(screens.PlaceTools)
	h.runs[0].done(flow.Process{Out: exampleReport(t), Code: 4})
	if win.place != screens.PlaceTools || findButton(win.w.Content(), "Decode") == nil {
		t.Fatal("the report of a run took the window from the Tools screen")
	}
	if findButton(win.w.Content(), words.T(words.SaveReport)) != nil {
		t.Error("the report is drawn on Tools")
	}
	win.tools.view.Tabs.Choose(screens.PlaceDiagnose)
	if findButton(win.w.Content(), words.T(words.SaveReport)) == nil {
		t.Error("going back to Diagnose does not show the report that ended there")
	}
	// The tabs pressed on the Tools screen, and Tools again from the report:
	// each screen shown again shows its own place chosen.
	win.diagnosis.tabs.Choose(screens.PlaceTools)
	if win.tools.view.Tabs.Chosen() != screens.PlaceTools {
		t.Error("the Tools screen came back with Diagnose chosen on its bar")
	}
	win.tools.view.Tabs.Choose(screens.PlaceDiagnose)
	if win.diagnosis.tabs.Chosen() != screens.PlaceDiagnose {
		t.Error("the report came back with Tools chosen on its bar")
	}
}

// TestATokenGoesThroughTheCommandLineAndItsAnswerIsShown drives a tool's page
// the way a person does: nothing to press until a token is typed, Decode hands
// it over on standard input, and the answer is drawn.
func TestATokenGoesThroughTheCommandLineAndItsAnswerIsShown(t *testing.T) {
	win, h, _ := testWindow(t)
	win.goTo(screens.PlaceTools)
	p := win.tools.view.Pages["jwt"]
	if !p.Run.Disabled() {
		t.Error("Decode can be pressed with no token")
	}
	p.Inputs["token"].SetText("eyJ.eyJ.sig")
	if p.Run.Disabled() {
		t.Fatal("Decode cannot be pressed with a token typed")
	}
	p.Run.OnTapped()
	p.Run.OnTapped()
	if len(h.runs) != 1 || !slices.Equal(h.runs[0].args, flow.ToolArgs("jwt")) {
		t.Fatalf("%d run(s), asked %q", len(h.runs), h.runs[0].args)
	}
	var sent struct {
		Inputs map[string]struct{ Text string } `json:"inputs"`
	}
	if err := json.Unmarshal(h.runs[0].input, &sent); err != nil || sent.Inputs["token"].Text != "eyJ.eyJ.sig" {
		t.Errorf("the token went over as %s (%v)", h.runs[0].input, err)
	}
	if !p.Run.Disabled() {
		t.Error("Decode can be pressed again while the token is being read")
	}
	h.runs[0].done(flow.Process{Out: []byte(toolAnswer)})
	if findButton(win.w.Content(), words.T(words.Copy)) == nil {
		t.Error("the answer's code block is not drawn")
	}
	if p.Run.Disabled() {
		t.Error("Decode stays off after the answer came")
	}
}

func TestARefusalIsShownInTheCommandLinesWords(t *testing.T) {
	win, h, _ := testWindow(t)
	win.goTo(screens.PlaceTools)
	p := win.tools.view.Pages["jwt"]
	p.Inputs["token"].SetText("abc.def")
	p.Run.OnTapped()
	h.runs[0].done(flow.Process{Code: 3, Printed: []byte("certdoctor: the token has 2 part(s)\n")})
	if !showsText(win.w.Content(), "The token has 2 part(s).") {
		t.Error("the refusal is not shown as a sentence of its own")
	}
}

// TestClearAndClosingEndATokensRun - a run whose page was cleared, or whose
// window closed, is ended, and an answer that comes after is not drawn.
func TestClearAndClosingEndATokensRun(t *testing.T) {
	win, h, _ := testWindow(t)
	win.goTo(screens.PlaceTools)
	p := win.tools.view.Pages["jwt"]
	p.Inputs["token"].SetText("eyJ.eyJ.sig")
	p.Run.OnTapped()
	p.Clear.OnTapped()
	if h.runs[0].ctx.Err() == nil || p.Inputs["token"].Text != "" {
		t.Error("Clear left the run going or the token in the box")
	}
	h.runs[0].done(flow.Process{Out: []byte(toolAnswer)})
	if findButton(win.w.Content(), words.T(words.Copy)) != nil {
		t.Error("the answer of a cleared run was drawn")
	}
	p.Inputs["token"].SetText("eyJ.eyJ.sig")
	p.Run.OnTapped()
	win.closed()
	if len(h.runs) != 2 || h.runs[1].ctx.Err() == nil {
		t.Error("closing the window left a token being read")
	}
}
