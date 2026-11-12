//go:build cgo

package main

import (
	"context"

	"fyne.io/fyne/v2"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/screens"
)

// THE WINDOW HAS TWO PLACES, Diagnose and Tools (D23), with the tabs between
// them on the bar of every screen. Each place keeps its screen as it was left:
// a diagnosis that ends while Tools is shown lands on Diagnose without taking
// the window from under the person, and a tool's page keeps what was typed in
// it and its answer while a diagnosis is looked at (GUI rule 3).

// onScreen is a screen with what stands on its bar.
type onScreen struct {
	page  fyne.CanvasObject
	links []screens.Link
	tabs  *parts.Tabs
}

// steer wires the tabs of the screen shown: its own place chosen, a press on
// another going there.
func (win *window) steer(tabs *parts.Tabs, place int) {
	if tabs == nil {
		return
	}
	tabs.Reset(place)
	tabs.OnChosen = win.goTo
}

// showDiagnosis keeps a screen of a diagnosis and puts it in the window when
// Diagnose is the place shown, saying whether it did.
func (win *window) showDiagnosis(s onScreen) bool {
	win.diagnosis = s
	if win.place != screens.PlaceDiagnose {
		return false
	}
	win.show(s.page, s.links, s.tabs, screens.PlaceDiagnose)
	return true
}

// goTo shows the place i of the window, as it was left.
func (win *window) goTo(i int) {
	win.place = i
	if i == screens.PlaceTools {
		win.showTools()
		return
	}
	if win.showDiagnosis(win.diagnosis) && win.diagnosis.page == win.start {
		win.w.Canvas().Focus(win.form.Address)
	}
}

// toolsPlace is the Tools screen, built the first time it is shown, and the
// run of each tool page that is running.
type toolsPlace struct {
	page fyne.CanvasObject
	view *screens.ToolsView
	runs map[string]*toolRun
}

// toolRun is one run of a tool, and how to end it.
type toolRun struct {
	stop context.CancelFunc
}

// end ends every tool's run - the window is closing.
func (t *toolsPlace) end() {
	for id, run := range t.runs {
		run.stop()
		delete(t.runs, id)
	}
}

// showTools shows the Tools screen, with the box of the tool shown ready to
// paste into.
func (win *window) showTools() {
	if win.tools.view == nil {
		win.buildTools()
	}
	v := win.tools.view
	win.show(win.tools.page, v.Links, v.Tabs, screens.PlaceTools)
	if p, ok := v.Pages[v.Shown()]; ok {
		win.w.Canvas().Focus(p.Inputs[p.Tool.Inputs[0].Name])
	}
}

// buildTools makes the Tools screen and wires every tool's page.
func (win *window) buildTools() {
	win.tools.page, win.tools.view = screens.Tools(win.icon, win.version)
	win.tools.runs = map[string]*toolRun{}
	for _, p := range win.tools.view.Pages {
		p.Run.OnTapped = func() { win.runTool(p) }
		p.Clear.OnTapped = func() { win.clearTool(p) }
		for _, box := range p.Inputs {
			box.OnChanged = func(string) { win.toolReady(p) }
		}
		win.toolReady(p)
	}
}

// toolReady lets a tool's action be pressed when every input has something
// in it and the tool is not already reading.
func (win *window) toolReady(p *screens.ToolPage) {
	if p.Ready() && win.tools.runs[p.Tool.ID] == nil {
		p.Run.Enable()
		return
	}
	p.Run.Disable()
}

// runTool hands what is typed into a tool's page to the command line, the
// way a diagnosis is handed to it (ADR141 point 7), and shows the answer
// when it comes.
func (win *window) runTool(p *screens.ToolPage) {
	if !p.Ready() || win.tools.runs[p.Tool.ID] != nil {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), flow.ToolLimit)
	run := &toolRun{stop: stop}
	win.tools.runs[p.Tool.ID] = run
	p.ShowRunning()
	win.toolReady(p)
	win.wait(ctx, win.port, flow.ToolArgs(p.Tool.ID), flow.ToolInput(p.Tool.ID, p.Request()),
		func(proc flow.Process) { win.toolAnswered(p, run, proc) })
}

// toolAnswered shows what came of a run of a tool - unless the run is no
// longer the page's, because Clear ended it.
func (win *window) toolAnswered(p *screens.ToolPage, run *toolRun, proc flow.Process) {
	if win.tools.runs[p.Tool.ID] != run {
		return
	}
	run.stop()
	delete(win.tools.runs, p.Tool.ID)
	a := flow.JudgeTool(p.Tool.ID, proc, win.version)
	switch {
	case a.Document != nil:
		p.ShowAnswer(*a.Document)
	case a.Refusal != "":
		p.ShowRefusal(a.Refusal)
	case a.Problem != nil:
		p.ShowProblem(a.Problem.Title, a.Problem.What, a.Problem.Todo, a.Problem.Printed)
	default:
		p.ShowReady()
	}
	win.toolReady(p)
}

// clearTool empties a tool's page and ends its run, if it has one.
func (win *window) clearTool(p *screens.ToolPage) {
	if run := win.tools.runs[p.Tool.ID]; run != nil {
		run.stop()
		delete(win.tools.runs, p.Tool.ID)
	}
	for _, box := range p.Inputs {
		box.SetText("")
	}
	p.ShowReady()
	win.toolReady(p)
}
