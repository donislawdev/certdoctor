// Package words is the catalogue every word the window writes comes from.
// English only, and no translations: a key and its text. What the report
// says - the verdict, a layer's sentence, a finding - comes from the report
// and is not here.
package words

// Key names one piece of the window's own text.
type Key string

// RepositoryURL and SupportURL are where GitHub and Donate lead. Addresses
// rather than words - the same in every language - so outside the map. The
// repository's address is also the namespace of the software bill of
// materials (cmd/sbom), which the window cannot import, so a guard reads the
// two out of the source and holds them equal (internal/guard/window_test.go).
const (
	RepositoryURL = "https://github.com/donislawdev/certdoctor"
	SupportURL    = "https://donislawdev.com/support/"
)

const (
	AppName         Key = "app.name"
	StartTitle      Key = "start.title"
	StartLead       Key = "start.lead"
	StartPromise    Key = "start.promise"
	TargetCard      Key = "target.card"
	TargetLabel     Key = "target.label"
	TargetHint      Key = "target.hint"
	TargetExample   Key = "target.example"
	OptionsCard     Key = "options.card"
	OptionsNote     Key = "options.note"
	OptPAC          Key = "opt.pac"
	OptPACHint      Key = "opt.pac.hint"
	OptPACExample   Key = "opt.pac.example"
	OptTimeout      Key = "opt.timeout"
	OptTimeoutHint  Key = "opt.timeout.hint"
	OptLayerTimeout Key = "opt.layertimeout"
	OptLayerHint    Key = "opt.layertimeout.hint"
	OptTimeoutUnit  Key = "opt.timeout.unit"
	OptRedact       Key = "opt.redact"
	OptRedactHint   Key = "opt.redact.hint"
	Diagnose        Key = "action.diagnose"
	RunAgain        Key = "action.again"
	NewTarget       Key = "action.new"
	SaveReport      Key = "action.save"
	Copy            Key = "action.copy"
	Copied          Key = "action.copied"
	Cancel          Key = "action.cancel"

	VerdictCard  Key = "verdict.card"
	ExitCode     Key = "verdict.exit"
	Duration     Key = "verdict.duration"
	Privilege    Key = "verdict.privilege"
	Platform     Key = "verdict.platform"
	LayersHead   Key = "layers.head"
	FindingsHead Key = "findings.head"

	ColTrusts   Key = "matrix.trusts"
	ColRuntime  Key = "matrix.runtime"
	ColInstance Key = "matrix.instance"
	ColAnchors  Key = "matrix.anchors"
	ColChosen   Key = "matrix.chosen"
	TrustsYes   Key = "matrix.yes"
	TrustsNo    Key = "matrix.no"
	TrustsNot   Key = "matrix.notassessed"

	ReportFor     Key = "report.for"
	MatrixCard    Key = "matrix.card"
	ShowCommand   Key = "matrix.show"
	TargetCardNew Key = "target.cardnew"

	RunningTitle   Key = "running.title"
	RunningNote    Key = "running.note"
	RunningElapsed Key = "running.elapsed"
	RunningLayers  Key = "running.layers"
	OptionsClosed  Key = "options.closed"
	SaveJSON       Key = "save.json"
	SaveJSONNote   Key = "save.json.note"
	SaveHTML       Key = "save.html"
	SaveHTMLNote   Key = "save.html.note"
	SaveMD         Key = "save.md"
	SaveMDNote     Key = "save.md.note"
	EmptyLayer     Key = "layer.empty"
	Back           Key = "action.back"
	ShowFolder     Key = "action.folder"
	MissingTitle   Key = "problem.missing.title"
	MissingWhat    Key = "problem.missing.what"
	MissingTodo    Key = "problem.missing.todo"
	VersionTitle   Key = "problem.version.title"
	VersionWhat    Key = "problem.version.what"
	VersionTodo    Key = "problem.version.todo"
	RefusedTitle   Key = "problem.refused.title"
	RefusedTodo    Key = "problem.refused.todo"
	CrashedTitle   Key = "problem.crashed.title"
	CrashedWhat    Key = "problem.crashed.what"
	CrashedTodo    Key = "problem.crashed.todo"
	Printed        Key = "problem.printed"

	// What became of a run that gave no report to draw (ADR121): the cases
	// the window tells apart, each with what happened and what to do. Where a
	// sentence takes %s it is a path, a version, a number of seconds or the
	// system's own words without their full stop.
	CrashedWhatCode     Key = "problem.crashed.whatcode"
	SchemaWhat          Key = "problem.version.schema"
	NotStartedTitle     Key = "problem.notstarted.title"
	NotStartedWhat      Key = "problem.notstarted.what"
	NotStartedTodo      Key = "problem.notstarted.todo"
	UnreadableTitle     Key = "problem.unreadable.title"
	UnreadableLong      Key = "problem.unreadable.long"
	UnreadableNotReport Key = "problem.unreadable.notreport"
	UnreadableExit      Key = "problem.unreadable.exit"
	UnreadableEmpty     Key = "problem.unreadable.empty"
	UnreadableNoHead    Key = "problem.unreadable.nohead"
	UnreadableTodo      Key = "problem.unreadable.todo"
	OverranTitle        Key = "problem.overran.title"
	OverranWhat         Key = "problem.overran.what"
	OverranTodo         Key = "problem.overran.todo"
	PrintedCut          Key = "problem.printed.cut"
	RunningNoLimit      Key = "running.nolimit"
	LinkGitHub          Key = "link.github"
	LinkDonate          Key = "link.donate"
	LinkFailed          Key = "link.failed"
	LinkFailedNote      Key = "link.failed.note"

	// Save report: the dialog that names the file, and what it says while the
	// command line writes it (ADR121 (c)). Where a sentence takes %s it is the
	// name of a format, the name of a file, or a number of seconds.
	SaveTitle       Key = "save.title"
	SaveFolder      Key = "save.folder"
	SaveName        Key = "save.name"
	SaveEnding      Key = "save.ending"
	SaveChoose      Key = "save.choose"
	SaveChooseTitle Key = "save.choose.title"
	SaveUseFolder   Key = "save.choose.use"
	SaveButton      Key = "save.button"
	SaveReplace     Key = "save.replace"
	SaveClose       Key = "save.close"
	SaveNoFolder    Key = "save.nofolder"
	SaveNotWhole    Key = "save.notwhole"
	SaveNoName      Key = "save.noname"
	SaveForbidden   Key = "save.forbidden"
	SaveDevice      Key = "save.device"
	SaveTaken       Key = "save.taken"
	SaveTakenWhat   Key = "save.taken.what"
	SaveWriting     Key = "save.writing"
	SaveFailed      Key = "save.failed"
	SaveStopped     Key = "save.stopped"
	SaveEndedCode   Key = "save.ended.code"
	SaveEnded       Key = "save.ended"
	SaveDone        Key = "save.done"
	SaveDoneWhat    Key = "save.done.what"

	CommandHead   Key = "command.head"
	CommandNote   Key = "command.note"
	NeedsAdmin    Key = "command.admin"
	Placeholder   Key = "command.placeholder"
	ShowDetails   Key = "details.show"
	HideDetails   Key = "details.hide"
	CatalogueHint Key = "catalogue.hint"

	// When the toolkit gave no window (ADR125 point 1), and the build with no
	// window in it. The same sentence goes to standard error and, on Windows,
	// to a system dialog. Two literals for the refusal rather than one built
	// from pieces, so each reads whole. The cause is the toolkit's own
	// sentence, quoted.
	WindowRefusedTitle  Key = "refusal.title"
	WindowRefused       Key = "refusal.window"
	WindowRefusedCause  Key = "refusal.window.cause"
	NoWindowInThisBuild Key = "refusal.nocgo"

	// The second attempt at a window, with the software renderer shipped
	// beside it on Windows (ADR125 point 2): the note before the second start,
	// what a window asked for the renderer says about loading it, and what the
	// refusal adds about the renderer. Where a sentence takes %s it is a path
	// or the system's own words, without their full stop.
	SoftwareAgain       Key = "software.again"
	SoftwareDrawing     Key = "software.drawing"
	SoftwareNotShipped  Key = "software.notshipped"
	SoftwareNotLoaded   Key = "software.notloaded"
	SoftwareNotBeside   Key = "software.notbeside"
	SoftwareNotReadable Key = "software.notreadable"
	SoftwareStartFailed Key = "software.startfailed"
	SoftwareDidNotHelp  Key = "software.didnothelp"

	// What goes to standard error when the toolkit's own words could not be
	// given to it in English (OBS206), with the toolkit's reason. The window
	// opens all the same.
	ToolkitNotEnglish Key = "toolkit.notenglish"

	// The two places of the window on its bar, and the Tools screen (D23,
	// ADR141). What each tool is called is in tools.go, by its id.
	NavDiagnose         Key = "nav.diagnose"
	NavTools            Key = "nav.tools"
	ToolsTitle          Key = "tools.title"
	ToolsLead           Key = "tools.lead"
	ToolsHead           Key = "tools.head"
	ToolsSearch         Key = "tools.search"
	ToolsNoMatch        Key = "tools.nomatch"
	ToolClear           Key = "tool.clear"
	ToolChecks          Key = "tool.checks"
	ToolNotes           Key = "tool.notes"
	ToolRunning         Key = "tool.running"
	ToolRefusedTitle    Key = "tool.refused.title"
	ToolRefusedTodo     Key = "tool.refused.todo"
	ToolOverranTitle    Key = "tool.overran.title"
	ToolOverranWhat     Key = "tool.overran.what"
	ToolCrashedTitle    Key = "tool.crashed.title"
	ToolCrashedWhat     Key = "tool.crashed.what"
	ToolUnreadableTitle Key = "tool.unreadable.title"
	ToolUnreadableWhat  Key = "tool.unreadable.what"
	ToolVersionWhat     Key = "tool.version.what"
	ToolTodo            Key = "tool.todo"
	ToolInputTooLong    Key = "tool.input.toolong"
	ToolInputFull       Key = "tool.input.full"
)

var english = map[Key]string{
	NavDiagnose:         "Diagnose",
	NavTools:            "Tools",
	ToolsTitle:          "Tools",
	ToolsLead:           "Small tools for what stands around a connection. Each reads only what you give it here, connects to nothing and changes nothing.",
	ToolsHead:           "Tools",
	ToolsSearch:         "Search tools",
	ToolsNoMatch:        "No tool matches what is typed above.",
	ToolClear:           "Clear",
	ToolChecks:          "Checks",
	ToolNotes:           "Before reading it",
	ToolRunning:         "Reading what you gave it...",
	ToolRefusedTitle:    "This cannot be read",
	ToolRefusedTodo:     "Check what was pasted - the whole of it, and nothing else - and try again.",
	ToolOverranTitle:    "The tool did not finish in time",
	ToolOverranWhat:     "It was still running after %s s, so the window stopped it.",
	ToolCrashedTitle:    "The tool stopped without an answer",
	ToolCrashedWhat:     "It ended with exit code %d and wrote nothing to show.",
	ToolUnreadableTitle: "The tool wrote an answer this window cannot read",
	ToolUnreadableWhat:  "What it wrote is not an answer: %s.",
	ToolVersionWhat:     "This window is %s and the certdoctor beside it says %s, so its answer is not drawn.",
	ToolInputTooLong:    "This box takes at most %d KiB, so that was not put in. The command line reads up to %d KiB from a file: certdoctor tool %s --%s <file>",
	ToolInputFull:       "This box takes at most %d KiB, so that was not put in.",
	ToolTodo:            "Run certdoctor tool %s in a terminal with the same input to see what it says, and report it on GitHub.",

	AppName:         "Cert Doctor",
	StartTitle:      "Diagnose a connection",
	StartLead:       "Follows the whole path to an address - name lookup, proxy, TCP and TLS - and asks every trust store on this machine whether it trusts the server.",
	StartPromise:    "Nothing on this machine is changed. Fixes are commands for you to read, copy and run.",
	TargetCard:      "Target",
	TargetLabel:     "Address",
	TargetHint:      "An https:// or http:// address, as you would type it into a browser.",
	TargetExample:   "https://example.com",
	OptionsCard:     "Options",
	OptionsNote:     "The same switches as the command line. A field left empty does what the command line does without its switch.",
	OptPAC:          "PAC script",
	OptPACHint:      "Also read this proxy auto-config script and say where it sends the address.",
	OptPACExample:   "http://proxy.example/proxy.pac",
	OptTimeout:      "Time limit",
	OptTimeoutHint:  "For the whole run. Zero means no limit.",
	OptLayerTimeout: "Layer time limit",
	OptLayerHint:    "For each layer on its own. Zero means no limit.",
	OptTimeoutUnit:  "seconds",
	OptRedact:       "Mask names",
	OptRedactHint:   "Replace host names, paths and user names, for sharing the report. Credentials are masked either way.",
	Diagnose:        "Diagnose",
	RunAgain:        "Run again",
	NewTarget:       "New target",
	SaveReport:      "Save report",
	Copy:            "Copy",
	Copied:          "Copied",
	Cancel:          "Cancel",

	VerdictCard:  "Verdict",
	ExitCode:     "exit code",
	Duration:     "took",
	Privilege:    "ran",
	Platform:     "on",
	LayersHead:   "Layers",
	FindingsHead: "Findings",

	ColTrusts:   "Trusts this chain",
	ColRuntime:  "Runtime",
	ColInstance: "Where",
	ColAnchors:  "Anchors",
	ColChosen:   "Found by",
	TrustsYes:   "Yes",
	TrustsNo:    "No",
	TrustsNot:   "Not assessed",

	ReportFor:     "Report for",
	MatrixCard:    "Trust stores on this machine",
	ShowCommand:   "Command",
	TargetCardNew: "What should Cert Doctor reach?",

	RunningTitle:   "Diagnosing",
	RunningNote:    "Cert Doctor follows the path layer by layer and writes the report when every layer has answered or the time limit is reached.",
	RunningElapsed: "%s s of the %s s limit",
	RunningLayers:  "Context, name lookup, proxy, TCP, TLS and every trust store on this machine",
	OptionsClosed:  "System proxy settings, default time limits, names shown",
	SaveJSON:       "JSON",
	SaveJSONNote:   "The whole report as data, for another tool or for certdoctor --from",
	SaveHTML:       "HTML",
	SaveHTMLNote:   "One page to read in a browser or attach to a ticket",
	SaveMD:         "Markdown",
	SaveMDNote:     "Text to paste into a ticket or a chat",
	EmptyLayer:     "This layer has nothing to list on this machine.",
	Back:           "Back",
	ShowFolder:     "Show the folder",
	MissingTitle:   "certdoctor is missing beside this window",
	MissingWhat:    "The window runs the certdoctor program that came with it, from its own folder, and %s is not there.",
	MissingTodo:    "Unpack the whole download again, so both programs stand in one folder.",
	VersionTitle:   "certdoctor beside this window is another version",
	VersionWhat:    "This window is %s and the certdoctor beside it says %s. A report of another version is not drawn, so nothing on screen can be wrong.",
	VersionTodo:    "Unpack the whole download again, so both programs come from one release.",
	RefusedTitle:   "certdoctor did not accept this",
	RefusedTodo:    "Change the address or the options and try again.",
	CrashedTitle:   "certdoctor stopped without a report",
	CrashedWhat:    "The run ended before it wrote a report, so there is nothing to show.",
	CrashedTodo:    "Run it again. If it stops again, the same command in a terminal shows the same message.",
	Printed:        "What certdoctor printed",

	CrashedWhatCode:     "The run ended with exit code %d (%s) before it wrote a report, so there is nothing to show.",
	SchemaWhat:          "This window draws reports of schema %s, and the certdoctor beside it wrote schema %s. A report of another schema is not drawn, so nothing on screen can be wrong.",
	NotStartedTitle:     "certdoctor beside this window did not start",
	NotStartedWhat:      "The system did not start %s: %s.",
	NotStartedTodo:      "Check that this account may run the file, or unpack the whole download again.",
	UnreadableTitle:     "certdoctor wrote a report this window cannot read",
	UnreadableLong:      "The report is longer than %d MB, the most this window reads.",
	UnreadableNotReport: "What it wrote is not a report: %s.",
	UnreadableExit:      "The report says the run ended with exit code %d, and the program ended with %d.",
	UnreadableEmpty:     "The report has no layers to show.",
	UnreadableNoHead:    "What it wrote does not say which version of certdoctor wrote it, or in which schema.",
	UnreadableTodo:      "Run the same address in a terminal with certdoctor --json to see what it writes, and report it on GitHub.",
	OverranTitle:        "certdoctor did not finish in time",
	OverranWhat:         "It was still running %s s after its %s s limit, so the window stopped it.",
	OverranTodo:         "Run it again. If it stops again, the same address in a terminal shows where certdoctor waits.",
	PrintedCut:          "(the rest is longer than this window shows)",
	RunningNoLimit:      "%s s, with no time limit",
	LinkGitHub:          "GitHub",
	LinkDonate:          "Donate",
	LinkFailed:          "The page did not open",
	LinkFailedNote:      "This desktop did not hand it to a browser. Copy the address and open it yourself.",

	SaveTitle:       "Save the report as %s",
	SaveFolder:      "Folder",
	SaveName:        "Name",
	SaveEnding:      "%s is added when the name does not end with it.",
	SaveChoose:      "Choose",
	SaveChooseTitle: "The folder to save the report in",
	SaveUseFolder:   "Use this folder",
	SaveButton:      "Save",
	SaveReplace:     "Replace",
	SaveClose:       "Close",
	SaveNoFolder:    "Choose a folder to save the report in.",
	SaveNotWhole:    "The folder has to be a whole path, the way Choose gives it.",
	SaveNoName:      "Give the file a name.",
	SaveForbidden:   "A name cannot hold < > : \" / \\ | ? * or an invisible character. Windows keeps them for itself, and a saved report is often opened on another machine.",
	SaveDevice:      "%s is a name Windows keeps for a device, so no file can be called that.",
	SaveTaken:       "%s is already in this folder",
	SaveTakenWhat:   "Replace it with this report, or give the file another name.",
	SaveWriting:     "Saving the report",
	SaveFailed:      "The report was not saved",
	SaveStopped:     "certdoctor was still writing it %s s later, so the window stopped it.",
	SaveEndedCode:   "certdoctor ended with exit code %d (%s) without writing it.",
	SaveEnded:       "certdoctor ended without writing it.",
	SaveDone:        "Saved",
	SaveDoneWhat:    "The report is in this file, and Save report opens in its folder next time.",

	CommandHead:   "Command to add the authority",
	CommandNote:   "Read it before you run it. Cert Doctor never runs it for you.",
	NeedsAdmin:    "Needs administrator rights",
	Placeholder:   "Replace the parts in angle brackets before running it.",
	ShowDetails:   "Show details",
	HideDetails:   "Hide details",
	CatalogueHint: "Every part of the window, in every state.",

	WindowRefusedTitle:  "Cert Doctor could not open its window",
	WindowRefused:       "The window could not be opened: the graphics toolkit was not given one. The window draws through OpenGL 2.1, which a virtual machine without 3D acceleration or a remote desktop session may not offer. The certdoctor command line in the same folder needs no graphics and diagnoses the same way - run \"certdoctor --help\". To get the window, use a graphics driver that provides OpenGL 2.1.",
	WindowRefusedCause:  "The window could not be opened: the graphics toolkit was not given one. The toolkit said: %s. The window draws through OpenGL 2.1, which a virtual machine without 3D acceleration or a remote desktop session may not offer. The certdoctor command line in the same folder needs no graphics and diagnoses the same way - run \"certdoctor --help\". To get the window, use a graphics driver that provides OpenGL 2.1.",
	NoWindowInThisBuild: "certdoctor-gui: this build has no window in it. It was compiled without cgo, which the graphics toolkit needs to reach OpenGL. The certdoctor command line needs neither and diagnoses the same way - run \"certdoctor --help\". To get the window, use a certdoctor-gui built for this system.",

	SoftwareAgain:       "The first attempt to open the window gave no window - usually a graphics driver without OpenGL 2.1. Starting again with the software renderer from the opengl folder beside the program.",
	SoftwareDrawing:     "This window is drawn by the software renderer from the opengl folder beside the program (Mesa llvmpipe), not by the graphics driver. Everything works, and drawing is slower than with a driver that provides OpenGL 2.1.",
	SoftwareNotShipped:  "No software renderer ships for this system, so --software-gl changes nothing here.",
	SoftwareNotLoaded:   "The software renderer from the opengl folder beside the program could not be loaded: %s.",
	SoftwareNotBeside:   "The software renderer was not tried: %s is missing. It ships in the opengl folder of the Windows archive - put that folder back next to certdoctor-gui.exe and start the window again.",
	SoftwareNotReadable: "The software renderer was not tried: a file of it beside the program could not be read (%s). Check who may read the opengl folder next to certdoctor-gui.exe.",
	SoftwareStartFailed: "The software renderer was not tried: starting the window again did not work (%s).",
	SoftwareDidNotHelp:  "The software renderer from the opengl folder beside the program was loaded, and the graphics toolkit still could not open a window with it.",
	ToolkitNotEnglish:   "The menus and dialogs the graphics toolkit draws itself may follow this system's language rather than English: %s",
}

// The words of the catalogue screen - the hidden screen that shows every
// part in every state.
const (
	CatPalette    Key = "cat.palette"
	CatSurfaces   Key = "cat.surfaces"
	CatInks       Key = "cat.inks"
	CatStatuses   Key = "cat.statuses"
	CatAction     Key = "cat.action"
	CatPairs      Key = "cat.pairs"
	CatPairsNote  Key = "cat.pairs.note"
	CatType       Key = "cat.type"
	CatParts      Key = "cat.parts"
	CatMarks      Key = "cat.marks"
	CatBadges     Key = "cat.badges"
	CatButtons    Key = "cat.buttons"
	CatFields     Key = "cat.fields"
	CatCommands   Key = "cat.commands"
	CatMatrix     Key = "cat.matrix"
	CatRail       Key = "cat.rail"
	CatVerdict    Key = "cat.verdict"
	CatRest       Key = "cat.rest"
	CatHover      Key = "cat.hover"
	CatPress      Key = "cat.press"
	CatFocus      Key = "cat.focus"
	CatDisabled   Key = "cat.disabled"
	CatPrimary    Key = "cat.primary"
	CatSecondary  Key = "cat.secondary"
	CatQuiet      Key = "cat.quiet"
	CatEmpty      Key = "cat.empty"
	CatFilled     Key = "cat.filled"
	CatChecked    Key = "cat.checked"
	CatNeed       Key = "cat.need"
	CatTextPair   Key = "cat.textpair"
	CatShapePair  Key = "cat.shapepair"
	CatSampleLong Key = "cat.sample.long"
	CatOpen       Key = "cat.open"
	CatSelected   Key = "cat.selected"
	CatStates     Key = "cat.states"
	CatQuietHeart Key = "cat.quiet.heart"
	CatHeader     Key = "cat.header"
	CatTrackStart Key = "cat.track.start"
	CatTrackHalf  Key = "cat.track.half"
	CatTrackFull  Key = "cat.track.full"
	CatChanging   Key = "cat.changing"
	CatCopied     Key = "cat.copied"
	CatNothing    Key = "cat.nothing"
	CatSelFocus   Key = "cat.selected.focus"
	CatSave       Key = "cat.save"
	CatAsking     Key = "cat.save.asking"
	CatUnusable   Key = "cat.save.unusable"
	CatTaken      Key = "cat.save.taken"
	CatWriting    Key = "cat.save.writing"
	CatFailed     Key = "cat.save.failed"
	CatSaved      Key = "cat.save.saved"
	// The title of the window when it shows the catalogue (--catalogue), and
	// what goes to standard error when the report its parts are drawn from
	// could not be read - with the reason.
	CatWindow    Key = "cat.window"
	CatNoExample Key = "cat.noexample"
	// The tools' parts (D23): the tabs on the bar, a tool in the list, and
	// the three kinds of block a tool's answer is drawn with.
	CatToolsPage Key = "cat.toolspage"
	// CatLongLabel names a sample of long words under it - a short label,
	// because the long words as their own label run into the next cell.
	CatLongLabel Key = "cat.long.label"
	CatTabs      Key = "cat.tabs"
	CatToolList  Key = "cat.toollist"
	CatToolParts Key = "cat.toolparts"
	CatToolCode  Key = "cat.toolcode"
	// A tool's input box (ADR144): what it says under itself when it took
	// nothing of a paste over its limit.
	CatToolInput Key = "cat.toolinput"
	CatTooLong   Key = "cat.toolong"
)

var catalogue = map[Key]string{
	CatPalette:    "Palette",
	CatSurfaces:   "Surfaces and edges",
	CatInks:       "Inks",
	CatStatuses:   "Statuses",
	CatAction:     "Main action and keyboard",
	CatPairs:      "Measured contrast",
	CatPairsNote:  "WCAG 2.2: 4.5 for words (1.4.3), 3.0 for edges of controls, focus rings and marks (1.4.11). Measured from the values in look/palette.go, not judged by eye.",
	CatType:       "Ladder of type",
	CatParts:      "Parts",
	CatMarks:      "Status marks - inline, row, verdict",
	CatBadges:     "Badges, answers and chips",
	CatButtons:    "Buttons",
	CatFields:     "Boxes to type in and switches",
	CatCommands:   "Commands",
	CatMatrix:     "Trust matrix rows",
	CatRail:       "Layer list",
	CatVerdict:    "Verdict",
	CatRest:       "rest",
	CatHover:      "pointer over",
	CatPress:      "pressed",
	CatFocus:      "keyboard focus",
	CatDisabled:   "disabled",
	CatPrimary:    "Primary",
	CatSecondary:  "Secondary",
	CatQuiet:      "Quiet",
	CatEmpty:      "empty",
	CatFilled:     "filled",
	CatChecked:    "on",
	CatNeed:       "needs",
	CatTextPair:   "words",
	CatShapePair:  "edge or mark",
	CatSampleLong: "A deliberately long name that keeps going well past the width the column was given",
	CatOpen:       "open",
	CatSelected:   "selected",
	CatStates:     "States of a screen",
	CatQuietHeart: "Quiet, heart",
	CatHeader:     "Bar across the top",
	CatTrackStart: "just started",
	CatTrackHalf:  "under way",
	CatTrackFull:  "at the limit",
	CatChanging:   "set again while the screen stands",
	CatCopied:     "just copied",
	CatNothing:    "nothing to open",
	CatSelFocus:   "selected, keyboard focus",
	CatSave:       "Save report dialog",
	CatAsking:     "asking, with the name chosen",
	CatUnusable:   "a name that cannot be used",
	CatTaken:      "a file of that name in the folder",
	CatWriting:    "saving",
	CatFailed:     "not saved, in the command line's words",
	CatSaved:      "saved",
	CatWindow:     "Cert Doctor - every part of the window",
	CatNoExample:  "The catalogue could not be shown: the example report its parts are drawn from did not read (%s).",
	CatToolsPage:  "Tools - every part of a tool's page",
	CatLongLabel:  "long words, cut short",
	CatTabs:       "Places of the window",
	CatToolList:   "Tool list",
	CatToolParts:  "A tool's answer - checks and fields",
	CatToolCode:   "A tool's answer - code and text",
	CatToolInput:  "A tool's input",
	CatTooLong:    "a paste over what it takes",
}

// Kind is the name the window gives a kind of finding. The kinds are the
// report's closed list (docs/18 section 3c); an unknown one is shown as the
// report spells it.
func Kind(kind string) string {
	if s, ok := kinds[kind]; ok {
		return s
	}
	return kind
}

var kinds = map[string]string{
	"environment_variable": "Environment variable",
	"name_resolution":      "Name lookup",
	"tcp_connect":          "TCP connection",
	"tls_handshake":        "TLS handshake",
	"trust_store":          "Trust store",
	"signing_authority":    "Who signed the certificate",
	"proxy_stack":          "Proxy setting",
	"stack_divergence":     "Proxy settings that disagree",
	"pac_script":           "PAC script",
	"proxy_challenge":      "Proxy sign-in",
}

// Reason is the name the window gives a reason for UNKNOWN. The reasons are
// the report's closed list (docs/18 section 5).
func Reason(code string) string {
	if s, ok := reasons[code]; ok {
		return s
	}
	return code
}

var reasons = map[string]string{
	"unrecognized_output":  "Unrecognised output",
	"timeout":              "Time limit reached",
	"access_denied":        "Access denied",
	"probe_error":          "A probe failed",
	"skipped_budget":       "Skipped for time",
	"transport_error":      "No answer on the wire",
	"nothing_to_check":     "Nothing to check",
	"undetermined":         "Undetermined",
	"limit_exceeded":       "A limit of this program stopped it",
	"credentials_required": "The proxy asks who you are",
}

// Toolkit is the English of the words the graphics toolkit writes itself -
// the menu of a box to type in, the dialog that chooses a folder, the names
// of the days - keyed by the toolkit's own message identifiers, the ones in
// lang/translations/base.en.json of fyne v2.8.2. The window gives them to
// the toolkit under every language it carries words in, so a window on a
// Polish system says Copy rather than Kopiuj, as the rest of it does (D21,
// OBS206). A copy, so no caller can change what the next one is given.
func Toolkit() map[string]string {
	words := make(map[string]string, len(toolkit))
	for id, text := range toolkit {
		words[id] = text
	}
	return words
}

var toolkit = map[string]string{
	"Advanced":          "Advanced",
	"Cancel":            "Cancel",
	"Confirm":           "Confirm",
	"Copy":              "Copy",
	"Create Folder":     "Create Folder",
	"Cut":               "Cut",
	"Enter filename":    "Enter filename",
	"Error":             "Error",
	"Favourites":        "Favourites",
	"File":              "File",
	"Folder":            "Folder",
	"New Folder":        "New Folder",
	"No":                "No",
	"OK":                "OK",
	"Open":              "Open",
	"Paste":             "Paste",
	"Quit":              "Quit",
	"Redo":              "Redo",
	"Save":              "Save",
	"Select all":        "Select all",
	"Show Hidden Files": "Show Hidden Files",
	"Undo":              "Undo",
	"Yes":               "Yes",
	"file.name":         "Name",
	"file.parent":       "Parent",
	"friday":            "Friday",
	"friday.short":      "Fri",
	"monday":            "Monday",
	"monday.short":      "Mon",
	"saturday":          "Saturday",
	"saturday.short":    "Sat",
	"sunday":            "Sunday",
	"sunday.short":      "Sun",
	"thursday":          "Thursday",
	"thursday.short":    "Thu",
	"tuesday":           "Tuesday",
	"tuesday.short":     "Tue",
	"wednesday":         "Wednesday",
	"wednesday.short":   "Wed",
}

// T is the text of a key. A key with no text comes back as itself in angle
// brackets, so it cannot pass for a sentence.
func T(k Key) string {
	if s, ok := english[k]; ok {
		return s
	}
	if s, ok := catalogue[k]; ok {
		return s
	}
	return "<" + string(k) + ">"
}
