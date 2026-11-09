package flow

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

const version = "0.1.0"

// report is the example.com report the model is drawn from: version 0.1.0,
// schema 2.4, exit code 4, a verdict about L5.
func report(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "model", "testdata", "example-com.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// document is a small report of this window's version and schema.
func document(layer string, code int, layers ...string) []byte {
	var rows []string
	for _, id := range layers {
		rows = append(rows, fmt.Sprintf(`{"id":%q,"status":"PASS"}`, id))
	}
	return []byte(fmt.Sprintf(`{"schema_version":%q,"tool":{"version":%q},"verdict":{"exit_code":%d,"layer":%s},"layers":[%s]}`,
		model.SchemaVersion, version, code, layer, strings.Join(rows, ",")))
}

// TestCappedKeepsWhatFitsAndSaysThereWasMore - nothing is refused, so a child
// writing more than the window keeps ends as it would have.
func TestCappedKeepsWhatFitsAndSaysThereWasMore(t *testing.T) {
	for _, c := range []struct {
		limit  int
		writes []string
		kept   string
		over   bool
	}{
		{5, []string{"abc"}, "abc", false},
		{5, []string{"abc", "de"}, "abcde", false},
		{5, []string{"abc", "def"}, "abcde", true},
		{5, []string{"abcdef", "gh"}, "abcde", true},
		{0, []string{"a"}, "", true},
		{5, nil, "", false},
	} {
		c2 := NewCapped(c.limit)
		for _, w := range c.writes {
			if n, err := c2.Write([]byte(w)); n != len(w) || err != nil {
				t.Errorf("limit %d: writing %q answered %d, %v - a write is never refused", c.limit, w, n, err)
			}
		}
		if string(c2.Bytes()) != c.kept || c2.Over() != c.over {
			t.Errorf("limit %d, writes %q: kept %q over %v, want %q over %v", c.limit, c.writes, c2.Bytes(), c2.Over(), c.kept, c.over)
		}
	}
}

// TestEachEndOfARunIsJudgedAsWhatItIs is the order judge asks in, case by
// case: every kind, and the report when nothing stood in the way.
func TestEachEndOfARunIsJudgedAsWhatItIs(t *testing.T) {
	other := func(head string) []byte { return []byte(head) }
	for _, c := range []struct {
		label string
		p     Process
		want  Kind
	}{
		{"nothing beside the window", Process{Program: "x/certdoctor", Missing: true, Out: report(t), Code: 4}, Missing},
		{"the system did not start it", Process{Program: "x/certdoctor", StartFailed: errors.New("access is denied")}, NotStarted},
		{"stopped by the window's own deadline", Process{Stopped: context.DeadlineExceeded, Out: report(t), Code: 4}, Overran},
		{"a refusal of the options", Process{Code: 2, Printed: []byte("certdoctor: unknown flag")}, Refused},
		{"options that do not go together", Process{Code: 3}, Refused},
		{"broke on its own", Process{Code: 1}, Crashed},
		{"interrupted", Process{Code: 130}, Crashed},
		{"ended by a signal", Process{Code: -1}, Crashed},
		{"ended well and wrote nothing", Process{Code: 0}, Crashed},
		{"wrote more than the window reads", Process{Out: report(t), OutTooLong: true, Code: 4}, TooLong},
		{"wrote words", Process{Out: []byte("certdoctor: not a URL"), Code: 4}, NotAReport},
		{"wrote a document without a head", Process{Out: other(`{"verdict":{}}`), Code: 4}, NoHead},
		{"wrote another version", Process{Out: other(`{"schema_version":"2.4","tool":{"version":"0.2.0"}}`), Code: 4}, OtherVersion},
		{"wrote another schema", Process{Out: other(`{"schema_version":"3.0","tool":{"version":"0.1.0"}}`), Code: 4}, OtherSchema},
		{"a head the rest does not go with", Process{Out: other(`{"schema_version":"2.4","tool":{"version":"0.1.0"},"verdict":{"exit_code":"four"}}`), Code: 4}, NotAReport},
		{"a report of another exit code", Process{Out: report(t), Code: 5}, OtherExit},
		{"a report with no layers", Process{Out: document("null", 0), Code: 0}, NoLayers},
	} {
		got := judge(c.p, version, 60)
		if got.Trouble == nil {
			t.Errorf("%s: drawn as a report, want trouble %d", c.label, c.want)
			continue
		}
		if got.Trouble.Kind != c.want {
			t.Errorf("%s: trouble %d, want %d", c.label, got.Trouble.Kind, c.want)
		}
	}
}

// TestAReportOpensOnTheLayerItsVerdictIsAbout - and on the first when the
// verdict names none or one the report does not carry.
func TestAReportOpensOnTheLayerItsVerdictIsAbout(t *testing.T) {
	for _, c := range []struct {
		label string
		doc   []byte
		code  int
		open  int
	}{
		{"the example.com report, about L5", report(t), 4, 5},
		{"a verdict about L1", document(`"L1"`, 0, "L0", "L1", "L2"), 0, 1},
		{"a verdict about no layer", document("null", 0, "L0", "L1"), 0, 0},
		{"a verdict about a layer the report does not carry", document(`"L7"`, 0, "L0", "L1"), 0, 0},
	} {
		got := judge(Process{Out: c.doc, Code: c.code, Printed: []byte("a note")}, version, 60)
		if got.Trouble != nil {
			t.Errorf("%s: judged as trouble %d", c.label, got.Trouble.Kind)
			continue
		}
		if got.Open != c.open || len(got.Report.Layers) == 0 {
			t.Errorf("%s: opens on %d of %d layers, want %d", c.label, got.Open, len(got.Report.Layers), c.open)
		}
	}
}

// TestEveryTroubleIsSaidInWholeSentences - each kind has a title and a thing
// to do, every verb of its sentences is filled, no key stands in for words,
// and the facts the sentence names are in it.
func TestEveryTroubleIsSaidInWholeSentences(t *testing.T) {
	for _, c := range []struct {
		trouble Trouble
		names   []string
	}{
		{Trouble{Kind: Missing, Program: "C:/apps/certdoctor.exe"}, []string{"C:/apps/certdoctor.exe"}},
		{Trouble{Kind: NotStarted, Program: "/opt/certdoctor", Said: "permission denied."}, []string{"/opt/certdoctor", "permission denied."}},
		{Trouble{Kind: Overran, Limit: 2.5}, []string{"30 s after its 2.5 s limit"}},
		{Trouble{Kind: Refused, Printed: "certdoctor: --timeout: 1,5 is not a number"}, nil},
		{Trouble{Kind: Crashed, Code: 1}, []string{"exit code 1 (RUNTIME)"}},
		{Trouble{Kind: Crashed, Code: -1}, nil},
		{Trouble{Kind: Crashed, Code: 99}, nil},
		{Trouble{Kind: TooLong}, []string{"32 MB"}},
		{Trouble{Kind: NotAReport, Said: "invalid character 'c' looking for beginning of value"}, []string{"invalid character"}},
		{Trouble{Kind: NoHead}, nil},
		{Trouble{Kind: OtherVersion, Theirs: "0.2.0", Ours: "0.1.0"}, []string{"This window is 0.1.0", "says 0.2.0"}},
		{Trouble{Kind: OtherSchema, Theirs: "3.0", Ours: "2.4"}, []string{"schema 2.4", "wrote schema 3.0"}},
		{Trouble{Kind: OtherExit, Reported: 4, Code: 5}, []string{"exit code 4", "ended with 5"}},
		{Trouble{Kind: NoLayers}, nil},
	} {
		s := c.trouble.Sentences()
		whole := s.Title + "\n" + s.What + "\n" + s.Todo
		if s.Title == "" || s.Todo == "" || strings.Contains(whole, "%!") || strings.Contains(whole, "%s") ||
			strings.Contains(whole, "%d") || strings.Contains(whole, "<problem.") || strings.Contains(whole, "..") {
			t.Errorf("kind %d is said as %q", c.trouble.Kind, whole)
		}
		for _, name := range c.names {
			if !strings.Contains(whole, name) {
				t.Errorf("kind %d does not name %q: %q", c.trouble.Kind, name, whole)
			}
		}
		if s.Printed != c.trouble.Printed {
			t.Errorf("kind %d shows %q of what was printed, want %q", c.trouble.Kind, s.Printed, c.trouble.Printed)
		}
	}
	if got := (Trouble{Kind: Refused}).Sentences().What; got != "" {
		t.Errorf("a refusal adds %q to what the command line printed, which says it whole", got)
	}
	if got := (Trouble{Kind: Crashed, Code: -1}).Sentences().What; got != words.T(words.CrashedWhat) {
		t.Errorf("a process ended by a signal is said as %q", got)
	}
}

// TestWhatWasPrintedIsShownFromTheTop - its first lines, as text, the end of
// a line and space at the end of it dropped, and a line saying so when there
// was more.
func TestWhatWasPrintedIsShownFromTheTop(t *testing.T) {
	var long []string
	for i := range 25 {
		long = append(long, fmt.Sprintf("line %d", i))
	}
	cut := words.T(words.PrintedCut)
	for _, c := range []struct {
		label, printed string
		more           bool
		want           string
	}{
		{"nothing", "", false, ""},
		{"only space", " \r\n\t\n", false, ""},
		{"one line with its end", "certdoctor: not a URL\r\n", false, "certdoctor: not a URL"},
		{"space at the ends of lines", "a  \nb\t\n\n", false, "a\nb"},
		{"more lines than shown", strings.Join(long, "\n"), false, strings.Join(long[:20], "\n") + "\n" + cut},
		{"more bytes than kept", "panic: x\ngoroutine 1", true, "panic: x\ngoroutine 1\n" + cut},
		{"bytes that are not text", "a\xffb", false, "a\ufffdb"},
	} {
		if got := excerpt([]byte(c.printed), c.more); got != c.want {
			t.Errorf("%s: shown as %q, want %q", c.label, got, c.want)
		}
	}
	if got := judge(Process{Code: 2, Printed: []byte("certdoctor: unknown flag\n")}, version, 60); got.Trouble.Printed != "certdoctor: unknown flag" {
		t.Errorf("a refusal shows %q of what was printed", got.Trouble.Printed)
	}
}

// TestARunGoesFromStartToAnswerAndBack is the flow across the screens: a run
// begins with the command line its request says and the deadline its limit
// gives, an answer is taken once and only from the run that is running, and
// Cancel and Back lead to the start screen.
func TestARunGoesFromStartToAnswerAndBack(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f := New(version)
	if f.Phase() != Starting || f.Cancel() {
		t.Fatalf("a new flow is on %d, and Cancel did something", f.Phase())
	}
	asked := request.Request{Address: "https://example.com", Typed: map[string]string{"timeout": "10"}}
	first := f.Begin(asked, now)
	if f.Phase() != Running || !slices.Equal(first.Args, asked.Args()) || !first.Deadline.Equal(now.Add(10*time.Second+Grace)) {
		t.Fatalf("began on %d with %q and the deadline %v", f.Phase(), first.Args, first.Deadline)
	}
	if !f.Cancel() || f.Phase() != Starting || f.Finish(first.ID, Process{Out: report(t), Code: 4}) {
		t.Fatal("a cancelled run left the start screen, or its answer was taken")
	}
	second := f.Again(now)
	if second.ID == first.ID || !slices.Equal(second.Args, first.Args) || f.Request().Address != asked.Address {
		t.Fatalf("Again began %+v after %+v", second, first)
	}
	if f.Finish(first.ID, Process{Code: 1}) || f.Phase() != Running {
		t.Fatal("the answer of the cancelled run was taken by the one after it")
	}
	if !f.Finish(second.ID, Process{Out: report(t), Code: 4}) || f.Phase() != Reported || f.Outcome().Open != 5 {
		t.Fatalf("the answer was not drawn: phase %d, %+v", f.Phase(), f.Outcome().Trouble)
	}
	if f.Finish(second.ID, Process{Code: 1}) || f.Phase() != Reported {
		t.Fatal("a second answer of the same run was taken")
	}
	f.Back()
	if f.Phase() != Starting {
		t.Fatalf("Back from a report is on %d", f.Phase())
	}
	third := f.Begin(request.Request{Address: "x", Typed: map[string]string{"timeout": "0"}}, now)
	if !third.Deadline.IsZero() {
		t.Errorf("a run with no limit is stopped by the window at %v", third.Deadline)
	}
	f.Back()
	if f.Phase() != Running {
		t.Error("Back left a running run - only Cancel does that")
	}
	if !f.Finish(third.ID, Process{Code: 2}) || f.Phase() != Troubled || f.Outcome().Trouble.Kind != Refused {
		t.Fatalf("a refusal was not shown as one: phase %d", f.Phase())
	}
	f.Back()
	if f.Phase() != Starting {
		t.Errorf("Back from a trouble is on %d", f.Phase())
	}
}

// TestTheDeadlineIsTheLimitAndTheGrace - the overran sentence says the limit
// the run had, and a run given the longest limit still has a deadline a
// duration can hold.
func TestTheDeadlineIsTheLimitAndTheGrace(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f := New(version)
	run := f.Begin(request.Request{Address: "x", Typed: map[string]string{"timeout": "86400"}}, now)
	if want := now.Add(86400*time.Second + Grace); !run.Deadline.Equal(want) {
		t.Errorf("the longest limit gives the deadline %v, want %v", run.Deadline, want)
	}
	f.Finish(run.ID, Process{Stopped: context.DeadlineExceeded})
	if got := f.Outcome().Trouble; got == nil || got.Kind != Overran || got.Limit != 86400 {
		t.Errorf("an overrun is judged as %+v", got)
	}
}

// TestProgressIsTheTimeAgainstTheLimit - whole seconds, the share of the limit
// gone in whole seconds too and held between nothing and all of it, and no
// share without a limit.
func TestProgressIsTheTimeAgainstTheLimit(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f := New(version)
	f.Begin(request.Request{Address: "x"}, now)
	for _, c := range []struct {
		after time.Duration
		text  string
		share float32
	}{
		{-time.Second, "0 s of the 60 s limit", 0},
		{0, "0 s of the 60 s limit", 0},
		{15900 * time.Millisecond, "15 s of the 60 s limit", 0.25},
		{16 * time.Second, "16 s of the 60 s limit", 0.2667},
		{90 * time.Second, "90 s of the 60 s limit", 1},
	} {
		p := f.Progress(now.Add(c.after))
		if p.Text != c.text || !p.Bounded || p.Share < c.share-0.001 || p.Share > c.share+0.001 {
			t.Errorf("after %v: %+v, want %q at %v", c.after, p, c.text, c.share)
		}
	}
	f.Begin(request.Request{Address: "x", Typed: map[string]string{"timeout": "2.5"}}, now)
	if p := f.Progress(now.Add(time.Second)); p.Text != "1 s of the 2.5 s limit" {
		t.Errorf("a limit with a fraction is shown as %q", p.Text)
	}
	f.Begin(request.Request{Address: "x", Typed: map[string]string{"timeout": "0"}}, now)
	if p := f.Progress(now.Add(42 * time.Second)); p.Bounded || p.Share != 0 || p.Text != "42 s, with no time limit" {
		t.Errorf("a run with no limit shows %+v", p)
	}
}

// TestTheWindowKeepsNoMoreThanSaveReportCanHandBack holds the window's bound on
// a run's output to the command line's bound on a saved report: a report the
// window drew is one Save report hands back to certdoctor --from, and a window
// keeping more would draw reports it could not save.
func TestTheWindowKeepsNoMoreThanSaveReportCanHandBack(t *testing.T) {
	if MaxDocument > request.MaxReport {
		t.Errorf("the window keeps %d bytes of a run and --from reads %d", MaxDocument, request.MaxReport)
	}
	if MaxDocument < 1<<20 {
		t.Errorf("the window keeps %d bytes of a run, less than a report of a machine with many stores", MaxDocument)
	}
}
