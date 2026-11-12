package flow

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/gui/words"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// TestTheWindowAsksAToolTheWayTheCommandLineReads holds the window's half of
// the request document to the command line's reader of it: what the window
// sends is what spec.ReadRequest accepts, with the text exactly as typed -
// quotes, line breaks and all - and never as an argument.
func TestTheWindowAsksAToolTheWayTheCommandLineReads(t *testing.T) {
	jwt, _ := spec.Find("jwt")
	typed := "Bearer \"eyJ.a.b\"\n\x1b[2Jtail"
	r, err := spec.ReadRequest(ToolInput("jwt", map[string]string{"token": typed}), jwt)
	if err != nil {
		t.Fatalf("the command line refuses the window's request: %v", err)
	}
	if got := r.Inputs["token"]; got.Text == nil || *got.Text != typed {
		t.Errorf("the token arrives as %+v", got)
	}
	for _, arg := range ToolArgs("jwt") {
		if strings.Contains(arg, "eyJ") {
			t.Errorf("the input is in the arguments: %q", ToolArgs("jwt"))
		}
	}
	if strings.Join(ToolArgs("jwt"), " ") != "tool jwt --request - --json" {
		t.Errorf("args %q", ToolArgs("jwt"))
	}
}

// toolDocument is a tool's answer as the command line writes it, of version.
func toolDocument(t *testing.T, version, tool string) []byte {
	t.Helper()
	jwt, _ := spec.Find("jwt")
	d, err := spec.NewDocument(jwt, version, "2026-11-12T12:00:00Z", spec.Outcome{
		Checks: []spec.Check{{ID: "expiry", Status: "PASS", Summary: "Valid."}},
		Data:   map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.Tool = tool
	out, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEveryEndingOfAToolsRunIsToldApart(t *testing.T) {
	for _, c := range []struct {
		name string
		p    Process
		want string // "answer", "refusal: <words>", "problem: <title>" or "nothing"
	}{
		{"an answer", Process{Out: toolDocument(t, "0.1.0", "jwt")}, "answer"},
		{"a refusal", Process{Code: 3, Printed: []byte("certdoctor: the token has 2 part(s) separated by dots\n")},
			"refusal: The token has 2 part(s) separated by dots."},
		{"a refusal that says nothing", Process{Code: 3}, "problem: " + words.T(words.ToolCrashedTitle)},
		{"the program missing", Process{Missing: true, Program: "certdoctor"}, "problem: " + words.T(words.MissingTitle)},
		{"the program not started", Process{StartFailed: errors.New("denied")}, "problem: " + words.T(words.NotStartedTitle)},
		{"past its time", Process{Stopped: context.DeadlineExceeded}, "problem: " + words.T(words.ToolOverranTitle)},
		{"ended by Clear", Process{Stopped: context.Canceled}, "nothing"},
		{"a crash", Process{Code: 1, Printed: []byte("panic: boom")}, "problem: " + words.T(words.ToolCrashedTitle)},
		{"a usage error", Process{Code: 2}, "problem: " + words.T(words.ToolCrashedTitle)},
		{"too long", Process{Out: []byte("{"), OutTooLong: true}, "problem: " + words.T(words.ToolUnreadableTitle)},
		{"not a document", Process{Out: []byte(`{"schema_version":"1.0"}`)}, "problem: " + words.T(words.ToolUnreadableTitle)},
		{"another version", Process{Out: toolDocument(t, "0.2.0", "jwt")}, "problem: " + words.T(words.VersionTitle)},
		{"another tool", Process{Out: toolDocument(t, "0.1.0", "pem")}, "problem: " + words.T(words.ToolUnreadableTitle)},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := JudgeTool("jwt", c.p, "0.1.0")
			got := "nothing"
			switch {
			case a.Document != nil:
				got = "answer"
			case a.Refusal != "":
				got = "refusal: " + a.Refusal
			case a.Problem != nil:
				got = "problem: " + a.Problem.Title
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
