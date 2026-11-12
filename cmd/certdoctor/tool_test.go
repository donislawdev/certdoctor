package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// testToken is a JWS with a marker in its payload, so a test can ask whether
// anything repeated the token back. It expires an hour after the harness's
// clock.
var testToken = func() string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"sub":"MARKERSUBJECT","exp":1770003600}`)) + "." + enc(bytes.Repeat([]byte("s"), 32))
}()

// toolRun runs a tool's command line with stdin piped in, or - with stdin nil
// - a terminal on standard input handing over typed, and files the files it
// can open. Both nil is a build with no terminal to read.
func toolRun(stdin, typed *string, files map[string]string, args ...string) *harness {
	return invokeAdjusted(nil, report.PrivilegeUnknown, func(e *environment) {
		switch {
		case stdin != nil:
			e.stdin = func() (io.Reader, error) { return strings.NewReader(*stdin), nil }
		case typed != nil:
			e.stdin = func() (io.Reader, error) { return strings.NewReader(*typed), errNothingPiped }
		}
		e.openFile = func(limit int64) file.Source {
			return func(path string) (io.ReadCloser, error) {
				content, ok := files[path]
				switch {
				case !ok:
					return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
				case int64(len(content)) > limit:
					return nil, &file.TooLarge{}
				}
				return io.NopCloser(strings.NewReader(content)), nil
			}
		}
	}, args...)
}

func ptr(s string) *string { return &s }

func TestEveryToolOnTheListRuns(t *testing.T) {
	for _, tool := range spec.All {
		if runs[tool.ID] == nil {
			t.Errorf("%s is on the list and has no code joined to it in runs", tool.ID)
		}
	}
	for id := range runs {
		if _, ok := spec.Find(id); !ok {
			t.Errorf("runs joins code to %q, which is not on the list", id)
		}
	}
	for _, c := range spec.Categories {
		if categoryTitles[c] == "" {
			t.Errorf("the category %q has no heading in the list of tools", c)
		}
	}
}

func TestAToolReadsItsInputEveryWay(t *testing.T) {
	request := func(input string) *string {
		return ptr(`{"schema_version":"1.0","tool":"jwt","inputs":{"token":` + input + `}}`)
	}
	files := map[string]string{"t.txt": testToken + "\n"}
	for _, c := range []struct {
		name   string
		run    *harness
		prompt bool
	}{
		{"piped", toolRun(ptr(testToken+"\r\n"), nil, nil, "tool", "jwt", "--json"), false},
		{"pasted", toolRun(nil, ptr(testToken+"\r\nmore lines are not read\n"), nil, "tool", "jwt", "--json"), true},
		{"a file", toolRun(nil, nil, files, "tool", "jwt", "--file", "t.txt", "--json"), false},
		{"a request with text", toolRun(request(`{"text":"`+testToken+`"}`), nil, nil,
			"tool", "jwt", "--request", "-", "--json"), false},
		{"a request with bytes", toolRun(request(`{"base64":"`+base64.StdEncoding.EncodeToString([]byte(testToken))+`"}`),
			nil, nil, "tool", "jwt", "--request", "-", "--json"), false},
		{"a request with a path", toolRun(request(`{"path":"t.txt"}`), nil, files,
			"tool", "jwt", "--request", "-", "--json"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.run.code != exitcode.OK {
				t.Fatalf("exit %d: %s", c.run.code, c.run.stderr.String())
			}
			doc, err := spec.ReadDocument(c.run.stdout.Bytes())
			if err != nil {
				t.Fatalf("the window could not read what the command line wrote: %v", err)
			}
			var data struct {
				Payload struct{ Sub string } `json:"payload"`
			}
			if err := json.Unmarshal(doc.Data, &data); err != nil || data.Payload.Sub != "MARKERSUBJECT" {
				t.Errorf("data %s (%v)", doc.Data, err)
			}
			if doc.EvaluatedAt != "2026-02-02T02:40:00Z" {
				t.Errorf("evaluated_at %q is not the harness's clock", doc.EvaluatedAt)
			}
			if asked := strings.Contains(c.run.stderr.String(), "Paste the token and press Enter:"); asked != c.prompt {
				t.Errorf("asked for a paste: %v, want %v (stderr %q)", asked, c.prompt, c.run.stderr.String())
			}
		})
	}
}

func TestAToolRefusesWhatItCannotUse(t *testing.T) {
	big := strings.Repeat("a", 256<<10+1)
	for _, c := range []struct {
		name string
		run  *harness
		code exitcode.Code
		says string
	}{
		{"the token as an argument", toolRun(nil, nil, nil, "tool", "jwt", testToken), exitcode.Usage, "takes no argument"},
		{"a mistyped tool", toolRun(nil, nil, nil, "tool", "jtw"), exitcode.Usage, `"jtw" is not a tool`},
		{"the token where the name goes", toolRun(nil, nil, nil, "tool", testToken), exitcode.Usage, "not repeated here"},
		{"an unknown switch", toolRun(nil, nil, nil, "tool", "jwt", "--key", "k"), exitcode.Usage, "--help lists"},
		{"a format of the report", toolRun(ptr(testToken), nil, nil, "tool", "jwt", "--format", "md"), exitcode.Config,
			"format of the diagnosis"},
		{"an unknown format", toolRun(ptr(testToken), nil, nil, "tool", "jwt", "--format", "xml"), exitcode.Usage,
			"terminal or json"},
		{"two formats", toolRun(ptr(testToken), nil, nil, "tool", "jwt", "--json", "--format", "terminal"),
			exitcode.Config, "two different formats"},
		{"a request and a file", toolRun(nil, nil, nil, "tool", "jwt", "--request", "r", "--file", "t"),
			exitcode.Config, "Use one of them"},
		{"an empty file switch", toolRun(nil, nil, nil, "tool", "jwt", "--file="), exitcode.Config, "given no file"},
		{"a file that is not there", toolRun(nil, nil, nil, "tool", "jwt", "--file", "gone.txt"), exitcode.Config,
			"nothing is there"},
		{"a file over the limit", toolRun(nil, nil, map[string]string{"big": big}, "tool", "jwt", "--file", "big"),
			exitcode.Config, "larger than 256 KiB"},
		{"UTF-16", toolRun(ptr("\xff\xfea\x00"), nil, nil, "tool", "jwt"), exitcode.Config, "UTF-16"},
		{"a NUL byte", toolRun(ptr("abc\x00def"), nil, nil, "tool", "jwt"), exitcode.Config, "NUL byte at byte 4"},
		{"not UTF-8", toolRun(ptr("ab\xffMARKERSUBJECT"), nil, nil, "tool", "jwt"), exitcode.Config, "at byte 3"},
		{"piped over the limit", toolRun(ptr(big), nil, nil, "tool", "jwt"), exitcode.Config, "more than 256 KiB"},
		{"pasted over the limit", toolRun(nil, ptr(big+"\n"), nil, "tool", "jwt"), exitcode.Config, "pasted"},
		{"nothing to paste into", toolRun(nil, nil, nil, "tool", "jwt"), exitcode.Config, "nothing is piped in"},
		{"a request from a terminal", toolRun(nil, nil, nil, "tool", "jwt", "--request", "-"), exitcode.Config,
			"nothing is piped in"},
		{"a request for another input", toolRun(ptr(`{"schema_version":"1.0","tool":"jwt","inputs":{"key":{"text":"k"}}}`),
			nil, nil, "tool", "jwt", "--request", "-"), exitcode.Config, `gives "key"`},
		{"not a token", toolRun(ptr("MARKERSUBJECT.x"), nil, nil, "tool", "jwt"), exitcode.Config, "2 part(s)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.run.code != c.code || !strings.Contains(c.run.stderr.String(), c.says) {
				t.Errorf("exit %d, stderr %q - want %d saying %q", c.run.code, c.run.stderr.String(), c.code, c.says)
			}
			if c.run.stdout.Len() != 0 {
				t.Errorf("a refusal wrote to standard output: %q", c.run.stdout.String())
			}
			for _, secret := range []string{testToken[:20], "MARKERSUBJECT"} {
				if strings.Contains(c.run.stderr.String(), secret) {
					t.Errorf("the refusal repeats the input back: %q", c.run.stderr.String())
				}
			}
		})
	}
}

func TestTheToolPageShowsWhatTheTokenSays(t *testing.T) {
	run := toolRun(ptr("Bearer "+testToken), nil, nil, "tool", "jwt")
	if run.code != exitcode.OK {
		t.Fatalf("exit %d: %s", run.code, run.stderr.String())
	}
	page := run.stdout.String()
	for _, want := range []string{
		"tool jwt - JWT decoder", "judged at 2026-02-02T02:40:00Z", "NOTES\n  Took off \"Bearer\"",
		"UNKNOWN  Not checked", "PASS     Valid for 60 minutes more, until 2026-02-02 03:40:00 UTC.",
		"TOKEN\n", "TIMES\n", "Expires (exp)  2026-02-02 03:40:00 UTC  in 60 minutes", "HEADER\n  {\n    \"alg\": \"HS256\",",
		"PAYLOAD\n", "\"sub\": \"MARKERSUBJECT\"", "Read it before pasting it anywhere.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not say %q:\n%s", want, page)
		}
	}
}

// TestTheToolTextsFitThePage holds the list and every tool's help to the
// width of a page (ADR109), with the main help naming the tools.
func TestTheToolTextsFitThePage(t *testing.T) {
	texts := map[string]string{"the list": toolRun(nil, nil, nil, "tool").stdout.String()}
	for _, tool := range spec.All {
		texts[tool.ID+" --help"] = toolRun(nil, nil, nil, "tool", tool.ID, "--help").stdout.String()
	}
	for name, text := range texts {
		if text == "" {
			t.Errorf("%s printed nothing", name)
		}
		for _, line := range strings.Split(text, "\n") {
			if utf8.RuneCountInString(line) > 100 {
				t.Errorf("%s has a line of %d characters: %q", name, utf8.RuneCountInString(line), line)
			}
		}
	}
	if help := invoke("--help").stdout.String(); !strings.Contains(help, "certdoctor tool [<name>]") {
		t.Error("the main help does not name the tools")
	}
}
