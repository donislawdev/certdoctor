package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

type outcome struct {
	code           int
	stdout, stderr string
}

func invoke(args []string, stdin io.Reader, stdout io.Writer, from tree) outcome {
	var out, errs bytes.Buffer
	if stdout == nil {
		stdout = &out
	}
	code := run(args, stdin, stdout, &errs, from)
	return outcome{code: code, stdout: out.String(), stderr: errs.String()}
}

func TestTheDocumentGoesToStandardOutputAndTheSummaryToStandardError(t *testing.T) {
	o := invoke(nil, strings.NewReader(fixtureListing()), nil, fixtureTree)
	if o.code != 0 {
		t.Fatalf("exit %d: %s", o.code, o.stderr)
	}
	var doc spdxDocument
	if err := json.Unmarshal([]byte(o.stdout), &doc); err != nil {
		t.Fatalf("standard output is not the document: %v", err)
	}
	if len(doc.Packages) != 4 {
		t.Errorf("%d packages, want the program, the standard library and two modules", len(doc.Packages))
	}
	want := "sbom: certdoctor 0.1.0 at 89c6fcaaf91f, 2 build(s) (linux/amd64, windows/arm64), 3 components beside the program\n"
	if o.stderr != want {
		t.Errorf("standard error is %q, want %q", o.stderr, want)
	}
}

func TestOneDocumentDescribesBothPrograms(t *testing.T) {
	o := invoke(nil, strings.NewReader(fixtureListing()+fixtureWindowListing()), nil, fixtureTree)
	if o.code != 0 {
		t.Fatalf("exit %d: %s", o.code, o.stderr)
	}
	want := "sbom: certdoctor 0.1.0 at 89c6fcaaf91f, 5 build(s) (certdoctor-gui darwin/arm64, certdoctor-gui linux/amd64, " +
		"certdoctor-gui windows/amd64, linux/amd64, windows/arm64), 9 components beside the programs\n"
	if o.stderr != want {
		t.Errorf("standard error is %q, want %q", o.stderr, want)
	}
}

// The notices this tree ships and a listing of builds of both programs that
// link what they name - the pair a release run feeds this command, short of
// building.
func TestTheShippedNoticesDescribeABuildThatLinksWhatTheyName(t *testing.T) {
	notes, err := parseTree(shippedTree)
	if err != nil {
		t.Fatal(err)
	}
	depsOf := func(n notices) map[string]string {
		deps := map[string]string{}
		for path, c := range n.modules {
			deps[path] = c.version
		}
		return deps
	}
	n, w := notes[programPath], notes[windowPath]
	listing := listingFor("dist/certdoctor", "linux/amd64", n.std.version, depsOf(n))
	for _, target := range []string{"windows/amd64", "linux/amd64", "darwin/arm64"} {
		listing += listingOf(windowPath, "dist/certdoctor-gui-"+target, target, w.std.version, depsOf(w))
	}
	o := invoke(nil, strings.NewReader(listing), nil, shippedTree)
	if o.code != 0 {
		t.Fatalf("exit %d: %s", o.code, o.stderr)
	}
	var doc spdxDocument
	if err := json.Unmarshal([]byte(o.stdout), &doc); err != nil {
		t.Fatal(err)
	}
	named := map[string]bool{}
	for _, p := range doc.Packages {
		named[p.Name] = true
	}
	for _, want := range []string{"certdoctor", "certdoctor-gui", "stdlib", "Inter", "Mesa 3D", "github.com/go-gl/gl", "github.com/dop251/goja"} {
		if !named[want] {
			t.Errorf("the document has no package %q", want)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the pipe broke") }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("the disk is full") }

func TestEveryWayTheCommandRefusesHasItsExitCode(t *testing.T) {
	mismatched := listingFor("dist/a", "linux/amd64", "go1.27.3", map[string]string{"example.com/alpha": "v1.2.3"})
	prerelease := fixtureTree
	prerelease.notices = strings.ReplaceAll(fixtureNotices, "go1.27.3", "go1.28rc1")
	for _, c := range []struct {
		name   string
		args   []string
		stdin  io.Reader
		stdout io.Writer
		from   tree
		code   int
		want   string
	}{
		{"arguments", []string{"-o", "x.json"}, strings.NewReader(""), nil, fixtureTree, 2, "usage:"},
		{"broken pipe", nil, failingReader{}, nil, fixtureTree, 2, "the pipe broke"},
		{"too much input", nil, strings.NewReader(strings.Repeat("x", inputCeiling+1)), nil, fixtureTree, 2, "is over"},
		{"not a listing", nil, strings.NewReader("hello\n"), nil, fixtureTree, 2, "names no binary"},
		{"notices unreadable", nil, strings.NewReader(fixtureListing()), nil, tree{notices: "no sections", version: "0.1.0"}, 1,
			"cannot describe a build"},
		{"disagreement", nil, strings.NewReader(mismatched), nil, fixtureTree, 1, "  the notices name example.com/beta/v2"},
		{"not a release toolchain", nil, strings.NewReader(strings.ReplaceAll(fixtureListing(), "go1.27.3", "go1.28rc1")), nil,
			prerelease, 1, "not a Go release"},
		{"output fails", nil, strings.NewReader(fixtureListing()), failingWriter{}, fixtureTree, 1, "the disk is full"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := invoke(c.args, c.stdin, c.stdout, c.from)
			if o.code != c.code || !strings.Contains(o.stderr, c.want) {
				t.Errorf("exit %d with %q, want %d with %q", o.code, o.stderr, c.code, c.want)
			}
			if o.stdout != "" {
				t.Errorf("a refusal wrote %d bytes of document", len(o.stdout))
			}
		})
	}
}
