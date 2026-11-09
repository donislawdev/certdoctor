package main

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// harness is one invocation with the outside world replaced.
//
// Nothing here can reach a clock, a terminal or a file system. The written map
// stands in for the disk, so a test - and the fuzz target especially - can
// exercise every path through --out without a single file appearing anywhere.
type harness struct {
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	written map[string][]byte
	code    exitcode.Code
}

func invoke(args ...string) *harness {
	return invokeAs(report.PrivilegeUnknown, args...)
}

// invokeAs is invoke with the privilege level the run reports.
//
// It exists because the report has to say something different depending on
// whether that level was established, and a test cannot elevate the process it
// runs in. The level arrives as a parameter for the same reason the clock does.
func invokeAs(level report.PrivilegeLevel, args ...string) *harness {
	return invokeIn(nil, level, args...)
}

// invokeIn is invokeAs with the environment L0 will read.
//
// A nil map is the ordinary case and means nothing is set. THE REAL ENVIRONMENT
// IS NEVER CONSULTED HERE, and that is not caution: the variables L0 reports are
// exactly the ones a developer machine behind a corporate proxy has set, so a
// test that read them would pass here and fail there, or worse, print somebody's
// internal proxy host into a test log.
//
// A name present with an empty value is a variable SET TO NOTHING, which is a
// different fact from absent and is one of the three states L0 has to tell
// apart.
func invokeIn(env map[string]string, level report.PrivilegeLevel, args ...string) *harness {
	return invokeAdjusted(env, level, nil, args...)
}

// savedPath is the one file the harness can read: a report saved with --json
// by a run of this same harness, so --from has a real document to write again
// and the fuzz target reaches that path as well as the run.
const savedPath = "saved.json"

// invokeAdjusted is invokeIn with a last word on the environment, for the
// tests that need a port to answer differently.
//
// Standard input is a terminal unless a test says otherwise, as it is for a
// person typing a command: --from - is refused for it, never left waiting.
func invokeAdjusted(env map[string]string, level report.PrivilegeLevel, adjust func(*environment),
	args ...string) *harness {
	h := &harness{written: map[string][]byte{}}
	live := environment{
		stdout: &h.stdout,
		stderr: &h.stderr,
		capability: func(bool) render.Capability {
			// A fixed answer. What a real console can render is decided by the
			// operating system, and a test that asked it would pass or fail
			// depending on where it ran.
			return render.Capability{}
		},
		now:       func() time.Time { return time.Unix(1_770_000_000, 0).UTC() },
		platform:  report.Platform{OS: "testos", Arch: "testarch"},
		privilege: level,
		lookupEnv: func(name string) (string, bool) {
			value, set := env[name]
			return value, set
		},
		writeFile: func(path string, data []byte) error {
			h.written[path] = data
			return nil
		},
		readSaved: func(path string) (io.ReadCloser, error) {
			if path != savedPath {
				return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
			}
			return io.NopCloser(bytes.NewReader(invoke("https://example.com", "--json").stdout.Bytes())), nil
		},
		stdin: func() (io.Reader, error) { return nil, errNothingPiped },
	}
	if adjust != nil {
		adjust(&live)
	}
	h.code = guarded(context.Background(), args, live)
	return h
}
