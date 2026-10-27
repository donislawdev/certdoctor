package main

import (
	"context"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/trust"
)

// A FORGOTTEN PORT IS OUR OMISSION AND HAS TO READ AS OURS. Without this branch
// a build wired without probes would look exactly like a machine with no
// runtimes on it, which is a claim about somebody else made out of our own gap.
func TestNoTrustPortMeansNoProbesRatherThanNoRuntimes(t *testing.T) {
	got := trustInput(&options{}, environment{}, &url.URL{Scheme: "https"})
	if got.Probes != nil {
		t.Errorf("a missing port produced %d probe(s), want none", len(got.Probes))
	}
}

func TestTheTrustPortIsPassedThrough(t *testing.T) {
	env := environment{
		trustProbes: func(bool) map[string]trust.Probe {
			return map[string]trust.Probe{
				"git": func(context.Context, [][]byte) ([]report.TrustStore, error) { return nil, nil },
			}
		},
	}
	got := trustInput(&options{}, env, &url.URL{Scheme: "https"})
	if len(got.Probes) != 1 {
		t.Fatalf("%d probe(s) reached L5, want 1", len(got.Probes))
	}
	if _, present := got.Probes["git"]; !present {
		t.Error("the git probe did not reach L5 under its own id")
	}
}

// WHETHER THE TARGET IS AN ADDRESS REACHES THE PROBES, worked out once here -
// OBS202. An IP address in either family is one, a name made of digits and dots
// is not, and neither is a name that merely contains an address.
func TestWhetherTheTargetIsAnAddressReachesTheProbes(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://127.0.0.1:8444/":    true,
		"https://[::1]:8444/":        true,
		"https://[fe80::1%25eth0]/":  true,
		"https://example.com/":       false,
		"https://1.2.3.4.nip.io/":    false,
		"https://localhost:8444/":    false,
		"https://xn--bcher-kva.com/": false,
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		var handed *bool
		env := environment{trustProbes: func(addressed bool) map[string]trust.Probe {
			handed = &addressed
			return map[string]trust.Probe{}
		}}
		trustInput(&options{}, env, parsed)
		if handed == nil || *handed != want {
			t.Errorf("%s: the probes were handed %v, want %v", raw, handed, want)
		}
	}
}

// NODE_EXTRA_CA_CERTS REACHES THE COMMAND GENERATOR through the seam L0 reads,
// so a node command adds to the file Node reads rather than naming another -
// ADR111 part 7. A run with no seam has nothing set.
func TestTheFileNodeReadsReachesTheCommandGenerator(t *testing.T) {
	env := environment{
		trustProbes: func(bool) map[string]trust.Probe { return map[string]trust.Probe{} },
		lookupEnv: func(name string) (string, bool) {
			if name == "NODE_EXTRA_CA_CERTS" {
				return "/etc/ssl/extra.pem", true
			}
			return "", false
		},
	}
	if got := trustInput(&options{}, env, &url.URL{Scheme: "https"}); got.Machine.NodeExtraCACerts != "/etc/ssl/extra.pem" {
		t.Errorf("the generator was handed %q", got.Machine.NodeExtraCACerts)
	}
	env.lookupEnv = nil
	if got := trustInput(&options{}, env, &url.URL{Scheme: "https"}); got.Machine.NodeExtraCACerts != "" {
		t.Errorf("with no seam the generator was handed %q", got.Machine.NodeExtraCACerts)
	}
}

// THE NOTE IS DERIVED FROM THE REGISTRY, WHICH IS THE WHOLE POINT. Its
// predecessor said the matrix was absent while the binary printed one three
// lines below - caught by running the program, not by a test. A note built from
// the registry cannot drift that way, and this test is what says so.
func TestTheCoverageNoteNamesTheRuntimesThisBuildCanAsk(t *testing.T) {
	probes := liveEnvironment().trustProbes(false)
	note := trustCoverageNote(probes)

	if note.Field != "trust_matrix" {
		t.Errorf("the note is filed under %q", note.Field)
	}
	for _, descriptor := range trust.All() {
		if probes[descriptor.ID] == nil {
			continue
		}
		if !strings.Contains(note.Detail, descriptor.Runtime) {
			t.Errorf("the note does not name %q, which this build can ask: %q", descriptor.Runtime, note.Detail)
		}
	}
	// It must not claim the matrix is missing - that is the sentence that went
	// stale, and the reason this function exists at all.
	if strings.Contains(note.Detail, "absent from this report") {
		t.Errorf("the note still claims the matrix is absent: %q", note.Detail)
	}
}

// A DECLARED FAMILY WITH NO PROBE WIRED IS NOT NAMED AS ASKED - ADR103. The
// platform's own store is declared on every platform and read only on Windows,
// so a note built from the declarations would tell a Linux reader it had been
// asked. Pinned with a hand-built map, so the test means the same thing on every
// platform it runs on.
func TestTheCoverageNoteNamesOnlyWhatIsWired(t *testing.T) {
	only := map[string]trust.Probe{
		"git": func(context.Context, [][]byte) ([]report.TrustStore, error) { return nil, nil },
	}
	note := trustCoverageNote(only)
	if !strings.Contains(note.Detail, "(git)") {
		t.Errorf("the note does not name the one family that is wired: %q", note.Detail)
	}
	for _, descriptor := range trust.All() {
		if descriptor.ID != "git" && strings.Contains(note.Detail, descriptor.Runtime) {
			t.Errorf("the note names %q, which nothing here asked: %q", descriptor.Runtime, note.Detail)
		}
	}
}

// A FAMILY ANOTHER PROBE ASKS IS NAMED WHEN THAT PROBE IS WIRED, and not
// otherwise - pip's rows come from python's probe, ADR112 part 1.
func TestTheCoverageNoteNamesPipWhenPythonIsWired(t *testing.T) {
	none := func(context.Context, [][]byte) ([]report.TrustStore, error) { return nil, nil }
	note := trustCoverageNote(map[string]trust.Probe{report.RuntimePython: none})
	if !strings.Contains(note.Detail, "(python, pip)") {
		t.Errorf("a run asking python does not name pip: %q", note.Detail)
	}
	note = trustCoverageNote(map[string]trust.Probe{"git": none})
	if strings.Contains(note.Detail, "pip") {
		t.Errorf("a run not asking python names pip: %q", note.Detail)
	}
}

// A build with no probes at all is a real state - it is what a port to a new
// platform looks like before its first probe lands - and the note has to say
// that rather than claim a complete matrix.
func TestWithNoProbesTheNoteSaysTheMatrixIsEmpty(t *testing.T) {
	note := coverageNoteFor(nil)
	if note.Field != "trust_matrix" {
		t.Errorf("the note is filed under %q", note.Field)
	}
	if !strings.Contains(note.Detail, "empty") {
		t.Errorf("a build with no probes does not say the matrix is empty: %q", note.Detail)
	}
}

// liveEnvironment builds the real ports. Asking it for the probes proves the
// wiring exists at all - without this the binary could ship with L5 wired to
// nothing and every test above would still pass.
func TestTheLiveEnvironmentCarriesTheTrustProbes(t *testing.T) {
	probes := liveEnvironment().trustProbes(false)
	if _, present := probes["git"]; !present {
		t.Errorf("the live environment offers %d probe(s) and none of them is git", len(probes))
	}
}

// THE PLATFORM'S OWN STORE IS WIRED EXACTLY WHERE IT CAN BE READ - Windows by
// ADR103, Linux by ADR104. Both directions: missing on either is the probe a
// slice existed for never running, and present elsewhere - macOS until M3 - is
// a probe answering for a store it never opened.
func TestThePlatformStoreIsWiredExactlyWhereItCanBeRead(t *testing.T) {
	_, present := liveEnvironment().trustProbes(false)[report.RuntimeSystemStore]
	if want := runtime.GOOS == "windows" || runtime.GOOS == "linux"; present != want {
		t.Errorf("on %s the platform store probe is wired=%v, want %v", runtime.GOOS, present, want)
	}
}
