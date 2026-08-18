package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/dns"
	"github.com/donislawdev/certdoctor/internal/adapter/privilege"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/allowed"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	corehandshake "github.com/donislawdev/certdoctor/internal/core/handshake"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	coretcp "github.com/donislawdev/certdoctor/internal/core/tcp"
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
	h := &harness{written: map[string][]byte{}}
	h.code = guarded(context.Background(), args, environment{
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
	})
	return h
}

// TestTheRawHostReachesTheResolvingLayerEvenUnderRedact is the guard for the one
// wiring mistake that would be invisible in every other test.
//
// run.Options.Target carries the target AFTER masking, and it is the obvious
// field to feed L1 from - it is right there, it is called Target, and under the
// default mode it even holds the real host. Under --redact it holds [host-1], so
// a run wired that way would ask this machine's resolvers to resolve the literal
// string [host-1], get NXDOMAIN from every one of them, and report a working
// machine as unable to resolve its own target.
//
// NOTHING ELSE WOULD NOTICE. The report would be well formed, the schema would
// validate, the verdict would agree with the rows, and the answer would be
// confidently wrong - which is the exact failure this product exists to prevent,
// committed by the product.
func TestTheRawHostReachesTheResolvingLayerEvenUnderRedact(t *testing.T) {
	for _, redacted := range []bool{false, true} {
		var asked []string
		h := &harness{written: map[string][]byte{}}
		args := []string{"https://internal.corp.example", "--format", "json"}
		if redacted {
			args = append(args, "--redact")
		}

		guarded(context.Background(), args, environment{
			stdout:     &h.stdout,
			stderr:     &h.stderr,
			capability: func(bool) render.Capability { return render.Capability{} },
			now:        func() time.Time { return time.Unix(1_770_000_000, 0).UTC() },
			platform:   report.Platform{OS: "testos", Arch: "testarch"},
			privilege:  report.PrivilegeUnknown,
			lookupEnv:  func(string) (string, bool) { return "", false },
			writeFile:  func(string, []byte) error { return nil },

			nameservers: func() (dns.Nameservers, error) {
				return dns.Nameservers{ToAsk: []string{"192.0.2.53"}, Known: []string{"192.0.2.53"}, From: "a test"}, nil
			},
			queryID: func() uint16 { return 1 },
			exchange: func(*allowed.Targets) resolve.Exchange {
				return func(_ context.Context, resolver string, query []byte) ([]byte, error) {
					// The name is read back out of the wire format, which is the
					// only place it can be checked without trusting the layer to
					// report what it actually sent.
					asked = append(asked, nameIn(query), resolver)
					return nil, resolve.ErrTimeout
				}
			},
		})

		if len(asked) == 0 {
			t.Fatalf("with --redact=%v no query was sent, so this proves nothing", redacted)
		}
		for _, value := range asked {
			if strings.Contains(value, "[") {
				t.Errorf("with --redact=%v a pseudonym was sent to a resolver: %q", redacted, value)
			}
		}
		if asked[0] != "internal.corp.example" {
			t.Errorf("with --redact=%v the layer was asked to resolve %q", redacted, asked[0])
		}
		if asked[1] != "192.0.2.53" {
			t.Errorf("with --redact=%v the query went to %q", redacted, asked[1])
		}
	}
}

// TestTheAllowedSetCarriesWhatWillActuallyBeDialled is inviolable rule 16 at the
// seam where it is easiest to break without noticing.
//
// The set stores strings and dial.Guarded compares strings, so allowing a bare
// address while dialling one with a port would refuse every query on a machine
// that works - and allowing the port form while something else dialled the bare
// one would let a connection through unchecked. Both failures look like the
// guard doing its job.
func TestTheAllowedSetCarriesWhatWillActuallyBeDialled(t *testing.T) {
	parsed, fault := readTarget(&options{target: "https://example.com/x"})
	if fault != nil {
		t.Fatalf("an ordinary URL was refused: %v", fault.message)
	}

	targets := allowedTargets(parsed, dns.Nameservers{
		// The last one is not an address. Windows keeps this setting as free
		// text, so somebody's registry can hold anything at all.
		Known: []string{"192.0.2.53", "2001:db8::53", "not-an-address"},
	})

	for _, resolver := range []string{"192.0.2.53", "2001:db8::53"} {
		dialled, err := dns.Target(resolver)
		if err != nil {
			t.Fatalf("%s could not be turned into a dial target: %v", resolver, err)
		}
		if reason, ok := targets.Permits(dialled); !ok {
			t.Errorf("%s will be dialled and the set refuses it", dialled)
		} else if reason != allowed.ReasonResolver {
			t.Errorf("%s is in the set as %q", dialled, reason)
		}
	}
	if _, ok := targets.Permits("example.com"); !ok {
		t.Error("the target the user asked about is not in the set")
	}
	if _, ok := targets.Permits("not-an-address:53"); ok {
		t.Error("something that is not an address reached the set of places this run may connect to")
	}
}

// TestTheSetAlsoCarriesTheSpellingThePlatformWillUse is ADR34, and the failure
// it defends against was measured rather than imagined.
//
// Probe S11 put "nameserver 2001:0DB8::1" in a container's resolv.conf and
// watched Go ask for "[2001:0DB8::1]:53" - the raw token joined with the port,
// which is what its own reader does. Our canonical form is "[2001:db8::1]:53",
// the set compares strings on purpose, and the guard therefore refused a
// resolver that was answering. Nothing in this program dials the raw form yet,
// and that is exactly why this belongs here now: the system view arrives next
// and this is the seam it lands on.
func TestTheSetAlsoCarriesTheSpellingThePlatformWillUse(t *testing.T) {
	parsed, fault := readTarget(&options{target: "https://example.com/x"})
	if fault != nil {
		t.Fatalf("an ordinary URL was refused: %v", fault.message)
	}

	targets := allowedTargets(parsed, dns.Nameservers{Known: []string{"2001:0DB8::1"}})

	for _, spelling := range []string{"[2001:0DB8::1]:53", "[2001:db8::1]:53"} {
		if reason, ok := targets.Permits(spelling); !ok {
			t.Errorf("the platform can ask for %s and the set refuses it", spelling)
		} else if reason != allowed.ReasonResolver {
			t.Errorf("%s is in the set as %q", spelling, reason)
		}
	}
}

// TestAMachineListingNoResolverStillHasOne is the other half of ADR34.
//
// An empty resolv.conf does not mean nothing will be asked - it means the
// platform asks loopback, which S11 measured by running: Go resolved the name
// through 127.0.0.1:53 while certdoctor reported having nobody to ask. Without
// these two entries the guard refuses the only resolver in play.
//
// AND THE OTHER DIRECTION IS PINNED IN THE SAME TEST, because it is the half
// that keeps the set narrow: a machine WITH a resolver never sends the platform
// to loopback, so loopback has no business being permitted there.
func TestAMachineListingNoResolverStillHasOne(t *testing.T) {
	parsed, fault := readTarget(&options{target: "https://example.com/x"})
	if fault != nil {
		t.Fatalf("an ordinary URL was refused: %v", fault.message)
	}

	empty := allowedTargets(parsed, dns.Nameservers{})
	for _, fallback := range dns.PlatformFallbackResolvers() {
		if _, ok := empty.Permits(fallback); !ok {
			t.Errorf("this machine lists no resolver, the platform will ask %s, and the set refuses it", fallback)
		}
	}

	listed := allowedTargets(parsed, dns.Nameservers{Known: []string{"192.0.2.53"}})
	for _, fallback := range dns.PlatformFallbackResolvers() {
		if _, ok := listed.Permits(fallback); ok {
			t.Errorf("a machine with its own resolver had %s permitted as well, which widens the set for nothing", fallback)
		}
	}
}

// TestAResolverThatCannotBeReadIsNotAMachineWithoutDNS covers the nil port.
//
// An empty list is a statement about somebody's machine. A build that could not
// look has no business making it, and the two send a reader to different places.
func TestAResolverThatCannotBeReadIsNotAMachineWithoutDNS(t *testing.T) {
	found, err := enumerate(environment{})
	if err == nil {
		t.Fatal("a build with no way to enumerate reported success")
	}
	if len(found.ToAsk) != 0 || len(found.Known) != 0 {
		t.Error("a failed enumeration still handed back resolvers")
	}
}

// TestEveryResolverIsHandedToTheMasking is ADR32 at the point of handover.
//
// The rule is enforced by the redaction, but the redaction only masks what it was
// told about - and the telling is one loop in one function, which is exactly the
// kind of line that gets deleted in a tidy-up with every other test still green.
func TestEveryResolverIsHandedToTheMasking(t *testing.T) {
	parsed, fault := readTarget(&options{target: "https://example.com"})
	if fault != nil {
		t.Fatalf("an ordinary URL was refused: %v", fault.message)
	}
	found := dns.Nameservers{Known: []string{"10.1.2.3", "10.4.5.6"}}

	redaction := redactionFor(&options{redact: true}, parsed, found)
	got := redaction.Text("asked 10.1.2.3 and then 10.4.5.6")
	for _, resolver := range found.Known {
		if strings.Contains(got, resolver) {
			t.Errorf("%s survived masking under --redact: %q", resolver, got)
		}
	}

	// The weaker mode leaves them, which is the documented behaviour rather than
	// an oversight: --redact is what promises names are hidden.
	plain := redactionFor(&options{}, parsed, found).Text("asked 10.1.2.3")
	if !strings.Contains(plain, "10.1.2.3") {
		t.Errorf("a resolver was masked without --redact: %q", plain)
	}
}

// TestQueryIdentifiersAreNotPredictable checks the one property that makes an
// off-path answer detectable at all.
//
// A counter would pass every other test in this repository: the layer would send
// queries, the parser would match identifiers, and every answer would come back
// clean. It would also make a forged reply trivial to land, and nothing in the
// report would look wrong.
func TestQueryIdentifiersAreNotPredictable(t *testing.T) {
	seen := map[uint16]int{}
	const draws = 512
	for i := 0; i < draws; i++ {
		seen[queryID()]++
	}
	// Sixteen bits over five hundred draws: a fair source lands a handful of
	// collisions and a counter or a constant lands far outside this.
	if len(seen) < draws*3/4 {
		t.Errorf("%d draws produced only %d distinct identifiers", draws, len(seen))
	}
	if len(seen) == 1 {
		t.Error("every query would carry the same identifier")
	}
}

// nameIn reads the question's name back out of a DNS query.
func nameIn(query []byte) string {
	var labels []string
	for at := 12; at < len(query); {
		length := int(query[at])
		if length == 0 || at+1+length > len(query) {
			break
		}
		labels = append(labels, string(query[at+1:at+1+length]))
		at += 1 + length
	}
	return strings.Join(labels, ".")
}

// TestOnlyASuccessfulRunWritesToStandardOutput is the channel guard.
//
// The rule is not "failures are quiet". It is that what goes to standard output
// is the DESCRIPTION of a run that happened, and a run that did not happen has
// no description. A run that could assess nothing did happen, and its report is
// a complete answer - so 5 prints in full while 2 and 3 print nothing at all.
// Reading the rule the other way would make this tool silent in precisely the
// situation it exists for.
func TestOnlyASuccessfulRunWritesToStandardOutput(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want exitcode.Code
	}{
		{"a run that assessed nothing", []string{"https://example.com"}, exitcode.Inconclusive},
		{"help", []string{"--help"}, exitcode.OK},
		{"version", []string{"--version"}, exitcode.OK},
		{"licence", []string{"--license"}, exitcode.OK},
		{"no target", nil, exitcode.Usage},
		{"unknown switch", []string{"https://example.com", "--nope"}, exitcode.Usage},
		{"target without a scheme", []string{"example.com"}, exitcode.Usage},
		{"two targets", []string{"https://a.example", "https://b.example"}, exitcode.Usage},
		{"format not built", []string{"https://example.com", "--format", "md"}, exitcode.Config},
		{"contradictory formats", []string{"https://example.com", "--json", "--format", "html"}, exitcode.Config},
		{"compare with nothing to compare", []string{"https://example.com", "--compare", "host,container"}, exitcode.Config},
		{"two places to run", []string{"https://example.com", "--in", "c", "--image", "i"}, exitcode.Config},
		{"opposite log levels", []string{"https://example.com", "--quiet", "--verbose"}, exitcode.Config},
		{"negative budget", []string{"https://example.com", "--timeout", "-1"}, exitcode.Config},
		{"budget that is not a number of seconds", []string{"https://example.com", "--timeout", "NaN"}, exitcode.Config},
		{"budget longer than a day", []string{"https://example.com", "--timeout", "1e300"}, exitcode.Config},
	}

	for _, c := range cases {
		h := invoke(c.args...)
		if h.code != c.want {
			t.Errorf("%s: ended with %s (%d), want %s (%d)\nstderr: %s",
				c.name, h.code.Name(), h.code.Int(), c.want.Name(), c.want.Int(), h.stderr.String())
			continue
		}
		printed := h.stdout.Len() > 0
		shouldPrint := c.want == exitcode.OK || c.want == exitcode.Diagnosis || c.want == exitcode.Inconclusive
		if printed != shouldPrint {
			t.Errorf("%s: ended with %s and wrote %d bytes to standard output, want %v",
				c.name, h.code.Name(), h.stdout.Len(), shouldPrint)
		}
		if !shouldPrint && h.stderr.Len() == 0 {
			t.Errorf("%s: ended with %s and said nothing anywhere", c.name, h.code.Name())
		}
	}
}

// TestASwitchAfterTheURLIsStillASwitch guards a defect that was measured rather
// than imagined.
//
// The standard library's flag package stops parsing at the first argument that
// is not a switch and reports nothing about it. Every example in this project's
// own plan puts the URL first, so without the pre-scan in splitTarget the
// command "certdoctor https://example.com --json" would print a terminal report,
// ignore --json, and say nothing about having done so. A program that looks like
// it worked is the worst thing this one can be.
func TestASwitchAfterTheURLIsStillASwitch(t *testing.T) {
	if out := invoke("https://example.com", "--json").stdout.String(); !strings.HasPrefix(out, "{") {
		t.Errorf("--json after the URL was ignored, the output starts:\n%.80s", out)
	}
	if h := invoke("https://example.com", "--format", "json"); !strings.HasPrefix(h.stdout.String(), "{") {
		t.Errorf("--format json after the URL was ignored, the output starts:\n%.80s", h.stdout.String())
	}
	// A switch taking a value must consume the value and not leave it looking
	// like a second URL.
	if h := invoke("https://example.com", "--timeout", "5"); h.code != exitcode.Inconclusive {
		t.Errorf("--timeout 5 after the URL ended with %s: %s", h.code.Name(), h.stderr.String())
	}
	// The same switch written with an equals sign takes no following argument,
	// and swallowing one would eat the URL.
	if h := invoke("--timeout=5", "https://example.com"); h.code != exitcode.Inconclusive {
		t.Errorf("--timeout=5 before the URL ended with %s: %s", h.code.Name(), h.stderr.String())
	}
}

// TestEveryEndingCarriesACodeFromTheTable is the second half of the same
// promise, and the one a pipeline actually depends on.
func TestEveryEndingCarriesACodeFromTheTable(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--help"}, {"--version"}, {"--license"}, {"https://example.com"},
		{"--"}, {"-"}, {"--out"}, {"--timeout"}, {"https://example.com", "--out", "report.json", "--json"},
	} {
		if code := invoke(args...).code; !code.Valid() {
			t.Errorf("%v ended with %d, which is not in the frozen table", args, code.Int())
		}
	}
}

// TestTheProcessCodeMatchesTheOneInsideTheReport keeps the redundancy in the
// machine readable document honest. A saved report whose exit_code disagrees
// with what the process returned is worse than one that carries no code at all.
func TestTheProcessCodeMatchesTheOneInsideTheReport(t *testing.T) {
	h := invoke("https://example.com", "--json")
	if h.code != exitcode.Inconclusive {
		t.Fatalf("the run ended with %s: %s", h.code.Name(), h.stderr.String())
	}

	var document struct {
		Verdict struct {
			ExitCode int `json:"exit_code"`
		} `json:"verdict"`
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &document); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	if document.Verdict.ExitCode != h.code.Int() {
		t.Errorf("the report says exit_code %d and the process returned %d",
			document.Verdict.ExitCode, h.code.Int())
	}
}

// TestTheTargetNeverCarriesACredential is the narrow, early form of the promise
// that credentials never reach a report.
//
// The masking function belongs to the next slice on purpose, so that no code
// capable of printing a password exists before it. This checks the consequence:
// until then the target is reduced to its origin, and nothing that could be a
// secret survives that.
func TestTheTargetNeverCarriesACredential(t *testing.T) {
	secrets := []string{"hunter2", "abc123token", "sessionid", "deep"}
	targets := []string{
		"https://user:hunter2@example.com/",
		"https://example.com/deep/path",
		"https://example.com/?token=abc123token",
		"https://example.com/#sessionid",
		"https://user:hunter2@example.com:8443/deep/path?token=abc123token#sessionid",
	}

	for _, target := range targets {
		for _, format := range []string{"terminal", "json"} {
			h := invoke(target, "--format", format)
			if h.code != exitcode.Inconclusive {
				t.Fatalf("%s as %s ended with %s: %s", target, format, h.code.Name(), h.stderr.String())
			}
			everything := h.stdout.String() + h.stderr.String()
			for _, secret := range secrets {
				if strings.Contains(everything, secret) {
					t.Errorf("%s as %s put %q in the output", target, format, secret)
				}
			}
		}
	}
}

// TestAReducedTargetSaysSoAndAnUntouchedOneDoesNot keeps the note above from
// becoming decoration. A note printed every time says nothing, and a note never
// printed hides that something was dropped.
func TestAReducedTargetSaysSoAndAnUntouchedOneDoesNot(t *testing.T) {
	if out := invoke("https://example.com/secret", "--json").stdout.String(); !strings.Contains(out, `"reduced"`) {
		t.Error("a target with a path was reduced and the report does not say so")
	}
	if out := invoke("https://example.com", "--json").stdout.String(); strings.Contains(out, `"reduced"`) {
		t.Error("a target with nothing to remove was reported as reduced")
	}
	if out := invoke("https://example.com/", "--json").stdout.String(); strings.Contains(out, `"reduced"`) {
		t.Error("a bare trailing slash was treated as something worth removing")
	}
}

// TestAnUndeterminedPrivilegeLevelIsAnnouncedAndAnEstablishedOneIsNot is the
// ban on silence applied to a metadata field.
//
// "unknown" is a legitimate answer here and it is also the answer that makes a
// later comparison of two reports meaningless, because certdoctor run as a user
// and as an administrator sees different trust stores. So it may never be
// quiet: a run that could not establish its level says so, in the notes and not
// only in the field.
//
// THE SECOND HALF MATTERS AS MUCH AS THE FIRST. A standing note that never goes
// away teaches people that notes are decoration, and then the one note that
// mattered is skipped with the rest. This is the shape that erodes on its own,
// because removing a note is the step nobody remembers.
func TestAnUndeterminedPrivilegeLevelIsAnnouncedAndAnEstablishedOneIsNot(t *testing.T) {
	unknown := invokeAs(report.PrivilegeUnknown, "https://example.com", "--json").stdout.String()
	if !strings.Contains(unknown, `"run.privilege_level"`) {
		t.Error("the level could not be established and the report does not say so")
	}

	for _, level := range []report.PrivilegeLevel{report.PrivilegeUser, report.PrivilegeElevated} {
		out := invokeAs(level, "https://example.com", "--json").stdout.String()
		if strings.Contains(out, `"run.privilege_level"`) {
			t.Errorf("level %q was established and the report still announces it was not", level)
		}
		if want := `"privilege_level": "` + string(level) + `"`; !strings.Contains(out, want) {
			t.Errorf("level %q is not in the document", level)
		}
	}
}

// TestTheLiveEnvironmentAsksForTheRealPrivilegeLevel pins the WIRING rather
// than the rule.
//
// Every other test here hands the level in through the harness, which is what
// makes them runnable anywhere - and it also means a build that stopped asking
// the operating system and passed a constant instead would leave all of them
// green, while every report on every machine said "unknown" for ever.
//
// NOTE: On a machine where the question genuinely fails this compares unknown
// against unknown and proves less. That is accepted: it is a pin on one line of
// wiring, not a statement about the platform.
func TestTheLiveEnvironmentAsksForTheRealPrivilegeLevel(t *testing.T) {
	if got, want := liveEnvironment().privilege, privilege.Level(); got != want {
		t.Errorf("the wiring reports %q where the platform answers %q", got, want)
	}
}

// TestEveryLayerInTheDocumentAppearsInTheTerminalReport is the parity rule.
// Every finding has to be expressible on every surface, and the way that erodes
// is one surface quietly gaining a row the others do not have.
func TestEveryLayerInTheDocumentAppearsInTheTerminalReport(t *testing.T) {
	terminal := invoke("https://example.com").stdout.String()

	var document struct {
		Layers []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(invoke("https://example.com", "--json").stdout.Bytes(), &document); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	if len(document.Layers) != len(layer.All) {
		t.Fatalf("the document has %d layers, there are %d declared", len(document.Layers), len(layer.All))
	}
	for _, row := range document.Layers {
		if !strings.Contains(terminal, row.ID) {
			t.Errorf("layer %s is in the document and not in the terminal report", row.ID)
		}
		if !strings.Contains(terminal, row.Status) {
			t.Errorf("status %s appears in the document and nowhere in the terminal report", row.Status)
		}
	}
}

// TestTheSameRunProducesTheSameBytes is the determinism property. Iteration over
// a Go map is randomised, so a renderer that walked one would reorder sections
// between runs of identical input - and every test written as a single
// comparison would still pass.
// THE EMPTINESS CHECK IS NOT DECORATION AND IT WAS ADDED AFTER A MEASUREMENT.
// Without it this test is satisfied by a program that prints NOTHING, because
// two empty strings are equal. That is not hypothetical: the mutation that makes
// the orchestrator walk its map instead of the registry produces rows in the
// wrong order, the report validator refuses them, and the run ends with an
// internal failure having written nothing at all. Sixteen silent runs agree
// perfectly. Measured 2026-08-04 over thirty runs of the register: the mutation
// was caught 13 times out of 30 - a guard that is a coin toss is not a guard,
// and it read as a clean pass in the summary line.
func TestTheSameRunProducesTheSameBytes(t *testing.T) {
	for _, format := range []string{"terminal", "json"} {
		first := invoke("https://example.com", "--format", format).stdout.String()
		if first == "" {
			t.Fatalf("a %s run produced no report at all, so comparing it with another proves nothing", format)
		}
		for attempt := 0; attempt < 15; attempt++ {
			again := invoke("https://example.com", "--format", format).stdout.String()
			if again == "" {
				t.Fatalf("a %s run produced no report at all, so comparing it with another proves nothing", format)
			}
			if again != first {
				t.Fatalf("two %s runs of the same command line differ", format)
			}
		}
	}
}

// TestThePanicPathEndsInRuntimeAndPrintsNothing covers the ending that would
// otherwise be reported to a pipeline as a usage error, because the Go runtime
// exits with 2 on a panic and 2 means USAGE in this table.
func TestThePanicPathEndsInRuntimeAndPrintsNothing(t *testing.T) {
	h := &harness{written: map[string][]byte{}}
	h.code = guarded(context.Background(), []string{"https://example.com"}, environment{
		stdout:     &h.stdout,
		stderr:     &h.stderr,
		capability: func(bool) render.Capability { panic("planted defect") },
		now:        func() time.Time { return time.Unix(0, 0) },
		platform:   report.Platform{OS: "testos", Arch: "testarch"},
		privilege:  report.PrivilegeUnknown,
		writeFile:  func(string, []byte) error { return nil },
	})

	if h.code != exitcode.Runtime {
		t.Errorf("a panic ended with %s (%d), want RUNTIME", h.code.Name(), h.code.Int())
	}
	if h.stdout.Len() != 0 {
		t.Errorf("a panic left %d bytes on standard output", h.stdout.Len())
	}
	if !strings.Contains(h.stderr.String(), "planted defect") {
		t.Errorf("the failure does not say what happened: %s", h.stderr.String())
	}
}

// TestAReportGoesToTheNamedPathAndNotToStandardOutput pins the two halves of
// --out. Writing to both would put internal data somewhere the user did not ask
// for, and writing to neither would lose the report entirely.
func TestAReportGoesToTheNamedPathAndNotToStandardOutput(t *testing.T) {
	h := invoke("https://example.com", "--json", "--out", "report.json")

	if h.code != exitcode.Inconclusive {
		t.Fatalf("the run ended with %s: %s", h.code.Name(), h.stderr.String())
	}
	if h.stdout.Len() != 0 {
		t.Errorf("the report was written to a file and %d bytes still went to standard output", h.stdout.Len())
	}
	written, ok := h.written["report.json"]
	if !ok {
		t.Fatalf("nothing was written to report.json, only to %v", keysOf(h.written))
	}
	if err := render.ValidateDocument(written); err != nil {
		t.Errorf("the written document does not match the declared schema:\n%v", err)
	}
}

// TestNothingIsWrittenWhenTheReportGoesToStandardOutput is the other side. A run
// without --out must not touch the file system at all.
func TestNothingIsWrittenWhenTheReportGoesToStandardOutput(t *testing.T) {
	for _, args := range [][]string{
		{"https://example.com"},
		{"https://example.com", "--json"},
		{"https://example.com", "--out", "-"},
		{"--help"},
	} {
		if h := invoke(args...); len(h.written) != 0 {
			t.Errorf("%v wrote %v", args, keysOf(h.written))
		}
	}
}

func keysOf(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}

// documentedSwitch matches a long switch as it is written in help.
var documentedSwitch = regexp.MustCompile(`--[a-z][a-z0-9-]*`)

// TestAnUnknownSwitchIsNamedRatherThanTheURLBlamed covers a message that
// pointed at the only correct part of the command line.
//
// An unregistered switch consumed nothing, so whatever followed it became the
// URL and the real URL became an "unexpected extra argument". The person with a
// typo in a flag name went looking at their address. The same typo also read
// differently before and after the URL, which is two diagnoses for one mistake.
func TestAnUnknownSwitchIsNamedRatherThanTheURLBlamed(t *testing.T) {
	orders := [][]string{
		{"--unknown-flag", "value", "https://example.com"},
		{"https://example.com", "--unknown-flag"},
		{"--unknown-flag=value", "https://example.com"},
	}
	for _, args := range orders {
		h := invoke(args...)
		if h.code != exitcode.Usage {
			t.Errorf("%v ended %d, want %d", args, h.code, exitcode.Usage)
		}
		if !strings.Contains(h.stderr.String(), "unknown-flag") {
			t.Errorf("%v: the message does not name the switch: %q", args, h.stderr.String())
		}
		if strings.Contains(h.stderr.String(), "extra argument") {
			t.Errorf("%v: the message blames the URL: %q", args, h.stderr.String())
		}
	}
}

// TestAnExplicitFormatContradictingJSONIsRefused keeps two requests for two
// different formats from being settled quietly.
//
// --format md with --json was already refused. --format terminal with --json
// was not, because the value alone cannot be told from the default, so --json
// won and the run produced a document in a form nobody had asked for in those
// words. The same contradiction had two different answers.
func TestAnExplicitFormatContradictingJSONIsRefused(t *testing.T) {
	for _, args := range [][]string{
		{"--format", "terminal", "--json", "https://example.com"},
		{"--json", "--format", "terminal", "https://example.com"},
	} {
		h := invoke(args...)
		if h.code != exitcode.Config {
			t.Errorf("%v ended %d, want %d", args, h.code, exitcode.Config)
		}
		if h.stdout.Len() != 0 {
			t.Errorf("%v printed a report over a contradiction: %q", args, h.stdout.String())
		}
	}
	// The alias on its own is not a contradiction and still has to work.
	if h := invoke("--json", "https://example.com"); !strings.Contains(h.stdout.String(), `"schema_version"`) {
		t.Errorf("--json alone stopped producing a document: %q", h.stdout.String())
	}
}

// TestTwoMetaSwitchesAreRefusedRatherThanOneBeingDropped is the ban on silence
// applied to the switches that describe the tool. Each is a complete answer, so
// two of them are two answers - and the version printed the first in a fixed
// order and dropped the rest without a word.
func TestTwoMetaSwitchesAreRefusedRatherThanOneBeingDropped(t *testing.T) {
	for _, args := range [][]string{
		{"--version", "--license"},
		{"--help", "--version"},
	} {
		h := invoke(args...)
		if h.code != exitcode.Config {
			t.Errorf("%v ended %d, want %d", args, h.code, exitcode.Config)
		}
	}
	if h := invoke("--version"); h.code != exitcode.OK || h.stdout.Len() == 0 {
		t.Errorf("--version on its own stopped working: code %d, %q", h.code, h.stdout.String())
	}
}

// TestABudgetTooShortToHonourIsRefusedRatherThanBecomingNoLimit covers the one
// value of this flag whose meaning inverted.
//
// A duration is a whole number of nanoseconds, so 1e-30 seconds truncated to
// zero - and zero is the documented way of asking for NO limit. Somebody typing
// the strictest budget they could imagine got an unlimited run, and the report
// then said the budget had not been exceeded.
func TestABudgetTooShortToHonourIsRefusedRatherThanBecomingNoLimit(t *testing.T) {
	for _, flag := range []string{"--timeout", "--probe-timeout"} {
		h := invoke("https://example.com", flag, "1e-30")
		if h.code != exitcode.Config {
			t.Errorf("%s 1e-30 ended %d, want %d: %q", flag, h.code, exitcode.Config, h.stderr.String())
		}
		// Zero still means no limit, and that has to keep working.
		if h := invoke("https://example.com", flag, "0"); h.code != exitcode.Inconclusive {
			t.Errorf("%s 0 stopped meaning no limit: %d %q", flag, h.code, h.stderr.String())
		}
	}
}

// TestTheHostIsReportedWithoutRegardToCase keeps one machine from appearing as
// two.
//
// Names in DNS are case insensitive. Left as typed, EXAMPLE.COM and example.com
// produced two different targets for one machine - two reports that do not
// compare, a difference --compare would report where nothing changed, and two
// pseudonyms under --redact for one host.
func TestTheHostIsReportedWithoutRegardToCase(t *testing.T) {
	upper := invoke("HTTPS://EXAMPLE.COM/", "--json")
	lower := invoke("https://example.com/", "--json")
	if upper.stdout.String() != lower.stdout.String() {
		t.Errorf("the same machine produced two different reports:\n  %q\n  %q",
			upper.stdout.String(), lower.stdout.String())
	}
}

// TestAnErrorMessageDoesNotReplayWhatTheUserTypedUnescaped closes a way into
// somebody's terminal.
//
// The suggestion in the scheme message pasted the raw argument back with %s.
// The URL parser refuses ASCII control characters, which is what made this look
// safe - it does not refuse the ones above them, so a bidirectional override or
// a zero width character from a URL in a ticket came out unescaped into a
// console and into a log. This tool's output is evidence in an argument about
// somebody's network, so forging how it reads is a real harm.
func TestAnErrorMessageDoesNotReplayWhatTheUserTypedUnescaped(t *testing.T) {
	// Written as numbers rather than pasted in as characters. A test carrying an
	// invisible character in its own source is a test nobody can read, and this
	// file would then be doing the thing it exists to forbid.
	invisible := []rune{
		0x202e, // right-to-left override
		0x200b, // zero width space
		0x009b, // the eight bit form of the control sequence introducer
	}
	for _, char := range invisible {
		raw := "ftp://ex" + string(char) + "mple.com"
		h := invoke(raw)
		if h.code != exitcode.Usage {
			t.Errorf("%U ended %d, want %d", char, h.code, exitcode.Usage)
		}
		if strings.ContainsRune(h.stderr.String(), char) {
			t.Errorf("%U reached the log unescaped: %q", char, h.stderr.String())
		}
	}
}

// TestWritingAReportToAPathSaysWhereItWent is the ban on silence over the only
// irreversible thing this program does. A successful --out used to produce
// nothing on either channel, so a typo in the path and a report written were
// indistinguishable until somebody went looking for the file.
func TestWritingAReportToAPathSaysWhereItWent(t *testing.T) {
	h := invoke("https://example.com", "--out", "report.json", "--json")
	if h.stdout.Len() != 0 {
		t.Errorf("a report going to a file also reached standard output: %q", h.stdout.String())
	}
	if !strings.Contains(h.stderr.String(), "report.json") {
		t.Errorf("nothing said where the report went: %q", h.stderr.String())
	}
}

// TestANumberWrittenWithACommaIsAnsweredWithTheDotItNeeds covers the wrong value
// this flag is most likely to be given.
//
// A Polish, German or French keyboard makes "1,5" the reflex, and the flag
// package answered it with `invalid value "1,5" for flag -timeout: parse error`
// - a switch named with one dash where every other line of this program uses
// two, and "parse error" as the explanation. The person who typed the comma is
// told nothing about the comma.
func TestANumberWrittenWithACommaIsAnsweredWithTheDotItNeeds(t *testing.T) {
	for _, args := range [][]string{
		{"https://example.com", "--timeout", "1,5"},
		{"https://example.com", "--timeout=1,5"},
		{"https://example.com", "--probe-timeout", "2,5"},
	} {
		h := invoke(args...)
		said := h.stderr.String()
		if h.code != exitcode.Usage {
			t.Errorf("%v ended %d, want %d", args, h.code, exitcode.Usage)
		}
		if !strings.Contains(said, "decimal point") {
			t.Errorf("%v: the message does not mention the decimal point: %q", args, said)
		}
		// The switch is named the way this program names switches everywhere
		// else, and the message says what to write instead.
		if !strings.Contains(said, "--timeout 1.5") && !strings.Contains(said, "--probe-timeout 2.5") {
			t.Errorf("%v: the message does not show the value to write: %q", args, said)
		}
	}
	// A value that is not a number for any other reason still says so, and a
	// value that IS a number still works.
	if h := invoke("https://example.com", "--timeout", "abc"); !strings.Contains(h.stderr.String(), "not a number") {
		t.Errorf("a non-numeric value was not named as such: %q", h.stderr.String())
	}
	if h := invoke("https://example.com", "--timeout", "1.5"); h.code != exitcode.Inconclusive {
		t.Errorf("a perfectly good number was refused: %d %q", h.code, h.stderr.String())
	}
}

// TestEveryFlagIsDocumentedAndEveryDocumentedFlagExists is the cheap guard the
// CLI rules ask for from the first flag onwards.
//
// Both directions matter and they fail differently. A switch accepted and not
// documented is a feature nobody can find. A switch documented and not accepted
// is worse: somebody types it, gets a usage error, and stops trusting the page.
//
// The declarations and the page are built from one table, so this cannot catch
// a mismatch between those two. What it catches is a switch registered straight
// onto the flag set, bypassing the table, and a name written into the page's
// prose by hand.
func TestEveryFlagIsDocumentedAndEveryDocumentedFlagExists(t *testing.T) {
	fs, _ := newFlagSet()
	page := helpText()

	registered := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		registered[f.Name] = true
		long, short := "--"+f.Name, "-"+f.Name
		if !strings.Contains(page, long) && !strings.Contains(page, short) {
			t.Errorf("the switch %s is accepted and does not appear in --help", long)
		}
	})
	if len(registered) == 0 {
		t.Fatal("no switches are registered, so this test would pass while checking nothing")
	}

	for _, mentioned := range documentedSwitch.FindAllString(page, -1) {
		name := strings.TrimPrefix(mentioned, "--")
		if !registered[name] {
			t.Errorf("--help mentions %s and nothing accepts it", mentioned)
		}
	}
}

// TestTheTargetIsMaskedRatherThanReducedToItsOrigin is the expiry of the rule
// that stood in for masking while masking was not wired to anything.
//
// The report used to show scheme, host and port and drop everything else, saying
// so in a note. That was strictly narrower than masking, deliberately, so that
// no code existed which could print a password. Now the whole URL is shown with
// the dangerous parts taken out by POSITION: user info replaced, every query
// value replaced with its name kept, the path reduced to one marker.
//
// The parameter NAME surviving is half the diagnosis - "your URL carries a
// token" can be said without saying the token - and it is the half a reduction
// to the origin threw away.
func TestTheTargetIsMaskedRatherThanReducedToItsOrigin(t *testing.T) {
	out := invoke("https://example.com/session/abc123?token=xyz789", "--json").stdout.String()

	for _, secret := range []string{"abc123", "xyz789", "session"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q reached the report", secret)
		}
	}
	if !strings.Contains(out, "token") {
		t.Error("the name of the query parameter was dropped, and that name is half the diagnosis")
	}
	if !strings.Contains(out, "example.com") {
		t.Error("the host was removed without --redact having been asked for")
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("nothing in the target was marked as removed:\n%s", out)
	}
}

// TestARedactedRunMasksTheTargetHostAndSaysSo is the flag doing something at
// last. It used to be accepted and announced as having changed nothing, which is
// the only honest thing to say about an option that does not work - and that
// note has to disappear the day it starts working, or notes become decoration.
func TestARedactedRunMasksTheTargetHostAndSaysSo(t *testing.T) {
	out := invoke("https://internal.corp.example/", "--redact", "--json").stdout.String()

	if strings.Contains(out, "internal.corp.example") {
		t.Error("--redact was asked for and the host is still in the report")
	}
	if !strings.Contains(out, `"redacted": true`) {
		t.Error("names were masked and the report does not say so")
	}
	if strings.Contains(out, "no_effect") {
		t.Error("--redact now changes the report and still claims it changed nothing")
	}

	// The other side: without the flag the host stays, because the floor removes
	// credentials and nothing else.
	plain := invoke("https://internal.corp.example/", "--json").stdout.String()
	if !strings.Contains(plain, "internal.corp.example") {
		t.Error("the host was masked without --redact, which is not what the floor does")
	}
	if !strings.Contains(plain, `"redacted": false`) {
		t.Error("no stronger mode was asked for and the report claims names were masked")
	}
}

// TestTheEntryPointHandsTheTargetHostToTheMasking is the wiring half of ADR26,
// and it exists because nothing else can see it yet.
//
// The rule has two halves: masking can pseudonymise a bare host name handed to
// it, and the entry point has to hand the target over. The first half is guarded
// in the masking package. The SECOND half has no witness until L1 produces a bare
// name, because every host in today's report sits inside a URL, where the pattern
// rule finds it whether or not it was handed over.
//
// So this reaches for the redaction the entry point built and asks it directly.
// Without this, the handover could be deleted with every test in the repository
// still green - which is the shape "the tool exists and the rule is not enforced"
// takes, and this project has paid for that once already with masking itself.
func TestTheEntryPointHandsTheTargetHostToTheMasking(t *testing.T) {
	for _, c := range []struct {
		flag   bool
		masked bool
	}{{flag: true, masked: true}, {flag: false, masked: false}} {
		o := &options{target: "https://internal.corp.example/a", redact: c.flag}
		parsed, fault := readTarget(o)
		if fault != nil {
			t.Fatalf("an ordinary URL was refused: %v", fault.message)
		}
		// Built the way the entry point builds it, resolvers and all. Reaching
		// for redactionFor rather than for a redaction made here is the point:
		// the handover could be deleted with every other test still green.
		redaction := redactionFor(o, parsed, dns.Nameservers{})

		// A BARE name, with no URL around it - which is what an L1 finding carries
		// and the one shape the pattern rule cannot find on its own.
		got := redaction.Text("internal.corp.example answered")
		if masked := !strings.Contains(got, "internal.corp.example"); masked != c.masked {
			t.Errorf("with --redact=%v a bare target host came back as %q", c.flag, got)
		}
	}
}

// TestNoEnvironmentCredentialReachesEitherSurface is the end this whole ordering
// was built for, checked on the real command line rather than on a fixture.
//
// The masking function was written BEFORE the layer that produces values to
// mask, deliberately, so that no version of this program ever existed with code
// that printed a password. This is the test that says the arrangement worked:
// the value goes in raw at the layer, and neither surface shows it.
func TestNoEnvironmentCredentialReachesEitherSurface(t *testing.T) {
	const secret = "s3kret"
	env := map[string]string{"HTTPS_PROXY": "http://someone:" + secret + "@proxy.example:8080"}

	for _, format := range []string{"terminal", "json"} {
		h := invokeIn(env, report.PrivilegeUnknown, "https://example.com", "--format", format)
		everything := h.stdout.String() + h.stderr.String()

		if strings.Contains(everything, secret) {
			t.Errorf("%s: the password from the environment reached the output", format)
		}
		if !strings.Contains(everything, "proxy.example") {
			t.Errorf("%s: the proxy host was removed as well, and the host is the diagnosis", format)
		}
	}
}

// TestTheDisabledCertificateCheckSurvivesTheWholeWay is the other direction, and
// it is the one that has already been got wrong once.
//
// A masking rule asking whether the NAME contained a credential word answered yes
// for NODE_TLS_REJECT_UNAUTHORIZED, because "unauthorized" contains "auth". What
// it removed was the value 0 - that is, the entire finding: certificate checking
// switched off. A rule that deletes the diagnosis to protect a secret that was
// never there is worse than no rule.
func TestTheDisabledCertificateCheckSurvivesTheWholeWay(t *testing.T) {
	h := invokeIn(map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
		report.PrivilegeUnknown, "https://example.com", "--json")

	if !strings.Contains(h.stdout.String(), `"value": "0"`) {
		t.Error("the value of NODE_TLS_REJECT_UNAUTHORIZED did not survive to the report")
	}
}

// TestTheTwoSpellingsAreShownSeparately keeps the report from folding away a
// difference that decides behaviour.
//
// curl honours the http proxy variable in lower case only. On Linux the two
// spellings are separate variables, so one being set and the other not is the
// whole answer to "why does curl ignore my proxy" - and a report that merged
// them into one row would be true and useless at once.
func TestTheTwoSpellingsAreShownSeparately(t *testing.T) {
	out := invokeIn(map[string]string{"HTTP_PROXY": "http://upper.example:8080"},
		report.PrivilegeUnknown, "https://example.com").stdout.String()

	if !strings.Contains(out, "HTTP_PROXY is set") {
		t.Error("the upper case spelling was set and the report does not say so")
	}
	if !strings.Contains(out, "http_proxy is not set") {
		t.Error("the lower case spelling was not set and the report does not say so - the two were merged")
	}
}

// TestAVariableSetToNothingReadsDifferentlyFromAnAbsentOne covers the state that
// the value column cannot show, because both print nothing.
//
// An empty HTTPS_PROXY switches proxying off in some tools while an absent one
// leaves them to look elsewhere. If the report showed those identically, the
// person reading it would be told the opposite of what their machine does.
func TestAVariableSetToNothingReadsDifferentlyFromAnAbsentOne(t *testing.T) {
	out := invokeIn(map[string]string{"NO_PROXY": ""},
		report.PrivilegeUnknown, "https://example.com").stdout.String()

	if !strings.Contains(out, "NO_PROXY is set to nothing") {
		t.Error("a variable set to nothing is not distinguishable in the report")
	}
	if !strings.Contains(out, "no_proxy is not set") {
		t.Error("an absent variable stopped being reported as absent")
	}
}

// TestTheVerdictCountsTheLayersItCouldNotAssess replaces a claim with a count.
//
// The report used to carry a standing note saying no layer was implemented. That
// sentence stopped being true the day L0 started reading this machine, and a note
// kept past the arrival of the thing it announced teaches people to skip notes.
// What it said is now worked out from the rows themselves.
func TestTheVerdictCountsTheLayersItCouldNotAssess(t *testing.T) {
	h := invoke("https://example.com")
	out := h.stdout.String()

	if !strings.Contains(out, "7 of 8 diagnostic layers could not be assessed.") {
		t.Errorf("the verdict does not count the unassessed layers:\n%.400s", out)
	}
	if strings.Contains(out, "Nothing could be assessed yet.") {
		t.Error("the verdict still says nothing was assessed, and L0 assesses this machine")
	}
	if strings.Contains(out, "no diagnostic layer is implemented yet") {
		t.Error("the standing note outlived the thing it announced")
	}
	if h.code != exitcode.Inconclusive {
		t.Errorf("the run ended with %d, want %d - one layer passing does not make a run conclusive", h.code, exitcode.Inconclusive)
	}
}

// TestAMissingNameSourcesFileIsNotAFailure is the distinction that hid a real
// defect for the length of one measurement.
//
// Windows has no nsswitch.conf and neither do some images, so ABSENT is the
// ordinary state of a working machine and must not read as something going
// wrong. Every OTHER failure has to survive as an error, because "nothing was
// declared" is a statement about somebody's configuration and "we could not read
// it" is a statement about us - and the second one dressed as the first is
// exactly what let a port that was never wired report a confident falsehood.
func TestAMissingNameSourcesFileIsNotAFailure(t *testing.T) {
	declared := resolve.NameSources{Declared: true, Order: []string{"files", "dns"}}

	cases := []struct {
		name      string
		sources   func() (resolve.NameSources, error)
		want      resolve.NameSources
		wantError bool
	}{
		{"no reader at all", nil, resolve.NameSources{}, false},
		{
			name:    "the file is not there",
			sources: func() (resolve.NameSources, error) { return resolve.NameSources{}, fs.ErrNotExist },
		},
		{
			name: "the file is wrapped and not there",
			sources: func() (resolve.NameSources, error) {
				return resolve.NameSources{}, fmt.Errorf("reading /etc/nsswitch.conf: %w", fs.ErrNotExist)
			},
		},
		{
			name:      "the file is there and unreadable",
			sources:   func() (resolve.NameSources, error) { return resolve.NameSources{}, errors.New("permission denied") },
			wantError: true,
		},
		{
			name:    "the file was read",
			sources: func() (resolve.NameSources, error) { return declared, nil },
			want:    declared,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := nameSources(environment{sources: c.sources})

			if c.wantError && err == nil {
				t.Error("a file that could not be read came back as a machine that declares nothing")
			}
			if !c.wantError && err != nil {
				t.Errorf("an ordinary machine produced an error: %v", err)
			}
			if got.Declared != c.want.Declared {
				t.Errorf("declared is %v, want %v", got.Declared, c.want.Declared)
			}
		})
	}
}

// TestThePortComesFromTheURLOrItsScheme covers the one number L3 connects to.
//
// GUESSING WRONG HERE MEANS CONNECTING SOMEWHERE THE USER DID NOT ASK ABOUT, so
// there are exactly two defaults and no third: the two schemes this program
// accepts. An explicit port always wins, including when it is unusual.
func TestThePortComesFromTheURLOrItsScheme(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"https://example.com", 443},
		{"http://example.com", 80},
		{"https://example.com:8443", 8443},
		{"http://example.com:8080", 8080},
		// A port the URL parser accepts and nobody would type by accident.
		{"https://example.com:1", 1},
	}
	for _, tc := range cases {
		parsed, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if got := portOf(parsed); got != tc.want {
			t.Errorf("%s connects on port %d, want %d", tc.raw, got, tc.want)
		}
	}
}

// TestOnlyDialableAddressesWidenTheAllowedSet is inviolable rule 16 at the third
// of its five derivations - the first one that cannot be known before the run.
//
// The set holds address and port joined, and the dialler must be handed the same
// string. An address that will not parse is left OUT rather than joined into
// something nothing can dial: leaving it out changes nothing about what this run
// can reach, and L3 still reports a row saying it was refused.
func TestOnlyDialableAddressesWidenTheAllowedSet(t *testing.T) {
	parsed, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("preparing: %v", err)
	}
	targets := allowed.New()
	authoriser(parsed, targets)([]string{"192.0.2.10", "2001:db8::10", "not-an-address", ""})

	for _, want := range []string{"192.0.2.10:443", "[2001:db8::10]:443"} {
		if _, permitted := targets.Permits(want); !permitted {
			t.Errorf("%s was not added, so L3 would refuse a place this run resolved to", want)
		}
	}
	for _, never := range []string{"not-an-address:443", "192.0.2.11:443", "192.0.2.10:80"} {
		if _, permitted := targets.Permits(never); permitted {
			t.Errorf("%s is permitted and nothing derived it", never)
		}
	}
}

// closedAtOnce stands in for a connection L3 opened. L3 closes what it is given
// immediately, so nothing more is needed.
type closedAtOnce struct{}

func (closedAtOnce) Close() error { return nil }

// TestTheRawHostReachesTheHandshakeLayerEvenUnderRedact is the L1 trap one layer
// further along, and here it is WORSE.
//
// The name this wiring hands L4 goes out in SNI, where it decides which
// certificate a virtual host chooses. Fed the masked target, a run under
// --redact would ask every server on earth for a certificate issued to the
// literal string [host-1], receive one issued to something else, and report a
// correctly configured server as presenting the wrong certificate.
//
// NOTHING ELSE WOULD NOTICE. The document would validate, the chain would be
// real, the fingerprints would be genuine, and the diagnosis would be
// confidently wrong about somebody else's machine - which is the exact failure
// this product exists to prevent, committed by the product.
func TestTheRawHostReachesTheHandshakeLayerEvenUnderRedact(t *testing.T) {
	for _, redacted := range []bool{false, true} {
		var namesSent []string
		h := &harness{written: map[string][]byte{}}
		args := []string{"https://internal.corp.example", "--format", "json"}
		if redacted {
			args = append(args, "--redact")
		}

		guarded(context.Background(), args, environment{
			stdout:     &h.stdout,
			stderr:     &h.stderr,
			capability: func(bool) render.Capability { return render.Capability{} },
			now:        func() time.Time { return time.Unix(1_770_000_000, 0).UTC() },
			platform:   report.Platform{OS: "testos", Arch: "testarch"},
			privilege:  report.PrivilegeUnknown,
			lookupEnv:  func(string) (string, bool) { return "", false },
			writeFile:  func(string, []byte) error { return nil },

			nameservers: func() (dns.Nameservers, error) {
				return dns.Nameservers{ToAsk: []string{"192.0.2.53"}, Known: []string{"192.0.2.53"}, From: "a test"}, nil
			},
			queryID: func() uint16 { return 1 },
			// One lens answering is enough to give L3 an address to reach.
			system: func(*allowed.Targets) resolve.SystemLookup {
				return func(context.Context, string) resolve.SystemAnswer {
					return resolve.SystemAnswer{Addresses: []string{"192.0.2.10"}}
				}
			},
			exchange: func(*allowed.Targets) resolve.Exchange {
				return func(context.Context, string, []byte) ([]byte, error) { return nil, resolve.ErrTimeout }
			},
			// The connection has to SUCCEED, or L4 is handed nothing and this
			// test passes by never asking the question.
			connect: func(*allowed.Targets) coretcp.Connect {
				return func(context.Context, string, int) (io.Closer, error) { return closedAtOnce{}, nil }
			},
			shake: func(*allowed.Targets) corehandshake.Shake {
				return func(_ context.Context, _ string, _ int, name string) (corehandshake.Presented, error) {
					namesSent = append(namesSent, name)
					return corehandshake.Presented{}, corehandshake.ErrRejected
				}
			},
		})

		if len(namesSent) == 0 {
			t.Fatalf("with --redact=%v no handshake was attempted, so this proves nothing", redacted)
		}
		for _, name := range namesSent {
			if strings.Contains(name, "[") {
				t.Errorf("with --redact=%v a pseudonym went out in SNI: %q", redacted, name)
			}
			if name != "internal.corp.example" {
				t.Errorf("with --redact=%v the name sent was %q, and the user typed internal.corp.example",
					redacted, name)
			}
		}
	}
}
