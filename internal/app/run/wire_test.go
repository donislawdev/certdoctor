package run

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/handshake"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/machine"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/core/tcp"
	"github.com/donislawdev/certdoctor/internal/core/trust"
)

func envOf(pairs map[string]string) machine.Lookup {
	return func(name string) (string, bool) {
		value, set := pairs[name]
		return value, set
	}
}

// TestWireStillCoversEveryDeclaredLayer is the property NotImplemented had and
// must not lose by being wrapped.
//
// Execute refuses to run at all when a declared layer has no function, so this
// would be caught eventually - but as an internal failure with no report, which
// is a much worse way to learn that somebody added a ninth layer.
func TestWireStillCoversEveryDeclaredLayer(t *testing.T) {
	layers := Wire(Wiring{Environment: envOf(nil)})

	if len(layers) != len(layer.All) {
		t.Fatalf("the wiring holds %d layers, the registry declares %d", len(layers), len(layer.All))
	}
	for _, id := range layer.All {
		if layers[id] == nil {
			t.Errorf("layer %s has no function", id)
		}
	}
}

// TestWiringPutsTheContextLayerInPlaceOfTheStub proves the override happened.
//
// Without this the whole piece could be built, merged and released with L0 still
// answering "not implemented", and every other test here would stay green -
// because they all assert on shapes that the stub satisfies too.
func TestWiringPutsTheContextLayerInPlaceOfTheStub(t *testing.T) {
	answer := Wire(Wiring{Environment: envOf(map[string]string{"HTTPS_PROXY": "http://proxy.example:8080"})})[layer.Context](context.Background())

	if answer.Status != status.Pass {
		t.Fatalf("L0 answered %s with a readable environment, want %s", answer.Status, status.Pass)
	}
	if answer.Detail == notImplementedDetail {
		t.Fatal("L0 is still the stub - the wiring did not replace it")
	}
	if len(answer.Findings) == 0 {
		t.Fatal("L0 passed and reported nothing, so nothing about the machine reached the report")
	}
}

// written is the set of layers that have grown code. It is written out by hand
// rather than derived, so that a layer starting to answer for itself has to be
// added here deliberately - the alternative is a wiring that quietly answers for
// all eight while the tool claims to have checked things it has not.
var written = map[layer.ID]bool{
	layer.Context:    true,
	layer.Resolution: true,
	layer.TCP:        true,
	layer.TLS:        true,
	// L5 joined on 2026-08-18 with P7a. It answers for itself now, so asserting
	// the stub for it would be asserting that a layer with code has none.
	layer.TrustMatrix: true,
}

// TestTheUnwrittenLayersStillSayTheyAreNotWritten is the other side of the
// override.
//
// THE COUNT IS NOT WRITTEN HERE and the list above is, which is the whole point:
// it has changed three times already. A number in the name of a test goes stale
// silently, and a test asserting the stub for a layer that has since grown code
// would have to be loosened to pass - which is how a guard turns into decoration.
func TestTheUnwrittenLayersStillSayTheyAreNotWritten(t *testing.T) {
	layers := Wire(Wiring{Environment: envOf(nil)})

	checked := 0
	for _, id := range layer.All {
		if written[id] {
			continue
		}
		checked++
		answer := layers[id](context.Background())
		if answer.Status != status.Unknown || answer.Detail != notImplementedDetail {
			t.Errorf("layer %s answered %s / %q, want unknown / %q",
				id, answer.Status, answer.Detail, notImplementedDetail)
		}
		if answer.Findings != nil {
			t.Errorf("layer %s did not look and reported a list of findings, which renders as a claim that it did", id)
		}
	}
	if checked == 0 {
		t.Fatal("every layer is claimed to be written, so this test checked nothing")
	}
}

// TestALayerWithNoPortsAnswersForItselfRatherThanAsAStub is what replaces the
// row this test used to cover for L1.
//
// A layer that HAS code and was handed nothing must not be indistinguishable
// from one that was never written. Both are unknown, and only one of them can be
// fixed by supplying a port - so the sentence has to say which.
func TestALayerWithNoPortsAnswersForItselfRatherThanAsAStub(t *testing.T) {
	answer := Wire(Wiring{Environment: envOf(nil)})[layer.Resolution](context.Background())

	if answer.Status != status.Unknown {
		t.Errorf("L1 with no ports answered %s", answer.Status)
	}
	if answer.Detail == notImplementedDetail {
		t.Error("L1 has code and answered with the stub for a layer that has none")
	}
	if !strings.Contains(answer.Detail, "no way to send a query") {
		t.Errorf("L1 explains itself with %q, which does not say what was missing", answer.Detail)
	}
}

// TestWithNoEnvironmentPortTheRunStillProducesAReport is the failure mode this
// wiring can actually have, followed all the way to the artefact.
//
// A forgotten assignment must cost that one layer and nothing else. The run
// completes, the other seven rows are untouched, and L0 says it could not look -
// with a reason, never a pass.
func TestWithNoEnvironmentPortTheRunStillProducesAReport(t *testing.T) {
	clock := newClock()
	options := baseOptions(clock)
	options.Layers = Wire(Wiring{})

	finished, err := Execute(context.Background(), options)
	if err != nil {
		t.Fatalf("a missing environment port ended the whole run: %v", err)
	}
	if err := report.Validate(finished); err != nil {
		t.Fatalf("the assembled report failed its own checks: %v", err)
	}

	context0 := finished.Layers[0]
	if context0.ID != layer.Context {
		t.Fatalf("the first row is %s, want %s", context0.ID, layer.Context)
	}
	if context0.Status != status.Unknown {
		t.Errorf("L0 answered %s with no way to read the environment, want %s", context0.Status, status.Unknown)
	}
	if context0.Reason != status.ReasonProbeError {
		t.Errorf("L0 reports the reason %q, want %q", context0.Reason, status.ReasonProbeError)
	}
	// THE ROW HAS TO CARRY THE LAYER'S OWN EXPLANATION, not the orchestrator's
	// apology for a broken contract. Both come back as an unknown with the same
	// reason, so the status alone cannot tell them apart - and one of them means
	// "no port was supplied" while the other means "L0 is built wrong".
	if !strings.Contains(context0.Detail, "no way to read the environment") {
		t.Errorf("L0 explains itself with %q, which is not the answer it should be giving", context0.Detail)
	}
	if context0.Findings != nil {
		t.Error("L0 could not look and still reported a list of findings")
	}
	for _, note := range finished.Notes {
		if note.Kind == report.NoteDegraded {
			t.Errorf("L0 was recorded as having broken its own contract: %s", note.Detail)
		}
	}
	// The other rows are untouched: one layer's missing port costs that layer and
	// nothing else. L1 is skipped because it has code of its own and answers for
	// itself here - which is exactly the property being checked, one row down.
	for _, row := range finished.Layers {
		if written[row.ID] {
			continue
		}
		if row.Detail != notImplementedDetail {
			t.Errorf("layer %s reads %q, want the untouched stub", row.ID, row.Detail)
		}
	}
}

// TestTheOrchestratorMasksWhatTheContextLayerFound is the end this piece was
// written for, and until now it could only be checked with invented evidence.
//
// The masking function has had property tests and two fuzz targets since it was
// written, and for two days nothing called it. Then it was called, and only test
// data went through it. This is the first time a real layer's own output makes
// the trip - and it is the trip that decides whether a password typed into a
// shell ends up in a ticket.
func TestTheOrchestratorMasksWhatTheContextLayerFound(t *testing.T) {
	const secret = "s3kret"
	clock := newClock()
	options := baseOptions(clock)
	options.Layers = Wire(Wiring{Environment: envOf(map[string]string{
		"HTTPS_PROXY":                  "http://someone:" + secret + "@proxy.example:8080",
		"NODE_TLS_REJECT_UNAUTHORIZED": "0",
	})})

	finished, err := Execute(context.Background(), options)
	if err != nil {
		t.Fatalf("the run failed: %v", err)
	}

	var proxy, node *report.EnvironmentVariable
	for _, finding := range finished.Layers[0].Findings {
		switch finding.EnvironmentVariable.Name {
		case "HTTPS_PROXY":
			proxy = finding.EnvironmentVariable
		case "NODE_TLS_REJECT_UNAUTHORIZED":
			node = finding.EnvironmentVariable
		}
	}
	if proxy == nil || node == nil {
		t.Fatal("the two variables under test did not reach the report")
	}

	if strings.Contains(proxy.Value, secret) {
		t.Errorf("the password survived into the report: %q", proxy.Value)
	}
	if !proxy.CarriedCredentials {
		t.Error("the proxy value carried credentials and the report does not say so - that fact is half the answer to a 407 and it can be said without saying the secret")
	}

	// THE OTHER DIRECTION, AND IT HAS BEEN GOT WRONG ONCE ALREADY. A masking rule
	// that asked whether the NAME contained a credential word deleted this value,
	// because "unauthorized" contains "auth" - and the value it deleted was the
	// entire finding: certificate validation switched off in Node.
	if node.Value != "0" {
		t.Errorf("the value of NODE_TLS_REJECT_UNAUTHORIZED is %q, want %q - masking ate the diagnosis", node.Value, "0")
	}
	if node.CarriedCredentials {
		t.Error("NODE_TLS_REJECT_UNAUTHORIZED was reported as carrying credentials")
	}
}

// TestTheLayerKeepsTheRawEvidenceItHandedOver covers the aliasing the copy
// exists to prevent.
//
// Copying a findings slice copies the POINTERS in it, so the body a layer built
// is the same object the report holds. Masking through that pointer would
// rewrite the layer's own evidence underneath it - harmless while layers are
// stateless, and a defect the day one is not.
func TestTheLayerKeepsTheRawEvidenceItHandedOver(t *testing.T) {
	const raw = "http://someone:s3kret@proxy.example:8080"
	answer := Wire(Wiring{Environment: envOf(map[string]string{"HTTPS_PROXY": raw})})[layer.Context](context.Background())

	options := baseOptions(newClock())
	options.Redaction = redact.New(redact.Credentials)
	// Masking is handed a COPY of the slice header, which is exactly what the
	// orchestrator does - and exactly why the pointers inside still need care.
	options.mask([]report.LayerResult{{Findings: copyFindings(answer.Findings)}}, nil)

	for _, finding := range answer.Findings {
		if finding.EnvironmentVariable.Name == "HTTPS_PROXY" && finding.EnvironmentVariable.Value != raw {
			t.Errorf("masking reached back into the layer's own evidence: %q", finding.EnvironmentVariable.Value)
		}
	}
}

// TestTheAddressesL1FoundReachL3AndTheAllowedSet is the seam, checked from both
// ends.
//
// It is the first thing in this program that one layer hands to another, and it
// has two consumers rather than one: L3 connects to those addresses, and the set
// of places this run may reach has to learn about them first. Missing either
// makes a working machine look broken - L3 with no addresses reports nothing to
// do, and L3 with addresses nobody authorised reports every connection refused by
// our own rule.
//
// THE ORDER IS WHAT MAKES IT WORK AND IT IS NOW LOAD-BEARING: the orchestrator
// walks layers in registry order, so L1 finishes before L3 starts.
func TestTheAddressesL1FoundReachL3AndTheAllowedSet(t *testing.T) {
	var authorised []string
	var seenByL3 []string

	w := Wiring{
		Environment: envOf(nil),
		Resolution: resolve.Input{
			Name:      "example.com",
			Resolvers: []string{"192.0.2.53"},
			Now:       func() time.Time { return time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC) },
			QueryID:   func() uint16 { return 7 },
			System: func(context.Context, string) resolve.SystemAnswer {
				return resolve.SystemAnswer{Addresses: []string{"192.0.2.10"}}
			},
			Exchange: func(context.Context, string, []byte) ([]byte, error) {
				return nil, resolve.ErrTimeout
			},
			// Without a per-query budget every query is skipped before it starts,
			// and the layer hands on nothing - which is what this fixture did the
			// first time and is worth keeping in view: no budget is not the same
			// as no answer.
			PerQuery: 2 * time.Second,
		},
		Reach: tcp.Input{
			Port:       443,
			PerAddress: 2 * time.Second,
			Now:        func() time.Time { return time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC) },
			Connect: func(_ context.Context, address string, _ int) (io.Closer, error) {
				seenByL3 = append(seenByL3, address)
				return nil, tcp.ErrRefused
			},
		},
		Authorise: func(addresses []string) { authorised = append(authorised, addresses...) },
	}

	layers := Wire(w)
	layers[layer.Resolution](context.Background())
	layers[layer.TCP](context.Background())

	if len(authorised) != 1 || authorised[0] != "192.0.2.10" {
		t.Errorf("the allowed set was told about %v, and L1 found 192.0.2.10", authorised)
	}
	if len(seenByL3) != 1 || seenByL3[0] != "192.0.2.10" {
		t.Errorf("L3 tried %v, and L1 found 192.0.2.10", seenByL3)
	}
}

// TestWithNothingToAuthoriseTheWalkStillRuns covers the nil rule: a forgotten
// wire must cost this layer and nothing else.
func TestWithNothingToAuthoriseTheWalkStillRuns(t *testing.T) {
	layers := Wire(Wiring{Environment: envOf(nil)})
	answer := layers[layer.TCP](context.Background())
	if answer.Status != status.Unknown {
		t.Errorf("L3 with no ports answered %s, want unknown", answer.Status)
	}
	// And L1 running with no ports of its own does not take the walk down.
	if got := layers[layer.Resolution](context.Background()); got.Status != status.Unknown {
		t.Errorf("L1 with no ports answered %s", got.Status)
	}
}

// walkTo runs the layers in order up to and including L5, through the real
// seams, and hands back what L5 answered.
//
// IT GOES THROUGH L1 AND L3 RATHER THAN AROUND THEM, and that is the point: Wire
// REPLACES the addresses on the L4 input with the ones L3 accepted, so a fixture
// that sets them directly tests a wiring nobody ships. The first version of this
// test did exactly that and reported an empty chain.
func walkTo(t *testing.T, w Wiring) Answer {
	t.Helper()
	layers := Wire(w)
	layers[layer.Resolution](context.Background())
	layers[layer.TCP](context.Background())
	layers[layer.TLS](context.Background())
	return layers[layer.TrustMatrix](context.Background())
}

// reachableWiring is a run where one address resolves, connects and hand shakes.
func reachableWiring(shown handshake.Presented, probes map[string]trust.Probe) Wiring {
	clock := func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
	return Wiring{
		Environment: envOf(nil),
		Resolution: resolve.Input{
			Name:      "example.com",
			Resolvers: []string{"192.0.2.53"},
			Now:       clock,
			QueryID:   func() uint16 { return 7 },
			System: func(context.Context, string) resolve.SystemAnswer {
				return resolve.SystemAnswer{Addresses: []string{"192.0.2.10"}}
			},
			Exchange: func(context.Context, string, []byte) ([]byte, error) {
				return nil, resolve.ErrTimeout
			},
			PerQuery: 2 * time.Second,
		},
		Reach: tcp.Input{
			Port: 443, PerAddress: 2 * time.Second, Now: clock,
			Connect: func(context.Context, string, int) (io.Closer, error) {
				return io.NopCloser(strings.NewReader("")), nil
			},
		},
		Handshake: handshake.Input{
			Port: 443, ServerName: "example.com", Now: clock,
			Shake: func(context.Context, string, int, string) (handshake.Presented, error) {
				return shown, nil
			},
		},
		Trust: trust.Input{Probes: probes},
	}
}

// THE THIRD SEAM. L4 says what the server presented and L5 judges THE SAME
// BYTES - not a chain fetched again and not a different address. Getting this
// wrong would produce a matrix about a certificate nobody was shown, which no
// reader could ever catch.
func TestTheChainL4SawIsTheChainL5Judges(t *testing.T) {
	presented := []byte{0x30, 0x82, 0x01, 0x02}
	var judged [][]byte

	walkTo(t, reachableWiring(
		handshake.Presented{
			Completed: true,
			Version:   "TLS 1.3",
			Chain: []handshake.Certificate{{
				Subject:           "CN=example.com",
				Issuer:            "CN=issuer",
				FingerprintSHA256: "aa",
				Raw:               presented,
			}},
		},
		map[string]trust.Probe{
			"git": func(_ context.Context, chain [][]byte) ([]report.TrustStore, error) {
				judged = chain
				return nil, nil
			},
		}))

	if len(judged) != 1 {
		t.Fatalf("L5 was handed %d certificate(s), want 1", len(judged))
	}
	if !bytes.Equal(judged[0], presented) {
		t.Errorf("L5 judged %x and L4 saw %x - they must be the same bytes", judged[0], presented)
	}
}

// A run where no handshake completed hands L5 nothing, and L5 has to read that
// as nothing to judge rather than as a store that failed. Blaming a store for
// our own empty hand is the shape inviolable rule 15 forbids.
func TestNoHandshakeMeansL5JudgesNothing(t *testing.T) {
	answer := walkTo(t, reachableWiring(
		handshake.Presented{Completed: false},
		map[string]trust.Probe{
			"git": func(context.Context, [][]byte) ([]report.TrustStore, error) {
				t.Error("a probe was asked about a chain that was never presented")
				return nil, nil
			},
		}))

	if answer.Status != status.Unknown {
		t.Errorf("status %s, want UNKNOWN when there was nothing to judge", answer.Status)
	}
	if answer.Reason != status.ReasonNothingToCheck {
		t.Errorf("reason %s, want nothing_to_check", answer.Reason)
	}
}
