package run

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/machine"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	"github.com/donislawdev/certdoctor/internal/core/status"
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
	layers := Wire(envOf(nil), resolve.Input{})

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
	answer := Wire(envOf(map[string]string{"HTTPS_PROXY": "http://proxy.example:8080"}), resolve.Input{})[layer.Context](context.Background())

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
var written = map[layer.ID]bool{layer.Context: true, layer.Resolution: true}

// TestTheUnwrittenLayersStillSayTheyAreNotWritten is the other side of the
// override.
//
// IT COUNTED SEVEN UNTIL 2026-08-10 AND NOW COUNTS SIX, which is the whole
// reason the list above exists rather than a subtraction from eight. A number in
// the name of a test goes stale silently, and a test asserting the stub for a
// layer that has since grown code would have to be loosened to pass - which is
// how a guard turns into decoration.
func TestTheUnwrittenLayersStillSayTheyAreNotWritten(t *testing.T) {
	layers := Wire(envOf(nil), resolve.Input{})

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
	answer := Wire(envOf(nil), resolve.Input{})[layer.Resolution](context.Background())

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
	options.Layers = Wire(nil, resolve.Input{})

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
	options.Layers = Wire(envOf(map[string]string{
		"HTTPS_PROXY":                  "http://someone:" + secret + "@proxy.example:8080",
		"NODE_TLS_REJECT_UNAUTHORIZED": "0",
	}), resolve.Input{})

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
	answer := Wire(envOf(map[string]string{"HTTPS_PROXY": raw}), resolve.Input{})[layer.Context](context.Background())

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
