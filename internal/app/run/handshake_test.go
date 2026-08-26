package run

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/handshake"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/core/tcp"
	coretrust "github.com/donislawdev/certdoctor/internal/core/trust"
)

// The fingerprints the handshake fixture is built from, full length because the
// contract says a fingerprint is never shortened. The leaf's appears twice - in
// the body and as the first entry of its own chain - and the core refuses a row
// where the two disagree.
const (
	handshakeLeafPrint = "aa11bb22cc33dd44ee55ff6607788990a1b2c3d4e5f60718293a4b5c6d7e8f90"
	handshakeCAPrint   = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
)

// handshakeAnswer is what L4 hands over: the row carrying the chain, and a
// second address that presented the same leaf and carries no chain of its own.
//
// BOTH ROWS ARE HERE BECAUSE THE MASKING RULE DIFFERS BETWEEN THEM in exactly one
// way - the second has a nil chain, and nil has to survive as nil. A rebuilt
// empty slice would say "this server presented nothing", which is a claim about
// somebody else's machine.
func handshakeAnswer() Answer {
	same := true
	return Answer{
		Status: status.Pass,
		Detail: "2 of 2 address(es) completed a handshake and presented the same chain of 2 certificate(s)",
		Findings: []report.Finding{
			{
				Kind:    report.FindingTLSHandshake,
				Summary: "192.0.2.10 on port 443 presented 2 certificate(s)",
				Source:  report.SourceDetected,
				TLSHandshake: &report.TLSHandshake{
					Address:               "192.0.2.10",
					Port:                  443,
					Completed:             true,
					Version:               "TLS 1.3",
					CipherSuite:           4865,
					CipherSuiteName:       "TLS_AES_128_GCM_SHA256",
					ALPN:                  "h2",
					ServerName:            "inside.corp",
					LeafFingerprintSHA256: handshakeLeafPrint,
					ChainComplete:         true,
					Chain: []report.Certificate{
						{
							Subject:           "CN=inside.corp",
							Issuer:            "CN=inside.corp issuing ca",
							DNSNames:          []string{"inside.corp", "www.inside.corp"},
							FingerprintSHA256: handshakeLeafPrint,
						},
						{
							Subject:           "CN=inside.corp issuing ca",
							Issuer:            "CN=inside.corp root",
							FingerprintSHA256: handshakeCAPrint,
							IsCA:              true,
						},
					},
				},
			},
			{
				Kind:    report.FindingTLSHandshake,
				Summary: "192.0.2.11 on port 443 presented the same certificate as the first address",
				Source:  report.SourceDetected,
				TLSHandshake: &report.TLSHandshake{
					Address:               "192.0.2.11",
					Port:                  443,
					Completed:             true,
					Version:               "TLS 1.3",
					CipherSuite:           4865,
					CipherSuiteName:       "TLS_AES_128_GCM_SHA256",
					ALPN:                  "h2",
					ServerName:            "inside.corp",
					LeafFingerprintSHA256: handshakeLeafPrint,
					MatchesFirstAddress:   &same,
				},
			},
		},
	}
}

// TestTheHandshakeBodyMasksNamesAndNeverFingerprints is the whole of the fourth
// masking entry, and both halves of it are load bearing.
//
// THE FIRST HALF IS INVIOLABLE RULE 17 REACHING A NEW FIELD. A distinguished name
// is where a host name lives when it is not inside a URL, and the subject of an
// internal certificate names the machine as surely as the URL would.
//
// THE SECOND HALF IS THE ONE THAT WOULD BE LOST TO TIDYING. A fingerprint is the
// evidence inviolable rule 21 requires beside any claim about interception. A
// report that accuses a middlebox and withholds the value proving it is worse
// than one that says nothing - and the tempting mistake is to run the whole body
// through masking because most of it is text from somebody else.
func TestTheHandshakeBodyMasksNamesAndNeverFingerprints(t *testing.T) {
	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything, redact.Host("inside.corp"))
	o.Layers[layer.TLS] = func(context.Context) Answer { return handshakeAnswer() }

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	row := rowFor(t, r, layer.TLS)
	if noteNames(r.Notes, layer.TLS) {
		t.Fatal("the layer was degraded, so what follows is not what it handed over")
	}
	if len(row.Findings) != 2 {
		t.Fatalf("two findings went in and %d came out", len(row.Findings))
	}

	carrier := row.Findings[0].TLSHandshake
	if strings.Contains(carrier.Chain[0].Subject, "inside.corp") {
		t.Errorf("the leaf's subject still names the machine: %q", carrier.Chain[0].Subject)
	}
	if strings.Contains(carrier.Chain[0].Issuer, "inside.corp") {
		t.Errorf("the leaf's issuer still names the machine: %q", carrier.Chain[0].Issuer)
	}
	if strings.Contains(carrier.Chain[1].Subject, "inside.corp") {
		t.Errorf("masking reached the first certificate and stopped: %q", carrier.Chain[1].Subject)
	}
	if strings.Contains(carrier.ServerName, "inside.corp") {
		t.Errorf("the name we sent in SNI is the host the user typed and survived: %q", carrier.ServerName)
	}
	// THE NAMES ARE HOST NAMES BY DEFINITION - ADR47 - and a certificate for one
	// host routinely lists several, so this is the field most likely to carry an
	// internal name that appears nowhere else in the report.
	for _, name := range carrier.Chain[0].DNSNames {
		if strings.Contains(name, "inside.corp") {
			t.Errorf("a name the certificate was issued for survived masking: %q", name)
		}
	}
	if len(carrier.Chain[0].DNSNames) != 2 {
		t.Errorf("masking changed how many names the certificate presented: %v", carrier.Chain[0].DNSNames)
	}

	// The half that must NOT change, checked on both certificates and on the
	// body's own copy of the leaf's.
	if carrier.LeafFingerprintSHA256 != handshakeLeafPrint {
		t.Errorf("the leaf fingerprint was masked to %q - it is the evidence somebody came for",
			carrier.LeafFingerprintSHA256)
	}
	if carrier.Chain[0].FingerprintSHA256 != handshakeLeafPrint || carrier.Chain[1].FingerprintSHA256 != handshakeCAPrint {
		t.Error("a certificate fingerprint was masked, and a claim about interception cannot travel without it")
	}
	// An address the target resolved to is the diagnosis, not infrastructure -
	// the same decision maskTCPConnect records one layer down.
	if carrier.Address != "192.0.2.10" {
		t.Errorf("the address the target resolved to was masked to %q", carrier.Address)
	}
	if carrier.Version != "TLS 1.3" || carrier.CipherSuiteName != "TLS_AES_128_GCM_SHA256" || carrier.ALPN != "h2" {
		t.Errorf("masking changed something nobody asked it to: %+v", *carrier)
	}

	// A row that carried no chain must not come back carrying an empty one.
	// Those two are different statements, and they encode identically unless
	// something asks.
	if second := row.Findings[1].TLSHandshake; second.Chain != nil {
		t.Errorf("the row with no chain came back with a chain of %d", len(second.Chain))
	}
}

// TestMaskingDoesNotRewriteTheLayersOwnChain is the rule maskFinding states and
// this body is the first one big enough to break it.
//
// Copying a findings slice copies the POINTERS in it, so the body a layer handed
// over is the same object the report holds - and the chain inside that body is a
// slice sharing its backing array. Masking in place would rewrite a layer's own
// evidence underneath it, which is harmless exactly until something looks at that
// evidence twice.
func TestMaskingDoesNotRewriteTheLayersOwnChain(t *testing.T) {
	answer := handshakeAnswer()
	handedOver := answer.Findings[0].TLSHandshake

	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything, redact.Host("inside.corp"))
	o.Layers[layer.TLS] = func(context.Context) Answer { return answer }

	if _, err := Execute(context.Background(), o); err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	if handedOver.Chain[0].Subject != "CN=inside.corp" {
		t.Errorf("the layer's own certificate was rewritten underneath it: %q", handedOver.Chain[0].Subject)
	}
	if handedOver.Chain[1].Issuer != "CN=inside.corp root" {
		t.Errorf("the layer's own chain was rewritten underneath it: %q", handedOver.Chain[1].Issuer)
	}
	if handedOver.ServerName != "inside.corp" {
		t.Errorf("the layer's own evidence was rewritten underneath it: %q", handedOver.ServerName)
	}
}

// openedThenClosed stands in for a connection L3 successfully opened. L3 closes
// whatever it is given at once, so nothing more is needed.
type openedThenClosed struct{}

func (openedThenClosed) Close() error { return nil }

// TestLayerFourHandShakesOnlyWithTheAddressesLayerThreeReached is the second
// seam, and it is the whole of ADR45's first half.
//
// AN ADDRESS THAT REFUSED A CONNECTION HAS NOTHING TO HAND SHAKE WITH. Handing
// L4 everything L1 resolved would produce a row per unreachable address saying
// the handshake failed - our own arithmetic printed as a fact about somebody's
// TLS, and one fault counted twice in a report read top to bottom.
//
// THE ORDER IS LOAD-BEARING, exactly as it is one layer up: the orchestrator
// walks layers in registry order, so L3 has finished before L4 is called.
// seamWiring is the fixture both seam tests below start from: one name, one
// system view handing back two addresses, one of which accepts a connection.
func seamWiring(name string, port int, authorised func([]string), shook *[]string) Wiring {
	at := func() time.Time { return time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC) }
	return Wiring{
		Environment: envOf(nil),
		Resolution: resolve.Input{
			Name:      name,
			Resolvers: []string{"192.0.2.53"},
			Now:       at,
			QueryID:   func() uint16 { return 7 },
			System: func(context.Context, string) resolve.SystemAnswer {
				return resolve.SystemAnswer{Addresses: []string{"192.0.2.10", "192.0.2.11"}}
			},
			Exchange: func(context.Context, string, []byte) ([]byte, error) {
				return nil, resolve.ErrTimeout
			},
			PerQuery: 2 * time.Second,
		},
		Reach: tcp.Input{
			Port: port, PerAddress: 2 * time.Second, Now: at,
			Connect: func(_ context.Context, address string, _ int) (io.Closer, error) {
				if address == "192.0.2.10" {
					return openedThenClosed{}, nil
				}
				return nil, tcp.ErrRefused
			},
		},
		Handshake: handshake.Input{
			Port: 443, ServerName: "example.com", PerAddress: 2 * time.Second, Now: at,
			Shake: func(_ context.Context, address string, _ int, _ string) (handshake.Presented, error) {
				*shook = append(*shook, address)
				return handshake.Presented{}, handshake.ErrRejected
			},
		},
		Authorise: authorised,
	}
}

// TestABrokenLayerDoesNotWidenWhereThisRunMayConnect is inviolable rule 16 at the
// one place it was being decided by data the run had already refused.
//
// The orchestrator judges a layer's answer AFTER the layer function returns, and
// an answer that breaks its own contract has every finding thrown away with the
// layer reported as "nothing it reported was used". The addresses inside that
// same answer were still being handed to Authorise, which is the function that
// widens the set of places this program may open a connection to. Whatever else
// that set is, it cannot be built out of an answer this program discarded.
func TestABrokenLayerDoesNotWidenWhereThisRunMayConnect(t *testing.T) {
	var shook []string
	// A row for no name at all breaks the resolution contract - "a row with
	// nothing in front of it" - so L1's whole answer is refused.
	widened := 0
	layers := Wire(seamWiring("", 443, func([]string) { widened++ }, &shook))
	answer := layers[layer.Resolution](context.Background())

	if contractBreach(answer) == "" {
		t.Fatal("the fixture no longer produces a broken answer, so this test proves nothing")
	}
	if widened != 0 {
		t.Errorf("a layer the run refused widened the allowed set %d time(s)", widened)
	}

	// The twin: an answer that survives its contract still authorises, or this
	// test would be satisfied by a program that never authorises anything.
	shook = nil
	widened = 0
	layers = Wire(seamWiring("example.com", 443, func([]string) { widened++ }, &shook))
	if answer := layers[layer.Resolution](context.Background()); contractBreach(answer) != "" {
		t.Fatalf("the good fixture produced a broken answer: %s", contractBreach(answer))
	}
	if widened != 1 {
		t.Errorf("a sound answer widened the allowed set %d time(s), want 1", widened)
	}
}

// TestABrokenLayerDoesNotFillTheSeamBelowIt is the same gate one floor down, and
// it is the one with the measured false sentence.
//
// MEASURED ON THE BINARY: a URL carrying a port outside the legal range made
// every L3 row breach, so L3 was thrown away - and L4 then announced that the
// name had resolved to no address, about a name that had resolved to four. The
// seam had been filled by the discarded answer, and an empty list from a layer
// that was refused reads exactly like a layer that looked and found nothing.
func TestABrokenLayerDoesNotFillTheSeamBelowIt(t *testing.T) {
	var shook []string
	layers := Wire(seamWiring("example.com", 99999, func([]string) {}, &shook))
	layers[layer.Resolution](context.Background())

	reach := layers[layer.TCP](context.Background())
	if contractBreach(reach) == "" {
		t.Fatal("port 99999 no longer breaks the connection contract, so this test proves nothing")
	}

	answer := layers[layer.TLS](context.Background())
	if len(shook) != 0 {
		t.Errorf("L4 hand shook with %v, handed to it by a layer the run had refused", shook)
	}
	if !strings.Contains(answer.Detail, "nothing was established") {
		t.Errorf("L4 says %q, and what actually happened is that the layer above it was discarded", answer.Detail)
	}

	// The twin: a sound L3 fills the seam and L4 speaks to what it reached.
	shook = nil
	layers = Wire(seamWiring("example.com", 443, func([]string) {}, &shook))
	layers[layer.Resolution](context.Background())
	layers[layer.TCP](context.Background())
	layers[layer.TLS](context.Background())
	if len(shook) != 1 || shook[0] != "192.0.2.10" {
		t.Errorf("L4 hand shook with %v, want only the address that accepted a connection", shook)
	}
}

// TestALayerThatConnectedToNothingSaysSoRatherThanEstablishingNothing is the
// other side of the same seam, and it is the half a deliberate breakage found
// missing: the test above passes whether L3 hands on nil or an empty list,
// because the gate above it blocks that path anyway.
//
// Here L3 RUNS, correctly, and nothing accepts a connection. That is a
// measurement, and it has to reach L4 as one - otherwise L4 says nothing was
// established about addresses it knows perfectly well were all refused.
func TestALayerThatConnectedToNothingSaysSoRatherThanEstablishingNothing(t *testing.T) {
	var shook []string
	w := seamWiring("example.com", 443, func([]string) {}, &shook)
	w.Reach.Connect = func(context.Context, string, int) (io.Closer, error) { return nil, tcp.ErrRefused }

	layers := Wire(w)
	layers[layer.Resolution](context.Background())
	reach := layers[layer.TCP](context.Background())
	if contractBreach(reach) != "" {
		t.Fatalf("the fixture produced a broken L3 answer, so this tests the wrong path: %s", contractBreach(reach))
	}

	answer := layers[layer.TLS](context.Background())
	if !strings.Contains(answer.Detail, "no address accepted a connection") {
		t.Errorf("L4 says %q, and what happened is that every address refused", answer.Detail)
	}
}

// TestABrokenHandshakeAnswerReachesNoTrustStore is the third seam behind the
// same gate, and the one where the consequence is loudest.
//
// A handshake that COMPLETES and presents no certificate breaks the report
// contract - it says the handshake finished and carries no leaf fingerprint - so
// L4's whole answer is discarded. The chain inside that answer used to cross to
// L5 anyway, and every trust store on the machine would then have been asked
// about a certificate the report itself refused to show. OBS78 is the state that
// produces it, and this is what the run does with it meanwhile.
func TestABrokenHandshakeAnswerReachesNoTrustStore(t *testing.T) {
	var shook []string
	w := seamWiring("example.com", 443, func([]string) {}, &shook)
	w.Handshake.Shake = func(context.Context, string, int, string) (handshake.Presented, error) {
		// A CERTIFICATE WITH NO ISSUER, WHICH RFC 5280 SECTION 4.1.2.4 FORBIDS -
		// so the row can only be a malformed certificate or a defect of ours, and
		// the contract refuses it either way.
		//
		// THE VEHICLE CHANGED WITH ADR66 AND THE TEST DID NOT. It used to be a
		// completed handshake presenting nothing, which the contract refused - and
		// that was the refusal OBS78 measured as wrong, because TLS 1.3 session
		// resumption and the anonymous suites produce exactly it. This test is
		// about the SEAM, not about which row is illegal, so it needs a row that
		// is still illegal.
		return handshake.Presented{
			Completed: true,
			Version:   "TLS 1.3",
			Chain: []handshake.Certificate{{
				Subject:           "CN=partner.test",
				FingerprintSHA256: "aa",
			}},
		}, nil
	}

	// L5 wired only as far as it needs to be to look at the chain at all: it
	// refuses on its own missing plumbing before it ever reads one.
	var askedAbout [][]byte
	w.Trust = coretrust.Input{
		Now:     func() time.Time { return time.Unix(1_770_000_000, 0).UTC() },
		Machine: coretrust.Machine{OS: "testos"},
		Probes: map[string]coretrust.Probe{
			"git": func(_ context.Context, chain [][]byte) ([]report.TrustStore, error) {
				askedAbout = chain
				return nil, nil
			},
		},
	}

	layers := Wire(w)
	layers[layer.Resolution](context.Background())
	layers[layer.TCP](context.Background())
	answer := layers[layer.TLS](context.Background())
	if contractBreach(answer) == "" {
		t.Fatal("a completed handshake with no certificate no longer breaks the contract, so this proves nothing")
	}

	trust := layers[layer.TrustMatrix](context.Background())
	if len(askedAbout) != 0 {
		t.Errorf("a trust store was asked about %d certificate(s) from an answer this run refused", len(askedAbout))
	}
	if !strings.Contains(trust.Detail, "no certificate") {
		t.Errorf("L5 says %q, and it was offered nothing because L4's answer was discarded", trust.Detail)
	}
}

func TestLayerFourHandShakesOnlyWithTheAddressesLayerThreeReached(t *testing.T) {
	var seenByL4 []string
	at := func() time.Time { return time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC) }

	w := Wiring{
		Environment: envOf(nil),
		Resolution: resolve.Input{
			Name:      "example.com",
			Resolvers: []string{"192.0.2.53"},
			Now:       at,
			QueryID:   func() uint16 { return 7 },
			System: func(context.Context, string) resolve.SystemAnswer {
				return resolve.SystemAnswer{Addresses: []string{"192.0.2.10", "192.0.2.11"}}
			},
			Exchange: func(context.Context, string, []byte) ([]byte, error) {
				return nil, resolve.ErrTimeout
			},
			PerQuery: 2 * time.Second,
		},
		Reach: tcp.Input{
			Port: 443, PerAddress: 2 * time.Second, Now: at,
			// One address accepts and one refuses, which is the only fixture that
			// can tell "the addresses L3 reached" apart from "the addresses L1
			// found". A fixture where everything connects would pass either way.
			Connect: func(_ context.Context, address string, _ int) (io.Closer, error) {
				if address == "192.0.2.10" {
					return openedThenClosed{}, nil
				}
				return nil, tcp.ErrRefused
			},
		},
		Handshake: handshake.Input{
			Port: 443, ServerName: "example.com", PerAddress: 2 * time.Second, Now: at,
			Shake: func(_ context.Context, address string, _ int, name string) (handshake.Presented, error) {
				seenByL4 = append(seenByL4, address+" as "+name)
				return handshake.Presented{}, handshake.ErrRejected
			},
		},
		Authorise: func([]string) {},
	}

	layers := Wire(w)
	layers[layer.Resolution](context.Background())
	layers[layer.TCP](context.Background())
	answer := layers[layer.TLS](context.Background())

	if len(seenByL4) != 1 {
		t.Fatalf("L4 hand shook with %v, and only 192.0.2.10 accepted a connection", seenByL4)
	}
	// The name travels beside the address rather than instead of it - the whole
	// of TLS in one assertion, checked at the seam that supplies both.
	if seenByL4[0] != "192.0.2.10 as example.com" {
		t.Errorf("L4 was given %q, want the reached address with the target name beside it", seenByL4[0])
	}
	if len(answer.Findings) != 1 {
		t.Errorf("L4 produced %d rows for the one address it was given", len(answer.Findings))
	}
}

// TestLayerFourWithNoConnectionsHasNothingToDoRatherThanFailing is the other
// side, and it is the rule that keeps one broken name from being counted three
// times.
//
// L1 already reports a name that resolves nowhere, and L3 already declines to
// report it a second time. A FAIL here would make it three.
func TestLayerFourWithNoConnectionsHasNothingToDoRatherThanFailing(t *testing.T) {
	at := func() time.Time { return time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC) }
	asked := false

	layers := Wire(Wiring{
		Environment: envOf(nil),
		Reach:       tcp.Input{Port: 443, Now: at, PerAddress: time.Second},
		Handshake: handshake.Input{
			Port: 443, ServerName: "example.com", Now: at, PerAddress: time.Second,
			Shake: func(context.Context, string, int, string) (handshake.Presented, error) {
				asked = true
				return handshake.Presented{}, nil
			},
		},
	})
	layers[layer.TCP](context.Background())
	answer := layers[layer.TLS](context.Background())

	if asked {
		t.Error("L4 hand shook with something although L3 reached nothing")
	}
	if answer.Status != status.Unknown {
		t.Errorf("L4 answered %s with nothing to hand shake with, want unknown", answer.Status)
	}
	if answer.Reason != status.ReasonNothingToCheck {
		t.Errorf("L4 gives the reason %q, and the name resolving nowhere is not L4's failure", answer.Reason)
	}
}

// TestLayerFourWithNoPortsAnswersForItselfRatherThanAsAStub is the distinction a
// forgotten wire would erase.
//
// A layer that HAS code and was handed nothing must not read the same as one
// that was never written. Both are unknown, and only one of them is fixed by
// supplying a port - so the sentence has to say which.
func TestLayerFourWithNoPortsAnswersForItselfRatherThanAsAStub(t *testing.T) {
	answer := Wire(Wiring{Environment: envOf(nil)})[layer.TLS](context.Background())

	if answer.Status != status.Unknown {
		t.Errorf("L4 with no ports answered %s", answer.Status)
	}
	if answer.Detail == notImplementedDetail {
		t.Error("L4 has code and answered with the stub for a layer that has none")
	}
	if !strings.Contains(answer.Detail, "no way to complete a handshake") {
		t.Errorf("L4 explains itself with %q, which does not say what was missing", answer.Detail)
	}
}
