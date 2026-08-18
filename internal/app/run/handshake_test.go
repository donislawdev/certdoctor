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
