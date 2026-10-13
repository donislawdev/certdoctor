package main

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/dns"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/allowed"
	corehandshake "github.com/donislawdev/certdoctor/internal/core/handshake"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	coretcp "github.com/donislawdev/certdoctor/internal/core/tcp"
	"github.com/donislawdev/certdoctor/internal/core/trust"
)

// TestTheSchemeTheUserTypedDecidesWhetherTLSIsAsked is the wiring half of
// ADR100, which closed OBS149.
//
// The layers are told whether the target uses TLS and never read the scheme
// themselves, so the one place that can get this wrong is here - and a wire that
// forgot the answer would not fail any layer test. It would bring back the FAIL
// the bench measured on http://auth.proxy.test/.
//
// THE PORT IS IN THE TABLE ON PURPOSE. The scheme decides and the port does not,
// so each scheme is tried on the other one's port too.
func TestTheSchemeTheUserTypedDecidesWhetherTLSIsAsked(t *testing.T) {
	for _, c := range []struct {
		target    string
		plaintext bool
	}{
		{"http://internal.corp.example/", true},
		{"http://internal.corp.example:443/", true},
		{"https://internal.corp.example/", false},
		{"https://internal.corp.example:80/", false},
	} {
		t.Run(c.target, func(t *testing.T) {
			shakes, probes, rows := runAgainst(t, c.target)

			if c.plaintext {
				if shakes != 0 || probes != 0 {
					t.Errorf("a target without TLS got %d handshake(s) and %d trust probe(s), want none", shakes, probes)
				}
				for _, id := range []layer.ID{layer.TLS, layer.TrustMatrix} {
					row := rows[string(id)]
					if row.Status != "UNKNOWN" || row.Reason != "nothing_to_check" {
						t.Errorf("%s answered %s/%s about a target without TLS", id, row.Status, row.Reason)
					}
					// THE SENTENCE IS THE ONLY THING TELLING THE TWO WIRES APART at
					// L5. Handed an empty chain and no answer, it also says
					// nothing_to_check and asks no probe - but blames a server
					// that was never asked.
					if !strings.Contains(row.Detail, "does not use TLS") {
						t.Errorf("%s does not say the target does not use TLS: %q", id, row.Detail)
					}
				}
				return
			}
			// THE TWIN, without which the half above is satisfied by a wiring that
			// never hands anybody a handshake at all.
			if shakes == 0 {
				t.Errorf("a TLS target got no handshake, so the answer above proves nothing")
			}
			if row := rows[string(layer.TLS)]; row.Reason == "nothing_to_check" {
				t.Errorf("L4 said there was nothing to check about a TLS target: %s", row.Detail)
			}
		})
	}
}

// TestTheSentenceForATargetWithoutTLSSurvivesRedaction is OBS152 measured on the
// binary and pinned here.
//
// The first wording of L4's sentence said "given as http://," and under
// --redact the comma came out as [host-2]. The masking read whatever followed a
// scheme up to the next space as a host name, so a sentence ABOUT a scheme was
// exactly the one it mangled - and no layer test can see it, because masking
// happens after the layers.
//
// The rule now steps over punctuation straight after the separator, so the
// comma alone would pass. This stays because the sentence still has to survive
// as a whole, and a word written straight after "://" is still read as a host -
// correctly, since that is what a host looks like.
func TestTheSentenceForATargetWithoutTLSSurvivesRedaction(t *testing.T) {
	_, _, plain := runAgainst(t, "http://internal.corp.example/")
	_, _, masked := runAgainst(t, "http://internal.corp.example/", "--redact")

	for _, id := range []layer.ID{layer.TLS, layer.TrustMatrix} {
		if got, want := masked[string(id)].Detail, plain[string(id)].Detail; got != want {
			t.Errorf("%s says something different under --redact, and it names no host:\n got %q\nwant %q", id, got, want)
		}
	}
}

// runAgainst drives the whole entry point against one target with the world
// replaced, and counts what reached the handshake and trust ports.
//
// THE CONNECTION HAS TO SUCCEED, or L4 is handed no address and a TLS target
// looks exactly like a plaintext one from the counter's side.
func runAgainst(t *testing.T, target string, extra ...string) (shakes, probes int, rows map[string]layerAnswer) {
	t.Helper()
	h := &harness{written: map[string][]byte{}}
	guarded(context.Background(), append([]string{target, "--format", "json"}, extra...), environment{
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
		system: func(*allowed.Targets) resolve.SystemLookup {
			return func(context.Context, string) resolve.SystemAnswer {
				return resolve.SystemAnswer{Addresses: []string{"192.0.2.10"}}
			}
		},
		exchange: func(*allowed.Targets) resolve.Exchange {
			return func(context.Context, string, []byte) ([]byte, error) { return nil, resolve.ErrTimeout }
		},
		connect: func(*allowed.Targets) coretcp.Connect {
			return func(context.Context, string, int) (io.Closer, error) { return closedAtOnce{}, nil }
		},
		shake: func(*allowed.Targets) corehandshake.Shake {
			return func(context.Context, string, int, string) (corehandshake.Presented, error) {
				shakes++
				return corehandshake.Presented{}, corehandshake.ErrRejected
			}
		},
		trustProbes: func() map[string]trust.Probe {
			return map[string]trust.Probe{"git": func(context.Context, [][]byte) ([]report.TrustStore, error) {
				probes++
				return nil, nil
			}}
		},
	})

	var document struct {
		Layers []layerAnswer `json:"layers"`
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &document); err != nil {
		t.Fatalf("the run produced no document to read: %v\n%s", err, h.stderr.String())
	}
	rows = map[string]layerAnswer{}
	for _, row := range document.Layers {
		rows[row.ID] = row
	}
	return shakes, probes, rows
}

// layerAnswer is the part of one layer row these checks read.
type layerAnswer struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}
