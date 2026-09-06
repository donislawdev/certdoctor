package run

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// The masking of the two proxy bodies, and it is the entry with the widest split
// in this tree between what is pseudonymised, what is withheld outright and what
// is left exactly as the layer wrote it.

// aProxyPlace is the shape measured on the owner's machine 2026-09-06, with the
// kind of internal names an exception list actually carries.
func aProxyPlace() report.Finding {
	server := report.ProxyServer{
		Protocol: "https", Scheme: "http", Address: "proxy.corp.internal:8080",
		CarriedCredentials: true,
	}
	selected := server
	return report.Finding{
		Kind:    report.FindingProxyStack,
		Summary: "the proxy environment variables this process was started with: a proxy applies to https://api.example.com",
		Source:  report.SourceDetected,
		ProxyStack: &report.ProxyStack{
			Stack:       "environment",
			Read:        true,
			Detail:      "http_proxy and HTTP_PROXY are both set",
			Servers:     []report.ProxyServer{server},
			Selected:    &selected,
			Bypass:      "secret.corp.internal,.corp.internal",
			BypassSet:   true,
			BypassRules: []report.ProxyBypassRule{{Rule: "no_proxy_curl", Bypasses: false}},
			PACURL:      "http://wpad.corp.internal/proxy.pac",
			AutoDetect:  report.DeterminedTrue,
			Caveats:     []string{"naming a script is not proof that anything uses it"},
		},
	}
}

// proxyLayerOf stands in for the layer. THE DETAIL IS NOT DECORATION: the
// orchestrator refuses a layer that reports anything but a pass without a line
// saying what happened, and the first version of this helper left it out - the
// findings were then thrown away and every assertion below failed on an empty
// row rather than on masking.
func proxyLayerOf(finding report.Finding) func(context.Context) Answer {
	return func(context.Context) Answer {
		return Answer{
			Status:   status.Warn,
			Detail:   "this machine names a proxy and this run did not establish the whole answer",
			Findings: []report.Finding{finding},
		}
	}
}

func placeFrom(t *testing.T, r report.Report) report.ProxyStack {
	t.Helper()
	row := rowFor(t, r, layer.Proxy)
	if len(row.Findings) == 0 || row.Findings[0].ProxyStack == nil {
		t.Fatal("the proxy row carries no place at all")
	}
	return *row.Findings[0].ProxyStack
}

// TestTheProxyItselfIsPseudonymisedLikeAnyOtherInfrastructure is ADR32 applied
// one layer along: a resolver's address is masked because it is a machine
// somebody's network owns rather than the answer the reader came for, and a
// proxy is the same kind of thing.
func TestTheProxyItselfIsPseudonymisedLikeAnyOtherInfrastructure(t *testing.T) {
	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything)
	o.Layers[layer.Proxy] = proxyLayerOf(aProxyPlace())

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	place := placeFrom(t, r)
	if strings.Contains(place.Servers[0].Address, "proxy.corp.internal") {
		t.Errorf("the proxy survived the stronger mode: %q", place.Servers[0].Address)
	}
	if !strings.HasSuffix(place.Servers[0].Address, ":8080") {
		t.Errorf("the port went with the name, and a port identifies nobody: %q", place.Servers[0].Address)
	}
	if place.Selected == nil || place.Selected.Address != place.Servers[0].Address {
		t.Errorf("the entry that applies was masked differently from the same entry in the list: %+v", place.Selected)
	}
	if !place.Servers[0].CarriedCredentials {
		t.Error("masking took the fact that a credential was carried, which is the half that can be said out loud")
	}
	if strings.Contains(place.PACURL, "wpad.corp.internal") {
		t.Errorf("the script address survived: %q", place.PACURL)
	}
}

// TestTheExceptionListIsWithheldRatherThanMasked is the decision in that
// function rather than its code. Its entries are wildcards and suffixes, so no
// rule recognises them as machines - masking them would leave most of them
// untouched while the document says it is redacted, which is a leak wearing a
// stamp.
func TestTheExceptionListIsWithheldRatherThanMasked(t *testing.T) {
	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything)
	o.Layers[layer.Proxy] = proxyLayerOf(aProxyPlace())

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	place := placeFrom(t, r)
	if strings.Contains(place.Bypass, "corp.internal") {
		t.Errorf("an exception list entry survived the stronger mode: %q", place.Bypass)
	}
	if !place.BypassSet {
		t.Error("withholding the text also withdrew the fact that a list exists")
	}
	// THE DIAGNOSTIC CONTENT SURVIVES, which is why withholding costs so little:
	// whether THIS target skips the proxy is the only thing a reader acts on.
	if len(place.BypassRules) != 1 || place.BypassRules[0].Rule != "no_proxy_curl" {
		t.Errorf("the readings were withheld along with the list: %v", place.BypassRules)
	}
}

// TestTheWeakerModeLeavesTheProxyAndItsListAlone is the other direction, and
// without it every assertion above would also pass against a masking that
// deleted everything.
func TestTheWeakerModeLeavesTheProxyAndItsListAlone(t *testing.T) {
	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Credentials)
	o.Layers[layer.Proxy] = proxyLayerOf(aProxyPlace())

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	place := placeFrom(t, r)
	if place.Servers[0].Address != "proxy.corp.internal:8080" {
		t.Errorf("the floor mode renamed the proxy: %q", place.Servers[0].Address)
	}
	if !strings.Contains(place.Bypass, "secret.corp.internal") {
		t.Errorf("the floor mode withheld the exception list: %q", place.Bypass)
	}
	if len(place.Caveats) != 1 {
		t.Errorf("our own sentences about the row were touched: %v", place.Caveats)
	}
}

// TestAPlaceThatWasNotReadCarriesNoListToMask is the nil case of the copy, and
// it is here because a conversion turning nil into an empty slice would say
// "read and naming nothing" about a place that said nothing at all.
func TestAPlaceThatWasNotReadCarriesNoListToMask(t *testing.T) {
	finding := report.Finding{
		Kind:    report.FindingProxyStack,
		Summary: "the macOS system configuration, as scutil reports it: could not be read",
		Source:  report.SourceDetected,
		ProxyStack: &report.ProxyStack{
			Stack: "macos_system", Detail: "scutil is not on this machine",
		},
	}

	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything)
	o.Layers[layer.Proxy] = proxyLayerOf(finding)

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	if place := placeFrom(t, r); place.Servers != nil {
		t.Errorf("a place that was not read came back holding %v", place.Servers)
	}
}

// TestTheComparisonIsOurOwnVocabularyAndSurvivesMasking is the second no-op
// entry written in order to say so. Every field of it is a word this program
// chose, and a pseudonym for our own vocabulary would take the sentence a reader
// pastes into a ticket.
func TestTheComparisonIsOurOwnVocabularyAndSurvivesMasking(t *testing.T) {
	finding := report.Finding{
		Kind:    report.FindingStackDivergence,
		Summary: "comparing 2 place(s) this machine keeps proxy settings in",
		Source:  report.SourceDerived,
		StackDivergence: &report.StackDivergence{
			Class: "one_sided", Stacks: []string{"wininet", "winhttp"},
		},
	}

	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything)
	o.Layers[layer.Proxy] = proxyLayerOf(finding)

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	compared := rowFor(t, r, layer.Proxy).Findings[0].StackDivergence
	if compared == nil {
		t.Fatal("the comparison did not survive the assembly path at all")
	}
	if compared.Class != "one_sided" || len(compared.Stacks) != 2 {
		t.Errorf("our own vocabulary was masked: %+v", compared)
	}
}

// TestTheProxyLayerIsWiredToTheOneThatReadsThisMachine is the seam, and it is
// the check OBS117 asks for: the macOS reading is one line behind a build tag,
// so the only thing pinnable on every platform is that the layer asks the port
// it was given, exactly once.
func TestTheProxyLayerIsWiredToTheOneThatReadsThisMachine(t *testing.T) {
	asked := 0
	layers := Wire(Wiring{
		Environment: envOf(nil),
		Proxy: proxy.Input{
			Lenses: func(context.Context) []proxy.Lens {
				asked++
				return []proxy.Lens{{
					Stack: proxy.StackMacSystem, Source: "test", Read: true, Servers: []proxy.Server{},
				}}
			},
			Target: proxy.Target{Scheme: "https", Host: "api.example.com"},
		},
	})

	answer := layers[layer.Proxy](context.Background())
	if asked != 1 {
		t.Fatalf("the layer asked the port %d time(s), want exactly one", asked)
	}
	if answer.Status != status.Unknown || answer.Reason != status.ReasonNothingToCheck {
		t.Errorf("the wired layer answered %s / %s, want unknown / nothing_to_check", answer.Status, answer.Reason)
	}
	if len(answer.Findings) != 1 {
		t.Errorf("one place produced %d row(s)", len(answer.Findings))
	}
}
