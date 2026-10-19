package handshake

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Whether the leaf covers the name this run asked for - ADR106, closing OBS162.
// The adapter answers the question; these tests are about what L4 makes of the
// answer: the status, the layer's sentence, each row's field and its summary.

// issuedTo is a complete two-certificate chain whose leaf names these hosts.
func issuedTo(fingerprint string, names ...string) []Certificate {
	chain := completeChain(fingerprint)
	chain[0].DNSNames = names
	return chain
}

// presenting is a shake that answers every address with the same chain and
// the same answer about the name.
func presenting(chain []Certificate, name NameMatch) Shake {
	return func(context.Context, string, int, string) (Presented, error) {
		return Presented{Completed: true, Version: "TLS 1.3", Chain: chain, Name: name}, nil
	}
}

// askedFor is a working input for one address, asking for host.
func askedFor(host string, shake Shake) Input {
	in := workingInput(shake)
	in.ServerName = host
	return in
}

const wrongHostSentence = "the server presented a certificate for *.badssl.com, badssl.com, and none of those names " +
	"covers wrong.host.badssl.com - clients refuse that whatever they trust, so this is a fact about the server or " +
	"about the name used to reach it"

// TestALeafForAnotherNameFailsTheLayer is OBS162 as measured on
// wrong.host.badssl.com: a complete chain, trusted by most stores, for a name
// one label short of the one asked for.
func TestALeafForAnotherNameFailsTheLayer(t *testing.T) {
	got := Ask(context.Background(), askedFor("wrong.host.badssl.com",
		presenting(issuedTo("aa", "*.badssl.com", "badssl.com"), NameNotCovered)))

	if got.Status != status.Fail {
		t.Errorf("a leaf for another name left L4 at %s", got.Status)
	}
	if got.Detail != wrongHostSentence {
		t.Errorf("the layer said %q", got.Detail)
	}
	// L5 IS UNTOUCHED - ADR106 part 3. The chain is whole and every store may
	// trust it, and saying otherwise there would send somebody to the wrong
	// machine.
	if !got.ChainWhole {
		t.Error("the chain was reported broken because the name did not fit")
	}
	rows := rowsOf(got)
	if len(rows) != 1 || rows[0].NameCovered == nil || *rows[0].NameCovered {
		t.Fatalf("the row does not say the name is not covered: %+v", rows)
	}
	if broken := got.Findings[0].Breach(); broken != "" {
		t.Errorf("the row is refused by its own contract: %s", broken)
	}
	if !strings.HasSuffix(got.Findings[0].Summary, ", and its certificate does not cover wrong.host.badssl.com") {
		t.Errorf("the row's own sentence does not say it, so no surface but --json would: %q", got.Findings[0].Summary)
	}
}

// TestACoveredNameChangesNothing is the positive twin on the same chain -
// OBS56. Every row says so in the field and nothing in prose.
func TestACoveredNameChangesNothing(t *testing.T) {
	in := askedFor("a.badssl.com", presenting(issuedTo("aa", "*.badssl.com", "badssl.com"), NameCovered))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	got := Ask(context.Background(), in)

	if got.Status != status.Pass {
		t.Errorf("a leaf covering the name left L4 at %s: %s", got.Status, got.Detail)
	}
	for i, row := range rowsOf(got) {
		if row.NameCovered == nil || !*row.NameCovered {
			t.Errorf("row %d does not say the name is covered", i)
		}
		if strings.Contains(got.Findings[i].Summary, "cover") {
			t.Errorf("row %d talks about the name when there is nothing to say: %q", i, got.Findings[i].Summary)
		}
	}
}

// TestANameOnlyInTheCommonNameIsAWarning is ADR106 part 2: a warning, because
// a client written to RFC 6125 may still accept it - and the field says false,
// because by RFC 9525 the name is not covered.
func TestANameOnlyInTheCommonNameIsAWarning(t *testing.T) {
	got := Ask(context.Background(), askedFor("legacy.example.com",
		presenting(issuedTo("aa"), NameInCommonNameOnly)))

	if got.Status != status.Warn {
		t.Errorf("a name only in the common name left L4 at %s", got.Status)
	}
	want := "the server presented a certificate with no subjectAltName, naming legacy.example.com only in its common " +
		"name - clients following RFC 9525 refuse that and older ones may still accept it, so whether this connection " +
		"works depends on the client"
	if got.Detail != want {
		t.Errorf("the layer said %q", got.Detail)
	}
	rows := rowsOf(got)
	if len(rows) != 1 || rows[0].NameCovered == nil || *rows[0].NameCovered {
		t.Fatalf("the row does not say false: %+v", rows)
	}
	if !strings.HasSuffix(got.Findings[0].Summary, ", and its certificate names legacy.example.com only in its common name") {
		t.Errorf("the row's own sentence does not say it: %q", got.Findings[0].Summary)
	}
}

// TestTheNameIsSaidBeforeAnIncompleteChain is ADR106 part 5. Completing the
// chain of a certificate issued to another name fixes nothing, so the name is
// what the layer says.
func TestTheNameIsSaidBeforeAnIncompleteChain(t *testing.T) {
	alone := leafOnly("aa")
	alone[0].DNSNames = []string{"*.badssl.com", "badssl.com"}
	got := Ask(context.Background(), askedFor("wrong.host.badssl.com", presenting(alone, NameNotCovered)))

	if got.Status != status.Fail || got.Detail != wrongHostSentence {
		t.Errorf("got %s %q, want the name sentence", got.Status, got.Detail)
	}
}

// TestAnIncompleteChainOutranksACommonNameWarning is the other half of the
// order: a failure is not hidden behind a warning.
func TestAnIncompleteChainOutranksACommonNameWarning(t *testing.T) {
	got := Ask(context.Background(), askedFor("legacy.example.com", presenting(leafOnly("aa"), NameInCommonNameOnly)))

	if got.Status != status.Fail || !strings.Contains(got.Detail, "did not send the issuer") {
		t.Errorf("got %s %q, want the incomplete chain", got.Status, got.Detail)
	}
}

// TestOneAddressOutOfTwoIsCountedNotGeneralised: a middlebox on one path
// presents another certificate, and the sentence must not say "the server"
// about an address that behaved.
func TestOneAddressOutOfTwoIsCountedNotGeneralised(t *testing.T) {
	in := askedFor("partner.test", func(_ context.Context, address string, _ int, _ string) (Presented, error) {
		if address == "192.0.2.11" {
			return Presented{Completed: true, Version: "TLS 1.3", Chain: issuedTo("bb", "elsewhere.test"), Name: NameNotCovered}, nil
		}
		return Presented{Completed: true, Version: "TLS 1.3", Chain: issuedTo("aa", "partner.test"), Name: NameCovered}, nil
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	got := Ask(context.Background(), in)

	if got.Status != status.Fail {
		t.Errorf("one address presenting another name's certificate left L4 at %s", got.Status)
	}
	if !strings.HasPrefix(got.Detail, "1 of 2 address(es) presented a certificate for elsewhere.test, and that does not cover partner.test") {
		t.Errorf("the sentence does not name the address count and the right certificate: %q", got.Detail)
	}
	rows := rowsOf(got)
	if len(rows) != 2 || rows[0].NameCovered == nil || !*rows[0].NameCovered || rows[1].NameCovered == nil || *rows[1].NameCovered {
		t.Errorf("each row does not carry its own answer: %+v", rows)
	}
}

// TestTheNamesInTheSentenceAreCapped: a shared certificate carries hundreds,
// and this sentence is the one the verdict quotes. The addresses are listed
// after the DNS names.
func TestTheNamesInTheSentenceAreCapped(t *testing.T) {
	for _, c := range []struct {
		name  string
		leaf  Certificate
		names string
	}{
		{"five DNS names", Certificate{DNSNames: []string{"a.test", "b.test", "c.test", "d.test", "e.test"}},
			"a certificate for a.test, b.test, c.test and 2 more, and none of those names covers"},
		{"a name and an address", Certificate{DNSNames: []string{"a.test"}, IPAddresses: []string{"192.0.2.1"}},
			"a certificate for a.test, 192.0.2.1, and none of those names covers"},
		{"one address", Certificate{IPAddresses: []string{"192.0.2.1"}},
			"a certificate for 192.0.2.1, and that does not cover"},
		{"nothing at all", Certificate{},
			"a certificate with no host name or address in its subjectAltName, so nothing in it covers"},
	} {
		t.Run(c.name, func(t *testing.T) {
			leaf := c.leaf
			got := nameDetail(nameTally{host: "x.test", withLeaf: 1, notCovered: 1, first: &leaf})
			if !strings.Contains(got, c.names+" x.test") {
				t.Errorf("got %q, want it to contain %q", got, c.names+" x.test")
			}
		})
	}
}

// TestAnUncheckedLeafIsRefusedByTheContract is the defect the zero value is
// for: a shake that forgot to ask produces a row the report contract refuses,
// rather than one that reads as a name that fits.
func TestAnUncheckedLeafIsRefusedByTheContract(t *testing.T) {
	got := Ask(context.Background(), askedFor("partner.test", presenting(issuedTo("aa", "partner.test"), NameUnchecked)))

	rows := rowsOf(got)
	if len(rows) != 1 || rows[0].NameCovered != nil {
		t.Fatalf("an unchecked leaf produced an answer: %+v", rows)
	}
	if broken := got.Findings[0].Breach(); !strings.Contains(broken, "does not say whether it covers the name") {
		t.Errorf("the contract accepted a leaf nothing was asked about: %q", broken)
	}
}
