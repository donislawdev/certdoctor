package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// handshakeReport is a report carrying all THREE shapes L4 produces, because a
// fixture holding only the happy one would leave the two nulls this body exists
// to express untested.
//
// The three are: the row that carries the chain, a row that presented the same
// leaf and carries a comparison instead, and a row where no handshake happened
// at all. The core refuses any row that mixes them up, so this is also the
// broadest fixture the contract allows.
func handshakeReport() report.Report {
	r := everyStatusReport()
	same := true
	for i := range r.Layers {
		if r.Layers[i].ID != layer.TLS {
			continue
		}
		r.Layers[i].Findings = []report.Finding{
			// The chain carrier, taken from the registry fixture rather than
			// spelled a second time here. Two spellings of one fixture drift, and
			// the leaf fingerprint has to match its own chain's first entry.
			bodyFixtures[report.FindingTLSHandshake],
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
					ServerName:            "example.com",
					LeafFingerprintSHA256: leafFingerprint,
					MatchesFirstAddress:   &same,
					NameCovered:           nameCovered(),
				},
			},
			{
				Kind:    report.FindingTLSHandshake,
				Summary: "2001:db8::1 on port 443: nothing answered before the deadline",
				Source:  report.SourceDetected,
				TLSHandshake: &report.TLSHandshake{
					Address:      "2001:db8::1",
					Port:         443,
					Completed:    false,
					NotCompleted: "nothing answered before the deadline",
				},
			},
		}
	}
	return r
}

// decodeBodies reads a document back and hands over its handshake bodies in the
// order they appear.
func decodeBodies(t *testing.T, document []byte) []map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return handshakeBodies(decoded)
}

// handshakeBodies digs out every handshake body in a decoded document, in order.
func handshakeBodies(d map[string]any) []map[string]any {
	var found []map[string]any
	for _, row := range d["layers"].([]any) {
		findings, ok := row.(map[string]any)["findings"].([]any)
		if !ok {
			continue
		}
		for _, finding := range findings {
			if body, ok := finding.(map[string]any)["tls_handshake"].(map[string]any); ok {
				found = append(found, body)
			}
		}
	}
	return found
}

// TestADocumentCarryingTheFourthKindValidates is the point of this slice: the
// contract grew a body with a nested array in it and the schema still describes
// what the encoder produces.
func TestADocumentCarryingTheFourthKindValidates(t *testing.T) {
	document, err := Encode(handshakeReport())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if err := ValidateDocument(document); err != nil {
		t.Fatalf("a document with a handshake finding is refused by its own schema:\n%v", err)
	}

	text := string(document)
	if !strings.Contains(text, `"tls_handshake"`) {
		t.Errorf("the handshake body is not under its own key:\n%s", text)
	}
	// The number is the fact and the name stands beside it - inviolable rule 19.
	// A document carrying only the name would be asking a consumer to branch on
	// our rendering of somebody else's registry.
	if !strings.Contains(text, `"cipher_suite": 4865`) {
		t.Error("the cipher suite is not carried as the IANA number that came off the wire")
	}
	if !strings.Contains(text, `"cipher_suite_name": "TLS_AES_128_GCM_SHA256"`) {
		t.Error("the number arrived without the name a person reads beside it")
	}
	// RFC3339 to the second. Certificate validity is issued that way, and
	// trailing zeroes would suggest a precision nobody stated.
	if !strings.Contains(text, `"not_after": "2026-09-01T23:59:59Z"`) {
		t.Errorf("a certificate's validity is not rendered as a plain timestamp:\n%s", text)
	}
}

// TestOnlyOneRowCarriesTheChain is ADR45 written as an assertion.
//
// THE COUNT IS THE DECISION. Three addresses completed or failed, and exactly one
// of them carries the certificates; the others carry the comparison instead. A
// second chain would be four times the page for none of the information, and a
// missing one would leave a run with no evidence in it at all.
func TestOnlyOneRowCarriesTheChain(t *testing.T) {
	document, err := Encode(handshakeReport())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	bodies := decodeBodies(t, document)
	if len(bodies) != 3 {
		t.Fatalf("the fixture put three handshake rows in and %d came out", len(bodies))
	}

	carrying := 0
	for _, body := range bodies {
		if body["chain"] != nil {
			carrying++
		}
	}
	if carrying != 1 {
		t.Errorf("%d of 3 rows carry a chain, and exactly one may", carrying)
	}

	// The carrier says nothing about matching the first address, because it IS
	// the first address. The core refuses a row holding both, and this is the
	// same rule seen from the document.
	if bodies[0]["matches_first_address"] != nil {
		t.Error("the row carrying the chain also compares itself against the first address")
	}
	if bodies[1]["chain"] != nil {
		t.Error("a second row carries the chain, which makes the report repeat itself")
	}
	if bodies[1]["matches_first_address"] != true {
		t.Errorf("the second row does not say whether it presented the same certificate: %v",
			bodies[1]["matches_first_address"])
	}
	// A row that carries no chain has nothing to say about whether that chain was
	// complete either.
	if bodies[1]["chain_complete"] != nil {
		t.Error("a row without a chain reports whether the chain was complete")
	}
}

// TestARowWithNoHandshakeCarriesNothingItDidNotNegotiate is the prohibition half
// of this body, which is where its value is.
//
// A version or a cipher beside a handshake that never happened is a measurement
// of something that did not occur - and it renders as an ordinary row, which is
// the quiet failure the whole contract exists to prevent. The reason has to be
// there instead, because silence about a failure is forbidden.
func TestARowWithNoHandshakeCarriesNothingItDidNotNegotiate(t *testing.T) {
	document, err := Encode(handshakeReport())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	failed := decodeBodies(t, document)[2]

	if failed["completed"] != false {
		t.Fatalf("the third row is not the one that failed: %v", failed["completed"])
	}
	for _, field := range []string{
		"version", "cipher_suite", "cipher_suite_name", "server_name", "alpn",
		"client_certificate_requested", "leaf_fingerprint_sha256", "chain_complete", "name_covered", "chain",
	} {
		if failed[field] != nil {
			t.Errorf("no handshake happened and %q is %v, which nothing established", field, failed[field])
		}
	}
	if failed["not_completed"] != "nothing answered before the deadline" {
		t.Errorf("the row does not say why no handshake happened: %v", failed["not_completed"])
	}
	// The two that are settled even for an attempt that failed. A row nobody can
	// attribute is a row nobody can act on.
	if failed["address"] != "2001:db8::1" || failed["port"] != float64(443) {
		t.Errorf("the failed attempt lost the address or the port it was made to: %v", failed)
	}
}

// TestTheSchemaRefusesAHandshakeBodyThatChangedShape keeps the second
// declaration honest, the same way the first three are kept honest.
func TestTheSchemaRefusesAHandshakeBodyThatChangedShape(t *testing.T) {
	document, err := Encode(handshakeReport())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}

	cases := []struct {
		name   string
		change func(map[string]any)
		expect string
	}{
		{"the cipher suite became its name", func(d map[string]any) {
			handshakeBodies(d)[0]["cipher_suite"] = "TLS_AES_128_GCM_SHA256"
		}, "cipher_suite"},
		{"the chain became one certificate", func(d map[string]any) {
			body := handshakeBodies(d)[0]
			body["chain"] = body["chain"].([]any)[0]
		}, "schema declares an array"},
		{"a certificate lost its fingerprint", func(d map[string]any) {
			certificate := handshakeBodies(d)[0]["chain"].([]any)[0].(map[string]any)
			delete(certificate, "fingerprint_sha256")
		}, "fingerprint_sha256"},
		{"a fingerprint became null", func(d map[string]any) {
			certificate := handshakeBodies(d)[0]["chain"].([]any)[0].(map[string]any)
			certificate["fingerprint_sha256"] = nil
		}, "fingerprint_sha256"},
		{"completed went missing", func(d map[string]any) {
			delete(handshakeBodies(d)[0], "completed")
		}, "completed"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateDocument(mutate(t, document, c.change))
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.expect) {
				t.Errorf("the refusal reads %q and does not mention %q", err, c.expect)
			}
		})
	}
}

// TestTheTerminalPrintsTheChainUnderTheRowThatCarriesIt is rule 12 for this kind:
// the certificates have to be expressible on the surface a person reads, not only
// in the document a program parses.
func TestTheTerminalPrintsTheChainUnderTheRowThatCarriesIt(t *testing.T) {
	page := renderPage(t, handshakeReport())

	// The whole fingerprint, never a prefix. Shortening it is the quiet kind of
	// truncation the evidence contract forbids, and half a fingerprint cannot be
	// compared against anything.
	if !strings.Contains(page, leafFingerprint) {
		t.Errorf("the leaf fingerprint does not reach the page whole:\n%s", page)
	}
	if !strings.Contains(page, issuerFingerprint) {
		t.Error("the issuing certificate reaches the page without its fingerprint")
	}
	if !strings.Contains(page, "issued by  C=US, O=Example CA, CN=Example Issuing CA") {
		t.Errorf("the leaf reaches the page without saying who signed it:\n%s", page)
	}
	if !strings.Contains(page, "(CA)") {
		t.Error("nothing on the page distinguishes an authority from a leaf")
	}
	// ADR45 from the other surface: three rows, one block.
	if blocks := strings.Count(page, "issued by"); blocks != 2 {
		t.Errorf("the page carries %d certificates and the fixture has one chain of 2", blocks)
	}
	// The negotiated parameters sit beside the summary rather than inside it, the
	// same division every other kind uses.
	if !strings.Contains(page, "TLS 1.3, TLS_AES_128_GCM_SHA256, h2") {
		t.Errorf("what was negotiated never reaches the page:\n%s", page)
	}
}

// TestARowWithNoChainPrintsNoBlock is the other side of the test above.
//
// Without it, the rule "print the chain under the row that carries it" would be
// satisfied by a renderer that printed a block under every row, or under none and
// once at the end. Both would pass the assertions above and neither is what ADR45
// asks for.
func TestARowWithNoChainPrintsNoBlock(t *testing.T) {
	r := handshakeReport()
	for i := range r.Layers {
		if r.Layers[i].ID != layer.TLS {
			continue
		}
		// Keep only the two rows that carry no chain.
		r.Layers[i].Findings = r.Layers[i].Findings[1:]
	}

	page := renderPage(t, r)
	if strings.Contains(page, "issued by") || strings.Contains(page, "sha256") {
		t.Errorf("a row carrying no chain printed one anyway:\n%s", page)
	}
	// The rows themselves still have to be there. A renderer that dropped them
	// would pass the assertion above for the wrong reason.
	if !strings.Contains(page, "presented the same certificate as the first address") {
		t.Error("the row comparing itself against the first address vanished from the page")
	}
	if !strings.Contains(page, "nothing answered before the deadline") {
		t.Error("the row where no handshake happened vanished from the page")
	}
}

// TestASubjectCannotSmuggleAnEscapeSequenceOntoThePage covers the reason a
// distinguished name is treated as hostile input.
//
// IT IS THE ONE FIELD ON THIS PAGE THAT AN ATTACKER CHOOSES. A subject arrives in
// a certificate from the network, and an escape sequence in it could make one
// name read as another - in the terminal of the person deciding whether they are
// being intercepted.
func TestASubjectCannotSmuggleAnEscapeSequenceOntoThePage(t *testing.T) {
	r := handshakeReport()
	for i := range r.Layers {
		if r.Layers[i].ID != layer.TLS {
			continue
		}
		body := *r.Layers[i].Findings[0].TLSHandshake
		chain := append([]report.Certificate(nil), body.Chain...)
		chain[0].Subject = "CN=example.com\x1b[31m\u202eevil"
		chain[0].Issuer = "CN=friendly\x07"
		body.Chain = chain
		finding := r.Layers[i].Findings[0]
		finding.TLSHandshake = &body
		r.Layers[i].Findings = []report.Finding{finding}
	}

	page := renderPage(t, r)
	if strings.ContainsAny(page, "\x1b\x07") {
		t.Error("a control byte out of a certificate reached the page as itself")
	}
	if strings.Contains(page, "\u202e") {
		t.Error("a bidirectional override out of a certificate reached the page, and it reorders the line")
	}
	if !strings.Contains(page, `\u001b`) || !strings.Contains(page, `\u202e`) {
		t.Errorf("the escape was dropped rather than shown, so the reader cannot see it is there:\n%s", page)
	}
}

// renderPage renders a report the way a terminal with no colour would.
func renderPage(t *testing.T, r report.Report) string {
	t.Helper()
	var page strings.Builder
	if err := (Terminal{}).Render(&page, r); err != nil {
		t.Fatalf("the terminal renderer failed: %v", err)
	}
	return page.String()
}

// TestTheDocumentCarriesTheNamesAClientMatchesOn is ADR47 on the machine
// readable surface.
//
// RFC 6125 section 6.4.4 forbids a client from matching on the common name when
// the certificate presents a DNS-ID, so a document carrying only the subject was
// handing a consumer the field it is not allowed to use.
func TestTheDocumentCarriesTheNamesAClientMatchesOn(t *testing.T) {
	document, err := Encode(handshakeReport())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if err := ValidateDocument(document); err != nil {
		t.Fatalf("a document carrying the names is refused by its own schema:\n%v", err)
	}

	chain := decodeBodies(t, document)[0]["chain"].([]any)
	leaf := chain[0].(map[string]any)
	names, ok := leaf["dns_names"].([]any)
	if !ok {
		t.Fatalf("the leaf carries no dns_names at all: %v", leaf["dns_names"])
	}
	if len(names) != 2 || names[0] != "example.com" {
		t.Errorf("the leaf was issued for %v", names)
	}

	// NEVER NULL, and the authority is where that bites: it presents no DNS name,
	// and an empty array says so while a null would say nobody looked. The
	// certificate was read either way.
	authority := chain[1].(map[string]any)
	empty, ok := authority["dns_names"].([]any)
	if !ok {
		t.Fatalf("the authority's dns_names is %v, and an empty list is a statement rather than a gap",
			authority["dns_names"])
	}
	if len(empty) != 0 {
		t.Errorf("the authority carries names it never presented: %v", empty)
	}
}

// TestThePageNamesWhatTheCertificateWasIssuedFor is the same rule on the surface
// a person reads.
func TestThePageNamesWhatTheCertificateWasIssuedFor(t *testing.T) {
	page := renderPage(t, handshakeReport())

	if !strings.Contains(page, "names      example.com, www.example.com") {
		t.Errorf("the page does not say what the leaf was issued for:\n%s", page)
	}
	// An authority is not issued for a host name, so a line saying "none" beside
	// it would be noise about the ordinary state.
	if strings.Count(page, "names      ") != 1 {
		t.Errorf("the page carries %d name lines and only the leaf has names", strings.Count(page, "names      "))
	}
}

// TestACertificateWithNoSubjectSaysSoRatherThanRenderingBlank is the half of
// ADR47 that exists so the fix does not mislead in a second way.
//
// Allowing an empty subject and then printing a blank where it goes would read
// as a defect in this tool, on a certificate that is correctly issued. The page
// has to say which of the two situations it is looking at.
func TestACertificateWithNoSubjectSaysSoRatherThanRenderingBlank(t *testing.T) {
	r := handshakeReport()
	for i := range r.Layers {
		if r.Layers[i].ID != layer.TLS {
			continue
		}
		body := *r.Layers[i].Findings[0].TLSHandshake
		chain := append([]report.Certificate(nil), body.Chain...)
		chain[0].Subject = ""
		body.Chain = chain
		finding := r.Layers[i].Findings[0]
		finding.TLSHandshake = &body
		r.Layers[i].Findings = []report.Finding{finding}
	}

	page := renderPage(t, r)
	if !strings.Contains(page, "(no subject - identified by the names below") {
		t.Errorf("an empty subject rendered as a gap the reader has to interpret:\n%s", page)
	}
	// And the names are still there, because they are now the only thing saying
	// what this certificate is for.
	if !strings.Contains(page, "names      example.com, www.example.com") {
		t.Error("the subject went and took the names with it, leaving nothing identifying the certificate")
	}

	// The other side: a certificate with neither must not claim to be identified
	// by names it does not have.
	for i := range r.Layers {
		if r.Layers[i].ID != layer.TLS {
			continue
		}
		body := *r.Layers[i].Findings[0].TLSHandshake
		chain := append([]report.Certificate(nil), body.Chain...)
		chain[0].DNSNames = nil
		body.Chain = chain
		finding := r.Layers[i].Findings[0]
		finding.TLSHandshake = &body
		r.Layers[i].Findings = []report.Finding{finding}
	}
	bare := renderPage(t, r)
	if !strings.Contains(bare, "(no subject and no names") {
		t.Errorf("a certificate identifying nothing claimed to be identified by names:\n%s", bare)
	}
	if !strings.Contains(bare, "names      none presented") {
		t.Error("a leaf presenting no name says nothing about it, and that is the reason a client would refuse it")
	}
}

// nameCovered is a fresh name_covered of true, so no two fixtures share one
// pointer - ADR106 made the field required on every row with a leaf.
func nameCovered() *bool {
	covered := true
	return &covered
}

// TestEveryRowWithALeafSaysWhetherItCoversTheName is ADR106 seen from the
// document: name_covered on the carrier AND on the row that only compares,
// because each address presented its own leaf - and a false is carried as a
// false rather than dropped as an empty value.
func TestEveryRowWithALeafSaysWhetherItCoversTheName(t *testing.T) {
	r := handshakeReport()
	notCovered := false
	for i := range r.Layers {
		if r.Layers[i].ID != layer.TLS {
			continue
		}
		second := *r.Layers[i].Findings[1].TLSHandshake
		second.NameCovered = &notCovered
		r.Layers[i].Findings[1].TLSHandshake = &second
	}

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	bodies := decodeBodies(t, document)
	if bodies[0]["name_covered"] != true {
		t.Errorf("the row carrying the chain says %v", bodies[0]["name_covered"])
	}
	if covered, present := bodies[1]["name_covered"]; !present || covered != false {
		t.Errorf("the comparing row says %v (present: %v), want false", covered, present)
	}
}
