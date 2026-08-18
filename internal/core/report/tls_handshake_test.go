package report

import (
	"strings"
	"testing"
	"time"
)

// The prohibitions of the TLS body, one case each.
//
// THIS TABLE IS WHERE THE CONTRACT'S VALUE IS. Half of what this body says is
// what it may NOT carry, and every one of those is a field a plausible mistake
// would fill in - a version beside a handshake that never happened, a chain on
// a row that only compares fingerprints, a "why not" on a row that succeeded.
// A filled-in row reads as a measurement, which is why each refusal is checked
// by name rather than by counting how many were reported.

func aCertificate() Certificate {
	return Certificate{
		Subject:           "CN=partner.test",
		Issuer:            "CN=testbed intermediate",
		NotBefore:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		FingerprintSHA256: "aa",
	}
}

// aCompletedRow is the row that carries the chain - the first address.
func aCompletedRow() TLSHandshake {
	return TLSHandshake{
		Address:               "192.0.2.10",
		Port:                  443,
		Completed:             true,
		Version:               "TLS 1.3",
		CipherSuite:           4865,
		CipherSuiteName:       "TLS_AES_128_GCM_SHA256",
		ALPN:                  "h2",
		ServerName:            "partner.test",
		LeafFingerprintSHA256: "aa",
		ChainComplete:         true,
		Chain:                 []Certificate{aCertificate()},
	}
}

// withoutSubject is a leaf carrying no subject and naming itself through the
// subjectAltName instead - the shape RFC 5280 section 4.1.2.6 requires.
func withoutSubject() TLSHandshake {
	b := aCompletedRow()
	b.Chain[0].Subject = ""
	b.Chain[0].DNSNames = []string{"partner.test", "www.partner.test"}
	return b
}

// aComparingRow is a later address: fingerprint and a comparison, no chain.
func aComparingRow() TLSHandshake {
	same := true
	return TLSHandshake{
		Address:               "192.0.2.11",
		Port:                  443,
		Completed:             true,
		Version:               "TLS 1.3",
		LeafFingerprintSHA256: "aa",
		MatchesFirstAddress:   &same,
	}
}

func anUnfinishedRow() TLSHandshake {
	return TLSHandshake{
		Address:      "192.0.2.10",
		Port:         443,
		Completed:    false,
		NotCompleted: "the server did not complete a TLS handshake",
	}
}

func TestTheTLSBodyRefusesWhatItMustNotCarry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   func() TLSHandshake
		refuse string
	}{
		{
			"no address at all",
			func() TLSHandshake { b := aCompletedRow(); b.Address = ""; return b },
			"attribute",
		},
		{
			"a port that is not a port",
			func() TLSHandshake { b := aCompletedRow(); b.Port = 0; return b },
			"not a port",
		},
		{
			// Inviolable rule 1 from the wrong side: a failure that does not say
			// why is silence, and silence is forbidden.
			"no handshake and no reason",
			func() TLSHandshake { b := anUnfinishedRow(); b.NotCompleted = ""; return b },
			"does not say why",
		},
		{
			"no handshake but a negotiated version",
			func() TLSHandshake { b := anUnfinishedRow(); b.Version = "TLS 1.3"; return b },
			"did not happen",
		},
		{
			"no handshake but a cipher suite",
			func() TLSHandshake { b := anUnfinishedRow(); b.CipherSuite = 4865; return b },
			"did not happen",
		},
		{
			"no handshake but an agreed protocol",
			func() TLSHandshake { b := anUnfinishedRow(); b.ALPN = "h2"; return b },
			"did not happen",
		},
		{
			"no handshake but a certificate",
			func() TLSHandshake {
				b := anUnfinishedRow()
				b.Chain = []Certificate{aCertificate()}
				return b
			},
			"nothing could have presented",
		},
		{
			"no handshake but a leaf fingerprint",
			func() TLSHandshake { b := anUnfinishedRow(); b.LeafFingerprintSHA256 = "aa"; return b },
			"nothing could have presented",
		},
		{
			"no handshake but the chain called complete",
			func() TLSHandshake { b := anUnfinishedRow(); b.ChainComplete = true; return b },
			"there was no chain",
		},
		{
			"a completed handshake that also says why it failed",
			func() TLSHandshake { b := aCompletedRow(); b.NotCompleted = "something"; return b },
			"also says why it did not",
		},
		{
			"a completed handshake with no leaf fingerprint",
			func() TLSHandshake { b := aCompletedRow(); b.LeafFingerprintSHA256 = ""; return b },
			"identifies what was presented",
		},
		{
			// The row carrying the chain IS the first address, so comparing it
			// against itself is a claim nobody could have made - ADR45.
			"the chain and a comparison against the first address",
			func() TLSHandshake {
				b := aCompletedRow()
				same := true
				b.MatchesFirstAddress = &same
				return b
			},
			"IS the first address",
		},
		{
			"neither the chain nor a comparison",
			func() TLSHandshake { b := aComparingRow(); b.MatchesFirstAddress = nil; return b },
			"says nothing about what this address presented",
		},
		{
			"a leaf fingerprint that is not the first certificate's",
			func() TLSHandshake { b := aCompletedRow(); b.LeafFingerprintSHA256 = "bb"; return b },
			"not the fingerprint of the first certificate",
		},
		{
			// THE SUBJECT USED TO BE HERE AND HAD TO LEAVE - ADR47. It is now in
			// the list of rows the contract MUST ACCEPT, one test down, because
			// RFC 5280 section 4.1.2.6 requires an empty subject when the identity
			// lives only in a critical subjectAltName. The issuer stays, and the
			// asymmetry is the decision: section 4.1.2.4 of the same RFC says the
			// issuer MUST be non-empty, so an empty one can only be a malformed
			// certificate or a defect here - and it is what chain completeness is
			// compared against.
			"a certificate with no issuer",
			func() TLSHandshake {
				b := aCompletedRow()
				b.Chain[0].Issuer = ""
				return b
			},
			"no issuer at all",
		},
		{
			// The evidence inviolable rule 21 requires beside any claim about
			// interception. A chain without it cannot support the claim it exists
			// to support.
			"a certificate with no fingerprint",
			func() TLSHandshake {
				b := aCompletedRow()
				b.Chain[0].FingerprintSHA256 = ""
				b.LeafFingerprintSHA256 = ""
				return b
			},
			"identifies what was presented",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body()
			got := Finding{
				Kind:         FindingTLSHandshake,
				Summary:      "a row about one address",
				Source:       SourceDetected,
				TLSHandshake: &body,
			}.Breach()

			if got == "" {
				t.Fatalf("the contract accepted a row it must refuse")
			}
			if !strings.Contains(got, tc.refuse) {
				t.Errorf("the refusal does not name what was wrong: %q, wanted it to mention %q", got, tc.refuse)
			}
		})
	}
}

// TestTheTLSBodyAcceptsTheRowsItMustAccept is the other side, and without it
// every refusal above would be satisfied by a contract that refuses everything.
func TestTheTLSBodyAcceptsTheRowsItMustAccept(t *testing.T) {
	for _, tc := range []struct {
		name string
		body TLSHandshake
	}{
		{"the first address, carrying the chain", aCompletedRow()},
		{"a later address, carrying the comparison", aComparingRow()},
		{"an address where no handshake happened", anUnfinishedRow()},
		// ADR47, AND THIS IS THE ROW THE OLD CONTRACT REFUSED. A leaf whose
		// identity lives only in a critical subjectAltName has an EMPTY subject,
		// and RFC 5280 section 4.1.2.6 does not merely permit that - it requires
		// it. Measured on 2026-08-18: crypto/x509 mints exactly this shape and
		// marks the extension critical by itself, so it is not exotic. Refusing it
		// degraded the whole layer, which made certdoctor answer "I could not
		// assess this" about a correctly issued certificate.
		{"a leaf identified only by its names", withoutSubject()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if got := (Finding{
				Kind:         FindingTLSHandshake,
				Summary:      "a row about one address",
				Source:       SourceDetected,
				TLSHandshake: &body,
			}).Breach(); got != "" {
				t.Errorf("the contract refused a well formed row: %s", got)
			}
		})
	}
}

// TestALaterAddressMayDisagreeWithTheFirst pins that the contract does not
// require agreement.
//
// A row saying the certificate DIFFERS is the single most important thing this
// layer can report, and a contract that only accepted "same" would make it
// unreportable.
func TestALaterAddressMayDisagreeWithTheFirst(t *testing.T) {
	differs := false
	body := aComparingRow()
	body.MatchesFirstAddress = &differs
	body.LeafFingerprintSHA256 = "bb"

	if got := (Finding{
		Kind:         FindingTLSHandshake,
		Summary:      "a row about one address",
		Source:       SourceDetected,
		TLSHandshake: &body,
	}).Breach(); got != "" {
		t.Errorf("the contract refused a row reporting a different certificate: %s", got)
	}
}
