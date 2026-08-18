package handshake

import (
	"bytes"
	"reflect"
	"testing"

	core "github.com/donislawdev/certdoctor/internal/core/handshake"
)

// FuzzACertificateIsSummarisedOrRefused is docs/22 row 3 at the one place in L4
// where somebody else's bytes are turned into a record.
//
// WHY HERE AND NOT AT THE HANDSHAKE. Everything else in this package runs on
// values crypto/x509 has already accepted, so the parsing of hostile data is
// reachable only through a real connection - and a fuzz target that needed a
// server would be a fuzz target nobody runs. CertificateFrom is the same path
// with the connection taken out.
//
// WHAT IT ASSERTS, AND THE LIST IS SHORT ON PURPOSE. Only properties that are
// TRUE of every input, because a target tuned until it passes is a target that
// has stopped saying anything:
//
//   - it returns rather than panicking, which is the whole of row 3;
//   - a refusal fills in NOTHING, so a caller cannot read half a record out of
//     an error it ignored;
//   - an acceptance carries the digest of exactly the bytes handed in, never of
//     anything re-encoded on the way;
//   - the same bytes give the same answer twice.
//
// WHAT IT DELIBERATELY DOES NOT ASSERT: that an accepted certificate has a
// non-empty subject or issuer. RFC 5280 section 4.1.2.4 requires a non-empty
// issuer and section 4.1.2.6 REQUIRES AN EMPTY SUBJECT when the identity lives
// only in a critical subjectAltName - and crypto/x509 accepts certificates that
// break the first of those anyway. Asserting either would be asserting something
// untrue, and the target would end up tuned until it passed.
func FuzzACertificateIsSummarisedOrRefused(f *testing.F) {
	root := mint(f, "certdoctor test root", nil, true)
	leaf := mint(f, "partner.test", &root, false)

	f.Add(root.der)
	f.Add(leaf.der)
	// Truncations, which is how a real certificate arrives off a connection that
	// was cut - and the likeliest malformed input that still looks structurally
	// plausible to a parser.
	f.Add(root.der[:len(root.der)/2])
	f.Add(leaf.der[:8])
	f.Add([]byte{})
	f.Add([]byte("not a certificate at all"))
	// A valid header over nothing, which is the shape that gets a parser to
	// allocate before it discovers there is no content.
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, der []byte) {
		summary, err := CertificateFrom(der)
		if err != nil {
			if !reflect.DeepEqual(summary, core.Certificate{}) {
				t.Errorf("refused these bytes and filled in a record anyway: %+v", summary)
			}
			return
		}

		if want := fingerprint(der); summary.FingerprintSHA256 != want {
			t.Errorf("the fingerprint is %q and the digest of the bytes handed in is %q",
				summary.FingerprintSHA256, want)
		}

		again, againErr := CertificateFrom(bytes.Clone(der))
		if againErr != nil {
			t.Errorf("the same bytes were accepted and then refused: %v", againErr)
			return
		}
		if !reflect.DeepEqual(again, summary) {
			t.Errorf("the same bytes summarised two ways:\n%+v\n%+v", summary, again)
		}
	})
}
