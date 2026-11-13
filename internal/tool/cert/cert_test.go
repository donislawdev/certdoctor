package cert

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// now is the moment every case is judged at: inside 2020-2040, ten days
// before fixtureSoon ends.
var now = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func chain(fixtures ...string) []byte { return []byte(strings.Join(fixtures, "")) }

func der(t testing.TB, fixture string) []byte {
	t.Helper()
	b, _ := pem.Decode([]byte(fixture))
	if b == nil {
		t.Fatal("a fixture is not PEM")
	}
	return b.Bytes
}

func decode(t *testing.T, raw []byte) spec.Outcome {
	t.Helper()
	out, err := Decode(raw, now)
	if err != nil {
		t.Fatalf("Decode refused: %v", err)
	}
	return out
}

func statuses(out spec.Outcome) map[string]status.Status {
	m := map[string]status.Status{}
	for _, c := range out.Checks {
		m[c.ID] = c.Status
	}
	return m
}

func summary(out spec.Outcome, id string) string {
	for _, c := range out.Checks {
		if c.ID == id {
			return c.Summary
		}
	}
	return ""
}

// TestEachRuleIsJudgedOnTheCertificateThatBreaksIt runs every rule against a
// certificate that breaks it and one that keeps it - so each check is seen
// both ways, and a check that never fires cannot pass for one that works.
func TestEachRuleIsJudgedOnTheCertificateThatBreaksIt(t *testing.T) {
	const absent = status.Status("")
	for _, tc := range []struct {
		name  string
		input []byte
		want  map[string]status.Status
	}{
		{"a complete chain in order", chain(fixtureLeaf, fixtureIntermediate, fixtureRoot), map[string]status.Status{
			"validity": status.Pass, "signature": status.Pass, "key_size": status.Pass, "subject_alt_name": status.Pass,
			"chain": status.Pass, "chain_order": status.Pass, "chain_unrelated": absent, "duplicates": absent}},
		{"a leaf and its intermediate, no root", chain(fixtureLeaf, fixtureIntermediate),
			map[string]status.Status{"chain": status.Pass, "chain_order": status.Pass}},
		{"a server certificate alone", chain(fixtureLeaf),
			map[string]status.Status{"chain": status.Warn, "chain_order": absent}},
		{"the chain out of order", chain(fixtureLeaf, fixtureRoot, fixtureIntermediate),
			map[string]status.Status{"chain": status.Pass, "chain_order": status.Warn}},
		{"the server's certificate last", chain(fixtureIntermediate, fixtureLeaf),
			map[string]status.Status{"chain_order": status.Warn, "chain_unrelated": absent}},
		{"a certificate of another chain", chain(fixtureLeaf, fixtureIntermediate, fixtureOtherLeaf),
			map[string]status.Status{"chain_unrelated": status.Warn}},
		{"a set of roots", chain(fixtureRoot, fixtureOtherRoot),
			map[string]status.Status{"chain": status.Pass, "chain_order": absent, "chain_unrelated": absent}},
		{"the same certificate twice", chain(fixtureLeaf, fixtureLeaf, fixtureIntermediate),
			map[string]status.Status{"duplicates": status.Warn, "chain_order": status.Pass}},
		{"a self-signed server certificate", chain(fixtureSelfSignedServer),
			map[string]status.Status{"chain": status.Pass, "subject_alt_name": status.Pass}},
		{"expired", chain(fixtureExpired), map[string]status.Status{"validity": status.Fail}},
		{"not valid yet", chain(fixtureNotYet), map[string]status.Status{"validity": status.Fail}},
		{"ten days left", chain(fixtureSoon), map[string]status.Status{"validity": status.Warn}},
		{"expired beside ten days left", chain(fixtureSoon, fixtureExpired), map[string]status.Status{"validity": status.Fail}},
		{"no end date", chain(fixtureForever), map[string]status.Status{"validity": status.Pass}},
		{"signed with MD5", chain(fixtureMD5), map[string]status.Status{"signature": status.Fail}},
		{"signed with SHA-1", chain(fixtureSHA1), map[string]status.Status{"signature": status.Warn}},
		{"a root signed itself with SHA-1", chain(fixtureSHA1Root), map[string]status.Status{"signature": status.Pass}},
		{"a root naming itself, signed with MD5", chain(fixtureMD5Root), map[string]status.Status{"signature": status.Pass}},
		{"an RSA key of 768 bits", chain(fixtureRSA768), map[string]status.Status{"key_size": status.Fail}},
		{"an RSA key of 1024 bits", chain(fixtureRSA1024), map[string]status.Status{"key_size": status.Warn}},
		{"a name in the common name only", chain(fixtureCommonNameOnly),
			map[string]status.Status{"subject_alt_name": status.Warn}},
		{"a client certificate without names", chain(fixtureClientOnly),
			map[string]status.Status{"subject_alt_name": absent}},
		{"an authority is not matched against a host", chain(fixtureIntermediate),
			map[string]status.Status{"subject_alt_name": absent}},
		{"a certificate the library refuses", chain(fixtureNegativeSerial, fixtureLeaf),
			map[string]status.Status{"unreadable": status.Unknown}},
		{"a private key beside the certificate", chain(fixtureLeaf, fixtureKey),
			map[string]status.Status{"private_key": status.Warn}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := statuses(decode(t, tc.input))
			for id, want := range tc.want {
				if got[id] != want {
					t.Errorf("%s: %q, want %q (all: %v)", id, got[id], want, got)
				}
			}
		})
	}
}

// TestTheSentencesNameTheCertificateAndTheRule pins what a person reads for
// the cases a person most often brings.
func TestTheSentencesNameTheCertificateAndTheRule(t *testing.T) {
	for _, tc := range []struct {
		input   []byte
		id      string
		reading string
	}{
		{chain(fixtureExpired), "validity", "Certificate 1 (expired.example.test) expired 5 years ago, at " +
			"2021-01-01 00:00:00 UTC - a client refuses a certificate outside its dates (RFC 5280 section 6.1.3)."},
		{chain(fixtureSoon), "validity", "Certificate 1 (soon.example.test) ends in 10 days, at " +
			"2026-11-23 12:00:00 UTC - less than 30 days left."},
		{chain(fixtureLeaf, fixtureIntermediate, fixtureRoot), "chain", "Certificate 1 is issued by 2 and 2 by 3, " +
			"which issued itself - the chain is complete here. A server may leave that root out (RFC 8446 " +
			"section 4.4.2)."},
		{chain(fixtureLeaf, fixtureRoot, fixtureIntermediate), "chain_order", "The chain runs 1, 3 and 2, which is " +
			"not the order of the input. TLS 1.2 requires each certificate to be followed by the one that issued " +
			"it (RFC 5246 section 7.4.2), and TLS 1.3 recommends it (RFC 8446 section 4.4.2)."},
		{chain(fixtureLeaf), "subject_alt_name", "Certificate 1 (leaf.example.test) is for leaf.example.test, " +
			"www.leaf.example.test and 192.0.2.10."},
		{chain(fixtureLeaf, fixtureKey), "private_key", "Block 2 of the input is a private key. It was not read " +
			"and is not shown here - a private key belongs on the machine that uses it, and a file that carries " +
			"one should not be handed around."},
	} {
		if got := summary(decode(t, tc.input), tc.id); got != tc.reading {
			t.Errorf("%s:\n got %q\nwant %q", tc.id, got, tc.reading)
		}
	}
}

// TestTheLastSecondStillCounts holds RFC 5280 section 4.1.2.5: notAfter is
// part of the validity period, so a certificate is valid at that very second
// and expired at the next.
func TestTheLastSecondStillCounts(t *testing.T) {
	end := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		at   time.Time
		want status.Status
	}{
		{end, status.Warn},
		{end.Add(time.Second), status.Fail},
	} {
		out, err := Decode(chain(fixtureLeaf), tc.at)
		if err != nil {
			t.Fatal(err)
		}
		if got := statuses(out)["validity"]; got != tc.want {
			t.Errorf("at %v: %q, want %q", tc.at, got, tc.want)
		}
	}
}

// TestASubjectAltNameWithoutAHostIsNamedForWhatItIs: an extension holding
// only an e-mail address is there - so the sentence is not "no subject
// alternative name" - and still gives a client no host to match (ADR106).
func TestASubjectAltNameWithoutAHostIsNamedForWhatItIs(t *testing.T) {
	got := summary(decode(t, chain(fixtureEmailOnly)), "subject_alt_name")
	if !strings.HasPrefix(got, "Certificate 1 (Mail Only) has a subject alternative name with no host name") {
		t.Errorf("%q", got)
	}
}

// TestEveryFormOfACertificateIsRead holds the forms a certificate is pasted
// in: PEM as a file has it, PEM copied out of JSON, the output of openssl
// s_client, OpenSSL's TRUSTED CERTIFICATE, base64 alone, an x5c array, DER.
func TestEveryFormOfACertificateIsRead(t *testing.T) {
	leafDER := der(t, fixtureLeaf)
	b64 := base64.StdEncoding.EncodeToString(leafDER)
	interB64 := base64.StdEncoding.EncodeToString(der(t, fixtureIntermediate))
	trusted := string(pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE",
		Bytes: append(append([]byte{}, leafDER...), 0x30, 0x00)}))
	for _, tc := range []struct {
		name   string
		input  []byte
		form   string
		count  int
		noting string
	}{
		{"PEM", chain(fixtureLeaf, fixtureIntermediate), formPEM, 2, ""},
		{"PEM with \\n written out", []byte(strings.ReplaceAll(fixtureLeaf, "\n", `\n`)), formPEM, 1, `\n`},
		{"openssl s_client output", []byte("CONNECTED(00000003)\ndepth=1 CN=x\n" + fixtureLeaf + "---\nNo client " +
			"certificate CA names sent\n"), formPEM, 1, "Text outside the PEM blocks"},
		{"TRUSTED CERTIFICATE", []byte(trusted), formPEM, 1, "trust settings"},
		{"a broken block beside a good one", chain("-----BEGIN CERTIFICATE-----\nnot base64!\n", fixtureLeaf),
			formPEM, 1, "1 block that starts like PEM could not be read"},
		{"base64 alone", []byte(b64), formBase64, 1, ""},
		{"base64 in quotes", []byte(`"` + b64 + `"`), formBase64, 1, "quotes"},
		{"base64url without padding", []byte(base64.RawURLEncoding.EncodeToString(leafDER)), formBase64, 1, ""},
		{"an x5c array", []byte(`["` + b64 + `", "` + interB64 + `"]`), formX5C, 2, ""},
		{"DER", leafDER, formDER, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := decode(t, tc.input)
			d := out.Data.(Data)
			if d.Form != tc.form || len(d.Certificates) != tc.count {
				t.Errorf("form %q with %d certificates, want %q with %d", d.Form, len(d.Certificates), tc.form, tc.count)
			}
			if tc.noting != "" && !strings.Contains(strings.Join(out.Notes, " "), tc.noting) {
				t.Errorf("no note says %q: %q", tc.noting, out.Notes)
			}
			if tc.noting == "" && len(out.Notes) > 0 {
				t.Errorf("notes where nothing was changed: %q", out.Notes)
			}
		})
	}
}

// TestWhatHoldsNoCertificateIsRefusedWithoutBeingQuoted holds ADR141 point 9:
// a refusal says what was found by kind, never by content.
func TestWhatHoldsNoCertificateIsRefusedWithoutBeingQuoted(t *testing.T) {
	const marker = "SECRETMARKER"
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte(marker)}))
	odd := string(pem.EncodeToMemory(&pem.Block{Type: marker, Bytes: []byte(marker)}))
	for _, tc := range []struct {
		name   string
		input  []byte
		saying string
	}{
		{"nothing", []byte(" \n"), "empty"},
		{"words", []byte("hello " + marker), "not a certificate"},
		{"a private key alone", []byte(fixtureKey), "a private key"},
		{"a request and a block of another kind", []byte(csr + odd), "a certificate request (CSR) and a block of a kind"},
		{"an x5c that is not one", []byte(`["` + marker), "not a JSON array"},
		{"a broken block alone", []byte("-----BEGIN CERTIFICATE-----\n" + marker + "!\n"), "none could be read"},
		{"base64 of something else", []byte(base64.StdEncoding.EncodeToString([]byte(marker + marker))),
			"cannot read"},
		{"a certificate the library refuses", []byte(fixtureNegativeSerial), "negative serial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.input, now)
			var refusal *spec.Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("not a refusal: %v", err)
			}
			if !strings.Contains(refusal.Reason, tc.saying) || strings.Contains(refusal.Reason, marker) {
				t.Errorf("reason %q - want it to say %q and never the input", refusal.Reason, tc.saying)
			}
		})
	}
}

// leaks says whether any text of an outcome - notes, checks, view, data -
// carries one of the lines of secret.
func leaks(out spec.Outcome, secret string) bool {
	data, _ := json.Marshal(out)
	for _, line := range strings.Split(secret, "\n") {
		if len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(string(data), line) {
			return true
		}
	}
	return false
}

// TestAPrivateKeyIsNeverShown holds the one secret this tool can be handed by
// mistake: a private key pasted with its certificate is not read, and no line
// of it comes back in anything the tool gives. The detector is checked on a
// planted leak first, so it is known to be able to see one.
func TestAPrivateKeyIsNeverShown(t *testing.T) {
	planted := spec.Outcome{Notes: []string{"x " + strings.Split(fixtureKey, "\n")[1]}}
	if !leaks(planted, fixtureKey) {
		t.Fatal("the detector does not see a line of the key planted in a note, so it proves nothing")
	}
	out := decode(t, chain(fixtureLeaf, fixtureKey, fixtureIntermediate))
	if leaks(out, fixtureKey) {
		t.Error("a line of the private key is in the outcome")
	}
	d := out.Data.(Data)
	if len(d.Skipped) != 1 || d.Skipped[0].Block != 2 || d.Skipped[0].Type != "PRIVATE KEY" {
		t.Errorf("skipped %+v, want block 2, a PRIVATE KEY", d.Skipped)
	}
}

// TestTheDataSpeaksTheReportsNames holds Data to the report's keys where the
// report has them, to lists that are never null, and to the values a person
// compares against another tool's.
func TestTheDataSpeaksTheReportsNames(t *testing.T) {
	out := decode(t, chain(fixtureLeaf, fixtureIntermediate, fixtureRoot, fixtureNegativeSerial))
	raw, err := json.Marshal(out.Data)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Certificates []map[string]any `json:"certificates"`
		Unreadable   []map[string]any `json:"unreadable"`
		Chain        map[string]any   `json:"chain"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	leaf := d.Certificates[0]
	for key, want := range map[string]any{
		"subject": "CN=leaf.example.test,O=certdoctor tests", "issuer": "CN=Fixture Intermediate,O=certdoctor tests",
		"not_before": "2020-01-01T00:00:00Z", "not_after": "2040-01-01T00:00:00Z", "is_ca": false,
		"self_signed": false, "signature_algorithm": "ECDSA-SHA256", "max_path_length": nil,
	} {
		if leaf[key] != want {
			t.Errorf("%s = %v, want %v", key, leaf[key], want)
		}
	}
	for key, length := range map[string]int{"fingerprint_sha256": 64, "fingerprint_sha1": 40, "spki_sha256": 44} {
		if s, _ := leaf[key].(string); len(s) != length {
			t.Errorf("%s = %q, want %d characters", key, s, length)
		}
	}
	for _, key := range []string{"dns_names", "ip_addresses", "email_addresses", "uris", "key_usage",
		"extended_key_usage", "issuing_certificate_urls", "ocsp_servers", "crl_distribution_points"} {
		if _, isList := leaf[key].([]any); !isList {
			t.Errorf("%s is %v, want a list", key, leaf[key])
		}
	}
	// The leaf's serial is 1003, 0x03eb: the bytes of the number, with the
	// leading zero Windows and OpenSSL show.
	if leaf["serial_number"] != "03eb" {
		t.Errorf("serial_number = %v, want 03eb", leaf["serial_number"])
	}
	if root := d.Certificates[2]; root["self_signed"] != true || root["max_path_length"] != 1.0 {
		t.Errorf("the root: self_signed %v, max_path_length %v", root["self_signed"], root["max_path_length"])
	}
	if len(d.Unreadable) != 1 || d.Unreadable[0]["number"] != 4.0 {
		t.Errorf("unreadable %v, want certificate 4", d.Unreadable)
	}
	if d.Chain["end"] != endSelfSigned || d.Chain["in_order"] != true {
		t.Errorf("chain %v", d.Chain)
	}
}

// TestEveryCertificateHasItsBlockAndEveryJudgementItsRow holds the view to
// the checks: a row carrying a judgement has the status its check has.
func TestEveryCertificateHasItsBlockAndEveryJudgementItsRow(t *testing.T) {
	out := decode(t, chain(fixtureExpired, fixtureMD5, fixtureNegativeSerial, fixtureForever))
	if len(out.View) != 5 || out.View[0].Title != "Input" {
		t.Fatalf("%d blocks, the first %q - want Input and one per certificate", len(out.View), out.View[0].Title)
	}
	row := func(block int, label string) spec.Field {
		for _, f := range out.View[block].Fields {
			if f.Label == label {
				return f
			}
		}
		t.Fatalf("block %d has no %q", block, label)
		return spec.Field{}
	}
	if f := row(1, "Valid until"); f.Status != status.Fail || !strings.HasSuffix(f.Note, "ago") {
		t.Errorf("expired: %+v", f)
	}
	if f := row(2, "Signature"); f.Status != status.Fail || f.Value != "MD5-RSA" {
		t.Errorf("MD5: %+v", f)
	}
	if f := row(3, "Read"); f.Status != status.Unknown {
		t.Errorf("unreadable: %+v", f)
	}
	if f := row(4, "Valid until"); f.Note != "no end date (RFC 5280 section 4.1.2.5)" || f.Status != "" {
		t.Errorf("no end date: %+v", f)
	}
	if f := row(1, "SHA-1"); f.Note != "the thumbprint Windows shows" {
		t.Errorf("thumbprint: %+v", f)
	}
}
