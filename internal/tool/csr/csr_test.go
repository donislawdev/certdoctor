package csr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// decoded is the outcome of raw, which must not be refused.
func decoded(t *testing.T, raw []byte) spec.Outcome {
	t.Helper()
	out, err := Decode(raw)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	return out
}

// checkOf is the check with id, and whether there is one.
func checkOf(out spec.Outcome, id string) (spec.Check, bool) {
	for _, c := range out.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return spec.Check{}, false
}

func dataOf(t *testing.T, out spec.Outcome) Request {
	t.Helper()
	d, ok := out.Data.(Data)
	if !ok {
		t.Fatalf("data is %T", out.Data)
	}
	return d.Request
}

// TestAnOrdinaryServerRequestPassesAndSaysWhatItAsks is the request most
// people make: a P-256 key, two names, the common name among them.
func TestAnOrdinaryServerRequestPassesAndSaysWhatItAsks(t *testing.T) {
	out := decoded(t, []byte(fixtureServer))
	for _, c := range out.Checks {
		if c.Status != status.Pass {
			t.Errorf("%s is %s: %s", c.ID, c.Status, c.Summary)
		}
	}
	var ids []string
	for _, c := range out.Checks {
		ids = append(ids, c.ID)
	}
	want := []string{"signature", "key_size", "key_type", "subject_alt_name", "names", "common_name",
		"challenge_password", "version"}
	if !slices.Equal(ids, want) {
		t.Errorf("checks %v, want %v", ids, want)
	}
	r := dataOf(t, out)
	parsed, err := x509.ParseCertificateRequest(derOf(t, fixtureServer))
	if err != nil {
		t.Fatal(err)
	}
	if r.SPKISHA256 != certfacts.SPKIPin(parsed.RawSubjectPublicKeyInfo) || r.SignatureValid == nil ||
		!*r.SignatureValid || r.PublicKey.Words() != "ECDSA, P-256" || r.Version != 0 ||
		r.SignatureAlgorithm != "ECDSA-SHA256" {
		t.Errorf("data: %+v", r)
	}
	if !slices.Equal(r.DNSNames, []string{"www.example.test", "example.test"}) ||
		!slices.Equal(r.KeyUsage, []string{"digitalSignature"}) || !slices.Equal(r.ExtendedKeyUsage, []string{"serverAuth"}) {
		t.Errorf("names and purposes: %+v", r)
	}
	if !slices.Equal(r.Attributes, []string{"1.2.840.113549.1.9.14"}) || r.ChallengePassword == nil ||
		*r.ChallengePassword {
		t.Errorf("attributes: %v %v", r.Attributes, r.ChallengePassword)
	}
	if len(out.Notes) > 0 {
		t.Errorf("notes where nothing was changed: %q", out.Notes)
	}
}

// TestTheDataHasTheKeysOfTheContract holds the names a script reads (ADR154
// decision 3) - the same as the certificate decoder's where they mean the same.
func TestTheDataHasTheKeysOfTheContract(t *testing.T) {
	raw, err := json.Marshal(decoded(t, []byte(fixtureServer)).Data)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	var request map[string]json.RawMessage
	if err := json.Unmarshal(top["request"], &request); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		got  map[string]json.RawMessage
		want []string
	}{
		{top, []string{"form", "request", "skipped"}},
		{request, []string{"attributes", "challenge_password", "dns_names", "email_addresses", "extended_key_usage",
			"extensions", "ip_addresses", "is_ca", "key_usage", "max_path_length", "public_key", "signature_algorithm",
			"signature_valid", "spki_sha256", "subject", "uris", "version"}},
	} {
		var keys []string
		for k := range c.got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if !slices.Equal(keys, c.want) {
			t.Errorf("keys %v, want %v", keys, c.want)
		}
	}
}

// ruleCase is one rule run on a request made to break it: the status and the
// words that say why.
type ruleCase struct {
	name   string
	der    []byte
	id     string
	status status.Status
	saying string
}

func runRules(t *testing.T, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name+" "+tc.id, func(t *testing.T) {
			c, ok := checkOf(decoded(t, tc.der), tc.id)
			if !ok {
				t.Fatalf("no %s check", tc.id)
			}
			if c.Status != tc.status || !strings.Contains(c.Summary, tc.saying) {
				t.Errorf("%s: %s %q - want %s saying %q", tc.id, c.Status, c.Summary, tc.status, tc.saying)
			}
		})
	}
}

// changed is server with one change.
func changed(t *testing.T, change func(r *request)) []byte {
	r := server(t)
	change(&r)
	return r.der(t)
}

// TestTheSignatureAndKeyRulesSpeak runs the rules on the signature and the
// key on requests made to break them.
func TestTheSignatureAndKeyRulesSpeak(t *testing.T) {
	tampered := derOf(t, fixtureServer)
	tampered[len(tampered)-3] ^= 0xff
	key := func(spki string, algorithm asn1.ObjectIdentifier) []byte {
		return changed(t, func(r *request) { r.spki, r.algorithm = spki, algorithm })
	}
	runRules(t, []ruleCase{
		{"a signature its key does not verify", tampered, "signature", status.Fail, "does not verify its signature"},
		{"an MD5 signature", key(spkiRSA2048, oidMD5WithRSA), "signature", status.Fail,
			"signed with MD5-RSA, which Go refuses"},
		{"a SHA-1 signature", derOf(t, fixtureSHA1), "signature", status.Warn, "but the signature is SHA1-RSA"},
		{"an algorithm the library does not know", key(spkiP256, oidEd448), "signature", status.Unknown,
			"made with 1.3.101.113 and a key of ECDSA, P-256 - the signature is not checked"},
		{"an RSA key too large to check with", key(spkiRSAOverCeiling, oidSHA256WithRSA), "signature",
			status.Unknown, "16392 bits, more than the 16384 this program checks"},
		{"an RSA key too small for Go", key(spkiRSA512, oidSHA256WithRSA), "signature", status.Unknown,
			"under 1024 bits"},
		{"an RSA key too small for Go", key(spkiRSA512, oidSHA256WithRSA), "key_size", status.Fail,
			"RSA key of 512 bits"},
		{"an RSA key of 1024 bits", key(spkiRSA1024, oidSHA256WithRSA), "key_size", status.Warn,
			"RSA key of 1024 bits - a public authority"},
		{"an RSA key not a multiple of 8", key(spkiRSA2049, oidSHA256WithRSA), "key_type", status.Warn,
			"2049 bits, not a multiple of 8"},
		{"a P-224 key", key(spkiP224, nil), "key_type", status.Warn, "on P-224"},
		{"an Ed25519 key", key(spkiEd25519, nil), "key_type", status.Warn,
			"is Ed25519 - a public authority issues TLS certificates only for RSA and ECDSA"},
		{"a key the library does not read", key(unknownSPKI(t), nil), "key_type", status.Unknown,
			"unknown (1.3.101.113)"},
		{"a version other than 0", changed(t, func(r *request) { r.version = 2 }), "version", status.Warn,
			"version field is 2"},
	})
}

// TestTheNameRulesSpeak runs the rules on the names on requests made to break
// them.
func TestTheNameRulesSpeak(t *testing.T) {
	with := func(change func(r *request)) []byte { return changed(t, change) }
	runRules(t, []ruleCase{
		{"no subject alternative name", with(func(r *request) { r.extensions = r.extensions[1:] }),
			"subject_alt_name", status.Warn, "asks for no subject alternative name"},
		{"an e-mail address alone", with(func(r *request) { r.extensions[0] = san(t, mail("someone@example.test")) }),
			"subject_alt_name", status.Warn, "no host name and no address"},
		{"names in Microsoft's attribute", with(func(r *request) {
			r.extensions = nil
			r.attributes = []asn1.RawValue{attribute(t, oidMSExtensionRequest, []pkix.Extension{san(t,
				dns("www.example.test"))})}
		}), "subject_alt_name", status.Unknown, "msExtReq"},
		{"two wildcards", withNames(t, "*.*.example.test").der(t), "names", status.Warn,
			"*.*.example.test (a wildcard that is not the whole first label)"},
		{"a wildcard inside a label", withNames(t, "w*.example.test").der(t), "names", status.Warn,
			"not the whole first label"},
		{"a dot at the end", withNames(t, "example.test.").der(t), "names", status.Warn, "(a dot at the end)"},
		{"an underscore", withNames(t, "a_b.example.test").der(t), "names", status.Warn, "(an underscore)"},
		{"a single label", withNames(t, "localhost").der(t), "names", status.Warn, "(a single label"},
		{"a wildcard over a single label", withNames(t, "*.com").der(t), "names", status.Warn, "(a single label"},
		{"an address as a host name", withNames(t, "192.0.2.1").der(t), "names", status.Warn,
			"(an address written as a host name"},
		{"a URL as a host name", withNames(t, "https://example.test").der(t), "names", status.Warn,
			"(a character other than a letter, a digit or a hyphen)"},
		{"a hyphen at the end", withNames(t, "a-.example.test").der(t), "names", status.Warn,
			"(a hyphen at the start or the end"},
		{"two hyphens in a reserved place", withNames(t, "ab--c.example.test").der(t), "names", status.Warn,
			"which only an xn-- label may have"},
		{"an empty label", withNames(t, "a..example.test").der(t), "names", status.Warn, "(an empty label)"},
		{"a long label", withNames(t, strings.Repeat("a", 64)+".example.test").der(t), "names", status.Warn,
			"(a label longer than 63 characters)"},
		{"a long name", withNames(t, strings.Repeat(strings.Repeat("a", 60)+".", 5)+"test").der(t), "names",
			status.Warn, "(longer than 253 characters)"},
		{"an e-mail address and a URI", with(func(r *request) {
			r.extensions[0] = san(t, dns("www.example.test"), mail("someone@example.test"), uri("https://example.test/x"))
		}), "names", status.Warn, "1 e-mail address and 1 URI, which a public authority does not put"},
		{"two common names", with(func(r *request) {
			r.subject = pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidCommonName, Value: "www.example.test"}, {Type: oidCommonName, Value: "example.test"}}}
		}), "common_name", status.Warn, "has 2 common names"},
		{"a common name outside the names", with(func(r *request) {
			r.subject = pkix.Name{CommonName: "other.example.test"}
		}), "common_name", status.Warn, "other.example.test is not one of the names"},
	})
}

// TestWhatTheRulesAllowPasses holds the other side of each rule: what they
// must not warn about.
func TestWhatTheRulesAllowPasses(t *testing.T) {
	named := func(cn string, names ...asn1.RawValue) []byte {
		r := server(t)
		r.subject = pkix.Name{CommonName: cn}
		r.extensions[0] = san(t, names...)
		return r.der(t)
	}
	address := named("192.0.2.10", ip(192, 0, 2, 10))
	for _, tc := range []struct {
		name, id, saying string
		der              []byte
	}{
		{"a common name in other letters", "common_name", "is one of the names",
			named("WWW.Example.Test", dns("www.example.test"))},
		{"an address as the common name", "common_name", "is one of the names", address},
		{"no common name", "common_name", "has no common name", named("", dns("www.example.test"))},
		{"addresses only", "names", "addresses only", address},
		{"a wildcard and an xn-- label", "names", "Every host name is spelled",
			named("", dns("*.example.test"), dns("xn--bcher-kva.example.test"), dns("Upper-Case.Example.Test"))},
		{"an RSA key of 2048 bits", "key_type", "The key is RSA", derOf(t, fixtureRSA2048)},
		{"an RSA key of 2048 bits", "key_size", "No RSA key is shorter than 2048 bits.", derOf(t, fixtureRSA2048)},
	} {
		t.Run(tc.name+" "+tc.id, func(t *testing.T) {
			c, ok := checkOf(decoded(t, tc.der), tc.id)
			if !ok || c.Status != status.Pass || !strings.Contains(c.Summary, tc.saying) {
				t.Errorf("%s: %+v, want a pass saying %q", tc.id, c, tc.saying)
			}
		})
	}
}

// TestARequestForSomethingElseIsNotJudgedAsAServers holds that the rules for a
// TLS server's certificate are asked of nothing else, and that skipping them
// is said.
func TestARequestForSomethingElseIsNotJudgedAsAServers(t *testing.T) {
	client := server(t)
	client.extensions = []pkix.Extension{purposes(t, oidClientAuth)}
	ca := server(t)
	ca.extensions = append(ca.extensions, authority(t))
	for _, tc := range []struct {
		name, note string
		r          request
	}{
		{"a client's", "asks for purposes that leave out serving TLS", client},
		{"an authority's", "asks to be an authority", ca},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := decoded(t, tc.r.der(t))
			for _, id := range []string{"key_type", "subject_alt_name", "names", "common_name"} {
				if c, ok := checkOf(out, id); ok {
					t.Errorf("%s judged: %+v", id, c)
				}
			}
			if !strings.Contains(strings.Join(out.Notes, " "), tc.note) {
				t.Errorf("notes %q do not say %q", out.Notes, tc.note)
			}
		})
	}
	r := dataOf(t, decoded(t, ca.der(t)))
	if !r.IsCA || r.MaxPathLength == nil || *r.MaxPathLength != 0 {
		t.Errorf("an authority with no authority below it: %+v", r)
	}
}

// TestAnExtensionThatCannotBeReadIsSaidAndNotTakenAsAsked holds the note for
// a requested extension whose value is broken.
func TestAnExtensionThatCannotBeReadIsSaidAndNotTakenAsAsked(t *testing.T) {
	r := server(t)
	r.extensions = append(r.extensions[:1], pkix.Extension{Id: oidKeyUsage, Value: []byte{0x05}},
		pkix.Extension{Id: oidExtKeyUsage, Value: []byte{0x05}}, pkix.Extension{Id: oidBasicConstraints,
			Value: []byte{0x05}})
	out := decoded(t, r.der(t))
	if !strings.Contains(strings.Join(out.Notes, " "), "key usage, extended key usage and basic constraints could "+
		"not be read") {
		t.Errorf("notes: %q", out.Notes)
	}
	if d := dataOf(t, out); len(d.KeyUsage)+len(d.ExtendedKeyUsage) > 0 || d.IsCA {
		t.Errorf("a broken extension taken as asked for: %+v", d)
	}
}

// leaks says whether any text of an outcome carries secret.
func leaks(out spec.Outcome, secret string) bool {
	raw, _ := json.Marshal(out)
	return strings.Contains(string(raw), secret)
}

// TestAChallengePasswordIsNoticedAndNeverShown holds ADR154: the password is
// found by its identifier, said to be there, and its value goes nowhere.
func TestAChallengePasswordIsNoticedAndNeverShown(t *testing.T) {
	const marker = "SECRETMARKER-password"
	r := server(t)
	r.attributes = []asn1.RawValue{attribute(t, oidChallengePassword, marker)}
	key := asPEM("PRIVATE KEY", []byte("SECRETMARKER-key-bytes-long-enough"))
	out := decoded(t, append(asPEM("CERTIFICATE REQUEST", r.der(t)), key...))
	// The canary: the detector finds the marker where it is.
	if !leaks(spec.Outcome{Notes: []string{marker}}, marker) {
		t.Fatal("the detector does not find what it looks for")
	}
	if leaks(out, marker) || leaks(out, "SECRETMARKER-key") {
		t.Fatal("the password or the key reached the outcome")
	}
	if c, _ := checkOf(out, "challenge_password"); c.Status != status.Warn {
		t.Errorf("challenge_password: %+v", c)
	}
	if c, _ := checkOf(out, "private_key"); c.Status != status.Warn {
		t.Errorf("private_key: %+v", c)
	}
	d := dataOf(t, out)
	if d.ChallengePassword == nil || !*d.ChallengePassword || !slices.Contains(d.Attributes, "1.2.840.113549.1.9.7") {
		t.Errorf("data: %v %v", d.ChallengePassword, d.Attributes)
	}
}

// TestAnAttributeThatCannotBeReadLeavesThePasswordUnknown holds that "no
// password" is never said of attributes not all read.
func TestAnAttributeThatCannotBeReadLeavesThePasswordUnknown(t *testing.T) {
	r := server(t)
	r.attributes = []asn1.RawValue{{FullBytes: []byte{0x30, 0x03, 0x02, 0x01, 0x05}}}
	out := decoded(t, r.der(t))
	if c, _ := checkOf(out, "challenge_password"); c.Status != status.Unknown {
		t.Errorf("challenge_password: %+v", c)
	}
	if d := dataOf(t, out); d.ChallengePassword != nil {
		t.Errorf("challenge_password in the data is %v, want null", *d.ChallengePassword)
	}
}

// TestEveryFormIsRead holds the shapes a request arrives in.
func TestEveryFormIsRead(t *testing.T) {
	der := derOf(t, fixtureServer)
	block := asPEM("CERTIFICATE REQUEST", der)
	for _, tc := range []struct {
		name, form, noting string
		input              []byte
	}{
		{"PEM", "pem", "", block},
		{"the label certreq and keytool write", "pem", "", asPEM("NEW CERTIFICATE REQUEST", der)},
		{"base64", "base64", "", []byte(base64.StdEncoding.EncodeToString(der))},
		{"DER", "der", "", der},
		{"quoted base64", "base64", "quotes", []byte(`"` + base64.StdEncoding.EncodeToString(der) + `"`)},
		{"PEM out of JSON", "pem", `\n`, []byte(strings.ReplaceAll(string(block), "\n", `\n`))},
		{"two requests", "pem", "holds 2 certificate requests", append(append([]byte{}, block...), block...)},
		{"a certificate beside it", "pem", "certdoctor tool cert reads it",
			append(append([]byte{}, block...), fixtureCertificate...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := decoded(t, tc.input)
			d := out.Data.(Data)
			notes := strings.Join(out.Notes, " ")
			if d.Form != tc.form || tc.noting != "" && !strings.Contains(notes, tc.noting) ||
				tc.noting == "" && notes != "" {
				t.Errorf("form %s, notes %q - want %s noting %q", d.Form, out.Notes, tc.form, tc.noting)
			}
		})
	}
}

// TestWhatHoldsNoRequestIsRefusedWithoutBeingQuoted holds ADR141 point 9: a
// refusal says what was found by kind, never by content, and a certificate
// is sent to the tool that reads it.
func TestWhatHoldsNoRequestIsRefusedWithoutBeingQuoted(t *testing.T) {
	const marker = "SECRETMARKER"
	certificate := derOf(t, fixtureCertificate)
	duplicated := server(t)
	duplicated.extensions = append(duplicated.extensions, keyUsage(t))
	signed := signedMessage(t)
	const cms = "is a CMS (PKCS #7) signed message, not a PKCS #10 certificate request"
	for _, tc := range []struct {
		name   string
		input  []byte
		saying string
	}{
		{"nothing", []byte(" \n"), "The input is empty - give it a certificate request"},
		{"words", []byte("hello " + marker), "not a certificate request"},
		{"a certificate in PEM", []byte(fixtureCertificate), "certdoctor tool cert reads a certificate"},
		{"a certificate in DER", certificate, "is a certificate, not a certificate request - certdoctor tool cert"},
		{"a certificate in base64", []byte(base64.StdEncoding.EncodeToString(certificate)), "is a certificate, not"},
		{"base64 of something else", []byte(base64.StdEncoding.EncodeToString([]byte(marker + marker))),
			"decodes as base64, but not to a certificate request"},
		{"a word starting with the byte DER starts with", []byte("0." + marker), "starts like DER, but is not"},
		{"a request the library refuses", asPEM("CERTIFICATE REQUEST", duplicated.der(t)),
			"cannot read: x509: certificate request contains duplicate requested extensions"},
		{"a CMC request under the header certreq gives it", asPEM("NEW CERTIFICATE REQUEST", signed), cms},
		{"a signed message in DER", signed, cms},
		{"a signed message in base64", []byte(base64.StdEncoding.EncodeToString(signed)), cms},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.input)
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

// TestTheViewSaysWhatTheChecksFound holds the rows a person reads against
// the checks: a bad signature is marked where the signature is shown.
func TestTheViewSaysWhatTheChecksFound(t *testing.T) {
	r := server(t)
	r.extensions = []pkix.Extension{san(t, dns("www.example.test")), extension(t, oidBasicConstraints, struct {
		IsCA bool `asn1:"optional"`
	}{false})}
	r.attributes = []asn1.RawValue{attribute(t, oidChallengePassword, "x"),
		attribute(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 13, 2, 3}, "10.0.26100.2")}
	out := decoded(t, r.der(t))
	rows := map[string]spec.Field{}
	for _, block := range out.View {
		for _, f := range block.Fields {
			rows[f.Label] = f
		}
	}
	for label, want := range map[string]string{
		"Signature":            "ECDSA-SHA256",
		"Attributes":           "extensionRequest, challengePassword (present, not shown), OS version (Microsoft)",
		"Extensions asked for": "subject alternative name, basic constraints",
		"Authority":            "asks not to be one",
		"Host names":           "www.example.test",
		"Read as":              "DER, one request",
	} {
		if rows[label].Value != want {
			t.Errorf("%s: %q, want %q", label, rows[label].Value, want)
		}
	}
	if rows["Signature"].Status != status.Fail || rows["Signature"].Note != "does not verify with its own key" {
		t.Errorf("signature row: %+v", rows["Signature"])
	}
	if rows["Attributes"].Status != status.Warn {
		t.Errorf("attributes row: %+v", rows["Attributes"])
	}
}

// TestChecksComeWorstFirst holds the order every tool lists checks in.
func TestChecksComeWorstFirst(t *testing.T) {
	r := server(t)
	r.version = 1
	out := decoded(t, r.der(t))
	if out.Checks[0].Status != status.Fail ||
		!reflect.DeepEqual(out.Checks, spec.SortChecks(slices.Clone(out.Checks), checkOrder)) {
		t.Errorf("order: %+v", out.Checks)
	}
}

// TestOneProblemGetsOneWarning holds ADR154: a request without a subject
// alternative name is warned about once, by subject_alt_name - its common
// name is not judged against names that are not there.
func TestOneProblemGetsOneWarning(t *testing.T) {
	out := decoded(t, changed(t, func(r *request) { r.extensions = r.extensions[1:] }))
	if c, _ := checkOf(out, "subject_alt_name"); c.Status != status.Warn {
		t.Fatalf("the request is not warned about at all: %+v", c)
	}
	for _, id := range []string{"common_name", "names"} {
		if c, ok := checkOf(out, id); ok {
			t.Errorf("a second warning about the same problem: %+v", c)
		}
	}
}
