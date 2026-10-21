package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The flags every Python from 3.13 on reported to probe S28: trusted first,
// strict and partial chains.
const python313 OpenSSLFlags = 0x88020

func keep(*x509.Certificate) {}

// The flags are read as OpenSSL defines them - 0x20 strict, 0x80000 partial.
func TestTheFlagsAreReadAsOpenSSLDefinesThem(t *testing.T) {
	if !python313.Strict() || !python313.PartialChain() {
		t.Error("the flags of Python 3.13 do not read as strict with partial chains")
	}
	if OpenSSLFlags(0x8000).Strict() || OpenSSLFlags(0x8000).PartialChain() {
		t.Error("the flags of Python 3.12 read as strict or with partial chains")
	}
}

func window() (time.Time, time.Time) { return atNoon().Add(-time.Hour), atNoon().Add(time.Hour) }

// strictRoot is the root every certificate below is issued under unless a test
// says otherwise - it keeps to every rule, and it has a key identifier, so what
// it signs names the key that signed it.
func strictRoot(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	notBefore, notAfter := window()
	return mint(t, "strict root", 1, nil, nil, true, notBefore, notAfter)
}

// under mints one certificate under the strict root, shaped by tweak.
func under(t *testing.T, isCA bool, tweak func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	rootDER, rootKey := strictRoot(t)
	notBefore, notAfter := window()
	der, _ := mint(t, "strict.test", 2, rootDER, rootKey, isCA, notBefore, notAfter, tweak)
	return parsed(t, der)[0]
}

func parsed(t *testing.T, ders ...[]byte) []*x509.Certificate {
	t.Helper()
	certificates := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("a fixture does not parse: %v", err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates
}

func extension(id asn1.ObjectIdentifier, critical bool, value ...byte) pkix.Extension {
	return pkix.Extension{Id: id, Critical: critical, Value: value}
}

func with(extensions ...pkix.Extension) func(*x509.Certificate) {
	return func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, extensions...) }
}

// constrained turns a certificate authority's basic constraints into an
// extension written here, so that their criticality is the test's - crypto/x509
// always marks the ones it writes critical. It writes no key identifier of its
// own then, so the test names one or none.
func constrained(critical bool, keyID []byte) func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.BasicConstraintsValid, c.IsCA = false, false
		c.SubjectKeyId = keyID
		c.ExtraExtensions = append(c.ExtraExtensions, extension(oidBasicConstraints, critical, 0x30, 0x03, 0x01, 0x01, 0xff))
	}
}

func rule(t *testing.T, c *x509.Certificate, i, num int) string {
	t.Helper()
	view, why := strictViewOf(c)
	if why != "" {
		t.Fatalf("the certificate was not judged: %s", why)
	}
	return view.breach(i, num)
}

// ruleCase is one certificate at position i of a chain num long, and what the
// rule it breaks says - empty when it keeps to them all.
type ruleCase struct {
	name   string
	cert   func(t *testing.T) *x509.Certificate
	i, num int
	says   string
}

func checkRules(t *testing.T, cases []ruleCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rule(t, c.cert(t), c.i, c.num)
			if c.says == "" && got != "" || c.says != "" && !strings.Contains(got, c.says) {
				t.Errorf("got %q, want %q", got, c.says)
			}
		})
	}
}

// MUST_BE_CA WITH THE STRICT FLAG ON - check_extensions asks X509_check_ca for 1
// of every certificate past the server's, and for 0 or 1 of the server's - in
// crypto/x509/x509_vfy.c and v3_purp.c of openssl-3.5, ADR112 part 3.
func TestTheAuthorityRuleIsTheOneOpenSSLApplies(t *testing.T) {
	checkRules(t, []ruleCase{
		{"a server's certificate keeping to every rule", func(t *testing.T) *x509.Certificate { return under(t, false, keep) }, 0, 3, ""},
		{"an authority keeping to every rule", func(t *testing.T) *x509.Certificate { return under(t, true, keep) }, 1, 3, ""},
		{"an authority whose key usage cannot sign", func(t *testing.T) *x509.Certificate {
			return under(t, true, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature })
		}, 1, 3, "does not allow signing certificates"},
		{"an authority whose constraints say it is not one", func(t *testing.T) *x509.Certificate {
			return under(t, false, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign })
		}, 1, 3, "saying it is not a certificate authority"},
		{"an authority with neither constraints nor a key usage", func(t *testing.T) *x509.Certificate {
			return under(t, true, func(c *x509.Certificate) { c.BasicConstraintsValid, c.IsCA, c.KeyUsage = false, false, 0 })
		}, 1, 3, "has no basic constraints extension"},
		{"a server's certificate that may sign and has no constraints", func(t *testing.T) *x509.Certificate {
			return under(t, false, func(c *x509.Certificate) {
				c.BasicConstraintsValid = false
				c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
			})
		}, 0, 3, "allows signing certificates in its key usage and has no basic constraints"},
		{"an authority only by a Netscape type", func(t *testing.T) *x509.Certificate {
			return under(t, true, func(c *x509.Certificate) {
				c.BasicConstraintsValid, c.IsCA, c.KeyUsage = false, false, 0
				with(extension(oidNetscapeCertType, false, 0x03, 0x02, 0x02, 0x04))(c)
			})
		}, 1, 3, "Netscape certificate type"},
	})
}

// EVERY RULE OF THE STRICT BLOCK, one certificate at a time, in the order
// check_extensions in crypto/x509/x509_vfy.c of openssl-3.5 checks them, and the
// key usage check_purpose refuses under the same flag - ADR112 part 3.
func TestEachStrictRuleIsTheOneOpenSSLApplies(t *testing.T) {
	selfSignedNoName := func(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
		notBefore, notAfter := window()
		return mint(t, "x", 9, nil, nil, true, notBefore, notAfter, func(c *x509.Certificate) { c.Subject = pkix.Name{} })
	}
	checkRules(t, []ruleCase{
		{"a path length on what is not an authority", func(t *testing.T) *x509.Certificate {
			// crypto/x509 refuses to write this one, so it is written here.
			return under(t, false, func(c *x509.Certificate) {
				c.BasicConstraintsValid = false
				with(extension(oidBasicConstraints, true, 0x30, 0x03, 0x02, 0x01, 0x00))(c)
			})
		}, 0, 2, "without being a certificate authority"},
		{"a path length without a key usage", func(t *testing.T) *x509.Certificate {
			return under(t, true, func(c *x509.Certificate) { c.KeyUsage, c.MaxPathLen = 0, 1 })
		}, 1, 3, "without a key usage that allows signing certificates"},
		{"constraints not marked critical", func(t *testing.T) *x509.Certificate {
			return under(t, true, constrained(false, []byte{1, 2, 3}))
		}, 1, 3, "basic constraints are not marked critical"},
		{"an authority with no key usage", func(t *testing.T) *x509.Certificate {
			return under(t, true, func(c *x509.Certificate) { c.KeyUsage = 0 })
		}, 1, 3, "with no key usage extension"},
		{"a server's certificate that may sign", func(t *testing.T) *x509.Certificate {
			return under(t, false, func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign })
		}, 0, 2, "still allows signing certificates"},
		{"an empty issuer", func(t *testing.T) *x509.Certificate {
			parentDER, parentKey := selfSignedNoName(t)
			notBefore, notAfter := window()
			der, _ := mint(t, "strict.test", 2, parentDER, parentKey, false, notBefore, notAfter)
			return parsed(t, der)[0]
		}, 0, 2, "has an empty issuer name"},
		{"an empty subject on an authority", func(t *testing.T) *x509.Certificate {
			return under(t, true, func(c *x509.Certificate) { c.Subject = pkix.Name{} })
		}, 1, 3, "has an empty subject name"},
		{"an empty subject beside a name not marked critical", func(t *testing.T) *x509.Certificate {
			return under(t, false, func(c *x509.Certificate) {
				c.Subject, c.DNSNames = pkix.Name{}, nil
				with(extension(oidSubjectAltName, false, 0x30, 0x03, 0x82, 0x01, 'a'))(c)
			})
		}, 0, 2, "does not mark its subject alternative name critical"},
		{"a subject alternative name with no name", func(t *testing.T) *x509.Certificate {
			return under(t, false, func(c *x509.Certificate) {
				c.DNSNames = nil
				with(extension(oidSubjectAltName, false, 0x30, 0x00))(c)
			})
		}, 0, 2, "with no name in it"},
		{"no key identifier for the key that signed it", func(t *testing.T) *x509.Certificate {
			return under(t, false, with(extension(oidAuthorityKeyID, false, 0x30, 0x00)))
		}, 0, 2, "no authority key identifier"},
		{"an authority with no key identifier of its own", func(t *testing.T) *x509.Certificate {
			return under(t, true, constrained(true, nil))
		}, 1, 3, "with no subject key identifier"},
		{"an empty key usage, in a chain", func(t *testing.T) *x509.Certificate {
			return under(t, false, with(extension(oidKeyUsage, true, 0x03, 0x01, 0x00)))
		}, 0, 2, "no usage in it"},
		{"an empty key usage, alone", func(t *testing.T) *x509.Certificate {
			return under(t, false, with(extension(oidKeyUsage, true, 0x03, 0x01, 0x00)))
		}, 0, 1, "no usage in it"},
		{"the strict block skipped for a chain of one", func(t *testing.T) *x509.Certificate {
			return under(t, true, func(c *x509.Certificate) { c.KeyUsage = 0 })
		}, 0, 1, ""},
	})
}

// versionOne makes a version 1 certificate by hand, since crypto/x509 writes
// version 3 alone - and writes extensions into its [3] field all the same when
// given, as some old issuers did.
func versionOne(t *testing.T, subject, issuer string, extensions ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("no public key: %v", err)
	}
	name := func(cn string) asn1.RawValue {
		der, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
		if err != nil {
			t.Fatalf("no name: %v", err)
		}
		return asn1.RawValue{FullBytes: der}
	}
	type validity struct{ NotBefore, NotAfter time.Time }
	algorithm := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	notBefore, notAfter := window()
	tbs, err := asn1.Marshal(struct {
		Serial     *big.Int
		Algorithm  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		Validity   validity
		Subject    asn1.RawValue
		Key        asn1.RawValue
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}{big.NewInt(7), algorithm, name(issuer), validity{notBefore, notAfter}, name(subject), asn1.RawValue{FullBytes: spki}, extensions})
	if err != nil {
		t.Fatalf("no TBSCertificate: %v", err)
	}
	digest := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("no signature: %v", err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, algorithm, asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}})
	if err != nil {
		t.Fatalf("no certificate: %v", err)
	}
	return parsed(t, der)[0]
}

// A VERSION 1 ROOT IS NOT A CERTIFICATE AUTHORITY TO THE STRICT RULES - check_ca
// answers 3 for it, and check_extensions asks for 1 of every certificate past the
// server's once the flag is on.
func TestAVersionOneCertificateIsReadAsOpenSSLReadsIt(t *testing.T) {
	root := versionOne(t, "v1 root", "v1 root")
	if got := rule(t, root, 1, 2); !strings.Contains(got, "version 1 certificate naming itself") {
		t.Errorf("a version 1 root at the end of a chain: %q", got)
	}
	if got := rule(t, versionOne(t, "v1 server", "v1 root"), 0, 2); got != "" {
		t.Errorf("a version 1 server's certificate with a name and no extensions: %q", got)
	}

	carrying := versionOne(t, "v1 server", "v1 root", extension(oidSubjectKeyID, false, 0x04, 0x01, 0x01))
	breach, why := firstBreach([]*x509.Certificate{carrying, root})
	if why != "" || !strings.Contains(breach, "before version 3 that carries extensions") {
		t.Errorf("version 1 with extensions in a chain: %q / %q", breach, why)
	}
	if breach, why = firstBreach([]*x509.Certificate{carrying}); breach != "" || !strings.Contains(why, "Go does not") {
		t.Errorf("version 1 with extensions alone: %q / %q", breach, why)
	}

	if _, why := strictViewOf(versionOne(t, "v1 Root", "V1 ROOT")); !strings.Contains(why, "another spelling") {
		t.Errorf("names apart only in case were judged: %q", why)
	}
	if _, why := strictViewOf(&x509.Certificate{Version: 1, RawTBSCertificate: []byte{5}}); why == "" {
		t.Error("an unreadable TBSCertificate was judged")
	}
}

// WHAT OPENSSL READS AND THIS PROGRAM DOES NOT IS NOT JUDGED - rule 15. Each of
// these is an extension crypto/x509 parses past, so the certificate reaches here.
func TestAnExtensionThisProgramCannotReadLeavesTheChainUnjudged(t *testing.T) {
	cases := map[string]pkix.Extension{
		"a proxy certificate":               extension(oidProxyCertInfo, false, 0x30, 0x00),
		"an IP address resource":            extension(oidIPAddrBlocks, false, 0x30, 0x00),
		"a Netscape type that is no bits":   extension(oidNetscapeCertType, false, 0x05, 0x00),
		"a name that is no GeneralName":     extension(oidSubjectAltName, false, 0x30, 0x03, 0x02, 0x01, 0x01),
		"a key identifier with bytes after": extension(oidAuthorityKeyID, false, 0x30, 0x00, 0x05, 0x00),
		"a key usage with bytes after":      extension(oidKeyUsage, true, 0x03, 0x02, 0x07, 0x80, 0x05, 0x00),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			c := under(t, false, with(e))
			breach, why := firstBreach([]*x509.Certificate{c})
			if breach != "" || !strings.HasPrefix(why, "the server's certificate CN=strict.test ") ||
				!strings.HasSuffix(why, "so what OpenSSL's strict checking makes of the chain is undetermined") {
				t.Errorf("got %q / %q", breach, why)
			}
		})
	}
}

// The sentence names where the certificate stands and what it is called, so a
// person knows which one to have issued again.
func TestABreachNamesTheCertificateAndItsPlace(t *testing.T) {
	rootDER, rootKey := strictRoot(t)
	notBefore, notAfter := window()
	leafDER, _ := mint(t, "strict.test", 2, rootDER, rootKey, false, notBefore, notAfter)
	if breach, why := firstBreach(parsed(t, leafDER, rootDER)); breach != "" || why != "" {
		t.Errorf("a chain keeping to every rule: %q / %q", breach, why)
	}

	bareDER, bareKey := mint(t, "bare root", 1, nil, nil, true, notBefore, notAfter, func(c *x509.Certificate) { c.KeyUsage = 0 })
	leafDER, _ = mint(t, "strict.test", 2, bareDER, bareKey, false, notBefore, notAfter)
	breach, _ := firstBreach(parsed(t, leafDER, bareDER))
	if breach != "the anchor CN=bare root is a certificate authority with no key usage extension, which OpenSSL's strict "+
		"checking refuses" {
		t.Errorf("got %q", breach)
	}

	for i, want := range []string{"the server's certificate", "the intermediate", "the anchor"} {
		if got := roleOf(i, 3); got != want {
			t.Errorf("position %d is %q", i, got)
		}
	}
	nameless := under(t, true, func(c *x509.Certificate) { c.Subject = pkix.Name{} })
	if got := certificateName(nameless); got != "issued by CN=strict root" {
		t.Errorf("a certificate with no subject is named %q", got)
	}
	if got := certificateName(&x509.Certificate{}); got != "with neither a subject nor an issuer" {
		t.Errorf("a certificate with no names is named %q", got)
	}
}

// The readers below take DER crypto/x509 has already parsed, so their refusals
// are reached here directly.
func TestTheReadersRefuseWhatTheyCannotRead(t *testing.T) {
	for name, der := range map[string][]byte{
		"nothing":                  nil,
		"not a sequence":           {0x02, 0x01, 0x01},
		"bytes after the sequence": {0x30, 0x00, 0x00},
		"a cut element":            {0x30, 0x02, 0x04, 0x05},
	} {
		if _, err := elements(der); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	if _, err := carriesExtensions([]byte{0x05}); err == nil {
		t.Error("a TBSCertificate that is no sequence was read")
	}
	if found, err := carriesExtensions([]byte{0x30, 0x06, 0xa3, 0x04, 0x30, 0x02, 0x30, 0x00}); !found || err != nil {
		t.Errorf("an extension in the [3] field: %v %v", found, err)
	}
	if found, err := carriesExtensions([]byte{0x30, 0x04, 0xa3, 0x02, 0x30, 0x00}); found || err != nil {
		t.Errorf("an empty [3] field: %v %v", found, err)
	}
	if found, err := carriesExtensions([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); found || err != nil {
		t.Errorf("no [3] field: %v %v", found, err)
	}
	for der, want := range map[string]uint16{"\x03\x01\x00": 0, "\x03\x02\x00\x04": 0x04, "\x03\x03\x07\x04\x80": 0x8004} {
		if got, err := bitsOf([]byte(der)); got != want || err != nil {
			t.Errorf("% x read as %#x %v", der, got, err)
		}
	}
	if _, err := namesIn([]byte{0x05}); err == nil {
		t.Error("names that are no sequence were read")
	}
	if found, err := keyIDIn([]byte{0x30, 0x03, 0x81, 0x01, 0x00}); found || err != nil {
		t.Errorf("an issuer and no key identifier: %v %v", found, err)
	}
}

// strictChain is a root, an intermediate under it and a server's certificate
// under that, each shaped by its tweak - and the store holding the root.
func strictChain(t *testing.T, inter func(*x509.Certificate)) (store, chain [][]byte) {
	t.Helper()
	notBefore, notAfter := window()
	rootDER, rootKey := strictRoot(t)
	interDER, interKey := mint(t, "strict intermediate", 2, rootDER, rootKey, true, notBefore, notAfter, inter)
	leafDER, _ := mint(t, "strict.test", 3, interDER, interKey, false, notBefore, notAfter)
	return [][]byte{rootDER, interDER}, [][]byte{leafDER, interDER}
}

func strictly(t *testing.T, store [][]byte, chain [][]byte, flags OpenSSLFlags) report.TrustStore {
	t.Helper()
	var row report.TrustStore
	VerifyStrictly(&row, bundleOf(t, store...), chain, atNoon(), flags)
	return row
}

func verdictOf(row report.TrustStore) string {
	switch {
	case row.TrustsPresentedChain == nil:
		return "undetermined: " + row.NotAssessed
	case *row.TrustsPresentedChain:
		return "trusted"
	}
	return "refused " + string(row.TrustFailure) + ": " + row.RefusalDetail
}

// STRICT ONLY TAKES AWAY, and what it takes away says which certificate and
// which rule - ADR112 part 3.
func TestStrictRulesRefuseOnlyWhatOpenSSLRefuses(t *testing.T) {
	roots, chain := strictChain(t, keep)
	if got := verdictOf(strictly(t, roots[:1], chain, python313)); got != "trusted" {
		t.Errorf("a chain keeping to every rule: %s", got)
	}

	roots, chain = strictChain(t, with(extension(oidAuthorityKeyID, false, 0x30, 0x00)))
	row := strictly(t, roots[:1], chain, python313)
	if got := verdictOf(row); got != "refused nonconforming_certificate: the intermediate CN=strict intermediate does "+
		"not name the key that signed it (no authority key identifier), which OpenSSL's strict checking refuses" ||
		row.TrustAnchorCount != 1 {
		t.Errorf("an intermediate with no key identifier: %s, %d anchors", got, row.TrustAnchorCount)
	}

	other, _ := strictRoot(t)
	if got := verdictOf(strictly(t, [][]byte{other}, chain, python313)); got != "refused unknown_authority: " {
		t.Errorf("a refusal before the rules: %s", got)
	}
	if got := verdictOf(strictly(t, nil, chain, python313)); !strings.HasPrefix(got, "undetermined: the store holds no") {
		t.Errorf("an empty store: %s", got)
	}
	for name, flags := range map[string]OpenSSLFlags{"no trusted first": 0x80020, "no partial chains": 0x8020} {
		if got := verdictOf(strictly(t, roots[:1], chain, flags)); !strings.Contains(got, "only a chain built with both") {
			t.Errorf("%s: %s", name, got)
		}
	}

	roots, chain = strictChain(t, with(extension(oidProxyCertInfo, false, 0x30, 0x00)))
	if got := verdictOf(strictly(t, roots[:1], chain, python313)); !strings.Contains(got, "proxy certificate") {
		t.Errorf("an intermediate this program cannot read: %s", got)
	}
}

// THE SERVER'S OWN CERTIFICATE ON THE LIST - OpenSSL first looks for what signed
// it, and settles for the certificate itself only when nothing did.
func TestTheServersOwnCertificateOnTheListIsJudgedOnlyWhenItSignedItself(t *testing.T) {
	roots, chain := strictChain(t, keep)
	if got := verdictOf(strictly(t, [][]byte{roots[0], chain[0]}, chain, python313)); !strings.Contains(got, "server's own certificate") {
		t.Errorf("a server's certificate signed by another: %s", got)
	}
	notBefore, notAfter := window()
	self, _ := mint(t, "strict.test", 1, nil, nil, false, notBefore, notAfter)
	if got := verdictOf(strictly(t, [][]byte{self}, [][]byte{self}, python313)); got != "trusted" {
		t.Errorf("a server's certificate signed by itself: %s", got)
	}
}

// OPENSSL STOPS AT THE FIRST CERTIFICATE FROM THE LIST. Windows hands Python 3.13
// its CA store beside its ROOT store, so an intermediate from a group policy is
// on the list - and the chain ends there, where the rule about a key identifier
// does not reach it.
func TestTheChainEndsAtTheFirstCertificateFromTheList(t *testing.T) {
	roots, chain := strictChain(t, with(extension(oidAuthorityKeyID, false, 0x30, 0x00)))
	if got := verdictOf(strictly(t, roots, chain, python313)); got != "trusted" {
		t.Errorf("an intermediate on the list ending the chain: %s", got)
	}
}

// crossSigned is one intermediate key under two roots: the first certificate for
// it shaped by first, the second by second, the server's certificate under the
// key, and both roots.
func crossSigned(t *testing.T, first, second func(*x509.Certificate)) (rootOne, rootTwo, interOne, interTwo, leaf []byte) {
	t.Helper()
	notBefore, notAfter := window()
	rootOne, keyOne := mint(t, "root one", 1, nil, nil, true, notBefore, notAfter)
	rootTwo, keyTwo := mint(t, "root two", 2, nil, nil, true, notBefore, notAfter)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no key: %v", err)
	}
	interOne = mintFor(t, interKey, "cross intermediate", 3, rootOne, keyOne, true, notBefore, notAfter, first)
	interTwo = mintFor(t, interKey, "cross intermediate", 4, rootTwo, keyTwo, true, notBefore, notAfter, second)
	leaf, _ = mint(t, "strict.test", 5, interOne, interKey, false, notBefore, notAfter)
	return rootOne, rootTwo, interOne, interTwo, leaf
}

// WHERE OPENSSL COULD BUILD MORE THAN ONE CHAIN, which it builds decides - so the
// answer is given only where every chain it could build agrees.
func TestMoreThanOneChainIsJudgedOnlyWhereTheyAgree(t *testing.T) {
	noKeyID := with(extension(oidAuthorityKeyID, false, 0x30, 0x00))

	rootOne, rootTwo, interOne, interTwo, leaf := crossSigned(t, keep, noKeyID)
	if got := verdictOf(strictly(t, [][]byte{rootOne, rootTwo}, [][]byte{leaf, interOne, interTwo}, python313)); !strings.Contains(got, "only some of them") {
		t.Errorf("one chain keeping to the rules and one not: %s", got)
	}

	rootOne, rootTwo, interOne, interTwo, leaf = crossSigned(t, noKeyID, noKeyID)
	if got := verdictOf(strictly(t, [][]byte{rootOne, rootTwo}, [][]byte{leaf, interOne, interTwo}, python313)); !strings.HasPrefix(got, "refused nonconforming_certificate: the intermediate CN=cross intermediate") {
		t.Errorf("every chain breaking a rule: %s", got)
	}

	// TRUSTED FIRST: the intermediate on the list is taken before the one the
	// server sent, so the chain through the server's never gets built.
	rootOne, rootTwo, interOne, interTwo, leaf = crossSigned(t, keep, noKeyID)
	if got := verdictOf(strictly(t, [][]byte{interOne, rootTwo}, [][]byte{leaf, interTwo}, python313)); got != "trusted" {
		t.Errorf("an intermediate on the list beside one the server sent: %s", got)
	}
}
