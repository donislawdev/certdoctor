package probe

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// OpenSSLFlags are the flags OpenSSL's verifier runs with, as a runtime reports
// them - Python's ssl module as verify_flags.
type OpenSSLFlags int64

// The flags that decide which chain OpenSSL builds and whether its strict rules
// apply - include/openssl/x509_vfy.h.in of OpenSSL's openssl-3.5 branch, read
// 2026-10-21.
const (
	flagX509Strict   OpenSSLFlags = 0x20
	flagTrustedFirst OpenSSLFlags = 0x8000
	flagPartialChain OpenSSLFlags = 0x80000
)

// Strict says OpenSSL holds every certificate of the chain to its strict rules,
// which can refuse a chain the verifier here accepts - measured by S28.
func (f OpenSSLFlags) Strict() bool { return f&flagX509Strict != 0 }

// PartialChain says every certificate on the list ends a chain, as it does for
// Python from 3.13 on - measured by S28. Without it only a self-signed one does.
func (f OpenSSLFlags) PartialChain() bool { return f&flagPartialChain != 0 }

// VerifyStrictly is Verify for a runtime whose OpenSSL 3 also holds the chain to
// its strict rules - X509_V_FLAG_X509_STRICT, ADR112 part 3, decided by the
// owner. The caller calls it for a runtime with that flag set.
//
// STRICT ONLY TAKES AWAY. A chain refused before the rules apply stays refused
// for the reason it was, and a chain accepted is refused only when the chain
// OpenSSL builds breaks one of them - nonconforming_certificate, with the
// certificate and the rule in RefusalDetail.
//
// THE RULES ARE check_extensions IN crypto/x509/x509_vfy.c, and they are the same
// from OpenSSL 3.0 to 3.6 - the branches openssl-3.0 to openssl-3.6 read
// 2026-10-21 differ in formatting and in nothing a rule tests. OpenSSL 1.1.1
// applies far fewer under the same flag, which is why the caller applies these
// to OpenSSL 3 alone. Two were measured by S28, an intermediate without an
// authority key identifier and one whose basic constraints were not critical,
// and the rest are read from the source.
func VerifyStrictly(store *report.TrustStore, anchorsPEM []byte, chain [][]byte, now time.Time, flags OpenSSLFlags) {
	built, stored := verify(store, anchorsPEM, chain, now, !flags.PartialChain())
	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		return
	}
	// THE CHAIN IS MODELLED AS EVERY PYTHON MEASURED BUILDS IT, with partial
	// chains and trusted certificates first - S28 saw 0x88020 on every 3.13 and
	// later. Another way of building it is not one this program can tell.
	if !flags.PartialChain() || flags&flagTrustedFirst == 0 {
		Undetermined(store, "this runtime checks OpenSSL's strict rules on a chain it builds without partial chains or "+
			"without its own certificates first, and only a chain built with both is judged here")
		return
	}
	breach, why := strictBreach(built, stored)
	switch {
	case why != "":
		Undetermined(store, why)
	case breach != "":
		refused := false
		store.TrustsPresentedChain = &refused
		store.TrustFailure = report.NonconformingCertificate
		store.RefusalDetail = breach
	}
}

// strictBreach is the rule the chain OpenSSL builds breaks, empty when it keeps
// to all of them, or why which it is cannot be told.
//
// OPENSSL BUILDS ONE CHAIN AND GO HANDS BACK EVERY CHAIN IT FOUND. With trusted
// certificates first, OpenSSL takes an issuer from the list before one the server
// sent, and with partial chains the first certificate from the list ends the
// chain - build_chain and check_trust in x509_vfy.c of openssl-3.5. So the chains
// Go found that OpenSSL would not have built are set aside, and when what is left
// does not agree, the answer depends on which one OpenSSL picks and is
// undetermined.
func strictBreach(built [][]*x509.Certificate, stored []*x509.Certificate) (string, string) {
	held := map[string]bool{}
	for _, c := range stored {
		held[string(c.Raw)] = true
	}
	clean, broken, first := 0, 0, ""
	for _, chain := range built {
		if len(chain) == 1 && !bytes.Equal(chain[0].RawSubject, chain[0].RawIssuer) {
			return "", "the server's own certificate is on this list, and OpenSSL looks for the certificate that signed it " +
				"before it settles for that one, so which chain it builds is undetermined"
		}
		if !builtByOpenSSL(chain, built, held) {
			continue
		}
		breach, why := firstBreach(chain)
		switch {
		case why != "":
			return "", why
		case breach == "":
			clean++
		default:
			broken++
			if first == "" {
				first = breach
			}
		}
	}
	switch {
	case broken > 0 && clean == 0:
		return first, ""
	case broken == 0 && clean > 0:
		return "", ""
	}
	return "", "OpenSSL could build more than one chain from this list, and only some of them keep to its strict " +
		"rules, so what it makes of the chain is undetermined"
}

// builtByOpenSSL says OpenSSL could have built this chain: it stops at the first
// certificate from the list, and it never takes a certificate the server sent
// where one from the list signed the same certificate.
func builtByOpenSSL(chain []*x509.Certificate, built [][]*x509.Certificate, held map[string]bool) bool {
	for k := 1; k < len(chain); k++ {
		if held[string(chain[k].Raw)] {
			return k == len(chain)-1
		}
		for _, other := range built {
			if len(other) > k && held[string(other[k].Raw)] && prefixOf(other, k) == prefixOf(chain, k) {
				return false
			}
		}
	}
	return true
}

// prefixOf is the first n certificates of a chain as one string. DER says how
// long each certificate is, so two prefixes are equal only when every
// certificate in them is.
func prefixOf(chain []*x509.Certificate, n int) string {
	var prefix strings.Builder
	for _, c := range chain[:n] {
		prefix.Write(c.Raw)
	}
	return prefix.String()
}

// firstBreach walks the chain as check_extensions does, certificate by
// certificate from the server's, and returns the first rule one of them breaks,
// or why that cannot be told.
func firstBreach(chain []*x509.Certificate) (string, string) {
	for i, c := range chain {
		who := roleOf(i, len(chain)) + " " + certificateName(c)
		v, why := strictViewOf(c)
		switch {
		case why == "" && v.extended && len(chain) == 1:
			why = "is a certificate before version 3 that carries extensions, which OpenSSL reads and Go does not"
		case why == "" && v.extended:
			// THE ONE RULE IT BREAKS FOR CERTAIN. OpenSSL reads extensions Go never
			// read, so a rule ahead of this one may be the one it reports - the
			// refusal is the same either way.
			return who + " is a certificate before version 3 that carries extensions, which OpenSSL's strict " +
				"checking refuses", ""
		}
		if why != "" {
			return "", who + " " + why + ", so what OpenSSL's strict checking makes of the chain is undetermined"
		}
		if rule := v.breach(i, len(chain)); rule != "" {
			return who + " " + rule + ", which OpenSSL's strict checking refuses", ""
		}
	}
	return "", ""
}

// roleOf names a certificate by where it stands in the chain.
func roleOf(i, num int) string {
	switch {
	case i == 0:
		return "the server's certificate"
	case i == num-1:
		return "the anchor"
	}
	return "the intermediate"
}

// certificateName is how a sentence names a certificate - its subject, or its issuer when
// the subject is the empty name a rule is about.
func certificateName(c *x509.Certificate) string {
	switch {
	case len(c.Subject.Names) > 0:
		return c.Subject.String()
	case len(c.Issuer.Names) > 0:
		return "issued by " + c.Issuer.String()
	}
	return "with neither a subject nor an issuer"
}

// The bits OpenSSL reads out of a key usage and a Netscape certificate type -
// include/openssl/x509.h.in and x509v3.h.in of openssl-3.5, read 2026-10-21.
const (
	usageCertSign  = 0x0004
	usageCRLSign   = 0x0002
	netscapeAnyCA  = 0x07
	lastNameChoice = 8 // registeredID, the last GeneralName of RFC 5280 4.2.1.6
)

// strictView is one certificate as check_extensions reads it - the fields
// ossl_x509v3_cache_extensions in crypto/x509/v3_purp.c of openssl-3.5 fills in.
//
// WHERE GO HAS ALREADY READ AN EXTENSION, ITS READING IS USED. crypto/x509 of
// go1.27.3 refuses to parse a certificate whose basic constraints, key usage,
// subject alternative name or key identifiers are malformed, whose extensions
// repeat, whose authority or subject key identifier is critical, whose path
// length is negative, or whose inner and outer signature algorithms differ
// (parser.go). So no certificate reaching here breaks the rules about the last
// three, and they are not checked. What Go reads differently or not at all - the
// bits of a key usage past the ninth, a Netscape certificate type, the names and
// key identifier inside the extensions - is read here.
type strictView struct {
	version int
	// extended is a certificate before version 3 that carries extensions, which
	// Go does not read for it and OpenSSL does.
	extended bool
	// authority is EXFLAG_CA and pathLength is a path length constraint present.
	authority, pathLength bool
	// constraints and constraintsCritical are EXFLAG_BCONS and its criticality.
	constraints, constraintsCritical bool
	keyUsage                         bool
	usage                            uint16
	netscapeCA                       bool
	// altNames is how many names the subject alternative name holds, and -1
	// when there is none.
	altNames         int
	altNamesCritical bool
	keyID            bool
	subjectKeyID     bool
	// v1Root is EXFLAG_V1 with EXFLAG_SS - a version 1 certificate naming itself
	// as its issuer. EXFLAG_SS also asks that the signature algorithm fit the key,
	// which is taken to hold - a certificate where it does not is refused here and
	// passed by OpenSSL, never the other way round.
	v1Root                    bool
	emptySubject, emptyIssuer bool
}

// strictViewOf reads one certificate, or says why it could not be read the way
// OpenSSL reads it.
func strictViewOf(c *x509.Certificate) (strictView, string) {
	v := strictView{
		version:      c.Version,
		authority:    c.BasicConstraintsValid && c.IsCA,
		pathLength:   c.BasicConstraintsValid && c.MaxPathLen >= 0,
		altNames:     -1,
		emptySubject: len(c.Subject.Names) == 0,
		emptyIssuer:  len(c.Issuer.Names) == 0,
		v1Root:       c.Version == 1 && bytes.Equal(c.RawSubject, c.RawIssuer),
	}
	if c.Version < 3 {
		return v, v.early(c)
	}
	for _, e := range c.Extensions {
		if why := v.read(e); why != "" {
			return v, why
		}
	}
	return v, ""
}

// early reads what a certificate before version 3 holds that Go does not read.
//
// THE NAMES ARE COMPARED BY THEIR BYTES, and OpenSSL compares them after folding
// case and spaces (X509_NAME_cmp). A version 1 certificate whose two names differ
// only so is the one case where the two readings part, so it is not judged.
func (v *strictView) early(c *x509.Certificate) string {
	extended, err := carriesExtensions(c.RawTBSCertificate)
	switch {
	case err != nil:
		return "could not be read the way OpenSSL reads a certificate before version 3"
	case c.Version == 1 && !v.v1Root && strings.EqualFold(c.Subject.String(), c.Issuer.String()):
		return "names itself as its issuer in another spelling, which OpenSSL may read as the same name"
	}
	v.extended = extended
	return ""
}

// The extensions read here - RFC 5280 4.2.1, the Netscape certificate type, and
// three OpenSSL reads and this program does not: the proxy certificate of RFC
// 3820 and the IP address and AS number resources of RFC 3779.
var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidNetscapeCertType = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
	oidProxyCertInfo    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 14}
	oidIPAddrBlocks     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 7}
	oidASIdentifiers    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 8}
)

// read takes one extension into the view, or says why the certificate cannot be
// judged.
func (v *strictView) read(e pkix.Extension) string {
	var err error
	switch {
	case e.Id.Equal(oidBasicConstraints):
		v.constraints, v.constraintsCritical = true, e.Critical
	case e.Id.Equal(oidKeyUsage):
		v.keyUsage = true
		v.usage, err = bitsOf(e.Value)
	case e.Id.Equal(oidNetscapeCertType):
		var bits uint16
		bits, err = bitsOf(e.Value)
		v.netscapeCA = bits&netscapeAnyCA != 0
	case e.Id.Equal(oidSubjectAltName):
		v.altNamesCritical = e.Critical
		v.altNames, err = namesIn(e.Value)
	case e.Id.Equal(oidAuthorityKeyID):
		v.keyID, err = keyIDIn(e.Value)
	case e.Id.Equal(oidSubjectKeyID):
		v.subjectKeyID = true
	case e.Id.Equal(oidProxyCertInfo):
		return "carries a proxy certificate extension, which OpenSSL reads and this program does not"
	case e.Id.Equal(oidIPAddrBlocks) || e.Id.Equal(oidASIdentifiers):
		return "carries an IP address or AS number extension, which OpenSSL reads and this program does not"
	}
	if err != nil {
		return "carries the extension " + e.Id.String() + " in a form this program could not read"
	}
	return ""
}

// breach is the first rule check_extensions holds this certificate to that it
// breaks, at position i of a chain num long, and empty when it keeps to them.
func (v strictView) breach(i, num int) string {
	if rule := v.authorityRule(i); rule != "" {
		return rule
	}
	if num > 1 {
		if rule := v.strictRule(i, num); rule != "" {
			return rule
		}
	}
	// AN EMPTY KEY USAGE MAKES THE CERTIFICATE INVALID to OpenSSL, and under the
	// strict flag check_purpose refuses an invalid one - v3_purp.c and x509_vfy.c.
	if v.keyUsage && v.usage == 0 {
		return "has a key usage extension with no usage in it"
	}
	return ""
}

// authorityRule is must_be_ca in check_extensions with the strict flag on: the
// server's certificate may be a certificate authority or not, and every other
// certificate must be one by basic constraints.
func (v strictView) authorityRule(i int) string {
	switch kind := v.caKind(); {
	case kind == 1 || i == 0 && kind == 0:
		return ""
	case kind == 3:
		return "is a version 1 certificate naming itself as its issuer, with no basic constraints"
	case kind == 4:
		return "allows signing certificates in its key usage and has no basic constraints extension"
	case kind == 5:
		return "is marked a certificate authority only by a Netscape certificate type"
	case v.keyUsage && v.usage&usageCertSign == 0:
		return "has a key usage that does not allow signing certificates"
	case v.constraints:
		return "has basic constraints saying it is not a certificate authority"
	}
	return "has no basic constraints extension"
}

// caKind is X509_check_ca as check_ca in v3_purp.c answers it: 0 not an
// authority, 1 an authority, 3 a version 1 certificate naming itself, 4 a key
// usage allowing signing certificates without basic constraints, 5 a Netscape
// type naming an authority.
func (v strictView) caKind() int {
	switch {
	case v.keyUsage && v.usage&usageCertSign == 0:
		return 0
	case v.constraints && v.authority:
		return 1
	case v.constraints:
		return 0
	case v.v1Root:
		return 3
	case v.keyUsage:
		return 4
	case v.netscapeCA:
		return 5
	}
	return 0
}

// strictRule is the block check_extensions runs only under the strict flag and
// only on a chain longer than one certificate, in its order.
func (v strictView) strictRule(i, num int) string {
	switch {
	case v.pathLength && !v.authority:
		return "limits the length of the path below it without being a certificate authority"
	case v.pathLength && v.usage&usageCertSign == 0:
		return "limits the length of the path below it without a key usage that allows signing certificates"
	case v.authority && !v.constraintsCritical:
		return "is a certificate authority whose basic constraints are not marked critical"
	case v.authority && !v.keyUsage:
		return "is a certificate authority with no key usage extension"
	case !v.authority && v.usage&usageCertSign != 0:
		return "is not a certificate authority and still allows signing certificates in its key usage"
	case v.emptyIssuer:
		return "has an empty issuer name"
	case v.emptySubject && (v.authority || v.usage&usageCRLSign != 0 || v.altNames < 0):
		return "has an empty subject name"
	case v.emptySubject && !v.altNamesCritical:
		return "has an empty subject name and does not mark its subject alternative name critical"
	case v.altNames == 0:
		return "has a subject alternative name extension with no name in it"
	case v.version >= 3 && i+1 < num && !v.keyID:
		return "does not name the key that signed it (no authority key identifier)"
	case v.version >= 3 && v.authority && !v.subjectKeyID:
		return "is a certificate authority with no subject key identifier"
	}
	return ""
}

var errUnread = errors.New("not the DER this program reads")

// elements reads one DER sequence and returns what it holds.
func elements(der []byte) ([]asn1.RawValue, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errUnread
	}
	var held []asn1.RawValue
	for inner := seq.Bytes; len(inner) > 0; {
		var element asn1.RawValue
		if inner, err = asn1.Unmarshal(inner, &element); err != nil {
			return nil, err
		}
		held = append(held, element)
	}
	return held, nil
}

// carriesExtensions says a TBSCertificate holds at least one extension - the
// [3] field of RFC 5280 4.1, which OpenSSL reads whatever the version says.
func carriesExtensions(tbs []byte) (bool, error) {
	fields, err := elements(tbs)
	if err != nil {
		return false, err
	}
	for _, f := range fields {
		if f.Class == asn1.ClassContextSpecific && f.Tag == 3 {
			extensions, err := elements(f.Bytes)
			return len(extensions) > 0, err
		}
	}
	return false, nil
}

// bitsOf reads a BIT STRING the way OpenSSL caches a key usage: its first byte,
// and its second as the high byte.
func bitsOf(der []byte) (uint16, error) {
	var bits asn1.BitString
	rest, err := asn1.Unmarshal(der, &bits)
	if err != nil || len(rest) != 0 {
		return 0, errUnread
	}
	var usage uint16
	if len(bits.Bytes) > 0 {
		usage = uint16(bits.Bytes[0])
	}
	if len(bits.Bytes) > 1 {
		usage |= uint16(bits.Bytes[1]) << 8
	}
	return usage, nil
}

// namesIn counts the names a subject alternative name holds. A name OpenSSL
// would not decode as a GeneralName makes the extension one it cannot read, and
// Go does not ask.
func namesIn(der []byte) (int, error) {
	names, err := elements(der)
	if err != nil {
		return 0, err
	}
	for _, name := range names {
		if name.Class != asn1.ClassContextSpecific || name.Tag > lastNameChoice {
			return 0, errUnread
		}
	}
	return len(names), nil
}

// keyIDIn says an authority key identifier holds the key identifier, its [0].
func keyIDIn(der []byte) (bool, error) {
	fields, err := elements(der)
	if err != nil {
		return false, err
	}
	for _, f := range fields {
		if f.Class == asn1.ClassContextSpecific && f.Tag == 0 {
			return true, nil
		}
	}
	return false, nil
}
