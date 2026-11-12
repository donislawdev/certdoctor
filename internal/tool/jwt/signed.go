package jwt

import (
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/jsontext"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// signed reads the payload and the signature of a JWS and judges its
// algorithm and the shape of its signature.
func (d *decoded) signed() error {
	if err := d.readPayload(); err != nil {
		return err
	}
	sig, err := d.tok.decodePart(2)
	if err != nil {
		return err
	}
	d.signature = sig
	d.checks = append(d.checks, d.algorithmChecks()...)
	if d.payload.isClaims {
		d.times = readTimes(d.payload.claims)
	}
	return nil
}

// encrypted decodes the four parts after the header of a JWE, so a part that
// is not base64url is refused here too, and says the payload stays unread.
func (d *decoded) encrypted() error {
	for i := 1; i < len(d.tok.parts); i++ {
		if _, err := d.tok.decodePart(i); err != nil {
			return err
		}
	}
	d.payload.encrypted = true
	d.checks = append(d.checks, spec.Check{ID: "encrypted", Status: status.Unknown,
		Summary: "The payload is encrypted (JWE) - reading it needs the recipient's key, which this tool does not take."})
	if _, ok := stringMember(d.header, "enc"); !ok {
		d.checks = append(d.checks, spec.Check{ID: "algorithm", Status: status.Fail,
			Summary: "The header names no content encryption (enc), which a JWE has to (RFC 7516 section 4.1.2)."})
	}
	return nil
}

// readPayload decodes the second part of a JWS and reads it as claims when it
// is a JSON object.
//
// With "b64": false the part is the payload itself, not its base64 (RFC 7797
// section 3). Such a payload is rarely carried in the compact form, because a
// dot in it would break the form (RFC 7797 section 5.2), and one with
// characters outside base64url is refused before this, by checkCharacters.
func (d *decoded) readPayload() error {
	text := d.tok.parts[1]
	if b64, ok := d.header.Get("b64"); ok && b64.Kind == jsontext.Bool && b64.Text == "false" {
		d.payload.unencoded = true
		d.checks = append(d.checks, d.unencodedChecks()...)
		d.payload.detached = text == ""
		d.payload.bytes = []byte(text)
		d.readClaims()
		return nil
	}
	if text == "" {
		d.payload.detached = true
		return nil
	}
	b, err := d.tok.decodePart(1)
	if err != nil {
		return err
	}
	d.payload.bytes = b
	if cty, ok := stringMember(d.header, "cty"); ok && strings.EqualFold(cty, "JWT") {
		d.payload.nested = true
		return nil
	}
	d.readClaims()
	return nil
}

// readClaims reads the payload as a JSON object. A payload that is not one is
// shown as it is and named by a check - it is a JWS, but not a JWT (RFC 7519
// section 7.2, step 10).
func (d *decoded) readClaims() {
	if d.payload.detached {
		return
	}
	v, dups, err := jsontext.Parse(d.payload.bytes)
	if err != nil || v.Kind != jsontext.Object {
		d.checks = append(d.checks, spec.Check{ID: "claims", Status: status.Warn,
			Summary: "The payload is not a JSON object, so this is a signed message but not a JWT " +
				"(RFC 7519 section 7.2) - it is shown as it is, and no claim in it is read."})
		return
	}
	d.payload.claims, d.payload.isClaims = v, true
	d.duplicates = append(d.duplicates, named("payload", dups)...)
}

// unencodedChecks warns when "b64": false is not named in "crit": a library
// that does not know b64 then reads the payload as base64 and gets something
// else (RFC 7797 section 6).
func (d *decoded) unencodedChecks() []spec.Check {
	if crit, ok := d.header.Get("crit"); ok && crit.Kind == jsontext.Array {
		for _, item := range crit.Items {
			if item.Kind == jsontext.String && item.Text == "b64" {
				return nil
			}
		}
	}
	return []spec.Check{{ID: "unencoded", Status: status.Warn,
		Summary: `The header says "b64": false and its "crit" does not name b64, so a library that does ` +
			"not know b64 reads the payload as base64 and gets something else (RFC 7797 section 6)."}}
}

// algorithmChecks judges the algorithm the header names and the signature it
// should have made.
func (d *decoded) algorithmChecks() []spec.Check {
	alg, ok := stringMember(d.header, "alg")
	if !ok {
		return []spec.Check{{ID: "algorithm", Status: status.Fail,
			Summary: "The header names no algorithm (alg), which a JWS has to (RFC 7515 section 4.1.1), " +
				"so no library can check this token."}}
	}
	if strings.EqualFold(alg, "none") {
		return []spec.Check{d.unsecured(alg)}
	}
	checks := []spec.Check{d.signatureCheck(alg)}
	if c, ok := shapeCheck(alg, d.signature); ok {
		checks = append(checks, c)
	}
	return checks
}

// unsecured is the verdict on "alg": "none" - a token anybody can write
// (RFC 7518 section 3.6: implementations MUST NOT accept one by default).
func (d *decoded) unsecured(alg string) spec.Check {
	summary := "alg is none: the token is not signed, so anyone can write one like it, and a library " +
		"must not accept it unless it was set up to (RFC 7518 section 3.6)."
	if alg != "none" {
		summary += fmt.Sprintf(" It is written %q, which a library comparing case by case does not take for none.", alg)
	}
	if len(d.signature) > 0 {
		summary += fmt.Sprintf(" It also carries a signature of %d bytes, where an unsigned token "+
			"must carry none.", len(d.signature))
	}
	return spec.Check{ID: "algorithm", Status: status.Fail, Summary: summary}
}

// signatureCheck says the signature was not checked, or that there is none
// where the algorithm says there should be.
func (d *decoded) signatureCheck(alg string) spec.Check {
	if len(d.signature) == 0 {
		return spec.Check{ID: "signature", Status: status.Fail,
			Summary: fmt.Sprintf("alg is %q but the signature is empty, so the token was cut short "+
				"or stripped of its signature.", alg)}
	}
	return spec.Check{ID: "signature", Status: status.Unknown,
		Summary: "Not checked: checking the signature needs the issuer's key, which this tool does not take."}
}

// fixedSizes are the algorithms whose signature has one size. HMAC gives the
// size of its hash (RFC 2104), and ECDSA in a JWS is R and S side by side,
// each the size of the curve's order (RFC 7518 section 3.4: 64, 96 and 132
// octets).
var fixedSizes = map[string]int{
	"HS256": 32, "HS384": 48, "HS512": 64,
	"ES256": 64, "ES384": 96, "ES512": 132,
}

// shapeCheck judges the size of a signature against what alg makes, when that
// is known. Only the size: the bytes themselves need the key.
func shapeCheck(alg string, sig []byte) (spec.Check, bool) {
	if len(sig) == 0 {
		return spec.Check{}, false
	}
	if want, ok := fixedSizes[alg]; ok && len(sig) != want {
		return fixedShape(alg, sig, want), true
	}
	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		return rsaShape(sig)
	}
	if alg == "EdDSA" && len(sig) != 64 && len(sig) != 114 {
		return spec.Check{ID: "signature_shape", Status: status.Fail,
			Summary: fmt.Sprintf("The signature is %d bytes, and EdDSA makes 64 with Ed25519 and 114 "+
				"with Ed448 (RFC 8032), so a library refuses it.", len(sig))}, true
	}
	return spec.Check{}, false
}

// fixedShape is the verdict on a signature of the wrong size for its
// algorithm, naming the DER form ECDSA is written in everywhere but JOSE.
func fixedShape(alg string, sig []byte, want int) spec.Check {
	summary := fmt.Sprintf("The signature is %d bytes, and %s makes %d, so a library refuses it.", len(sig), alg, want)
	if strings.HasPrefix(alg, "ES") && looksDER(sig) {
		summary = fmt.Sprintf("The signature is ASN.1 DER (%d bytes), the way ECDSA is written outside JOSE, "+
			"but a JWS carries R and S side by side - %d bytes for %s (RFC 7518 section 3.4) - so a "+
			"library refuses it.", len(sig), want, alg)
	}
	return spec.Check{ID: "signature_shape", Status: status.Fail, Summary: summary}
}

// rsaShape warns about an RSA key under 2048 bits. An RSA signature is as long
// as the key's modulus, so its size gives the key's.
func rsaShape(sig []byte) (spec.Check, bool) {
	if len(sig) >= 256 {
		return spec.Check{}, false
	}
	return spec.Check{ID: "signature_shape", Status: status.Warn,
		Summary: fmt.Sprintf("The signature is %d bytes, so the RSA key is about %d bits, and RFC 7518 "+
			"section 3.3 requires 2048 or more.", len(sig), len(sig)*8)}, true
}

// looksDER says sig starts as a DER SEQUENCE whose length is the rest of sig
// and whose first element is an INTEGER - the encoding of an ECDSA signature
// outside JOSE.
func looksDER(sig []byte) bool {
	if len(sig) < 8 || sig[0] != 0x30 {
		return false
	}
	body := 2
	switch {
	case sig[1] < 0x80:
		if int(sig[1]) != len(sig)-2 {
			return false
		}
	case sig[1] == 0x81:
		if int(sig[2]) != len(sig)-3 {
			return false
		}
		body = 3
	default:
		return false
	}
	return sig[body] == 0x02
}
