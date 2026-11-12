// Package jwt is the JWT decoder (ADR141 point 12): it shows what a JSON Web
// Token says and judges what can be judged without a key.
//
// IT NEVER CHECKS A SIGNATURE, and says so in every outcome. Checking one needs
// the issuer's key, and a decoder that took a token's own word for which key
// that is would be a verifier anybody can fool. What it can tell without a key
// it tells: an unsigned token, a signature of the wrong shape for its
// algorithm, a token past its expiry, names carried twice.
//
// THE TOKEN IS HOSTILE. It comes from a log, a ticket or somebody else's
// system, and it is a credential. So nothing here quotes it back - a refusal
// names a part and a position - and everything decoded out of it goes through
// internal/tool/jsontext, which refuses what it cannot read exactly.
//
// The rules are the RFCs', and each is cited where it is applied: 7515 (JWS),
// 7516 (JWE), 7518 (algorithms), 7519 (JWT) and 7797 (unencoded payload).
package jwt

import (
	"encoding/json"
	"time"

	"github.com/donislawdev/certdoctor/internal/tool/jsontext"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// Data is what the decoder found, for a script to read.
type Data struct {
	// Form is "jws" for a signed token (three parts) and "jwe" for an
	// encrypted one (five parts).
	Form string `json:"form"`
	// Header is the header as one JSON object, members in the token's order,
	// and null when it carries a name twice - which of the two a reader takes
	// is the question, so this does not answer it for them.
	Header json.RawMessage `json:"header"`
	// Payload is the claims as one JSON object, and null when the payload is
	// not one, carries a name twice, is detached or is encrypted.
	Payload json.RawMessage `json:"payload"`
	// PayloadBytes is the size of the payload, null when there is none to
	// count - detached, or encrypted.
	PayloadBytes *int `json:"payload_bytes"`
	// SignatureBytes is the size of the signature of a signed token, null for
	// an encrypted one.
	SignatureBytes *int `json:"signature_bytes"`
	// Times are the three times RFC 7519 registers, each in RFC 3339 and in
	// UTC, null when the claim is not there or is not a time.
	Times Times `json:"times"`
}

// Times are the registered time claims (RFC 7519 sections 4.1.4 to 4.1.6).
type Times struct {
	IssuedAt  *string `json:"iat"`
	NotBefore *string `json:"nbf"`
	Expires   *string `json:"exp"`
}

// Decode reads raw as a token and judges it at now. A refusal is a
// *spec.Refusal and means raw is not a token this can read.
func Decode(raw []byte, now time.Time) (spec.Outcome, error) {
	tok, err := prepare(raw)
	if err != nil {
		return spec.Outcome{}, err
	}
	header, dups, err := tok.readHeader()
	if err != nil {
		return spec.Outcome{}, err
	}
	d := &decoded{tok: tok, header: header, now: now, duplicates: named("header", dups)}
	if tok.form == formJWE {
		err = d.encrypted()
	} else {
		err = d.signed()
	}
	if err != nil {
		return spec.Outcome{}, err
	}
	return d.outcome(), nil
}

// decoded is a token on its way to an outcome.
type decoded struct {
	tok        token
	header     jsontext.Value
	now        time.Time
	payload    payload
	signature  []byte
	duplicates []duplicate
	checks     []spec.Check
	times      []moment
}

// payload is what the second part turned out to be.
type payload struct {
	// encrypted, detached, unencoded and nested say why the bytes are not, or
	// are not only, a claims set: a JWE, an empty part (RFC 7515 appendix F),
	// "b64": false (RFC 7797) and "cty": "JWT" (RFC 7519 section 5.2).
	encrypted bool
	detached  bool
	unencoded bool
	nested    bool
	bytes     []byte
	// claims is the payload read as a JSON object, when isClaims.
	claims   jsontext.Value
	isClaims bool
}

// duplicate is a name carried twice, with the part it was found in.
type duplicate struct {
	in  string
	dup jsontext.Duplicate
}

// named says which part each duplicate was found in.
func named(in string, dups []jsontext.Duplicate) []duplicate {
	out := make([]duplicate, len(dups))
	for i, d := range dups {
		out[i] = duplicate{in: in, dup: d}
	}
	return out
}

// stringMember is the member name of an object when it is a string.
func stringMember(v jsontext.Value, name string) (string, bool) {
	m, ok := v.Get(name)
	if !ok || m.Kind != jsontext.String {
		return "", false
	}
	return m.Text, true
}

// outcome puts together what was found.
func (d *decoded) outcome() spec.Outcome {
	d.checks = append(d.checks, d.timeChecks()...)
	d.checks = append(d.checks, d.tok.encodingChecks()...)
	if c, ok := duplicateCheck(d.duplicates); ok {
		d.checks = append(d.checks, c)
	}
	return spec.Outcome{
		Notes:  d.tok.notes,
		Checks: sortChecks(d.checks),
		Data:   d.data(),
		View:   d.view(),
	}
}
