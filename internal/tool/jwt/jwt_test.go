package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// now is the moment every case is judged at.
var now = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

// at is now moved by d, as a NumericDate.
func epoch(d time.Duration) string { return json.Number(itoa(now.Add(d).Unix())).String() }

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// b64 is base64url without padding, the encoding of every part.
func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// signed is a JWS with header, payload and a signature of n bytes.
func signed(header, payload string, n int) string {
	return b64(header) + "." + b64(payload) + "." + b64(strings.Repeat("s", n))
}

func decode(t *testing.T, raw string) spec.Outcome {
	t.Helper()
	out, err := Decode([]byte(raw), now)
	if err != nil {
		t.Fatalf("Decode refused: %v", err)
	}
	return out
}

// check is the check with id, failing the test when there is none.
func check(t *testing.T, out spec.Outcome, id string) spec.Check {
	t.Helper()
	for _, c := range out.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q among %v", id, out.Checks)
	return spec.Check{}
}

func hasCheck(out spec.Outcome, id string) bool {
	for _, c := range out.Checks {
		if c.ID == id {
			return true
		}
	}
	return false
}

func TestATokenIsShownWithItsTimesAndAnUncheckedSignature(t *testing.T) {
	raw := signed(`{"alg":"HS256","typ":"JWT","kid":"k1"}`,
		`{"sub":"alice","iat":`+epoch(-time.Hour)+`,"exp":`+epoch(2*time.Hour)+`}`, 32)
	out := decode(t, raw)
	if c := check(t, out, "signature"); c.Status != status.Unknown || !strings.Contains(c.Summary, "Not checked") {
		t.Errorf("signature: %+v", c)
	}
	if c := check(t, out, "expiry"); c.Status != status.Pass || c.Summary != "Valid for 2 hours more, until 2026-11-12 14:00:00 UTC." {
		t.Errorf("expiry: %+v", c)
	}
	if len(out.Notes) != 0 || hasCheck(out, "encoding") || hasCheck(out, "signature_shape") {
		t.Errorf("a clean token gathered notes %v or checks %v", out.Notes, out.Checks)
	}
	var titles []string
	for _, b := range out.View {
		titles = append(titles, b.Title)
	}
	if strings.Join(titles, ",") != "Token,Times,Header,Payload" {
		t.Errorf("view blocks %v", titles)
	}
	data := out.Data.(Data)
	if string(data.Header) != `{"alg":"HS256","typ":"JWT","kid":"k1"}` || data.Form != "jws" || *data.SignatureBytes != 32 {
		t.Errorf("data %+v", data)
	}
	if *data.Times.Expires != "2026-11-12T14:00:00Z" || data.Times.NotBefore != nil {
		t.Errorf("times %+v", data.Times)
	}
	if _, err := json.Marshal(data); err != nil {
		t.Errorf("the data does not marshal: %v", err)
	}
}

func TestWhatIsCopiedAroundATokenIsTakenOffAndSaid(t *testing.T) {
	raw := signed(`{"alg":"HS256"}`, `{"exp":`+epoch(time.Hour)+`}`, 32)
	out := decode(t, "  Authorization: Bearer \""+raw+"\"\r\n")
	if len(out.Notes) != 3 {
		t.Errorf("notes %v, want the header name, Bearer and the quotes", out.Notes)
	}
	if out := decode(t, "bearer\t"+raw); len(out.Notes) != 1 {
		t.Errorf("a lower case bearer and a tab: notes %v", out.Notes)
	}
	if _, err := Decode([]byte("Bearertoken"), now); err == nil {
		t.Error("Bearer with no space after it was taken off")
	}
}

func TestTheTimesAreJudgedAgainstNow(t *testing.T) {
	for _, c := range []struct {
		name, claims, id string
		want             status.Status
		summary          string
	}{
		{"expired", `{"exp":` + epoch(-3*time.Hour) + `}`, "expiry", status.Fail,
			"Expired 3 hours ago, at 2026-11-12 09:00:00 UTC"},
		{"expiring this second", `{"exp":` + epoch(0) + `}`, "expiry", status.Fail, "Expired 0 seconds ago"},
		{"no expiry", `{"sub":"a"}`, "expiry", status.Warn, "no expiry"},
		{"not yet", `{"nbf":` + epoch(90*time.Minute) + `,"exp":` + epoch(3*time.Hour) + `}`, "not_before", status.Fail,
			"Not valid yet - for 90 minutes more"},
		{"issued in the future", `{"iat":` + epoch(10*time.Minute) + `,"exp":` + epoch(time.Hour) + `}`, "issued_at",
			status.Warn, "Issued 10 minutes from now"},
		{"never valid", `{"iat":` + epoch(-time.Hour) + `,"exp":` + epoch(-2*time.Hour) + `}`, "time_order", status.Warn,
			"no later than its iat"},
		{"a string", `{"exp":"tomorrow"}`, "times", status.Warn, "exp: not a number of seconds"},
		// 1e15 is a float64 past the year 9999, -1e20 one before the year 1,
		// and 1e400 no float64 at all - three different ways out of range.
		{"outside the years 1 to 9999", `{"iat":1e400,"nbf":-1e20,"exp":1e15}`, "times", status.Warn,
			"iat, nbf and exp: not a number"},
		{"years away", `{"exp":253402300799}`, "expiry", status.Pass, "Valid for 7972 years more"},
		{"a fraction", `{"exp":` + epoch(time.Hour) + `.5}`, "expiry", status.Pass, "until 2026-11-12 13:00:00 UTC"},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := decode(t, signed(`{"alg":"HS256"}`, c.claims, 32))
			got := check(t, out, c.id)
			if got.Status != c.want || !strings.Contains(got.Summary, c.summary) {
				t.Errorf("%s: %s %q, want %s containing %q", c.id, got.Status, got.Summary, c.want, c.summary)
			}
		})
	}
}

func TestTheAlgorithmAndTheSignatureShapeAreJudged(t *testing.T) {
	der := append([]byte{0x30, 0x44, 0x02, 0x20}, make([]byte, 66)...)
	for _, c := range []struct {
		name, token, id string
		want            status.Status
		summary         string
	}{
		{"unsigned", b64(`{"alg":"none"}`) + "." + b64(`{}`) + ".", "algorithm", status.Fail, "not signed"},
		{"unsigned spelled otherwise", b64(`{"alg":"nOnE"}`) + "." + b64(`{}`) + ".", "algorithm", status.Fail,
			`written "nOnE"`},
		{"unsigned with a signature", signed(`{"alg":"none"}`, `{}`, 4), "algorithm", status.Fail, "4 bytes"},
		{"no algorithm", signed(`{"typ":"JWT"}`, `{}`, 32), "algorithm", status.Fail, "names no algorithm"},
		{"signature stripped", b64(`{"alg":"RS256"}`) + "." + b64(`{}`) + ".", "signature", status.Fail, "stripped"},
		{"ECDSA in DER", b64(`{"alg":"ES256"}`) + "." + b64(`{}`) + "." + base64.RawURLEncoding.EncodeToString(der),
			"signature_shape", status.Fail, "ASN.1 DER (70 bytes)"},
		{"ECDSA cut short", signed(`{"alg":"ES256"}`, `{}`, 63), "signature_shape", status.Fail, "63 bytes, and ES256 makes 64"},
		{"HMAC the wrong size", signed(`{"alg":"HS512"}`, `{}`, 32), "signature_shape", status.Fail, "HS512 makes 64"},
		{"a short RSA key", signed(`{"alg":"RS256"}`, `{}`, 128), "signature_shape", status.Warn, "about 1024 bits"},
		{"EdDSA the wrong size", signed(`{"alg":"EdDSA"}`, `{}`, 65), "signature_shape", status.Fail, "Ed448"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := check(t, decode(t, c.token), c.id)
			if got.Status != c.want || !strings.Contains(got.Summary, c.summary) {
				t.Errorf("%s: %s %q, want %s containing %q", c.id, got.Status, got.Summary, c.want, c.summary)
			}
		})
	}
	for _, fine := range []string{
		signed(`{"alg":"ES256"}`, `{}`, 64), signed(`{"alg":"RS256"}`, `{}`, 256),
		signed(`{"alg":"EdDSA"}`, `{}`, 114), signed(`{"alg":"XYZ9"}`, `{}`, 7),
	} {
		if out := decode(t, fine); hasCheck(out, "signature_shape") {
			t.Errorf("a signature of the right size, or of an algorithm with no one size, was judged: %v", out.Checks)
		}
	}
}

func TestANameCarriedTwiceIsWarnedAboutAndLeftOutOfTheData(t *testing.T) {
	out := decode(t, signed(`{"alg":"HS256","alg":"none"}`, `{"sub":"a","sub":"b","exp":`+epoch(time.Hour)+`}`, 32))
	c := check(t, out, "duplicate_names")
	if c.Status != status.Warn || !strings.Contains(c.Summary, `"alg" in the header and "sub" in the payload`) {
		t.Errorf("duplicate_names: %+v", c)
	}
	data := out.Data.(Data)
	if data.Header != nil || data.Payload != nil {
		t.Errorf("a part carrying a name twice went into the data: %s %s", data.Header, data.Payload)
	}
	if !strings.Contains(check(t, out, "algorithm").Summary, "not signed") {
		t.Error("the algorithm read is not the last one, which RFC 7515 lets a parser take")
	}
}

func TestLooseBase64IsReadAndNamed(t *testing.T) {
	// 22 bytes, which base64 pads with two = - a header a multiple of three
	// long would need none, and this case would prove nothing.
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256","x":12}`))
	payload := base64.RawStdEncoding.EncodeToString([]byte(`{"exp":` + epoch(time.Hour) + `,"x":"??>>"}`))
	out := decode(t, header+"."+payload+"."+b64(strings.Repeat("s", 32)))
	c := check(t, out, "encoding")
	for _, want := range []string{"part 1 that is padded with =", "part 2 that uses + or / of standard base64"} {
		if !strings.Contains(c.Summary, want) {
			t.Errorf("encoding %q does not say %q", c.Summary, want)
		}
	}
	if loose := decode(t, signed(`{"alg":"HS256"}`, `{}`, 32)[:len(signed(`{"alg":"HS256"}`, `{}`, 32))-1]+"t"); !strings.Contains(check(t, loose, "encoding").Summary, "bits that should be zero") {
		t.Error("a part ending in bits that are not zero was read without a word")
	}
}

func TestAnEncryptedTokenShowsItsHeaderOnly(t *testing.T) {
	raw := b64(`{"alg":"RSA-OAEP","enc":"A256GCM"}`) + ".a2V5.aXY.Y2lwaGVy.dGFn"
	out := decode(t, raw)
	if c := check(t, out, "encrypted"); c.Status != status.Unknown {
		t.Errorf("encrypted: %+v", c)
	}
	data := out.Data.(Data)
	if data.Form != "jwe" || data.Payload != nil || data.PayloadBytes != nil || data.SignatureBytes != nil {
		t.Errorf("data %+v", data)
	}
	if c := check(t, decode(t, b64(`{"alg":"dir"}`)+"..aXY.Y2lwaGVy.dGFn"), "algorithm"); c.Status != status.Fail {
		t.Errorf("a JWE naming no enc: %+v", c)
	}
}

func TestPayloadsThatAreNotClaimsAreShownAsTheyAre(t *testing.T) {
	text := decode(t, signed(`{"alg":"HS256"}`, "plain words", 32))
	if c := check(t, text, "claims"); c.Status != status.Warn || text.View[len(text.View)-1].Body != "plain words" {
		t.Errorf("a text payload: %+v, %+v", c, text.View[len(text.View)-1])
	}
	binary := decode(t, b64(`{"alg":"HS256"}`)+"."+base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xfe})+"."+b64("sig"))
	if body := binary.View[len(binary.View)-1].Body; body != "2 bytes that are not UTF-8 text, so they are not shown." {
		t.Errorf("a binary payload: %q", body)
	}
	nested := decode(t, signed(`{"alg":"HS256","cty":"jwt"}`, "aaa.bbb.ccc", 32))
	if last := nested.View[len(nested.View)-1]; !strings.Contains(last.Title, "another token") || hasCheck(nested, "claims") {
		t.Errorf("a nested token: %+v", last)
	}
	detached := decode(t, b64(`{"alg":"HS256","b64":false,"crit":["b64"]}`)+".."+b64("sig"))
	if last := detached.View[len(detached.View)-1]; !strings.HasPrefix(last.Body, "Detached") || hasCheck(detached, "unencoded") {
		t.Errorf("a detached unencoded payload: %+v %v", last, detached.Checks)
	}
	if c := check(t, decode(t, b64(`{"alg":"HS256","b64":false}`)+".."+b64("sig")), "unencoded"); c.Status != status.Warn {
		t.Errorf("b64 false without crit: %+v", c)
	}
}

func TestChecksAreListedWorstFirst(t *testing.T) {
	out := decode(t, signed(`{"alg":"HS256","a":1,"a":2}`, `{"exp":`+epoch(-time.Hour)+`,"nbf":`+epoch(-2*time.Hour)+`}`, 32))
	var order []string
	for _, c := range out.Checks {
		order = append(order, string(c.Status)+" "+c.ID)
	}
	want := "FAIL expiry,WARN duplicate_names,UNKNOWN signature,PASS not_before"
	if strings.Join(order, ",") != want {
		t.Errorf("checks in the order %v, want %s", order, want)
	}
}

func TestWhatIsNotATokenIsRefusedWithoutQuotingIt(t *testing.T) {
	secret := "SECRETSECRET"
	for _, c := range []struct{ name, raw, reason string }{
		{"empty", "  \n", "is empty"},
		{"two parts", b64(secret) + "." + b64(secret), "has 2 part(s)"},
		{"four parts", "a.b.c.d", "has 4 part(s)"},
		{"a space inside", b64(secret) + " ." + b64("x") + ".c", "space or a line break at byte 17"},
		{"a stranger byte", b64(secret) + "\xc3\xa9.x.y", "position 17"},
		{"padding inside", "ab=c.x.y", "'=' inside part 1"},
		{"two alphabets", "ab+_.x.y", "mixes the URL-safe alphabet"},
		{"not base64", "a.x.y", "part 1 that is not base64url"},
		{"a header that is not JSON", b64(secret) + ".x.y", "header (part 1) that is not valid JSON at byte 1"},
		{"a header that is an array", b64(`["`+secret+`"]`) + ".x.y", "JSON but not an object"},
		{"a bad signature part", b64(`{"alg":"HS256"}`) + "." + b64("{}") + ".a", "part 3 that is not base64url"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode([]byte(c.raw), now)
			var refusal *spec.Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("Decode gave %v, want a refusal", err)
			}
			if !strings.Contains(refusal.Reason, c.reason) {
				t.Errorf("reason %q, want it to say %q", refusal.Reason, c.reason)
			}
			if strings.Contains(refusal.Reason, secret) || strings.Contains(refusal.Reason, b64(secret)[:8]) {
				t.Errorf("the reason quotes the input: %q", refusal.Reason)
			}
		})
	}
}
