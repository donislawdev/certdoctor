// Package idna turns a host name a person typed into the spelling that goes on
// the wire.
//
// WHY THIS EXISTS, AND IT IS MEASURED RATHER THAN ANTICIPATED - 2026-08-26, this
// binary, one site asked about twice:
//
//	certdoctor https://bucher.de      (with an u-umlaut)  L4 FAIL, exit 4
//	certdoctor https://xn--bcher-kva.de                   everything green
//
// One machine, one server, two spellings of one name, opposite diagnoses. The
// first run put the label on the wire as raw UTF-8, every resolver answered
// NXDOMAIN, and the report then said - with the whole layer still at PASS - that
// the name did not exist. crypto/tls dropped the same bytes out of the SNI
// extension, so the server behind the CDN closed the connection and L4 reported
// a failure about a server that works. A tool built on "never claim to have
// checked what was not checked" accused a working site and exited 4, on names
// that are ordinary in the languages this product is for.
//
// WHY OUR OWN AND NOT golang.org/x/net/idna. Inviolable rule 5 - a dependency
// needs a reason, a licence check and a version to pin, and the whole of what we
// need from that module is one algorithm published as an RFC.
//
// WHAT THIS PACKAGE DOES NOT DO, SAID HERE RATHER THAN DISCOVERED LATER. It is
// Punycode conversion, not the IDNA2008 mapping and validity tables. It does not
// normalise to NFC, it does not apply Bidi or ContextO rules, and it does not
// know which scripts may sit beside each other in one label. A name that needs
// composing before conversion is REFUSED rather than converted wrongly - see
// ToASCII - because a wrong A-label is the same failure this package exists to
// remove, arriving silently.
package idna

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bootstring parameters for Punycode.
//
// SOURCE, AS INVIOLABLE RULE 18 REQUIRES: RFC 3492, "Punycode: A Bootstring
// encoding of Unicode for Internationalized Domain Names in Applications
// (IDNA)", section 5, read 2026-08-26. It fixes these seven values for the
// Punycode instance of Bootstring, and the digits are the letters a-z for 0..25
// followed by the digits 0-9 for 26..35.
const (
	base        = 36
	tmin        = 1
	tmax        = 26
	skew        = 38
	damp        = 700
	initialBias = 72
	initialN    = 0x80
)

// acePrefix is what marks a label as carrying a converted name.
//
// SOURCE: RFC 5890, "Internationalized Domain Names for Applications (IDNA):
// Definitions and Document Framework", section 2.3.2.5, read 2026-08-26. It
// defines the ACE prefix as the four characters "xn--" at the start of every
// A-label, and puts the whole label under the 63 octet limit RFC 1035 already
// imposes - so at most 59 characters of Punycode may follow.
const acePrefix = "xn--"

// maxLabel is the 63 octets a DNS label may carry.
//
// It is checked HERE as well as in dnsmsg because the order matters: converting
// first and measuring afterwards is the only way to measure the bytes that
// actually travel. A label of thirty accented characters is well under 63 bytes
// as UTF-8 and over it once converted, and the reverse never happens.
const maxLabel = 63

// maxInputLabel bounds what will be converted at all.
//
// The arithmetic below is exact in a 64 bit int for any label a DNS server would
// accept, and this is the cheap way of saying so rather than reasoning about it:
// delta grows with the code point value times the label length, so a bound on
// the length is a bound on the sum. It is far above anything that can survive
// the 63 octet check, so nothing usable is refused by it.
const maxInputLabel = 512

// ToASCII returns host with every label converted to its A-label form.
//
// AN ALL-ASCII HOST COMES BACK BYTE FOR BYTE, AND THAT IS THE FIRST THING THIS
// FUNCTION DOES. Every name this program has ever been able to diagnose is
// ASCII, so the path that must not change is the one taken before any of the
// rest of this file runs. It is also why nothing here validates ASCII labels:
// tightening what an ordinary name may contain is a separate decision with its
// own way of being wrong, and this change is about names that DID NOT WORK.
//
// A LABEL CARRYING A COMBINING MARK IS REFUSED RATHER THAN CONVERTED. Composing
// it is what NFC normalisation does, that needs the Unicode tables this package
// deliberately does not carry, and converting the decomposed form produces a
// VALID-LOOKING A-label for a different name - which resolves nowhere and puts
// us back where we started, with the report confidently wrong. The refusal names
// what happened so the person can retype or paste the xn-- form.
func ToASCII(host string) (string, error) {
	if isASCII(host) {
		return host, nil
	}
	host = strings.ToLower(host)

	labels := strings.Split(host, ".")
	for i, label := range labels {
		if isASCII(label) {
			continue
		}
		converted, err := convert(label)
		if err != nil {
			return "", err
		}
		labels[i] = converted
	}
	return strings.Join(labels, "."), nil
}

// convert is one non-ASCII label, refusals included.
func convert(label string) (string, error) {
	if !utf8.ValidString(label) {
		return "", fmt.Errorf("the label %q is not valid UTF-8, so there is no name in it to convert", label)
	}
	runes := []rune(label)
	if len(runes) > maxInputLabel {
		return "", fmt.Errorf("the label %q holds %d characters, which is past anything a DNS label can carry", label, len(runes))
	}
	for _, r := range runes {
		if unicode.In(r, unicode.Mn, unicode.Mc, unicode.Me) {
			return "", fmt.Errorf(
				"the name carries a combining mark in %q, and certdoctor converts international names without composing them first - "+
					"give the name in its xn-- form, which is what your browser sends", label)
		}
	}

	encoded, err := punycode(runes)
	if err != nil {
		return "", err
	}
	out := acePrefix + encoded
	if len(out) > maxLabel {
		return "", fmt.Errorf("the label %q becomes %s, which is %d octets and %d is the most a DNS label may carry",
			label, out, len(out), maxLabel)
	}
	return out, nil
}

// punycode is the encoding procedure of RFC 3492 section 6.3, read 2026-08-26.
//
// IT IS WRITTEN TO FOLLOW THE PSEUDOCODE LINE BY LINE rather than to be clever,
// because the only thing anybody will ever want to do with this function is
// compare it against that page.
func punycode(runes []rune) (string, error) {
	var out []byte
	basic := 0
	for _, r := range runes {
		if r < initialN {
			out = append(out, byte(r))
			basic++
		}
	}
	h := basic
	if basic > 0 {
		// The delimiter separating the basic code points from the encoded ones.
		out = append(out, '-')
	}

	n := rune(initialN)
	delta := 0
	bias := initialBias

	for h < len(runes) {
		// The smallest code point still to be dealt with.
		m := rune(0)
		found := false
		for _, r := range runes {
			if r >= n && (!found || r < m) {
				m, found = r, true
			}
		}
		if !found {
			// Unreachable while h < len(runes): something not yet encoded is by
			// definition at or above n. Returning rather than panicking keeps the
			// promise this whole package is for - a name we cannot convert is an
			// answer, never a dead process.
			return "", fmt.Errorf("converting %q ran out of code points with %d of %d done", string(runes), h, len(runes))
		}

		delta += int(m-n) * (h + 1)
		n = m

		for _, r := range runes {
			if r < n {
				delta++
			}
			if r == n {
				q := delta
				for k := base; ; k += base {
					t := k - bias
					if t < tmin {
						t = tmin
					} else if t > tmax {
						t = tmax
					}
					if q < t {
						break
					}
					out = append(out, digit(t+(q-t)%(base-t)))
					q = (q - t) / (base - t)
				}
				out = append(out, digit(q))
				bias = adapt(delta, h+1, h == basic)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return string(out), nil
}

// adapt is the bias adaptation function of RFC 3492 section 6.1, read
// 2026-08-26.
func adapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= damp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((base-tmin)*tmax)/2 {
		delta /= base - tmin
		k += base
	}
	return k + (base-tmin+1)*delta/(delta+skew)
}

// digit is the code point for one Punycode digit - a-z for 0..25, 0-9 for
// 26..35, RFC 3492 section 5.
func digit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// isASCII reports whether s is entirely code points below 0x80.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
