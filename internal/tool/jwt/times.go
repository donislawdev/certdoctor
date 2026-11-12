package jwt

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/jsontext"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// The seconds of 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z. A time
// outside them has no four-digit year to be written with, so it is named as
// not a time this tool can show rather than written wrong.
const (
	firstSecond = -62135596800
	lastSecond  = 253402300799
)

// moment is one of the registered time claims as the token has it.
type moment struct {
	claim string
	label string
	kind  jsontext.Kind
	at    time.Time
	// ok says at is the claim read as a time. A claim that is not a number,
	// or is a number no year can hold, is not.
	ok bool
}

// timeClaims are the registered time claims (RFC 7519 sections 4.1.4 to
// 4.1.6) in the order a person reads a token's life.
var timeClaims = []struct{ claim, label string }{
	{"iat", "Issued"},
	{"nbf", "Not before"},
	{"exp", "Expires"},
}

// readTimes reads the time claims a claims set has.
func readTimes(claims jsontext.Value) []moment {
	var out []moment
	for _, c := range timeClaims {
		v, ok := claims.Get(c.claim)
		if !ok {
			continue
		}
		m := moment{claim: c.claim, label: c.label, kind: v.Kind}
		if v.Kind == jsontext.Number {
			m.at, m.ok = numericDate(v.Text)
		}
		out = append(out, m)
	}
	return out
}

// numericDate reads a NumericDate - seconds since 1970-01-01T00:00:00Z UTC,
// fractions allowed (RFC 7519 section 2).
func numericDate(text string) (time.Time, bool) {
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(f) || f < firstSecond || f > lastSecond {
		return time.Time{}, false
	}
	whole, frac := math.Modf(f)
	return time.Unix(int64(whole), int64(math.Round(frac*1e9))).UTC(), true
}

// moment is the time claim called claim, and whether the token has it.
func (d *decoded) moment(claim string) (moment, bool) {
	for _, m := range d.times {
		if m.claim == claim {
			return m, true
		}
	}
	return moment{}, false
}

// timeChecks judges the token's times against now.
func (d *decoded) timeChecks() []spec.Check {
	if !d.payload.isClaims {
		return nil
	}
	var checks []spec.Check
	for _, judge := range []func() (spec.Check, bool){
		d.expiryCheck, d.notBeforeCheck, d.issuedCheck, d.orderCheck, d.notATimeCheck,
	} {
		if c, ok := judge(); ok {
			checks = append(checks, c)
		}
	}
	return checks
}

// expiryCheck: on or after exp a token MUST NOT be accepted (RFC 7519 section
// 4.1.4), so the moment of exp itself is already too late.
func (d *decoded) expiryCheck() (spec.Check, bool) {
	exp, ok := d.moment("exp")
	switch {
	case !ok:
		return spec.Check{ID: "expiry", Status: status.Warn,
			Summary: "The token has no expiry (exp), so nothing in it stops it being accepted for ever."}, true
	case !exp.ok:
		return spec.Check{}, false
	case !d.now.Before(exp.at):
		return spec.Check{ID: "expiry", Status: status.Fail,
			Summary: fmt.Sprintf("Expired %s ago, at %s - from that moment on it must not be accepted "+
				"(RFC 7519 section 4.1.4).", span(d.now, exp.at), clock(exp.at))}, true
	default:
		return spec.Check{ID: "expiry", Status: status.Pass,
			Summary: fmt.Sprintf("Valid for %s more, until %s.", span(d.now, exp.at), clock(exp.at))}, true
	}
}

// notBeforeCheck: before nbf a token MUST NOT be accepted (RFC 7519 section
// 4.1.5).
func (d *decoded) notBeforeCheck() (spec.Check, bool) {
	nbf, ok := d.moment("nbf")
	switch {
	case !ok || !nbf.ok:
		return spec.Check{}, false
	case d.now.Before(nbf.at):
		return spec.Check{ID: "not_before", Status: status.Fail,
			Summary: fmt.Sprintf("Not valid yet - for %s more, until %s (RFC 7519 section 4.1.5).",
				span(d.now, nbf.at), clock(nbf.at))}, true
	default:
		return spec.Check{ID: "not_before", Status: status.Pass,
			Summary: fmt.Sprintf("Valid since %s.", clock(nbf.at))}, true
	}
}

// issuedCheck warns about a token issued in the future, which says a clock is
// wrong - the issuer's or this machine's.
func (d *decoded) issuedCheck() (spec.Check, bool) {
	iat, ok := d.moment("iat")
	if !ok || !iat.ok || !iat.at.After(d.now) {
		return spec.Check{}, false
	}
	return spec.Check{ID: "issued_at", Status: status.Warn,
		Summary: fmt.Sprintf("Issued %s from now, at %s - the clock of whoever issued it, or of this "+
			"machine, is wrong.", span(d.now, iat.at), clock(iat.at))}, true
}

// orderCheck warns about a token whose times leave no moment it was valid.
func (d *decoded) orderCheck() (spec.Check, bool) {
	exp, ok := d.moment("exp")
	if !ok || !exp.ok {
		return spec.Check{}, false
	}
	for _, claim := range []string{"nbf", "iat"} {
		if m, ok := d.moment(claim); ok && m.ok && !exp.at.After(m.at) {
			return spec.Check{ID: "time_order", Status: status.Warn,
				Summary: fmt.Sprintf("It expires (%s) no later than its %s (%s), so there was never a "+
					"moment it could be accepted.", clock(exp.at), claim, clock(m.at))}, true
		}
	}
	return spec.Check{}, false
}

// notATimeCheck names the time claims that could not be read as times.
func (d *decoded) notATimeCheck() (spec.Check, bool) {
	var names []string
	for _, m := range d.times {
		if !m.ok {
			names = append(names, m.claim)
		}
	}
	if len(names) == 0 {
		return spec.Check{}, false
	}
	return spec.Check{ID: "times", Status: status.Warn,
		Summary: fmt.Sprintf("%s: not a number of seconds since 1970 between the years 1 and 9999 "+
			"(RFC 7519 section 2), so not read as a time.", joinNames(names))}, true
}

// clock writes a time for a person, in UTC, to the second.
func clock(t time.Time) string { return t.Format("2006-01-02 15:04:05 UTC") }

// span says how far apart two times are, in the largest unit that has at
// least two of itself, rounded down. It counts seconds, not a time.Duration,
// because a Duration stops at 292 years and a token can say the year 9999.
func span(a, b time.Time) string {
	s := b.Unix() - a.Unix()
	if s < 0 {
		s = -s
	}
	switch {
	case s < 2*60:
		return plural(s, "second")
	case s < 2*3600:
		return plural(s/60, "minute")
	case s < 2*86400:
		return plural(s/3600, "hour")
	case s < 2*365*86400:
		return plural(s/86400, "day")
	default:
		return plural(s/31557600, "year")
	}
}

func plural(n int64, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// joinNames writes names as "a", "a and b" or "a, b and c".
func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		out := names[0]
		for _, n := range names[1 : len(names)-1] {
			out += ", " + n
		}
		return out + " and " + names[len(names)-1]
	}
}
