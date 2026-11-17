package csr

import (
	"net/netip"
	"strings"
)

// nameProblem says what in a host name a public authority does not issue
// for, or "" when nothing this tool checks is wrong with it. The rules are the
// CA/Browser Forum's Baseline Requirements 2.3.1 (2026-10-04), section
// 7.1.2.7.12 with the terms of section 1.6.1: a dNSName is a Fully-Qualified
// Domain Name or "*." followed by one, made of P-Labels or Non-Reserved LDH
// Labels joined by dots, without the dot of the root at the end. An LDH label
// is letters, digits and hyphens, no hyphen at either end, at most 63 octets
// (RFC 5890, quoted there).
//
// WHAT IS NOT CHECKED, said so the PASS sentence claims no more: whether a
// label starting xn-- is valid Punycode (RFC 3492 - no decoder here), whether
// a name of two labels or more ends in a top-level domain IANA has (a list
// this program does not carry), and who controls the name - the authority's
// own check.
func nameProblem(name string) string {
	if _, err := netip.ParseAddr(name); err == nil {
		return "an address written as a host name - a client matches an address only against an address entry"
	}
	if strings.HasSuffix(name, ".") {
		return "a dot at the end"
	}
	body := strings.TrimPrefix(name, "*.")
	if strings.Contains(body, "*") {
		return "a wildcard that is not the whole first label"
	}
	if len(name) > 253 {
		return "longer than 253 characters"
	}
	labels := strings.Split(body, ".")
	if len(labels) == 1 && body != "" {
		return "a single label, a name inside a network that a public authority cannot check"
	}
	for _, label := range labels {
		if problem := labelProblem(label); problem != "" {
			return problem
		}
	}
	return ""
}

// labelProblem says what is wrong with one label of a host name, or "".
func labelProblem(label string) string {
	switch {
	case label == "":
		return "an empty label"
	case len(label) > 63:
		return "a label longer than 63 characters"
	case strings.Contains(label, "_"):
		return "an underscore"
	}
	for _, c := range []byte(label) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
			return "a character other than a letter, a digit or a hyphen"
		}
	}
	switch {
	case label[0] == '-' || label[len(label)-1] == '-':
		return "a hyphen at the start or the end of a label"
	case len(label) >= 4 && label[2:4] == "--" && !strings.EqualFold(label[:2], "xn"):
		return "two hyphens in the third and fourth places, which only an xn-- label may have"
	}
	return ""
}
