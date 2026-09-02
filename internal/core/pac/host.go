package pac

import "strings"

// IsPlainHostName reports whether host carries no domain name at all.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - "true if and only if
// there is no domain name in the hostname", with isPlainHostName("www") true and
// isPlainHostName("www.mozilla.org") false. The test is the presence of a dot
// and nothing else.
//
// IT IS THE FIRST BRANCH OF THE BENCH'S OWN PAC FILE, where a bare name is
// answered DIRECT because a single label has no domain to route on.
func IsPlainHostName(host string) bool {
	return !strings.Contains(host, ".")
}

// DNSDomainIs reports whether host ends with domain.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02, and the original
// Netscape implementation it describes, which is a plain suffix comparison:
// host.substring(host.length - domain.length) == domain, guarded by a length
// check.
//
// THE CONSEQUENCE WORTH KNOWING IS THAT THE ZONE APEX DOES NOT MATCH ITS OWN
// SUFFIX FORM. dnsDomainIs("proxy.test", ".proxy.test") is FALSE, because the
// host is shorter than the pattern - which is why the bench's PAC file spells
// the apex out separately. Anybody who "fixes" this into a domain-aware suffix
// match would make certdoctor answer differently from the browser it is
// describing, which is inviolable rule 18 broken in the direction that looks
// like an improvement.
//
// THE COMPARISON IS CASE-SENSITIVE, LIKE THE ORIGINAL. JavaScript's == is, and
// browsers hand FindProxyForURL a host they have already lower-cased, so the
// case that reaches a real PAC file is settled before it arrives.
func DNSDomainIs(host, domain string) bool {
	return len(host) >= len(domain) && host[len(host)-len(domain):] == domain
}

// LocalHostOrDomainIs reports whether host is hostDom, or is the unqualified
// form of it.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - true if "the hostname
// matches exactly the specified hostname", or if "there is no domain name part
// in the hostname" and the unqualified name matches. Its four documented cases:
//
//	("www.mozilla.org", "www.mozilla.org") -> true, exact
//	("www",             "www.mozilla.org") -> true, unqualified
//	("www.google.com",  "www.mozilla.org") -> false, different domain
//	("home.mozilla.org","www.mozilla.org") -> false, different host
//
// THE SECOND CASE IS THE ONE THAT GETS WRITTEN WRONG, and the fourth is what
// stops the wrong version passing. A qualified host must match in full: it is
// not enough for it to share a first label with hostDom, which is why the
// unqualified branch is gated on the host having no dot rather than on a prefix
// test alone.
func LocalHostOrDomainIs(host, hostDom string) bool {
	if host == hostDom {
		return true
	}
	if !IsPlainHostName(host) {
		return false
	}
	return strings.HasPrefix(hostDom, host+".")
}

// DNSDomainLevels returns how many dots host carries.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - dnsDomainLevels("www")
// is 0, ("mozilla.org") is 1 and ("www.mozilla.org") is 2. It counts dots, not
// labels, so the two never have to be reconciled.
func DNSDomainLevels(host string) int {
	return strings.Count(host, ".")
}
