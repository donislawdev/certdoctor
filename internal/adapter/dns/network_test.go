package dns

import "testing"

// TestBothSpellingsOfAResolverReachTheAllowedSet is OBS54 and ADR34, pinned.
//
// The allowed set compares strings and does so on purpose. Go joins the RAW
// token from resolv.conf with the port, so a machine writing "2001:0DB8::1" has
// the platform ask for "[2001:0DB8::1]:53" while the canonical form is
// "[2001:db8::1]:53" - and unless BOTH are in the set, this run's own guard
// refuses a resolver that is answering.
func TestBothSpellingsOfAResolverReachTheAllowedSet(t *testing.T) {
	if got := RawTarget("2001:0DB8::1"); got != "[2001:0DB8::1]:53" {
		t.Errorf("the raw spelling came back as %q", got)
	}
	if got := RawTarget("192.0.2.53"); got != "192.0.2.53:53" {
		t.Errorf("an IPv4 resolver came back as %q", got)
	}
}

// TestTheFallbackResolversAreTheOnesGoActuallyAsks is ADR34.
//
// SOURCE, AS INVIOLABLE RULE 18 REQUIRES: net/dnsconfig.go declares defaultNS as
// 127.0.0.1:53 and [::1]:53 and uses it when resolv.conf is missing, unreadable,
// or carries no nameserver line. Probe S11 confirmed it by running rather than by
// reading: with an empty resolv.conf and a resolver answering on loopback, Go
// resolved the name through these two while certdoctor reported having nobody to
// ask.
func TestTheFallbackResolversAreTheOnesGoActuallyAsks(t *testing.T) {
	got := PlatformFallbackResolvers()
	want := []string{"127.0.0.1:53", "[::1]:53"}

	if len(got) != len(want) {
		t.Fatalf("%d fallback resolver(s), want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fallback %d is %q, want %q", i, got[i], want[i])
		}
	}
}
