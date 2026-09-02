package pac

import "net/netip"

// LoopbackFallback is what myIpAddress answers when this machine's address
// cannot be established.
//
// IT IS SOMEBODY ELSE'S BEHAVIOUR REPRODUCED, NOT OUR CHOICE. Mozilla's PAC
// documentation, read 2026-09-02, says myIpAddress "tries several alternatives
// before falling back to loopback address (e.g. 127.0.0.1)". A PAC file written
// against a browser has therefore already met this answer, and a sandbox that
// invented a different one would evaluate the file differently from the client
// the user is asking about.
const LoopbackFallback = "127.0.0.1"

// DNSResolve returns the address host resolves to, and whether it resolved.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - it returns "the IP
// address as a string in dot-separated format".
//
// IT PREFERS THE FIRST IPv4 ADDRESS RATHER THAN SIMPLY THE FIRST, AND THAT IS
// ADR10 POINT 3 TURNED INTO CODE. The ready-made library this project rejected
// handed back ips[0] from a list with no defined order, so the same PAC rule
// could route through IPv4 on one run and IPv6 on the next - not merely
// non-deterministic, but a DIFFERENT ANSWER about what the machine will do.
// Browsers answer this function with an IPv4 address and offer dnsResolveEx for
// anything else, so preferring IPv4 is both stable and what the client being
// described would say.
//
// A HOST THAT IS ALREADY AN ADDRESS IS RETURNED UNCHANGED AND IS NEVER ASKED
// ABOUT. Sending it to a resolver would be a lookup the user did not ask for,
// which is ADR62 one layer along.
func (p Ports) DNSResolve(host string) (string, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String(), true
	}
	if p.Resolve == nil {
		return "", false
	}
	found, err := p.Resolve(host)
	if err != nil {
		return "", false
	}

	var firstAny string
	for _, candidate := range found {
		addr, err := netip.ParseAddr(candidate)
		if err != nil {
			continue
		}
		if addr.Is4() {
			return addr.String(), true
		}
		if firstAny == "" {
			firstAny = addr.String()
		}
	}
	return firstAny, firstAny != ""
}

// IsResolvable reports whether host resolves to anything.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - "true if DNS
// resolution of the hostname succeeds".
//
// A RUN WITH NO RESOLVER BEHIND THE PORT ANSWERS FALSE, AND THAT IS A KNOWN
// UNTRUTH THIS FUNCTION CANNOT FIX ALONE. The PAC contract has one boolean here
// and no way to say "nobody could be asked", so the honest report of that state
// has to be made by the layer, which knows whether a resolver existed. This is
// the shape inviolable rule 15 warns about arriving through somebody else's
// interface: the answer that is not a lie has nowhere to go.
func (p Ports) IsResolvable(host string) bool {
	_, ok := p.DNSResolve(host)
	return ok
}

// MyIPAddress returns this machine's address, and whether it is a real answer
// rather than the loopback fallback.
//
// The second return value exists so a caller can say WHICH of the two happened.
// The PAC file cannot tell them apart - it gets a string either way, exactly as
// it would from a browser - but a report that showed a PAC branch taken on
// 127.0.0.1 without saying so would be describing a decision made on a fact
// nobody established.
func (p Ports) MyIPAddress() (string, bool) {
	if p.LocalAddress == nil {
		return LoopbackFallback, false
	}
	address, err := p.LocalAddress()
	if err != nil {
		return LoopbackFallback, false
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return LoopbackFallback, false
	}
	return addr.String(), true
}

// IsInNet reports whether host's address falls inside pattern masked by mask.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - host is "a DNS
// hostname or IP address", hostnames are resolved, and mask is an "IP address
// pattern" where 0 ignores a byte and 255 matches it.
//
// IT IS IPv4 ONLY, AND THE LIMIT IS THE FUNCTION'S, NOT OURS. A dotted mask
// cannot express an IPv6 prefix, and no browser extends it to one; a PAC file
// that wants IPv6 uses isInNetEx. An IPv6 host therefore answers false here,
// which is what the client being described would answer.
func (p Ports) IsInNet(host, pattern, mask string) bool {
	resolved, ok := p.DNSResolve(host)
	if !ok {
		return false
	}
	addr, err := netip.ParseAddr(resolved)
	if err != nil || !addr.Is4() {
		return false
	}
	want, err := netip.ParseAddr(pattern)
	if err != nil || !want.Is4() {
		return false
	}
	bits, err := netip.ParseAddr(mask)
	if err != nil || !bits.Is4() {
		return false
	}

	have, target, m := addr.As4(), want.As4(), bits.As4()
	for i := range have {
		if have[i]&m[i] != target[i]&m[i] {
			return false
		}
	}
	return true
}
