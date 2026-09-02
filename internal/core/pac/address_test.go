package pac

import (
	"errors"
	"testing"
)

// answering builds ports whose resolver hands back a fixed answer.
func answering(answers map[string][]string) Ports {
	return Ports{Resolve: func(host string) ([]string, error) {
		found, known := answers[host]
		if !known {
			return nil, nil
		}
		return found, nil
	}}
}

func TestDNSResolvePrefersIPv4SoTheAnswerCannotChangeBetweenRuns(t *testing.T) {
	// THE ORDER HERE IS THE POINT - ADR10 point 3. A resolver may hand back its
	// addresses in any order, and the library this project rejected returned
	// whichever came first. Two runs would then answer a PAC rule differently,
	// which is not merely non-deterministic but a different claim about what the
	// machine will do.
	ports := answering(map[string][]string{
		"dual.example": {"2001:db8::1", "192.0.2.10"},
		"six.example":  {"2001:db8::1"},
	})

	if got, ok := ports.DNSResolve("dual.example"); !ok || got != "192.0.2.10" {
		t.Errorf("DNSResolve(dual) = %q, %v - want the IPv4 address even though it is listed second", got, ok)
	}
	// A name with only IPv6 still resolves: refusing would say the name does
	// not exist, which is a different fact.
	if got, ok := ports.DNSResolve("six.example"); !ok || got != "2001:db8::1" {
		t.Errorf("DNSResolve(six) = %q, %v - want the address it has", got, ok)
	}
	if _, ok := ports.DNSResolve("absent.example"); ok {
		t.Error("DNSResolve claimed to resolve a name the resolver did not know")
	}
}

func TestDNSResolveDoesNotAskAboutAnAddress(t *testing.T) {
	// A host that is already an address is returned unchanged and never sent to
	// a resolver - a lookup nobody asked for, ADR62 one layer along.
	ports := Ports{Resolve: func(string) ([]string, error) {
		t.Error("the resolver was asked about something that was already an address")
		return nil, nil
	}}
	if got, ok := ports.DNSResolve("192.0.2.10"); !ok || got != "192.0.2.10" {
		t.Errorf("DNSResolve(address) = %q, %v", got, ok)
	}
}

func TestDNSResolveWithoutAResolver(t *testing.T) {
	var none Ports
	if _, ok := none.DNSResolve("example.test"); ok {
		t.Error("DNSResolve answered without anybody to ask")
	}
	failing := Ports{Resolve: func(string) ([]string, error) { return nil, errors.New("no resolver") }}
	if _, ok := failing.DNSResolve("example.test"); ok {
		t.Error("DNSResolve treated a resolver failure as an answer")
	}
}

func TestIsInNet(t *testing.T) {
	ports := answering(map[string][]string{
		"inside.example":  {"192.0.2.172"},
		"outside.example": {"198.51.100.5"},
		"six.example":     {"2001:db8::1"},
	})

	for _, c := range []struct {
		name                string
		host, pattern, mask string
		want                bool
	}{
		// Mozilla's documented example, exact match on every byte.
		{"exact", "inside.example", "192.0.2.172", "255.255.255.255", true},
		{"exact, different host", "outside.example", "192.0.2.172", "255.255.255.255", false},
		// A mask that ignores the last byte.
		{"same /24", "inside.example", "192.0.2.0", "255.255.255.0", true},
		{"different /24", "outside.example", "192.0.2.0", "255.255.255.0", false},

		// THE PATTERN MUST BE MASKED TOO, AND THIS ROW IS THE ONLY ONE THAT SAYS
		// SO. Every case above happens to carry zeroes wherever the mask does,
		// so masking the pattern and not masking it give the same answer - the
		// mutation register found that the assertions could not tell the two
		// apart. A real PAC file writes the network's own address rather than a
		// tidied one, as Mozilla's documented example does with
		// isInNet(host, "192.0.2.172", ...), so the untidy form is the common
		// one rather than the exotic one.
		{"pattern carries bits outside the mask", "inside.example", "192.0.2.99", "255.255.255.0", true},
		{"pattern outside the mask, different network", "outside.example", "192.0.2.99", "255.255.255.0", false},
		// An address given directly rather than resolved.
		{"literal address", "192.0.2.172", "192.0.2.0", "255.255.255.0", true},
		// IPv6 is outside what a dotted mask can express, and no browser
		// extends it - so false here is the same answer the client gives.
		{"IPv6 host", "six.example", "192.0.2.0", "255.255.255.0", false},
		// Rubbish arguments are refused rather than half-matched.
		{"pattern is not an address", "inside.example", "not-an-address", "255.255.255.0", false},
		{"mask is not an address", "inside.example", "192.0.2.0", "nonsense", false},
		{"unknown host", "absent.example", "192.0.2.0", "255.255.255.0", false},
	} {
		if got := ports.IsInNet(c.host, c.pattern, c.mask); got != c.want {
			t.Errorf("%s: IsInNet(%q, %q, %q) = %v, want %v", c.name, c.host, c.pattern, c.mask, got, c.want)
		}
	}
}

func TestIsResolvableFollowsDNSResolve(t *testing.T) {
	ports := answering(map[string][]string{"known.example": {"192.0.2.10"}})
	if !ports.IsResolvable("known.example") {
		t.Error("a name the resolver answered was called unresolvable")
	}
	if ports.IsResolvable("absent.example") {
		t.Error("a name the resolver did not know was called resolvable")
	}
}

func TestMyIPAddressFallsBackToLoopbackAndSaysSo(t *testing.T) {
	// The fallback is somebody else's behaviour reproduced: Mozilla documents
	// myIpAddress falling back to the loopback address. The second return value
	// is ours, so a report can tell a real answer from that fallback - the PAC
	// file cannot, exactly as it could not in a browser.
	var none Ports
	if got, real := none.MyIPAddress(); got != LoopbackFallback || real {
		t.Errorf("MyIPAddress with no port = %q, %v - want the loopback fallback, marked as not real", got, real)
	}

	failing := Ports{LocalAddress: func() (string, error) { return "", errors.New("no route") }}
	if got, real := failing.MyIPAddress(); got != LoopbackFallback || real {
		t.Errorf("MyIPAddress after a failure = %q, %v", got, real)
	}

	// An answer that is not an address is not an answer.
	rubbish := Ports{LocalAddress: func() (string, error) { return "not-an-address", nil }}
	if got, real := rubbish.MyIPAddress(); got != LoopbackFallback || real {
		t.Errorf("MyIPAddress with a bad address = %q, %v", got, real)
	}

	working := Ports{LocalAddress: func() (string, error) { return "192.0.2.10", nil }}
	if got, real := working.MyIPAddress(); got != "192.0.2.10" || !real {
		t.Errorf("MyIPAddress = %q, %v - want the real address", got, real)
	}
}
