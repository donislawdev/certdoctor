package main

import (
	"context"
	"net/url"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// The composition L2 is handed, and it is the one seam OBS117 says can be
// checked on every platform.
//
// THE PLATFORM READING IS ONE LINE BEHIND A BUILD TAG and cannot be exercised
// here - proxyconf.Read on macOS runs somebody else's process, and this machine
// is not a Mac. What CAN be pinned anywhere is that the entry point puts the two
// kinds of stack together, and that a build with no platform reading still
// answers about the environment.

// proxyTarget is named for this file's subject because aTarget already exists in
// acceptance_checks_test.go, which sits behind the "acceptance" build tag.
//
// A PLAIN go test COMPILES NEITHER OF THEM TOGETHER AND SAYS NOTHING, which is
// the trap: the package was green here and broke four gates at once - the audit,
// its own probes, the acceptance suite and the mutation anchors - because all
// four build with the tag on.
func proxyTarget(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the fixture URL does not parse: %v", err)
	}
	return parsed
}

// TestTheProxyInputAlwaysCarriesTheEnvironmentStack is the Linux shape, where
// proxyconf.Read returns nothing at all: there is no one place every program on
// that system reads. A run there still has to answer about the variables.
func TestTheProxyInputAlwaysCarriesTheEnvironmentStack(t *testing.T) {
	in := proxyInput(environment{
		lookupEnv: func(name string) (string, bool) {
			if name == "https_proxy" {
				return "http://proxy.example:8080", true
			}
			return "", false
		},
	}, proxyTarget(t, "https://api.example.com/"))

	lenses := in.Lenses(context.Background())
	if len(lenses) != 1 {
		t.Fatalf("a build with no platform reading produced %d lens(es), want the environment alone", len(lenses))
	}
	if lenses[0].Stack != proxy.StackEnvironment {
		t.Errorf("the one lens is %s, want the environment", lenses[0].Stack)
	}
	if !lenses[0].NamesAProxy() {
		t.Error("the environment lens did not see a variable this test set")
	}
}

// TestTheProxyInputAppendsWhateverThePlatformReads is the other half, and it is
// the seam itself: the entry point asks the port and puts what it gets AFTER the
// environment, rather than either of them owning both.
func TestTheProxyInputAppendsWhateverThePlatformReads(t *testing.T) {
	asked := 0
	in := proxyInput(environment{
		lookupEnv: func(string) (string, bool) { return "", false },
		systemProxy: func(context.Context) []proxy.Lens {
			asked++
			return []proxy.Lens{
				{Stack: proxy.StackWinINET, Source: "test", Read: true, Servers: []proxy.Server{}},
				{Stack: proxy.StackWinHTTP, Source: "test", Read: true, Servers: []proxy.Server{}},
			}
		},
	}, proxyTarget(t, "https://api.example.com/"))

	lenses := in.Lenses(context.Background())
	if asked != 1 {
		t.Fatalf("the platform port was asked %d time(s), want exactly one", asked)
	}
	if len(lenses) != 3 {
		t.Fatalf("one environment lens plus two platform lenses came back as %d", len(lenses))
	}
	if lenses[0].Stack != proxy.StackEnvironment {
		t.Errorf("the environment is not first: %s", lenses[0].Stack)
	}
}

// TestTheProxyTargetGoesInAsItGoesOnTheWire pins the spelling, because every
// exception list rule is compared against it. url.Hostname strips the brackets
// of an IPv6 literal and the port, which is what proxy.Target documents wanting.
func TestTheProxyTargetGoesInAsItGoesOnTheWire(t *testing.T) {
	in := proxyInput(environment{
		lookupEnv: func(string) (string, bool) { return "", false },
	}, proxyTarget(t, "https://xn--bcher-kva.de:8443/path"))

	want := proxy.Target{Scheme: "https", Host: "xn--bcher-kva.de", Port: "8443"}
	if in.Target != want {
		t.Errorf("the target reached L2 as %+v, want %+v", in.Target, want)
	}
}
