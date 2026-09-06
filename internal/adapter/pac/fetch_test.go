package pac

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// served starts a server on a loopback port of the operating system's choosing
// and hands back the address it is listening on.
//
// A REAL LISTENER RATHER THAN A ROUND TRIPPER, and the difference is the whole
// point of testing this file at all. What is under test here is a transport
// with a dialler in front of it and a redirect policy behind it; a fake round
// tripper replaces exactly the layer those two live in, so it would exercise
// this package's imports and none of its decisions. It is the shape the tcp and
// handshake tests already use one layer along.
func served(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("a loopback listener could not be opened: %v", err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// permit is a rule that allows everything, for the tests whose subject is not
// the rule.
func permit(string) error { return nil }

// refuse is the other one, and it carries a value the caller can recognise so a
// test can tell a refusal from a network failure without reading prose.
var errRefused = errors.New("refused by the test's rule")

func refuse(string) error { return errRefused }

func TestTargetSpellsAnAddressTheTransportWillDial(t *testing.T) {
	for _, tc := range []struct {
		rawURL string
		want   string
	}{
		{"http://pac.example/proxy.pac", "pac.example:80"},
		{"https://pac.example/proxy.pac", "pac.example:443"},
		{"http://pac.example:8080/proxy.pac", "pac.example:8080"},
		// AN IPv6 LITERAL GOES IN BRACKETED, because that is how net/http will
		// ask for it. url.Hostname strips the brackets and JoinHostPort puts
		// them back, which is why both sides have to go through this one
		// function rather than joining a host and a port twice.
		{"http://[2001:db8::1]:8080/proxy.pac", "[2001:db8::1]:8080"},
		{"http://[2001:db8::1]/proxy.pac", "[2001:db8::1]:80"},
	} {
		got, err := Target(tc.rawURL)
		if err != nil {
			t.Errorf("%s could not be spelled: %v", tc.rawURL, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s dials %q, want %q", tc.rawURL, got, tc.want)
		}
	}
}

// TestTargetRefusesEverySchemeButHTTP is docs/14 section 3a as a test. A
// Windows AutoConfigURL may be a file: URL and a Windows file path may be a UNC
// path, so following one opens a connection to a host nobody named - and the
// network guard cannot see it, because nothing passes through a network package
// on the way.
func TestTargetRefusesEverySchemeButHTTP(t *testing.T) {
	for _, rawURL := range []string{
		"file:///etc/proxy.pac",
		"ftp://pac.example/proxy.pac",
		"pac.example/proxy.pac",
	} {
		if _, err := Target(rawURL); !errors.Is(err, ErrSchemeRefused) {
			t.Errorf("%s was answered with %v, want the scheme refusal", rawURL, err)
		}
	}

	// THE UNC FORM IS REFUSED BY A DIFFERENT SENTENCE AND THAT IS RECORDED
	// RATHER THAN SMOOTHED OVER. url.Parse rejects the backslashes before the
	// scheme is ever compared, so this one comes back as an address that will
	// not parse. Both answers are refusals and only the wording differs, but
	// asserting the scheme error here would be asserting something this function
	// does not decide - and the day url.Parse grows more tolerant, the test that
	// matters is that the address is still refused.
	if _, err := Target(`file://\\fileserver\share\proxy.pac`); err == nil {
		t.Error("a UNC path dressed as a file URL was accepted, and opening one is a connection the network guard cannot see")
	}
}

func TestTargetRefusesAnAddressWithNothingToDial(t *testing.T) {
	for _, rawURL := range []string{
		"http:///proxy.pac",
		"http://pac.example:0/proxy.pac",
		"http://pac.example:99999/proxy.pac",
	} {
		if _, err := Target(rawURL); err == nil {
			t.Errorf("%s was accepted, and there is nothing there to dial", rawURL)
		}
	}
}

func TestFetchReturnsWhatTheServerSent(t *testing.T) {
	body := "function FindProxyForURL(url, host) { return \"DIRECT\"; }"
	address := served(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	})

	got, err := Fetch(permit, 1<<20)(context.Background(), "http://"+address+"/proxy.pac")
	if err != nil {
		t.Fatalf("a script that was there could not be fetched: %v", err)
	}
	if got != body {
		t.Errorf("the fetched script is %q, want %q", got, body)
	}
}

// TestFetchAsksThePermissionRuleForTheAddressItDials is inviolable rule 16 at
// the one place this file can break it. The rule is asked with the string the
// transport is about to dial, so an entry in the allowed set spelled any other
// way would refuse a machine where everything works.
func TestFetchAsksThePermissionRuleForTheAddressItDials(t *testing.T) {
	address := served(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "DIRECT") })

	var asked []string
	rule := func(a string) error {
		asked = append(asked, a)
		return nil
	}
	if _, err := Fetch(rule, 1<<20)(context.Background(), "http://"+address+"/proxy.pac"); err != nil {
		t.Fatalf("the fetch failed: %v", err)
	}
	if len(asked) != 1 || asked[0] != address {
		t.Fatalf("the rule was asked about %v, want exactly [%s]", asked, address)
	}
}

func TestFetchRefusesWhenTheRuleRefuses(t *testing.T) {
	address := served(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "DIRECT") })

	_, err := Fetch(refuse, 1<<20)(context.Background(), "http://"+address+"/proxy.pac")
	if err == nil {
		t.Fatal("an address the rule refused was fetched anyway")
	}
}

// TestFetchWithNoRuleReachesNothing is the direction every port in this program
// chose: a forgotten wire reads as a program that cannot reach anything, never
// as one with no restrictions.
func TestFetchWithNoRuleReachesNothing(t *testing.T) {
	address := served(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "DIRECT") })

	if _, err := Fetch(nil, 1<<20)(context.Background(), "http://"+address+"/proxy.pac"); err == nil {
		t.Fatal("a fetch with no permission rule went ahead")
	}
}

// TestFetchDoesNotFollowARedirect is the second address problem. A run derived
// the first address and nothing else, so a server pointing somewhere else is
// pointing outside what this run may reach - and saying so is a different
// sentence from "the connection failed".
func TestFetchDoesNotFollowARedirect(t *testing.T) {
	var reached int
	address := served(t, func(w http.ResponseWriter, r *http.Request) {
		reached++
		if r.URL.Path == "/proxy.pac" {
			http.Redirect(w, r, "/elsewhere.pac", http.StatusFound)
			return
		}
		fmt.Fprint(w, "DIRECT")
	})

	_, err := Fetch(permit, 1<<20)(context.Background(), "http://"+address+"/proxy.pac")
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("a redirect was answered with %v, want the redirect refusal", err)
	}
	if reached != 1 {
		t.Errorf("the server was asked %d times, and a refused redirect must be asked once", reached)
	}
}

// TestFetchDoesNotQuoteTheAddressBack is ADR83's shape met from the other side.
// Go's transport errors embed the URL, and this field travels into a report
// beside one this program masks - so an error quoted whole would put an unmasked
// copy of the script's address next to the masked one.
func TestFetchDoesNotQuoteTheAddressBack(t *testing.T) {
	// A port nothing listens on. The dial fails, which is the path that carries
	// somebody else's error.
	_, err := Fetch(permit, 1<<20)(context.Background(), "http://127.0.0.1:1/secret-name.pac")
	if err == nil {
		t.Fatal("a connection to a closed port succeeded")
	}
	if strings.Contains(err.Error(), "secret-name") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("the failure quotes the address back: %q", err)
	}
}

// TestFetchStopsReadingPastTheLimit is docs/14 section 2.3: the bound is on what
// this process will HOLD, not a second opinion about what is too large. It hands
// back max+1 bytes so that the sandbox - which owns that rule - can see the
// limit was passed and answer too_large.
func TestFetchStopsReadingPastTheLimit(t *testing.T) {
	const max = 64
	address := served(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 100*max))
	})

	got, err := Fetch(permit, max)(context.Background(), "http://"+address+"/proxy.pac")
	if err != nil {
		t.Fatalf("an oversized script failed rather than being cut short: %v", err)
	}
	if len(got) != max+1 {
		t.Errorf("a body of %d bytes came back where a limit of %d should have stopped at %d", len(got), max, max+1)
	}
}

func TestFetchRefusesAnythingButTwoHundred(t *testing.T) {
	address := served(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such thing", http.StatusNotFound)
	})

	_, err := Fetch(permit, 1<<20)(context.Background(), "http://"+address+"/proxy.pac")
	if err == nil {
		t.Fatal("a 404 was read as a script")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("the failure does not name the status code: %q", err)
	}
}

// TestTheTransportNeverConsultsTheProxyVariables is the measured trap this whole
// slice was warned about, and the assertion is STRUCTURAL for a reason that was
// measured rather than chosen.
//
// http.DefaultTransport calls ProxyFromEnvironment, so a default client would
// read HTTPS_PROXY and route this request through whatever it found - docs/14
// section 3 broken from the inside, and what this program's own bench calls "A
// REAL DEFECT".
//
// THE BEHAVIOURAL TEST BELOW CANNOT CATCH IT AND THIS ONE CAN. The mutation
// register aimed an entry at that line and the behavioural test SURVIVED,
// because Go documents that a request to localhost or a loopback address is
// never proxied - read at source 2026-09-06 - and a unit test serves from
// 127.0.0.1. So no test that actually fetches can ever observe the fault, and
// the only assertion that fails when the line changes is this one.
func TestTheTransportNeverConsultsTheProxyVariables(t *testing.T) {
	if scriptTransport(permit).Proxy != nil {
		t.Error("the transport carries a proxy function, so a fetch would follow the configuration it is describing")
	}
}

// TestFetchWorksWithTheProxyVariablesSet is the behavioural half, kept with an
// honest name. It proves a fetch succeeds on a machine whose environment names a
// proxy; it does NOT prove the transport ignores that proxy, for the reason
// written above.
func TestFetchWorksWithTheProxyVariablesSet(t *testing.T) {
	address := served(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "DIRECT") })

	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, "http://127.0.0.1:1")
	}

	got, err := Fetch(permit, 1<<20)(context.Background(), "http://"+address+"/proxy.pac")
	if err != nil {
		t.Fatalf("the fetch went through the environment's proxy instead of straight to the server: %v", err)
	}
	if got != "DIRECT" {
		t.Errorf("the fetched script is %q, want the server's own body", got)
	}
}

// TestFetchStopsWhenTheRunDoes keeps the layer's budget meaningful: a server
// that accepts a connection and never answers must not outlive the run.
func TestFetchStopsWhenTheRunDoes(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	address := served(t, func(w http.ResponseWriter, _ *http.Request) { <-release })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := time.Now()
	if _, err := Fetch(permit, 1<<20)(ctx, "http://"+address+"/proxy.pac"); err == nil {
		t.Fatal("a server that never answered was read as a script")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("the fetch took %v to give up on a 50ms budget", elapsed)
	}
}

// TestResolverKeepsAFailedFetchApartFromABadAnswer is the pair proxy.ScriptAnswer
// exists to hold. A web server nobody can reach and a file that answers badly
// send a reader to different places, and a type that merged them would have this
// program report a broken PAC on a machine whose PAC is fine and whose web server
// is down.
func TestResolverKeepsAFailedFetchApartFromABadAnswer(t *testing.T) {
	sandbox := testSandbox()

	broken := Resolver(func(context.Context, string) (string, error) {
		return "this is not JavaScript (((", nil
	}, sandbox, "https://api.example.com/", "api.example.com")
	answer := broken(context.Background(), "http://pac.example/proxy.pac")
	if !answer.Fetched {
		t.Error("a script that arrived and would not parse came back as unfetched")
	}
	if answer.Result.Outcome != corepac.OutcomeMalformed {
		t.Errorf("a file that will not parse came back as %s", answer.Result.Outcome)
	}

	unreachable := Resolver(func(context.Context, string) (string, error) {
		return "", errors.New("the dial failed")
	}, sandbox, "https://api.example.com/", "api.example.com")
	answer = unreachable(context.Background(), "http://pac.example/proxy.pac")
	if answer.Fetched {
		t.Error("a script nobody could fetch came back as fetched")
	}
	if answer.Detail != "the dial failed" {
		t.Errorf("the failure sentence is %q, want the fetcher's own", answer.Detail)
	}
	if answer.Result.Outcome != "" {
		t.Errorf("a script nobody fetched carries an evaluation outcome: %s", answer.Result.Outcome)
	}
}

// TestResolverAsksTheScriptAboutTheTargetTheRunIsFor pins the two values a PAC
// file is handed. A script asked about the wrong URL answers a different
// question, correctly, and nothing downstream can tell.
func TestResolverAsksTheScriptAboutTheTargetTheRunIsFor(t *testing.T) {
	resolve := Resolver(func(context.Context, string) (string, error) {
		return `function FindProxyForURL(url, host) { return "PROXY " + host + ":1"; }`, nil
	}, testSandbox(), "https://api.example.com/deep", "api.example.com")

	answer := resolve(context.Background(), "http://pac.example/proxy.pac")
	if answer.Result.Raw != "PROXY api.example.com:1" {
		t.Errorf("the script was asked about %q, want the run's own target", answer.Result.Raw)
	}
}

// TestResolverWithNoFetcherSaysTheGapIsOurs is the safe direction for a
// forgotten wire, and it must not read as a machine with no script.
func TestResolverWithNoFetcherSaysTheGapIsOurs(t *testing.T) {
	answer := Resolver(nil, testSandbox(), "https://api.example.com/", "api.example.com")(
		context.Background(), "http://pac.example/proxy.pac")

	if answer.Fetched {
		t.Fatal("a build with no fetcher fetched something")
	}
	if !strings.Contains(answer.Detail, "certdoctor") {
		t.Errorf("the sentence blames the machine rather than this build: %q", answer.Detail)
	}
}
