package pac

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// Fetcher retrieves the bytes of an automatic configuration script.
//
// THE SIGNATURE IS THE PORT L2 DECLARED, and the string it returns is the
// script's source with nothing done to it. Deciding what the file MEANS belongs
// to the evaluator and the layer; this half only gets the bytes.
type Fetcher func(ctx context.Context, rawURL string) (string, error)

// ErrSchemeRefused is returned for an address this program will not fetch from.
//
// IT IS A VALUE RATHER THAN A MESSAGE so a test and a caller can tell it from
// every network failure without reading prose - inviolable rule 19 applied to
// our own errors as well as to somebody else's output.
var ErrSchemeRefused = errors.New("certdoctor fetches an automatic configuration script over http or https and over nothing else")

// ErrRedirectRefused is returned when the server answers with a redirect.
var ErrRedirectRefused = errors.New("the server answered with a redirect, and certdoctor does not follow one to fetch an automatic configuration script")

// fetchableSchemes is the closed set of schemes a script may be fetched over.
//
// THE ONE THAT IS MISSING IS THE REASON THIS SET EXISTS: file. A Windows
// AutoConfigURL may legally be a file: URL, and on Windows a file path may be a
// UNC path - so following one would open a connection to a host nobody named,
// authenticated with the user's own token, and the network guard CANNOT SEE IT
// because nothing would pass through a network package on the way. That is
// docs/14 section 3a exactly, which is not our reasoning but a measured review
// of a neighbouring project, where an existence check under a UNC path to an
// unreachable host answered after 21 seconds.
//
// A REFUSAL IS AN ANSWER AND NOT A GAP - docs/14 section 2.5. The row says the
// machine names a script this program will not fetch, and says why, rather than
// going quiet about a place a proxy could be coming from.
var fetchableSchemes = map[string]bool{"http": true, "https": true}

// defaultPorts is what a scheme means when the address names no port. It is the
// same table net/http applies, restated here for one reason only: Target has to
// produce the string the transport will dial, and a second guess would make the
// allowed set and the dialler disagree about what "the same address" is.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// Target is the address a fetch of rawURL will dial, spelled the one way both
// the allowed set and the transport will see it.
//
// THE SAME STRING GOES INTO THE SET AND INTO THE DIALLER, which is the whole
// reason this function exists rather than the join happening twice. tcp.Target
// exists for the identical reason one layer along, and the failure mode it
// prevents is the expensive one: two spellings of an address mean either a
// refusal on a machine where everything works, or a connection nothing checked.
//
// IT IS BUILT THE WAY net/http BUILDS IT - Hostname without brackets, joined
// back through JoinHostPort - so an IPv6 script address goes into the set in the
// bracketed form the transport will ask about.
func Target(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("%q is not an address an automatic configuration script could be fetched from", rawURL)
	}
	if !fetchableSchemes[parsed.Scheme] {
		return "", ErrSchemeRefused
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("%q names no host, so there is nowhere to fetch an automatic configuration script from", rawURL)
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPorts[parsed.Scheme]
	}
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return "", fmt.Errorf("%q asks for port %q, which is not a port", rawURL, port)
	}
	return net.JoinHostPort(host, port), nil
}

// scriptTransport builds the transport one fetch runs on.
//
// THE Proxy FIELD IS SET TO nil EXPLICITLY AND THAT LINE IS THE MOST IMPORTANT
// ONE IN THIS FILE. http.DefaultTransport calls ProxyFromEnvironment, so a
// default client would read HTTPS_PROXY and route this request through whatever
// it found - and this program's own bench calls that "A REAL DEFECT" in
// testbed/expected/proxy-env.txt. docs/14 section 3 is the rule behind it: proxy
// variables are diagnostic INPUT, so reading one must never change where this
// program connects. A tool that quietly obeyed the configuration it is
// describing could not describe it.
//
// THE RULE IS BORROWED, NEVER COPIED - ADR35. dial.Permission is the same
// function the DNS diallers, L3 and L4 ask, so "may this run reach that address"
// is decided once for the whole program and a mutation entry aimed at that rule
// still aims at this caller.
//
// IT IS A FUNCTION OF ITS OWN BECAUSE THE MOST IMPORTANT LINE IN THIS FILE
// COULD NOT OTHERWISE BE CHECKED, and that was measured rather than reasoned.
// The mutation register aimed an entry at "Proxy: nil" - swapping it for
// http.ProxyFromEnvironment, which is exactly the defect this package must not
// have - and the behavioural test SURVIVED it. The reason is in Go's own
// source, read 2026-09-06 at src/vendor/golang.org/x/net/http/httpproxy: "As a
// special case, if reqURL.Host is 'localhost' or a loopback address (with or
// without a port number), then a nil URL and nil error will be returned."
//
// A UNIT TEST SERVES FROM 127.0.0.1, SO NO TEST OF THIS KIND CAN EVER OBSERVE
// THE FAULT. The test asserting that a fetch works with proxy variables set is
// still worth having and it proves less than its name suggests; the assertion
// that can fail is the structural one, and it needs something to assert about.
func scriptTransport(mayReach func(address string) error) *http.Transport {
	return &http.Transport{
		// Explicitly nil. See the paragraph on Fetch; this is not the zero value
		// being relied on, it is the zero value being chosen.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if err := mayReach(address); err != nil {
				return nil, err
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
		// One request, one connection, nothing kept. A pooled connection would
		// outlive the layer whose budget paid for it.
		DisableKeepAlives: true,
	}
}

// Fetch builds the port that retrieves a script, with the permission rule in
// front of it.
//
// A NIL RULE REFUSES EVERYTHING, the direction every other port in this program
// chose: a forgotten wire has to read as a program that cannot reach anything.
//
// THE BODY IS BOUNDED BUT NOT JUDGED HERE. It is read through a LimitReader of
// max+1 bytes, which is a bound on what this process will hold rather than a
// second opinion about what is too large: the sandbox owns that rule and answers
// too_large from it, and the extra byte is what lets it see that the limit was
// passed. Reading it all in and asking afterwards is what docs/14 section 2.3
// forbids - after the bytes are in, it is already too late.
func Fetch(mayReach func(address string) error, max int) Fetcher {
	return func(ctx context.Context, rawURL string) (string, error) {
		if mayReach == nil {
			return "", errors.New("no permission rule was supplied, so no automatic configuration script could be fetched")
		}
		if _, err := Target(rawURL); err != nil {
			return "", err
		}

		transport := scriptTransport(mayReach)
		defer transport.CloseIdleConnections()

		client := &http.Client{
			Transport: transport,
			// A REDIRECT IS A SECOND ADDRESS AND THIS RUN DERIVED ONLY THE
			// FIRST. The dialler above would refuse it, which is the safe
			// direction but the wrong sentence: the row would report a
			// connection failure where the truth is that the server pointed
			// somewhere nobody authorised. Refusing here says that instead.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrRedirectRefused
			},
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return "", fmt.Errorf("an automatic configuration script could not be asked for: %w", err)
		}
		response, err := client.Do(request)
		if err != nil {
			// UNWRAPPED TO OUR OWN SENTENCE WHEN IT IS OUR OWN REFUSAL. A
			// redirect arrives here inside a *url.Error, and a row saying "Get
			// http://...: the server answered with a redirect" would put the
			// address back into a field that has no rule able to mask it.
			if errors.Is(err, ErrRedirectRefused) {
				return "", ErrRedirectRefused
			}
			return "", failedFetch(err)
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			// THE CODE AND NOT THE SERVER'S SENTENCE - inviolable rule 19. A
			// status line is somebody else's text and may be in any language;
			// the number is the part that means the same thing everywhere.
			return "", fmt.Errorf("the server answered %d rather than 200, so there was no script to read", response.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(response.Body, int64(max)+1))
		if err != nil {
			return "", failedFetch(err)
		}
		return string(body), nil
	}
}

// failedFetch keeps somebody else's error out of the report while keeping the
// fact that it happened.
//
// THE ADDRESS IS NOT REPEATED HERE. Go's own transport errors embed the URL
// being fetched, and that URL travels into a report field beside one this
// program masks - so quoting the error whole would put an unmasked copy of the
// script's address next to the masked one. The same shape ADR83 measured on
// four usage messages, met from the other side.
func failedFetch(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("fetching the automatic configuration script ran past the time this run allows")
	}
	if errors.Is(err, context.Canceled) {
		return errors.New("fetching the automatic configuration script stopped when the run did")
	}
	var refusal *net.OpError
	if errors.As(err, &refusal) {
		// THE OPERATION AND NOT THE MESSAGE - inviolable rule 19. Op is one of a
		// handful of words the standard library sets itself ("dial", "read",
		// "write"), while the text beside it comes from the operating system and
		// is localised: measured in this tree already, a Polish Windows answers
		// a refused connection in Polish.
		return fmt.Errorf("the automatic configuration script could not be fetched: the %s failed", refusal.Op)
	}
	return errors.New("the automatic configuration script could not be fetched")
}

// Resolver composes the two halves into the port L2 declared: fetch the script,
// then run it against the target this run is asking about.
//
// IT LIVES HERE RATHER THAN AT THE ENTRY POINT, AND THAT WAS A COVERAGE
// MEASUREMENT BEFORE IT WAS A JUDGEMENT. The first version was a closure inside
// the entry point's wiring, beside the four one-line seams for the diallers -
// and nothing there is executed by any test, because it is the production
// wiring. Six statements deciding what a failed fetch means and what a
// successful one carries went in unexecuted, which is exactly the question the
// coverage gate exists to ask. Here they are ordinary code with ordinary tests.
//
// A FETCH THAT FAILED IS NOT AN EVALUATION THAT WENT BADLY, and keeping those
// apart is the whole shape of proxy.ScriptAnswer: a web server nobody can reach
// and a file that answers badly send a reader to different places.
func Resolver(fetch Fetcher, sandbox Sandbox, targetURL, targetHost string) proxy.Evaluate {
	return func(ctx context.Context, scriptURL string) proxy.ScriptAnswer {
		if fetch == nil {
			return proxy.ScriptAnswer{Detail: "this build has no way to fetch an automatic configuration script, " +
				"which is a gap in certdoctor rather than anything about this machine"}
		}
		source, err := fetch(ctx, scriptURL)
		if err != nil {
			return proxy.ScriptAnswer{Detail: err.Error()}
		}
		return proxy.ScriptAnswer{Fetched: true, Result: sandbox.Evaluate(ctx, source, targetURL, targetHost)}
	}
}
