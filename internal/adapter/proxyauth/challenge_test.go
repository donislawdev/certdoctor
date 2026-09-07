package proxyauth

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// budget is generous, because none of these tests is about the clock except the
// one that says so.
const budget = 5 * time.Second

// fakeProxy is a listener that reads one request and answers with fixed bytes.
//
// IT IS A REAL SOCKET AND NOT A SEAM, and that is the whole reason this file
// exists. What this adapter has to get right is the shape of the bytes it puts
// on a wire and the way it reads the ones that come back - neither of which a
// stub in front of net can observe. The request it received is handed back, so
// a test can assert on the line the proxy actually saw.
type fakeProxy struct {
	address string
	answer  string
	// hold is how long the proxy waits before answering, for the one test about
	// a proxy that accepts a connection and says nothing.
	hold time.Duration

	mu       sync.Mutex
	requests []string
	dialled  int
}

func startProxy(t *testing.T, answer string) *fakeProxy {
	t.Helper()
	return startProxyHolding(t, answer, 0)
}

func startProxyHolding(t *testing.T, answer string, hold time.Duration) *fakeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	p := &fakeProxy{address: listener.Addr().String(), answer: answer, hold: hold}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.serve(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return p
}

func (p *fakeProxy) serve(conn net.Conn) {
	defer conn.Close()
	p.mu.Lock()
	p.dialled++
	p.mu.Unlock()

	_ = conn.SetDeadline(time.Now().Add(budget))
	reader := bufio.NewReader(conn)
	var request strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		request.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	p.mu.Lock()
	p.requests = append(p.requests, request.String())
	p.mu.Unlock()

	if p.hold > 0 {
		time.Sleep(p.hold)
		return
	}
	_, _ = conn.Write([]byte(p.answer))
}

func (p *fakeProxy) received(t *testing.T) string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.requests) != 1 {
		t.Fatalf("the proxy saw %d request(s), want 1", len(p.requests))
	}
	return p.requests[0]
}

func (p *fakeProxy) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dialled
}

// permitting is a permission rule that allows one address and refuses the rest,
// which is the shape dial.Permission has without importing an adapter this
// package may not reach.
func permitting(allowed string) func(string) error {
	return func(address string) error {
		if address == allowed {
			return nil
		}
		return fmt.Errorf("%s is not permitted", address)
	}
}

func demand(headers string) string {
	return "HTTP/1.1 407 Proxy Authentication Required\r\n" + headers +
		"Content-Length: 0\r\nConnection: close\r\n\r\n"
}

// TestAProxyDemandingCredentialsIsReadAsOne is the whole point of this file, end
// to end over a real socket: the bytes go out, the answer comes back, and the
// code and the scheme are read out of it.
func TestAProxyDemandingCredentialsIsReadAsOne(t *testing.T) {
	p := startProxy(t, demand("Proxy-Authenticate: Basic realm=\"certdoctor testbed proxy\"\r\n"))
	answer := Ask(permitting(p.address), budget)(context.Background(), proxy.ChallengeRequest{
		Endpoint:  p.address,
		Query:     proxy.QueryConnect,
		Authority: "api.example.com:443",
	})

	if !answer.Asked {
		t.Fatalf("nothing was asked: %q", answer.Detail)
	}
	if answer.Status != 407 {
		t.Errorf("read status %d, want 407", answer.Status)
	}
	if len(answer.Schemes) != 1 {
		t.Fatalf("read %d scheme(s), want 1: %v", len(answer.Schemes), answer.Schemes)
	}
	if answer.Schemes[0].Scheme != "Basic" {
		t.Errorf("read scheme %q, want Basic", answer.Schemes[0].Scheme)
	}
	if answer.Schemes[0].Realm != "certdoctor testbed proxy" {
		t.Errorf("read realm %q, want the one the proxy named", answer.Schemes[0].Realm)
	}
}

// TestTheQuestionTakesTheShapeItWasAskedFor is probe S15 turned into an
// assertion about bytes. A CONNECT to a port outside a proxy's SSL_ports is
// refused by proxies that want no credentials at all, so asking that way about
// an http:// target would accuse a working proxy.
func TestTheQuestionTakesTheShapeItWasAskedFor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query proxy.Query
		first string
	}{
		{"a tunnel for an https target", proxy.QueryConnect, "CONNECT api.example.com:443 HTTP/1.1"},
		{"absolute form for an http target", proxy.QueryAbsoluteForm, "HEAD http://api.example.com:80/ HTTP/1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority := "api.example.com:443"
			if tc.query == proxy.QueryAbsoluteForm {
				authority = "api.example.com:80"
			}
			p := startProxy(t, demand(""))
			Ask(permitting(p.address), budget)(context.Background(), proxy.ChallengeRequest{
				Endpoint: p.address, Query: tc.query, Authority: authority,
			})

			request := p.received(t)
			if !strings.HasPrefix(request, tc.first+"\r\n") {
				t.Errorf("the proxy saw %q, want it to begin %q", request, tc.first)
			}
			if !strings.Contains(request, "Host: "+authority+"\r\n") {
				t.Errorf("the proxy saw no Host naming the origin: %q", request)
			}
		})
	}
}

// TestNoCredentialIsEverSent is inviolable rule 17 asserted on the wire rather
// than trusted to the shape of a type. The bytes this adapter writes are the
// last place a secret could enter, and nothing upstream can check them.
func TestNoCredentialIsEverSent(t *testing.T) {
	p := startProxy(t, demand("Proxy-Authenticate: Basic realm=\"corporate\"\r\n"))
	Ask(permitting(p.address), budget)(context.Background(), proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	request := strings.ToLower(p.received(t))
	for _, forbidden := range []string{"authorization", "proxy-authorization", "cookie"} {
		if strings.Contains(request, forbidden) {
			t.Errorf("the question carried a %q header: %q", forbidden, request)
		}
	}
}

// TestTheUsersPathNeverLeavesTheMachine. The question is about an ORIGIN, and
// the path is the most identifying part of a URL - sending it to a machine that
// has not been established as the user's would be a leak with no diagnostic
// value.
func TestTheUsersPathNeverLeavesTheMachine(t *testing.T) {
	p := startProxy(t, demand(""))
	Ask(permitting(p.address), budget)(context.Background(), proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryAbsoluteForm, Authority: "api.example.com:80",
	})

	if request := p.received(t); strings.Contains(request, "api.example.com:80/v1/") {
		t.Errorf("the question carried more than an origin: %q", request)
	}
}

// TestSeveralWaysOfAuthenticatingAreAllRead. A domain joined network offers
// Negotiate beside Basic, and a row naming only the first would send somebody to
// set up the wrong one.
func TestSeveralWaysOfAuthenticatingAreAllRead(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers string
		want    []string
		realms  []string
	}{
		{
			"one header for each",
			"Proxy-Authenticate: Negotiate\r\nProxy-Authenticate: Basic realm=\"corporate\"\r\n",
			[]string{"Negotiate", "Basic"}, []string{"", "corporate"},
		},
		{
			"both on one line",
			"Proxy-Authenticate: Basic realm=\"corporate\", Negotiate\r\n",
			[]string{"Basic", "Negotiate"}, []string{"corporate", ""},
		},
		{
			"a realm holding a comma",
			"Proxy-Authenticate: Basic realm=\"head office, floor 2\"\r\n",
			[]string{"Basic"}, []string{"head office, floor 2"},
		},
		{
			"a parameter that is not a scheme",
			"Proxy-Authenticate: Basic realm=\"corporate\", charset=\"UTF-8\"\r\n",
			[]string{"Basic"}, []string{"corporate"},
		},
		{
			"an unquoted realm",
			"Proxy-Authenticate: Basic realm=corporate\r\n",
			[]string{"Basic"}, []string{"corporate"},
		},
		{
			// A realm holding an escaped quote. RFC 9110 allows one, and a
			// splitter that did not know about the escape would cut the header
			// in the middle of somebody's prose.
			"a realm holding a quote",
			"Proxy-Authenticate: Basic realm=\"say \\\"hello\\\"\"\r\n",
			[]string{"Basic"}, []string{"say \"hello\""},
		},
		{
			// A trailing comma, which costs nothing to tolerate and would
			// otherwise produce a scheme with no name.
			"a list that ends in a separator",
			"Proxy-Authenticate: Basic realm=\"corporate\",\r\n",
			[]string{"Basic"}, []string{"corporate"},
		},
		{
			"none offered at all",
			"",
			nil, nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := startProxy(t, demand(tc.headers))
			answer := Ask(permitting(p.address), budget)(context.Background(), proxy.ChallengeRequest{
				Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
			})

			if len(answer.Schemes) != len(tc.want) {
				t.Fatalf("read %v, want %v", answer.Schemes, tc.want)
			}
			for at := range tc.want {
				if answer.Schemes[at].Scheme != tc.want[at] {
					t.Errorf("scheme %d is %q, want %q", at, answer.Schemes[at].Scheme, tc.want[at])
				}
				if answer.Schemes[at].Realm != tc.realms[at] {
					t.Errorf("realm %d is %q, want %q", at, answer.Schemes[at].Realm, tc.realms[at])
				}
			}
		})
	}
}

// TestAnAddressThisRunDidNotDeriveIsNotDialledAtAll is inviolable rule 16 at the
// last place it can be broken. The assertion that matters is the connection
// COUNT: a refusal reported after the socket opened would be a rule kept in the
// report and broken on the wire.
func TestAnAddressThisRunDidNotDeriveIsNotDialledAtAll(t *testing.T) {
	p := startProxy(t, demand(""))
	answer := Ask(permitting("somewhere.else:8080"), budget)(context.Background(), proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	if answer.Asked {
		t.Error("an address outside the allowed set was asked")
	}
	if p.connections() != 0 {
		t.Errorf("an address outside the allowed set was dialled %d time(s)", p.connections())
	}
	if !strings.Contains(answer.Detail, "not one of the places this run derived") {
		t.Errorf("the refusal does not say what refused it: %q", answer.Detail)
	}
	if strings.Contains(answer.Detail, p.address) {
		t.Errorf("the refusal repeats the address, which the row already carries masked: %q", answer.Detail)
	}
}

// TestAForgottenPermissionRuleRefusesEverything pins the direction a miswiring
// has to fail in: loud, and wrong in the safe direction.
func TestAForgottenPermissionRuleRefusesEverything(t *testing.T) {
	p := startProxy(t, demand(""))
	answer := Ask(nil, budget)(context.Background(), proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	if answer.Asked || p.connections() != 0 {
		t.Errorf("a run with no permission rule reached a proxy anyway: asked=%v dialled=%d", answer.Asked, p.connections())
	}
	if !strings.Contains(answer.Detail, "gap in certdoctor") {
		t.Errorf("the sentence blames the machine rather than us: %q", answer.Detail)
	}
}

// TestAnIncompleteRequestIsOurGapAndNotAProxyThatRefused.
func TestAnIncompleteRequestIsOurGapAndNotAProxyThatRefused(t *testing.T) {
	for _, request := range []proxy.ChallengeRequest{
		{Query: proxy.QueryConnect, Authority: "api.example.com:443"},
		{Endpoint: "p.example:8080", Query: proxy.QueryConnect},
	} {
		answer := Ask(permitting("p.example:8080"), budget)(context.Background(), request)
		if answer.Asked {
			t.Error("an incomplete request was reported as a question that was put")
		}
		if !strings.Contains(answer.Detail, "gap in certdoctor") {
			t.Errorf("the sentence blames the machine rather than us: %q", answer.Detail)
		}
	}
}

// TestAProxyNobodyIsListeningOnSaysTheDialFailed - the operation and not the
// message, because the text beside it comes from the operating system and is
// localised.
func TestAProxyNobodyIsListeningOnSaysTheDialFailed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()

	answer := Ask(permitting(address), budget)(context.Background(), proxy.ChallengeRequest{
		Endpoint: address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	if answer.Asked {
		t.Error("a closed port was reported as a proxy that answered")
	}
	if !strings.Contains(answer.Detail, "could not be reached") {
		t.Errorf("the sentence does not say the proxy was out of reach: %q", answer.Detail)
	}
}

// TestAProxyThatAcceptsAndSaysNothingIsNotCalledUnreadable. Those two send a
// reader to different places: one is a proxy behind a filter, the other is a
// proxy that is broken.
func TestAProxyThatAcceptsAndSaysNothingIsNotCalledUnreadable(t *testing.T) {
	p := startProxyHolding(t, demand(""), 2*time.Second)
	answer := Ask(permitting(p.address), 150*time.Millisecond)(context.Background(), proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	if answer.Asked {
		t.Error("a proxy that said nothing was reported as one that answered")
	}
	if !strings.Contains(answer.Detail, "did not answer within the time") {
		t.Errorf("the sentence does not say the proxy went quiet: %q", answer.Detail)
	}
}

// TestSomethingThatIsNotHTTPIsNotReadAsAStatusCode. A SOCKS proxy answers on the
// same kind of socket with something that is not HTTP at all, and a number read
// out of that would be one this program invented. The layer keeps SOCKS away
// from here; this is what happens if anything else ever does not.
func TestSomethingThatIsNotHTTPIsNotReadAsAStatusCode(t *testing.T) {
	p := startProxy(t, "\x05\x00not an http response at all\r\n")
	answer := Ask(permitting(p.address), budget)(context.Background(), proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	if answer.Asked || answer.Status != 0 {
		t.Errorf("something that is not HTTP was read as status %d", answer.Status)
	}
	if !strings.Contains(answer.Detail, "could not read as an HTTP response") {
		t.Errorf("the sentence does not say what was wrong with the answer: %q", answer.Detail)
	}
}

// TestTheBodyIsNeverRead. A 407 carries an error page, and this exchange has to
// come back on the status line alone - both because that page is somebody else's
// prose and because a body with no end would hold the layer's budget.
func TestTheBodyIsNeverRead(t *testing.T) {
	// A body far larger than the header cap, announced but never sent. Reading
	// it would block until the deadline; reading only the head cannot.
	p := startProxy(t, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
		"Proxy-Authenticate: Basic realm=\"corporate\"\r\n"+
		"Content-Length: 100000000\r\n\r\n")

	started := time.Now()
	answer := Ask(permitting(p.address), 3*time.Second)(context.Background(), proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	if !answer.Asked || answer.Status != 407 {
		t.Fatalf("the exchange did not come back on the head alone: asked=%v status=%d detail=%q",
			answer.Asked, answer.Status, answer.Detail)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Errorf("the exchange took %s, which is long enough to have waited for a body", waited)
	}
}

// TestAnAnswerLargerThanThisRunAcceptsIsRefusedRatherThanHeld - docs/14 section
// 2.3. The bound is on the stream, because reading it all in and asking
// afterwards is too late by definition.
func TestAnAnswerLargerThanThisRunAcceptsIsRefusedRatherThanHeld(t *testing.T) {
	p := startProxy(t, "HTTP/1.1 407 Proxy Authentication Required\r\nX-Long: "+
		strings.Repeat("a", maxHeaderBytes+1)+"\r\n\r\n")

	answer := Ask(permitting(p.address), budget)(context.Background(), proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	if answer.Asked {
		t.Errorf("a header past the cap was read as an answer: status %d", answer.Status)
	}
}

// TestTheLayersOwnDeadlineWinsWhenItIsTheEarlierOne. One unreachable proxy must
// not be able to spend more than the layer had left, whichever bound is tighter.
func TestTheLayersOwnDeadlineWinsWhenItIsTheEarlierOne(t *testing.T) {
	p := startProxyHolding(t, demand(""), 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	started := time.Now()
	answer := Ask(permitting(p.address), time.Minute)(ctx, proxy.ChallengeRequest{
		Endpoint: p.address, Query: proxy.QueryConnect, Authority: "api.example.com:443",
	})

	if answer.Asked {
		t.Error("a proxy that said nothing was reported as one that answered")
	}
	if waited := time.Since(started); waited > time.Second {
		t.Errorf("the exchange took %s, so the layer's own deadline was not what stopped it", waited)
	}
}
