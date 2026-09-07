// Package proxyauth asks one proxy whether it wants to be told who is asking.
//
// IT IS THE SIXTH PLACE IN THIS PROGRAM THAT CAN OPEN A CONNECTION, and it is
// one FILE on the dial allowlist rather than a package, like every entry before
// it. What makes it a new WAY to reach the network rather than a fifth answer to
// "may we" is the shape of the exchange: nothing else here speaks HTTP to a
// machine that is not the target and not a resolver.
//
// NO CREDENTIALS ARE EVER SENT AND THERE IS NOWHERE TO PUT ANY. Inviolable rule
// 17 says they never reach the report or the log whatever --redact says, and
// ADR89 made that structural one field earlier by cutting userinfo where a proxy
// address is READ. The question this file asks is what happens to a machine that
// offers nothing, because that is the machine whose build is failing.
package proxyauth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// maxHeaderBytes is how much of a proxy's answer this program will hold.
//
// THE BOUND IS ON THE STREAM AND NOT ON WHAT CAME BACK - docs/14 section 2.3.
// Reading it all in and asking afterwards is too late by definition, and the
// answer here comes from a machine this run has been told about rather than one
// the user named, so the amount of it that reaches memory is not that machine's
// decision to make. The body is never read at all; this is the header alone,
// which is generous for a status line, a Proxy-Authenticate or three and the
// usual furniture.
const maxHeaderBytes = 64 * 1024

// Ask builds the port L2 declared, with the permission rule in front of it.
//
// THE RULE IS BORROWED, NEVER COPIED - ADR35. mayReach is the same function the
// DNS diallers, L3, L4 and the script fetch ask, so "may this run reach that
// address" is decided once for the whole program and a mutation entry aimed at
// that rule still aims at this caller.
//
// A NIL RULE REFUSES EVERYTHING, the direction every other port in this program
// chose: a forgotten wire has to read as a program that cannot reach anything,
// which is loud and wrong in the safe direction.
//
// THE BUDGET IS PER ENDPOINT AND NOT PER LAYER, and it is bounded again by
// whatever the layer's own context still holds - the earlier of the two wins.
// One unreachable proxy must not be able to spend everything the layer had left
// for the ones after it.
func Ask(mayReach func(address string) error, perEndpoint time.Duration) proxy.ChallengeAsk {
	return func(ctx context.Context, request proxy.ChallengeRequest) proxy.ChallengeAnswer {
		if mayReach == nil {
			return notAsked("no permission rule was supplied, so no proxy was asked whether it wants " +
				"credentials, which is a gap in certdoctor rather than anything about this machine")
		}
		if request.Endpoint == "" || request.Authority == "" {
			return notAsked("this run did not work out both which proxy to ask and which host and port " +
				"to ask it about, which is a gap in certdoctor rather than anything about this machine")
		}
		if err := mayReach(request.Endpoint); err != nil {
			// THE ERROR IS NOT QUOTED AND THAT IS DELIBERATE. A refusal names the
			// address it refused, and that address travels into a report field
			// beside ones this program masks - so repeating it here would put an
			// unmasked copy next to the masked one. The same shape ADR83 measured
			// on four usage messages. The address is already in the row.
			return notAsked("certdoctor did not ask this proxy, because its address is not one of the " +
				"places this run derived from the question it was asked")
		}
		return exchange(ctx, request, perEndpoint)
	}
}

// exchange opens one connection, asks once, reads the answer's head and hangs
// up.
//
// NOTHING IS POOLED AND NOTHING IS KEPT. A connection that outlived this call
// would outlive the layer whose budget paid for it, and this one is to a machine
// the user never named.
func exchange(ctx context.Context, request proxy.ChallengeRequest, perEndpoint time.Duration) proxy.ChallengeAnswer {
	deadline := time.Now().Add(perEndpoint)
	if layer, ok := ctx.Deadline(); ok && layer.Before(deadline) {
		deadline = layer
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", request.Endpoint)
	if err != nil {
		return notAsked(whyNotReached(err))
	}
	defer conn.Close()
	// A DEADLINE ON THE SOCKET AND NOT ONLY ON THE CONTEXT. A context bounds the
	// dial; only this bounds a proxy that accepts the connection and then never
	// answers, which is the failure this exchange is most likely to meet.
	_ = conn.SetDeadline(deadline)

	if _, err := io.WriteString(conn, requestLine(request)); err != nil {
		return notAsked("the question could not be put to this proxy: the connection opened and the " +
			"request could not be sent")
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, maxHeaderBytes)), asked(request))
	if err != nil {
		return notAsked(whyNoAnswer(err))
	}
	// THE BODY IS CLOSED AND NEVER READ. What the answer means is in the status
	// line and in the Proxy-Authenticate headers; an error page is somebody
	// else's prose about a machine this run was told about rather than asked
	// about, and inviolable rule 19 forbids deciding anything from it.
	defer response.Body.Close()

	return proxy.ChallengeAnswer{
		Asked:   true,
		Status:  response.StatusCode,
		Schemes: schemesOf(response.Header.Values("Proxy-Authenticate")),
	}
}

// requestLine is the one question, in the shape the target's scheme decides.
//
// THE TWO SHAPES ARE NOT INTERCHANGEABLE - probe S15, 2026-09-07. A CONNECT to a
// port outside a proxy's SSL_ports is refused by proxies that want no
// credentials at all, so asking that way about an http:// target would accuse a
// working proxy and a working machine.
//
// THE PATH IS "/" AND NOT THE USER'S. The question is about an origin, and
// sending somebody's path and query to a machine that has not been established
// as theirs would put the most identifying part of the run on a wire nobody
// asked us to use.
func requestLine(request proxy.ChallengeRequest) string {
	if request.Query == proxy.QueryConnect {
		return fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", request.Authority, request.Authority)
	}
	return fmt.Sprintf("HEAD http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		request.Authority, request.Authority)
}

// asked is the request http.ReadResponse needs in order to know whether an
// answer carries a body.
//
// IT IS A STRUCTURE AND NOT A PARSE. The only field ReadResponse consults is the
// method, and building it by hand keeps this file from having a second opinion
// about the request it just wrote.
func asked(request proxy.ChallengeRequest) *http.Request {
	if request.Query == proxy.QueryConnect {
		return &http.Request{Method: http.MethodConnect}
	}
	return &http.Request{Method: http.MethodHead}
}

// whyNoAnswer keeps "it said nothing" apart from "it said something unreadable".
//
// THOSE TWO SEND A READER TO DIFFERENT PLACES, which is the same distinction
// proxy.ScriptAnswer draws between a server nobody reached and a file that
// answers badly. A proxy that accepts a connection and then goes silent is the
// ordinary shape of a proxy behind a filter, and calling that an unreadable
// answer would send somebody looking for a broken proxy.
func whyNoAnswer(err error) string {
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "this proxy accepted the connection and did not answer within the time this run allows"
	}
	return "this proxy answered with something certdoctor could not read as an HTTP response"
}

// whyNotReached says a proxy could not be reached without repeating somebody
// else's sentence.
//
// THE OPERATION AND NOT THE MESSAGE - inviolable rule 19. Op is one of a handful
// of words the standard library sets itself, while the text beside it comes from
// the operating system and is localised: measured in this tree already, a Polish
// Windows answers a refused connection in Polish.
func whyNotReached(err error) string {
	var operation *net.OpError
	if errors.As(err, &operation) {
		return fmt.Sprintf("this proxy could not be reached: the %s failed", operation.Op)
	}
	return "this proxy could not be reached"
}

// schemesOf reads the ways a proxy offered to be told who is asking.
//
// SOURCE: RFC 9110 section 11 - a challenge is an auth-scheme token optionally
// followed by parameters, several challenges may share one header line separated
// by commas, and a quoted string may itself contain a comma. So the split below
// is quote aware, and a piece that is a bare parameter belongs to the challenge
// before it rather than starting a new one.
//
// THE SCHEME IS AN IDENTIFIER AND THE REALM IS NOT. A scheme name comes from the
// IANA registry, so inviolable rule 19 is satisfied by printing it; a realm is
// free text an administrator typed, which is why the report withholds it under
// --redact rather than masking it.
func schemesOf(headers []string) []report.ProxyAuthScheme {
	var schemes []report.ProxyAuthScheme
	for _, header := range headers {
		for _, piece := range splitOutsideQuotes(header) {
			piece = strings.TrimSpace(piece)
			if piece == "" {
				continue
			}
			// A piece that is one parameter belongs to the challenge before it
			// rather than starting a new one: "charset=UTF-8" names no way of
			// authenticating. A bare token does start one, which is ordinary for
			// Negotiate and for NTLM.
			if isParameter(piece) {
				continue
			}
			name, rest := firstWord(piece)
			if name == "" {
				continue
			}
			scheme := report.ProxyAuthScheme{Scheme: name}
			if realm, found := realmOf(rest); found {
				scheme.Realm = realm
			}
			schemes = append(schemes, scheme)
		}
	}
	return schemes
}

// isParameter reports whether a piece is one challenge parameter rather than the
// start of a new challenge.
//
// THE TEST IS "A BARE NAME, THEN AN EQUALS SIGN", and it is done on the equals
// sign OUTSIDE any quoted string. "Basic realm=x" holds a space before its
// equals and starts a challenge; "charset=UTF-8" does not and continues one.
func isParameter(piece string) bool {
	at := indexOutsideQuotes(piece, '=')
	if at < 0 {
		return false
	}
	return !strings.ContainsAny(strings.TrimSpace(piece[:at]), " \t")
}

// indexOutsideQuotes finds the first want that is not inside a quoted string.
func indexOutsideQuotes(s string, want rune) int {
	quoted, escaped := false, false
	for at, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && quoted:
			escaped = true
		case r == '"':
			quoted = !quoted
		case r == want && !quoted:
			return at
		}
	}
	return -1
}

// realmOf pulls the realm out of one challenge's parameters.
func realmOf(parameters string) (string, bool) {
	for _, piece := range splitOutsideQuotes(parameters) {
		piece = strings.TrimSpace(piece)
		key, value, found := strings.Cut(piece, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "realm") {
			continue
		}
		return unquote(strings.TrimSpace(value)), true
	}
	return "", false
}

// splitOutsideQuotes cuts on commas that are not inside a quoted string.
//
// IT WALKS NOTHING OF ITS OWN, and the first draft did. Two functions in this
// file were stepping through the same string with the same quote and escape
// bookkeeping, which is one rule in two places even inside one file - the shape
// OBS50 measures, and the one that turns a mutation entry aimed at either of
// them into a SKIP.
func splitOutsideQuotes(s string) []string {
	var pieces []string
	for {
		at := indexOutsideQuotes(s, ',')
		if at < 0 {
			return append(pieces, s)
		}
		pieces = append(pieces, s[:at])
		s = s[at+1:]
	}
}

// firstWord splits a piece into its first token and everything after it.
func firstWord(s string) (string, string) {
	at := strings.IndexAny(s, " \t")
	if at < 0 {
		return s, ""
	}
	return s[:at], strings.TrimSpace(s[at+1:])
}

// unquote takes the quotes off a quoted-string and undoes its escapes.
func unquote(s string) string {
	if len(s) < 2 || !strings.HasPrefix(s, `"`) || !strings.HasSuffix(s, `"`) {
		return s
	}
	return strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)
}

// notAsked is an answer that says nothing was asked, and why.
func notAsked(detail string) proxy.ChallengeAnswer {
	return proxy.ChallengeAnswer{Detail: detail}
}
