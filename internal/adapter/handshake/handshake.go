// Package handshake completes the TLS handshakes layer L4 asks for.
//
// IT IS THE FOURTH PLACE IN THIS PROGRAM THAT REACHES THE NETWORK, and the file
// below is on the dial allowlist for that reason. The list is short on purpose:
// the promise of inviolable rule 16 - this run reaches only what it was pointed
// at - is checkable exactly as long as the number of places that can open a
// socket stays small enough to read.
//
// IT IS ALSO THE ONE PLACE ALLOWED TO SKIP CERTIFICATE VERIFICATION, and that
// has a guard of its own. See the comment on the config below before deciding
// this looks like a defect.
package handshake

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/adapter/tcp"
	core "github.com/donislawdev/certdoctor/internal/core/handshake"
)

// alpn is what this program offers, and it is what a browser offers.
//
// THE RISK IS NAMED RATHER THAN IGNORED. RFC 7301 lets a server abort with
// no_application_protocol when it supports none of the offered protocols, so
// offering these can turn a reachable server into a failed handshake. It is
// still the right list: the question this product answers is "why does my HTTPS
// client fail here", and this is the pair every HTTPS client offers. A server
// that refuses both would refuse their client too, which makes it a finding
// rather than an artefact of our instrument.
var alpn = []string{"h2", "http/1.1"}

// Shake turns the permission rule and crypto/tls into the port L4 declared.
//
// THE RULE IS BORROWED, NEVER COPIED - ADR35. The same dial.Permission the DNS
// dialler and L3 ask, so "may this run reach that address" is decided in one
// place for the whole program. THE SPELLING IS BORROWED TOO: tcp.Target builds
// the string the allowed set was given, so the address checked here and the
// address dialled cannot drift apart. Writing either of them again would be the
// shape OBS50 measured, where a duplicated rule quietly disarmed three existing
// mutation entries by making each of them ambiguous.
//
// A NIL RULE REFUSES EVERYTHING, the same direction every other port in this
// program chose: a forgotten wire must read as a program that cannot reach
// anything, never as one with no restrictions.
func Shake(mayReach func(address string) error) core.Shake {
	return func(ctx context.Context, address string, port int, serverName string) (core.Presented, error) {
		target, err := permitted(mayReach, address, port)
		if err != nil {
			return core.Presented{}, err
		}

		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			// NOT DIAGNOSED HERE. L3 has already tried this address and reported
			// why it would not open, and naming the reason again would count one
			// fault twice in a report a person reads top to bottom.
			return core.Presented{}, core.ErrNotReached
		}
		// The connection is closed whatever happens next. Nothing is ever sent
		// over it beyond the handshake itself.
		defer conn.Close()

		return negotiate(ctx, conn, serverName)
	}
}

// permitted answers with the string to dial, or with the refusal.
//
// It is separate so that every way of saying no arrives as one sentinel. The
// layer above tells "we were not allowed to try" apart from every network
// failure, and a refusal carrying a network error inside it invites the two to
// be confused.
func permitted(mayReach func(address string) error, address string, port int) (string, error) {
	if mayReach == nil {
		return "", core.ErrRefusedByRule
	}
	target, err := tcp.Target(address, port)
	if err != nil {
		return "", core.ErrRefusedByRule
	}
	if err := mayReach(target); err != nil {
		return "", core.ErrRefusedByRule
	}
	return target, nil
}

// negotiate completes the handshake on an open connection and reports what the
// server presented.
func negotiate(ctx context.Context, conn net.Conn, serverName string) (core.Presented, error) {
	// requested is written by the callback below and read after the handshake
	// returns. The callback runs on the handshake's own call path, in this
	// goroutine, so nothing here is shared between goroutines - the fan-out gives
	// every address its own call and its own closure.
	requested := false
	// read is set by the library itself once it has read every certificate the
	// server sent and accepted them - the hook below runs only then, after the
	// parse in verifyServerCertificate (go1.27.3). Written and read on this
	// goroutine, like requested.
	read := false

	client := tls.Client(conn, &tls.Config{
		// THE NAME IS SENT SEPARATELY FROM THE ADDRESS AND THAT IS THE POINT OF
		// TLS. SNI decides which certificate a virtual host chooses; the address
		// decides where the packets go. Sending the address as the name would ask
		// for a certificate nobody issued, and the failure would look exactly like
		// a misconfigured server.
		ServerName: serverName,

		// THE CERTIFICATE IS NOT VERIFIED HERE, ON PURPOSE, AND THIS IS ADR46.
		// DO NOT "FIX" THIS.
		//
		// With ordinary verification a broken chain aborts the handshake and NOT
		// ONE CERTIFICATE IS LEFT TO SHOW - and the evidence is this product,
		// not a decoration on it. A tool that says "the handshake failed" instead
		// of "the server presented one certificate and did not send its issuer"
		// diagnoses nothing a browser has not already said.
		//
		// WHAT THIS DOES NOT DO: trust anything. L4's verdict is STRUCTURAL and
		// reads only the bytes that arrived. Whether this machine trusts them is
		// one answer per runtime and belongs to L5. Nothing is sent over this
		// connection, which is closed as soon as the handshake finishes.
		//
		// A guard refuses this field in every other file of this program.
		InsecureSkipVerify: true,

		// PINNED TO WHAT THE LIBRARY DOES TODAY, SO THAT A VERDICT NEVER CHANGES
		// BECAUSE A TOOLCHAIN DID. Leaving this unset takes crypto/tls's own
		// client default, which is TLS 1.2 now and is a number the standard
		// library is free to raise - and the day it does, servers this tool
		// reported on last week would come back as servers that refuse a
		// handshake, with nothing in this repository having changed. That is the
		// same argument the toolchain line in go.mod already carries.
		//
		// WHAT IT DELIBERATELY DOES NOT DO, WRITTEN DOWN BECAUSE IT IS A REAL
		// DIAGNOSTIC GAP: a server speaking only TLS 1.0 or 1.1 - an internal
		// appliance, which is exactly the machine this tool is for - is refused
		// by US. Since ADR129 the row says so when the server answers with its
		// old version: our own library ended the handshake, in its own words,
		// and the layer says it cannot tell whether another client would
		// complete it. Answering that properly means trying again at a lower
		// floor and reporting the old version as the finding, which is a new
		// behaviour and a new sentence rather than a constant. Open question O10
		// is the other half of it: a real 1.0 server usually offers only cipher
		// suites Go has removed, so the version alone would not settle the retry.
		MinVersion: tls.VersionTLS12,

		NextProtos: alpn,

		// The server asking us to authenticate is one of the commonest causes of
		// "works in the browser, fails in the tool", and it is invisible from a
		// browser that already holds a certificate. An empty Certificate means we
		// send none, which is the truth: this program holds no client identity
		// and must never present one.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			requested = true
			return &tls.Certificate{}, nil
		},

		// IT RECORDS AND NEVER REFUSES - this is not verification coming back
		// in through a side door. With InsecureSkipVerify the library hands it
		// no verified chains, and it answers nil whatever arrives. What it says
		// is WHERE a failed handshake stopped: past this point the library had
		// read the server's certificates, so a failure after it is about what
		// the server did next - ADR129.
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
			read = true
			return nil
		},
	})

	if err := client.HandshakeContext(ctx); err != nil {
		return core.Presented{}, failure(err, read)
	}
	return presented(client.ConnectionState(), serverName, requested), nil
}

// presented carries what the standard library established into our own record.
//
// BOTH NAMES COME FROM THE STANDARD LIBRARY AND NEVER FROM A TABLE OF OURS.
// A hand-kept table of version and cipher names is a claim about somebody else's
// registry that nothing keeps current - the class of mistake inviolable rule 18
// exists for. Both functions return a readable rendering of the raw number when
// they do not recognise it, so an unknown suite is reported as itself rather
// than as a blank.
func presented(state tls.ConnectionState, serverName string, requested bool) core.Presented {
	return core.Presented{
		Completed:                  true,
		Version:                    tls.VersionName(state.Version),
		CipherSuite:                state.CipherSuite,
		CipherSuiteName:            tls.CipherSuiteName(state.CipherSuite),
		Protocol:                   state.NegotiatedProtocol,
		ServerName:                 serverName,
		ClientCertificateRequested: requested,
		// EXACTLY WHAT THE SERVER SENT, leaf first, and never what a verifier
		// would have built. The gap between those two IS the diagnosis in the
		// commonest real misconfiguration there is.
		Chain: certificates(state.PeerCertificates),
		// THE SAME LEAF THE CHAIN STARTS WITH, asked here because the parsed
		// certificate is here - the core only ever sees the summary.
		Name: nameMatch(state.PeerCertificates, serverName),
	}
}

// failure maps whatever went wrong onto the layer's sentinels.
//
// BY ERROR VALUE, NEVER BY MESSAGE TEXT - inviolable rule 19. The same rule the
// connection adapter one layer down follows, and for the same measured reason: a
// localised system or a reworded error stops matching silently, and the layer
// then reports a wrong diagnosis that looks exactly like a right one.
//
// THE DEFAULT IS "the server would not complete a handshake" rather than any
// sharper claim. An unanticipated failure must not be reported as a timeout,
// because a timeout sends a person to look at their firewall.
//
// THE ONE EXCEPTION IS A FAILURE OUR OWN LIBRARY MADE BEFORE IT HAD READ THE
// SERVER'S CERTIFICATES - ADR129. read says whether it got that far, and
// endedHere whether anything from the other side or the wire is in the error.
func failure(err error, read bool) error {
	var timeout net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return core.ErrTimeout
	case errors.As(err, &timeout) && timeout.Timeout():
		return core.ErrTimeout
	case !read && endedHere(err):
		return core.EndedHere{Words: bounded(err.Error())}
	}
	return core.ErrRejected
}

// endedHere says the error carries nothing that came from the server or from
// the wire, so the library ended the handshake by its own decision.
//
// DECIDED BY THE SHAPE OF THE ERROR, NEVER BY ITS TEXT - inviolable rule 19.
// Read in src/crypto/tls of go1.27.3: an alert the server sent arrives as a
// *net.OpError, and so does an alert the library sends when the server's message
// is malformed or out of order - both a fact about the server. A connection the
// server closed arrives as io.EOF or io.ErrUnexpectedEOF, and something that is
// not TLS at all as a RecordHeaderError. What the library refuses for reasons of
// its own - a certificate it cannot read, a version below our floor, a key it
// will not use - it reports with a bare errors.New, and that is the only shape
// left.
//
// THE DIRECTION OF A MISTAKE IS SAFE. A future library wrapping a server's
// refusal in a new shape turns a FAIL into an UNKNOWN, never into a PASS - and
// the test with a certificate Go cannot read catches the opposite drift.
func endedHere(err error) bool {
	var op *net.OpError
	var header tls.RecordHeaderError
	return !errors.As(err, &op) && !errors.As(err, &header) &&
		!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)
}

// wordsLimit is how much of the library's own words a row may quote.
//
// A CEILING, BECAUSE THE SERVER CHOSE SOME OF THEM. crypto/x509 quotes a field
// it could not parse - a URI from the subjectAltName, for one - and a server
// may send a certificate message of hundreds of kilobytes, so without it one
// row could carry all of that onto the top line of the report.
const wordsLimit = 240

// bounded cuts the library's words at wordsLimit bytes, on a character
// boundary, and says it did.
func bounded(words string) string {
	if len(words) <= wordsLimit {
		return words
	}
	cut := wordsLimit
	for cut > 0 && !utf8.RuneStart(words[cut]) {
		cut--
	}
	return words[:cut] + "..."
}
