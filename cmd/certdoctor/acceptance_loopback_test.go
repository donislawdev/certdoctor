//go:build acceptance

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// aLoopbackTarget starts a TLS server on this machine's loopback interface and
// returns its URL, for every check whose question needs no internet.
//
// WHY THESE CHECKS STOPPED USING A REAL NAME - OBS150, measured 2026-09-23.
// Seventeen checks about files, pipes, pages and colour ran against example.com
// and asked for one exact exit code, without asking whether a network was
// there. Three runs in a row gave three different sets of failures, each a code
// 4 where 5 was wanted after about ten seconds, while the binary run by hand
// gave 5 every time. Their questions never involved the internet - they were
// handed it as a dependency nobody declared, and red stopped meaning anything.
//
// WHY TLS AND NOT A PLAIN PORT. A target without TLS stops the run after L3
// (ADR100), so L4 and L5 never run. The file census would then stop watching
// the trust store probes, which start other programs, and the pages would carry
// no chain and no matrix to render. That would be a quieter guard dressed as a
// more reliable one.
//
// THE CHAIN IS INCOMPLETE ON PURPOSE, AND THAT IS WHAT MAKES THE EXIT CODE THE
// SAME ON EVERY MACHINE. The leaf is signed by an authority minted here, never
// sent and never stored anywhere, so L4 fails on a fact about the server - the
// issuer was not sent - whatever stores the machine has. A complete chain would
// leave the code to L5, which answers FAIL where a store exists and UNKNOWN
// where none does, and the code would again depend on the machine.
//
// The server answers every connection until the test ends, because one check
// may start the program several times and each run connects more than once.
func aLoopbackTarget(t *testing.T) string {
	t.Helper()

	authority := mintForLoopback(t, nil)
	leaf := mintForLoopback(t, &authority)
	config := &tls.Config{
		// The leaf alone. Sending the authority too would make the chain
		// complete and hand the exit code back to whatever stores exist here.
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.der}, PrivateKey: leaf.key}},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("no loopback port to listen on: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Far shorter than the default probe timeout, so the run is
				// never the side that gives up first. The error is dropped on
				// purpose - L3 connects and leaves without a handshake, and that
				// is a normal visit rather than a fault.
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	return fmt.Sprintf("https://%s/", listener.Addr().String())
}

// aPortNobodyListensOn returns a loopback address with nothing behind it.
//
// It is where a check points a proxy it needs to be NAMED rather than used.
// L2 asks every proxy it finds whether it wants credentials, and a proxy under
// a documentation name sent that question to a resolver somewhere - the same
// undeclared network OBS150 is about. Here the question is refused at once
// and nothing leaves the machine.
//
// The port was free a moment ago and is closed now. Something else could take
// it in between, and then L2 asks that instead - which changes nothing any
// check here looks at.
func aPortNobodyListensOn(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("no loopback port to borrow: %v", err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

// loopbackCertificate is one certificate minted for aLoopbackTarget, with what
// it takes to sign the next one.
type loopbackCertificate struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// mintForLoopback makes the authority when parent is nil, and a leaf for
// 127.0.0.1 signed by parent otherwise.
//
// THE LEAF NAMES THE ADDRESS IT IS SERVED ON, so the only thing wrong with this
// server is the issuer it does not send. A name mismatch on top of that would
// be a second fault, and a change to how L4 grades names could then move the
// exit code for a reason no check here is about.
func mintForLoopback(t *testing.T, parent *loopbackCertificate) loopbackCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certdoctor acceptance authority", Organization: []string{"certdoctor test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	signer, signerKey := template, key
	if parent != nil {
		template.SerialNumber = big.NewInt(2)
		template.Subject.CommonName = "certdoctor acceptance loopback"
		template.IsCA = false
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		signer, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("signing %s: %v", template.Subject.CommonName, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("reading back %s: %v", template.Subject.CommonName, err)
	}
	return loopbackCertificate{der: der, cert: parsed, key: key}
}
