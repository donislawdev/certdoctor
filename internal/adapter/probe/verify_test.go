package probe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// anchorAndLeaf mints a tiny chain so verification is exercised without a
// network and without a fixture nobody can regenerate.
func anchorAndLeaf(t *testing.T) (anchorPEM, leafDER []byte) {
	t.Helper()

	anchorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certdoctor test anchor"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	anchorDER, err := x509.CreateCertificate(rand.Reader, template, template, &anchorKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatalf("no anchor: %v", err)
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		t.Fatalf("anchor will not parse: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no leaf key: %v", err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "partner.test"},
		DNSNames:     []string{"partner.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leaf, anchor, &leafKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatalf("no leaf: %v", err)
	}

	var bundle bytes.Buffer
	if err := pem.Encode(&bundle, &pem.Block{Type: "CERTIFICATE", Bytes: anchorDER}); err != nil {
		t.Fatalf("no bundle: %v", err)
	}
	return bundle.Bytes(), leafDER
}

func TestAStoreHoldingTheIssuingAnchorTrustsTheChain(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, anchorPEM, [][]byte{leafDER})

	if store.TrustsPresentedChain == nil {
		t.Fatalf("no verdict: %s", store.NotAssessed)
	}
	if !*store.TrustsPresentedChain {
		t.Error("a store holding the issuing anchor did not trust the chain")
	}
	if store.TrustAnchorCount != 1 {
		t.Errorf("counted %d anchors, want 1", store.TrustAnchorCount)
	}
}

// DISTRUST IS A VERDICT, NOT A FAILURE. It is the answer the whole matrix exists
// to produce, and it must never be confused with "could not be read".
func TestAStoreWithoutTheAnchorDistrustsRatherThanFails(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	otherAnchor, _ := anchorAndLeaf(t)

	var store report.TrustStore
	Verify(&store, otherAnchor, [][]byte{leafDER})

	if store.TrustsPresentedChain == nil {
		t.Fatalf("distrust came back as unassessed: %s", store.NotAssessed)
	}
	if *store.TrustsPresentedChain {
		t.Error("a store holding an unrelated anchor trusted the chain")
	}
	if store.NotAssessed != "" {
		t.Errorf("a verdict was reached and a reason was given too: %q", store.NotAssessed)
	}
}

// A STORE WITH NOTHING READABLE IN IT IS UNKNOWN, NEVER DISTRUST. "There are no
// anchors here" is a fact about the store, not about the chain.
func TestAStoreWithNoReadableAnchorIsUnassessed(t *testing.T) {
	var store report.TrustStore
	Verify(&store, []byte("not a certificate at all"), [][]byte{{0x30}})

	if store.TrustsPresentedChain != nil {
		t.Error("an unreadable store produced a verdict about trust")
	}
	if !strings.Contains(store.NotAssessed, "no certificate") {
		t.Errorf("the reason does not say what was missing: %q", store.NotAssessed)
	}
}

// ONE BROKEN ENTRY IN SOMEBODY'S STORE IS NOT A REASON TO DISCARD THE REST.
func TestAStoreSurvivesOneUnparsableEntry(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	var junk bytes.Buffer
	_ = pem.Encode(&junk, &pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	_ = pem.Encode(&junk, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte{4, 5, 6}})

	var store report.TrustStore
	Verify(&store, append(junk.Bytes(), anchorPEM...), [][]byte{leafDER})

	if store.TrustAnchorCount != 1 {
		t.Errorf("counted %d anchors beside the junk, want 1", store.TrustAnchorCount)
	}
	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		t.Errorf("the good anchor was lost with the bad one: %+v", store)
	}
}

// NO CHAIN MEANS NOTHING TO JUDGE, and the anchor count goes back to zero
// because counting anchors in a store nobody asked about reads as a measurement.
func TestNoChainMeansNothingToJudge(t *testing.T) {
	anchorPEM, _ := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, anchorPEM, nil)

	if store.TrustsPresentedChain != nil {
		t.Error("a verdict was produced with no chain to judge")
	}
	if store.TrustAnchorCount != 0 {
		t.Errorf("anchors were counted for a question nobody asked: %d", store.TrustAnchorCount)
	}
}

func TestAnUnparsableLeafIsUnassessed(t *testing.T) {
	anchorPEM, _ := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, anchorPEM, [][]byte{{0x00, 0x01}})

	if store.TrustsPresentedChain != nil || store.NotAssessed == "" {
		t.Errorf("an unparsable leaf did not come back unassessed: %+v", store)
	}
}
