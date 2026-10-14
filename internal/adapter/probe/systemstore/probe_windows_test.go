//go:build windows

package systemstore

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// These tests ask the REAL crypt32 on the machine running them, about chains
// generated in memory - so they need no network and change no store. What they
// pin is the measurement of 2026-10-14 that judge.go is built on: which bits
// Windows reports, with the network switched off, for the shapes judge weighs.

// TestWindowsReportsTheBitsJudgeIsBuiltOn asks both engines.
func TestWindowsReportsTheBitsJudgeIsBuiltOn(t *testing.T) {
	now := time.Now()
	root := anAuthorityValid(t, "certdoctor test root", now.Add(-72*time.Hour), now.Add(24*time.Hour))
	fresh := leafOptions{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}
	leaf := aLeaf(t, root, fresh)
	withAddress := aLeaf(t, root, leafOptions{notBefore: fresh.notBefore, notAfter: fresh.notAfter,
		issuerAddress: []string{"http://127.0.0.1:9/never-fetched.crt"}})
	expired := aLeaf(t, root, leafOptions{notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)})

	cases := []struct {
		name  string
		chain [][]byte
		want  uint32
	}{
		{"the authority was not sent", [][]byte{leaf.Raw}, partialChain},
		// The address in the certificate is never tried - noNetwork - so the
		// answer is the same partial chain, not a fetched issuer or a timeout.
		{"the certificate names its issuer's address", [][]byte{withAddress.Raw}, partialChain},
		{"the server sent a root nobody installed", [][]byte{leaf.Raw, root.certificate.Raw}, untrustedRoot},
		{"the leaf is out of date", [][]byte{expired.Raw, root.certificate.Raw}, notTimeValid | untrustedRoot},
	}
	for _, e := range engines {
		for _, c := range cases {
			t.Run(e.instance+"/"+c.name, func(t *testing.T) {
				b, err := build(e.engine, c.chain, now)
				if err != nil {
					t.Fatalf("Windows could not build the chain: %v", err)
				}
				if b.status != c.want {
					t.Errorf("status 0x%08X, want 0x%08X", b.status, c.want)
				}
				if len(b.elements) == 0 {
					t.Fatal("no element came back, so judge would have nothing to weigh")
				}
				if got := b.elements[0].der; string(got) != string(c.chain[0]) {
					t.Error("the first element is not the leaf that was presented")
				}
			})
		}
	}
}

// TestTheIssuerAddressInACertificateIsNeverFetched is inviolable rule 16 in the
// one place crypt32 would break it - ADR101. The address is written into the
// certificate by the server under diagnosis, so this serves the issuer at it and
// counts: one request is this program connecting where a server pointed.
//
// THE ISSUER IS REALLY THERE, so a fetch would also change the answer - the
// chain would reach the root and report it untrusted instead of partial. Two
// witnesses, because a server that was asked and failed to answer would leave
// the status alone.
func TestTheIssuerAddressInACertificateIsNeverFetched(t *testing.T) {
	now := time.Now()
	root := anAuthorityValid(t, "certdoctor test root", now.Add(-time.Hour), now.Add(24*time.Hour))
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(root.certificate.Raw)
	}))
	defer server.Close()
	leaf := aLeaf(t, root, leafOptions{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
		issuerAddress: []string{server.URL + "/issuer.crt"}})

	for _, e := range engines {
		b, err := build(e.engine, [][]byte{leaf.Raw}, now)
		if err != nil {
			t.Fatal(err)
		}
		if b.status != partialChain {
			t.Errorf("%s: status 0x%08X, want a partial chain - the issuer was found somewhere it should not have been looked for", e.instance, b.status)
		}
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("the address a certificate named was fetched %d time(s) - a connection the user never pointed at", n)
	}
}

// TestAnUndeterminedRowCarriesNoCount is the contract's rule that a count
// travels only with a verdict, through the whole probe rather than judge alone -
// the count is attached in storeFor, after judge has answered.
func TestAnUndeterminedRowCarriesNoCount(t *testing.T) {
	now := time.Now()
	root := anAuthorityValid(t, "certdoctor test root", now.Add(-time.Hour), now.Add(24*time.Hour))
	leaf := aLeaf(t, root, leafOptions{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
		issuerAddress: []string{"http://127.0.0.1:9/never-fetched.crt"}})

	stores, err := Probe(func() time.Time { return now })(context.Background(), [][]byte{leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range stores {
		if store.TrustsPresentedChain != nil || store.NotAssessed == "" {
			t.Fatalf("%s: a certificate naming its issuer's address was answered: %+v", store.Instance, store)
		}
		finding := report.Finding{Kind: report.FindingTrustStore, Summary: "a row", Source: report.SourceDetected, TrustStore: &store}
		if broken := finding.Breach(); broken != "" {
			t.Errorf("%s: the contract refuses the row: %s", store.Instance, broken)
		}
	}
}

// TestTheClockThisProbeIsHandedIsTheOneWindowsUses is pTime. A leaf valid only
// in the past is accepted as time-valid when the probe is handed that past -
// so "expired" in this row is decided by the same clock as every other row.
func TestTheClockThisProbeIsHandedIsTheOneWindowsUses(t *testing.T) {
	then := time.Now().Add(-30 * 24 * time.Hour)
	// The root spans both moments, so the leaf is the only thing that changes.
	root := anAuthorityValid(t, "certdoctor test root", then.Add(-24*time.Hour), time.Now().Add(24*time.Hour))
	leaf := aLeaf(t, root, leafOptions{notBefore: then.Add(-time.Hour), notAfter: then.Add(time.Hour)})
	chain := [][]byte{leaf.Raw, root.certificate.Raw}

	past, err := build(engineCurrentUser, chain, then)
	if err != nil {
		t.Fatal(err)
	}
	if past.status&notTimeValid != 0 {
		t.Errorf("at the moment the leaf was valid, Windows still called it out of date: 0x%08X", past.status)
	}
	present, err := build(engineCurrentUser, chain, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if present.status&notTimeValid == 0 {
		t.Errorf("today, a leaf that expired a month ago was not out of date: 0x%08X", present.status)
	}
}

// TestARootThisMachineHoldsIsTrusted is the positive path through the real
// library: a root from this machine's own store, presented as its own chain.
// Without it every test above passes on a build that never says "trusted".
func TestARootThisMachineHoldsIsTrusted(t *testing.T) {
	now := time.Now()
	for _, der := range rootsIn(t, storeLocalMachine) {
		certificate, err := x509.ParseCertificate(der)
		if err != nil || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			continue
		}
		b, err := build(engineLocalMachine, [][]byte{der}, now)
		if err != nil {
			t.Fatal(err)
		}
		if b.status == 0 {
			return
		}
	}
	t.Error("not one root in this machine's own store came back trusted, so the trusted branch was never reached")
}

// TestBothRootStoresCanBeCounted is the count the rows carry.
func TestBothRootStoresCanBeCounted(t *testing.T) {
	for _, e := range engines {
		count, err := countAnchors(e.location)
		if err != nil {
			t.Fatalf("%s: %v", e.instance, err)
		}
		if count == 0 {
			t.Errorf("%s: the Root store counted empty, and a Windows machine always ships roots", e.instance)
		}
		if want := len(rootsIn(t, e.location)); count > want {
			t.Errorf("%s: %d anchors counted from %d certificates enumerated", e.instance, count, want)
		}
	}
}

// TestThisMachinesProgramListIsRead is the parser against the value Windows
// actually wrote. A machine that never synchronised has no list, and that is
// skipped aloud rather than passed in silence.
func TestThisMachinesProgramListIsRead(t *testing.T) {
	list := readProgramList()
	if !list.available() {
		t.Skipf("this machine has no readable program list, so the parser was not tried against a real one: %s", list.unreadable)
	}
	if len(list.subjects) < 100 || len(list.keys) == 0 || len(list.names) == 0 {
		t.Errorf("the list read as %d roots, %d keys and %d names - measured here 2026-10-13: 562, 553 and 549",
			len(list.subjects), len(list.keys), len(list.names))
	}
	if list.synced.IsZero() {
		t.Error("the list carries no synchronisation date")
	}
	// Every root this machine holds from the program is on the list by its own
	// fingerprint - measured 78 of 90 on 2026-10-13, the rest being Microsoft's
	// own and the enterprise ones.
	found := 0
	for _, der := range rootsIn(t, storeLocalMachine) {
		if list.holdsRoot(der) {
			found++
		}
	}
	if found == 0 {
		t.Error("not one root in this machine's store is on its own program list, so the fingerprint lookup reads nothing")
	}
}

// TestTheProbeWritesTwoRowsTheContractAccepts is the whole probe, end to end,
// against an authority nobody installed - the product's main scenario.
func TestTheProbeWritesTwoRowsTheContractAccepts(t *testing.T) {
	now := time.Now()
	root := anAuthorityValid(t, "certdoctor test root", now.Add(-time.Hour), now.Add(24*time.Hour))
	leaf := aLeaf(t, root, leafOptions{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)})

	stores, err := Probe(func() time.Time { return now })(context.Background(), [][]byte{leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(stores) != 2 || stores[0].Instance != report.InstanceCurrentUser || stores[1].Instance != report.InstanceLocalMachine {
		t.Fatalf("rows %+v, want CurrentUser then LocalMachine", stores)
	}
	listFit := readProgramList().cannotRuleOut(now) == ""
	for _, store := range stores {
		finding := report.Finding{Kind: report.FindingTrustStore, Summary: "a row", Source: report.SourceDetected, TrustStore: &store}
		if broken := finding.Breach(); broken != "" {
			t.Errorf("%s: the contract refuses the row: %s", store.Instance, broken)
		}
		refused := store.TrustsPresentedChain != nil && !*store.TrustsPresentedChain &&
			store.TrustFailure == report.UnknownAuthority
		if listFit && !refused {
			t.Errorf("%s: with a list fit to rule it out, an authority nobody installed was not refused: %+v", store.Instance, store)
		}
		if !listFit && store.NotAssessed == "" {
			t.Errorf("%s: with no list fit to rule it out, the row still claims an answer: %+v", store.Instance, store)
		}
	}
}

// TestACancelledRunAsksNothing is the one check the probe makes before crypt32,
// which cannot be interrupted once called.
func TestACancelledRunAsksNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stores, err := Probe(time.Now)(ctx, [][]byte{{1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range stores {
		if store.TrustsPresentedChain != nil || store.NotAssessed == "" {
			t.Errorf("%s: a cancelled run still answered: %+v", store.Instance, store)
		}
	}
}

// rootsIn enumerates one location's logical Root store, for the tests above to
// pick from. It is a test helper on purpose - the probe only ever counts.
func rootsIn(t *testing.T, location uint32) [][]byte {
	t.Helper()
	name, _ := syscall.UTF16PtrFromString("Root")
	store, err := syscall.CertOpenStore(storeProviderSystem, 0, 0, location|storeOpenExisting|storeReadOnly, uintptr(unsafe.Pointer(name)))
	if err != nil {
		t.Fatalf("the Root store could not be opened: %v", err)
	}
	defer func() { _ = syscall.CertCloseStore(store, 0) }()
	var out [][]byte
	var certificate *syscall.CertContext
	for {
		certificate, _ = syscall.CertEnumCertificatesInStore(store, certificate)
		if certificate == nil {
			return out
		}
		out = append(out, append([]byte(nil), unsafe.Slice(certificate.EncodedCert, certificate.Length)...))
	}
}
