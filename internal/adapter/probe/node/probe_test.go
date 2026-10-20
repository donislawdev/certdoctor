package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

func atNoon() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }

// mint makes one certificate under parent, or a self-signed one when parent is
// nil - the three shapes these tests need and nothing more.
func mint(t *testing.T, name string, serial int64, parentDER []byte, parentKey *ecdsa.PrivateKey, isCA bool) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: atNoon().Add(-time.Hour), NotAfter: atNoon().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	if !isCA {
		template.DNSNames = []string{name}
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	parent, signer := template, key
	if parentDER != nil {
		issuer, err := x509.ParseCertificate(parentDER)
		if err != nil {
			t.Fatalf("no issuer: %v", err)
		}
		parent, signer = issuer, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("no certificate: %v", err)
	}
	return der, key
}

// bench is one root, the intermediate under it, a leaf under that, and a root
// that signed none of them - the shape of the S27 bench.
type bench struct{ root, inter, leaf, other []byte }

func newBench(t *testing.T) bench {
	rootDER, rootKey := mint(t, "certdoctor test root", 1, nil, nil, true)
	interDER, interKey := mint(t, "certdoctor test intermediate", 2, rootDER, rootKey, true)
	leafDER, _ := mint(t, "partner.test", 3, interDER, interKey, false)
	otherDER, _ := mint(t, "certdoctor unrelated root", 4, nil, nil, true)
	return bench{root: rootDER, inter: interDER, leaf: leafDER, other: otherDER}
}

func pemOf(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// answerOf is what the script would print for these three lists.
func answerOf(t *testing.T, version string, trusted, system, extra [][]byte) string {
	t.Helper()
	a := answer{Node: version, Lists: &lists{Default: []int{}, System: []int{}, Extra: []int{}}, PEM: []string{}}
	at := func(der []byte) int {
		if i := slices.Index(a.PEM, pemOf(der)); i >= 0 {
			return i
		}
		a.PEM = append(a.PEM, pemOf(der))
		return len(a.PEM) - 1
	}
	for _, der := range trusted {
		a.Lists.Default = append(a.Lists.Default, at(der))
	}
	for _, der := range system {
		a.Lists.System = append(a.Lists.System, at(der))
	}
	for _, der := range extra {
		a.Lists.Extra = append(a.Lists.Extra, at(der))
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	return string(raw)
}

// call is one run the probe asked for.
type call struct {
	binary string
	args   []string
}

// replying is a runner that answers every run with out and err, and records it.
func replying(out probe.Output, err error, calls *[]call) probe.Runner {
	return func(_ context.Context, binary string, args ...string) (probe.Output, error) {
		*calls = append(*calls, call{binary: binary, args: args})
		return out, err
	}
}

// starting hands back run whatever is withheld, and records what was.
func starting(run probe.Runner, asked *[]string) func(...string) probe.Runner {
	return func(names ...string) probe.Runner {
		*asked = append(*asked, names...)
		return run
	}
}

func sourceOf(paths ...string) func(string) (io.ReadCloser, error) {
	return func(path string) (io.ReadCloser, error) {
		if !slices.Contains(paths, filepath.Clean(path)) {
			return nil, errors.New("no such file")
		}
		return io.NopCloser(strings.NewReader("binary")), nil
	}
}

var (
	firstDir   = filepath.FromSlash("/opt/node/bin")
	secondDir  = filepath.FromSlash("/usr/bin")
	firstNode  = filepath.Join(firstDir, "node")
	secondNode = filepath.Join(secondDir, "node")
)

// rowsFor runs the probe over one node on PATH with this reply and environment.
func rowsFor(t *testing.T, out probe.Output, err error, env Environment, chain [][]byte) ([]report.TrustStore, []call) {
	t.Helper()
	var calls []call
	var asked []string
	stores, probeErr := Probe(sourceOf(firstNode), nil, starting(replying(out, err, &calls), &asked),
		[]string{firstDir}, env, atNoon)(context.Background(), chain)
	if probeErr != nil {
		t.Fatalf("the probe failed: %v", probeErr)
	}
	if len(stores) != 1 {
		t.Fatalf("got %d rows for one node, want 1", len(stores))
	}
	if broken := (report.Finding{Kind: report.FindingTrustStore, Summary: "one row", Source: report.SourceDetected,
		TrustStore: &stores[0]}).Breach(); broken != "" {
		t.Fatalf("the row breaks the contract: %s", broken)
	}
	return stores, calls
}

// EVERY node ON PATH IS A ROW - ADR111 part 1, the rule git keeps in ADR74.
func TestEveryNodeOnPathIsARow(t *testing.T) {
	b := newBench(t)
	var calls []call
	var asked []string
	run := replying(probe.Output{Stdout: answerOf(t, "v26.9.0", [][]byte{b.root}, nil, nil)}, nil, &calls)
	stores, err := Probe(sourceOf(firstNode, secondNode), nil, starting(run, &asked), []string{firstDir, secondDir},
		Environment{}, atNoon)(context.Background(), [][]byte{b.leaf, b.inter})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if len(stores) != 2 || stores[0].Instance != firstNode || stores[1].Instance != secondNode {
		t.Fatalf("rows %+v, want one for each node in PATH order", stores)
	}
	if len(calls) != 2 || calls[0].binary != firstNode || calls[1].binary != secondNode {
		t.Errorf("asked %+v, want each binary once", calls)
	}
}

// NO node IS NO ROW, NOT A FAILURE - docs/20 rule 1.
func TestNoNodeIsNoRow(t *testing.T) {
	var asked []string
	stores, err := Probe(sourceOf(), nil, starting(nil, &asked), []string{firstDir}, Environment{}, atNoon)(
		context.Background(), nil)
	if stores != nil || err != nil {
		t.Errorf("a machine without node gave %v, %v", stores, err)
	}
}

// THE PROCESS STARTS WITHOUT EXACTLY THE FIVE VARIABLES ADR111 part 2 AND OBS188
// NAME, and its arguments are the CA flags read out of NODE_OPTIONS and the
// constant script - never NODE_OPTIONS itself, whose --require would run
// somebody's code, nor OPENSSL_CONF, whose provider module would.
func TestNodeStartsWithoutTheNamedVariablesAndWithOnlyItsCAFlags(t *testing.T) {
	b := newBench(t)
	var calls []call
	var asked []string
	run := replying(probe.Output{Stdout: answerOf(t, "v26.9.0", [][]byte{b.root}, nil, nil)}, nil, &calls)
	env := Environment{Options: `--max-old-space-size=100 --use_system_ca --require "./x.js"`}
	if _, err := Probe(sourceOf(firstNode), nil, starting(run, &asked), []string{firstDir}, env, atNoon)(
		context.Background(), [][]byte{b.leaf, b.inter}); err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if want := []string{"NODE_OPTIONS", "NODE_V8_COVERAGE", "NODE_REDIRECT_WARNINGS", "NODE_COMPILE_CACHE", "OPENSSL_CONF"}; !slices.Equal(asked, want) {
		t.Errorf("withheld %q, want %q", asked, want)
	}
	if want := []string{"--use-system-ca", "-e", script}; len(calls) != 1 || !slices.Equal(calls[0].args, want) {
		t.Errorf("ran with %q, want the CA flag and the script alone", calls)
	}
}

// A CHAIN UNDER A ROOT NODE HOLDS IS TRUSTED, and the row says what it is: the
// list compiled into this binary, with no path - ADR111 part 4. The root is on
// the list twice, as Node's own list repeats what several sources hold, and is
// counted once.
func TestAChainUnderARootNodeHoldsIsTrusted(t *testing.T) {
	b := newBench(t)
	stores, _ := rowsFor(t, probe.Output{Stdout: answerOf(t, "v26.9.0", [][]byte{b.other, b.root, b.root}, nil, nil)}, nil,
		Environment{}, [][]byte{b.leaf, b.inter})
	store := stores[0]
	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		t.Fatalf("refused: %s %s", store.NotAssessed, store.TrustFailure)
	}
	if store.Runtime != "node" || store.StoreForm != report.StoreBuiltin || store.StorePath != "" || store.TrustAnchorCount != 2 {
		t.Errorf("the row is %+v", store)
	}
	if !slices.Equal(store.SelectedBy, []string{"PATH"}) {
		t.Errorf("selected by %q, want PATH alone", store.SelectedBy)
	}
}

// THE INTERMEDIATE IN NODE'S LIST ENDS NO CHAIN - S27, at the level of the row.
// Judged with every entry a root, this row would say the opposite.
func TestAnIntermediateInNodesListEndsNoChain(t *testing.T) {
	b := newBench(t)
	stores, _ := rowsFor(t, probe.Output{Stdout: answerOf(t, "v26.9.0", [][]byte{b.other, b.inter}, nil, [][]byte{b.inter})},
		nil, Environment{}, [][]byte{b.leaf})
	if store := stores[0]; store.TrustsPresentedChain == nil || *store.TrustsPresentedChain ||
		store.TrustFailure != report.UnknownAuthority {
		t.Errorf("an intermediate alone ended the chain: %+v", store)
	}
}

// EVERY ROW WITHOUT A VERDICT SAYS WHY, each in its own words - ADR111 part 5.
func TestEachRowWithoutAVerdictSaysWhy(t *testing.T) {
	b := newBench(t)
	good := answerOf(t, "v26.9.0", [][]byte{b.root}, nil, nil)
	cases := []struct {
		name    string
		options string
		out     probe.Output
		err     error
		says    string
		noRun   bool
	}{
		{name: "NODE_OPTIONS Node will not start with", options: `--use-system-ca "unfinished`, says: "quoted string",
			noRun: true},
		{name: "node could not be run", err: errors.New("no such file"), says: "could not be asked"},
		{name: "a cut answer", out: probe.Output{Stdout: good, Truncated: true}, says: "more than this program keeps"},
		{name: "node refused the flags NODE_OPTIONS carries", options: "--use-system-ca", out: probe.Output{ExitCode: 9},
			says: "exited with 9 when started with --use-system-ca"},
		{name: "node refused the script", out: probe.Output{ExitCode: 1}, says: "exited with 1 when asked"},
		{name: "not JSON", out: probe.Output{Stdout: "Welcome to Node.js"}, says: "not the JSON"},
		{name: "no version", out: probe.Output{Stdout: `{"lists":null,"pem":[]}`}, says: "not the JSON"},
		{name: "a position past the end", out: probe.Output{Stdout: `{"node":"v26.9.0","lists":{"default":[3]},"pem":[]}`},
			says: "not the JSON"},
		{name: "a distribution's build", says: "NODE_OPENSSL_CERT_STORE",
			out: probe.Output{Stdout: `{"node":"v20.19.2","cert_store":true,"lists":null,"pem":[]}`}},
		{name: "a build with a system path of its own", says: "/etc/pki/tls/certs",
			out: probe.Output{Stdout: `{"node":"v26.9.0","system_ca_path":"/etc/pki/tls/certs","lists":{},"pem":[]}`}},
		{name: "a node too old to list", says: "node v20.19.2 has no tls.getCACertificates",
			out: probe.Output{Stdout: `{"node":"v20.19.2","lists":null,"pem":[]}`}},
		{name: "OpenSSL's store asked for", options: "--use-openssl-ca", out: probe.Output{Stdout: good},
			says: "--use-openssl-ca"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stores, calls := rowsFor(t, c.out, c.err, Environment{Options: c.options}, [][]byte{b.leaf, b.inter})
			store := stores[0]
			if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, c.says) {
				t.Errorf("the row is %v %q, want no verdict and a reason mentioning %q",
					store.TrustsPresentedChain, store.NotAssessed, c.says)
			}
			if c.noRun && len(calls) != 0 {
				t.Errorf("node was run %d times with options it would not start with", len(calls))
			}
		})
	}
}

// SELECTED BY NAMES WHAT THE LIST SHOWS, not what the environment says - a node
// that ignores NODE_USE_SYSTEM_CA was not changed by it.
func TestSelectedByNamesWhatTheListShows(t *testing.T) {
	b := newBench(t)
	cases := []struct {
		name    string
		env     Environment
		trusted [][]byte
		system  [][]byte
		extra   [][]byte
		want    []string
	}{
		{"the variable turned the system list on", Environment{UseSystemCA: "1"},
			[][]byte{b.other, b.root}, [][]byte{b.root}, nil, []string{"PATH", "NODE_USE_SYSTEM_CA"}},
		{"the flag turned it on", Environment{Options: "--use-system-ca", UseSystemCA: "1"},
			[][]byte{b.other, b.root}, [][]byte{b.root}, nil, []string{"PATH", "NODE_OPTIONS"}},
		{"a node that ignored the variable", Environment{UseSystemCA: "1"},
			[][]byte{b.other}, [][]byte{b.root}, nil, []string{"PATH"}},
		{"an empty system list extends nothing", Environment{UseSystemCA: "1"},
			[][]byte{b.other}, nil, nil, []string{"PATH"}},
		{"the extra file was read", Environment{},
			[][]byte{b.other, b.root}, nil, [][]byte{b.root}, []string{"PATH", "NODE_EXTRA_CA_CERTS"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stores, _ := rowsFor(t, probe.Output{Stdout: answerOf(t, "v26.9.0", c.trusted, c.system, c.extra)}, nil,
				c.env, [][]byte{b.leaf, b.inter})
			if !slices.Equal(stores[0].SelectedBy, c.want) {
				t.Errorf("selected by %q, want %q", stores[0].SelectedBy, c.want)
			}
		})
	}
}

// THE PLATFORM'S LIST CLOSES THE CHAIN ONLY WHERE NODE_USE_SYSTEM_CA=1 WOULD
// TURN IT ON - ADR111 part 7. Every case but the first is one way the command
// it selects would change nothing. The default list holds only an unrelated
// root, so each row refuses for an unknown authority unless the case says
// otherwise.
func TestThePlatformListClosesOnlyWhereTheVariableWouldTurnItOn(t *testing.T) {
	b := newBench(t)
	cases := []struct {
		name    string
		version string
		env     Environment
		trusted [][]byte
		system  [][]byte
		want    bool
	}{
		{"an unset variable on a node that reads it", "v26.9.0", Environment{}, nil, [][]byte{b.root}, true},
		{"the first v22 that reads it", "v22.19.0", Environment{}, nil, [][]byte{b.root}, true},
		{"the last v22 that does not", "v22.18.0", Environment{}, nil, [][]byte{b.root}, false},
		{"a v23, which never read it", "v23.11.1", Environment{}, nil, [][]byte{b.root}, false},
		{"the first v24 that reads it", "v24.6.0", Environment{}, nil, [][]byte{b.root}, true},
		{"the last v24 that does not", "v24.5.0", Environment{}, nil, [][]byte{b.root}, false},
		{"the first line that always read it", "v25.0.0", Environment{}, nil, [][]byte{b.root}, true},
		// A major alone would vouch for the variable, so this shows an unread
		// version is turned down rather than half read.
		{"a version this cannot read", "v25", Environment{}, nil, [][]byte{b.root}, false},
		{"the variable set to a value of somebody's", "v26.9.0", Environment{UseSystemCA: "true"}, nil,
			[][]byte{b.root}, false},
		{"an explicit off in NODE_OPTIONS, which beats the variable", "v26.9.0",
			Environment{Options: "--no-use-system-ca"}, nil, [][]byte{b.root}, false},
		{"an explicit on in NODE_OPTIONS", "v26.9.0", Environment{Options: "--use-system-ca"}, nil,
			[][]byte{b.root}, false},
		{"a system list already in effect", "v26.9.0", Environment{}, [][]byte{b.inter}, [][]byte{b.inter}, false},
		{"an empty system list", "v26.9.0", Environment{}, nil, nil, false},
		{"a system list holding only the intermediate", "v26.9.0", Environment{}, nil, [][]byte{b.inter}, false},
		// The row trusts, so the fact would select a command for a store that is
		// fine - and rowsFor checks the contract, which refuses that.
		{"a row that trusts already", "v26.9.0", Environment{}, [][]byte{b.root}, [][]byte{b.other}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trusted := append([][]byte{b.other}, c.trusted...)
			stores, _ := rowsFor(t, probe.Output{Stdout: answerOf(t, c.version, trusted, c.system, nil)}, nil, c.env,
				[][]byte{b.leaf, b.inter})
			if got := stores[0].PlatformListCloses; got != c.want {
				t.Errorf("the platform's list closes: %v, want %v (row %+v)", got, c.want, stores[0])
			}
		})
	}
}

// TestTheScriptRunsOnTheNodeThisMachineHas asks a real node the constant
// script, through the narrowed runner, and reads the answer the probe reads.
// A script whose output drifted from the struct would pass every test above.
// It is skipped where no node is on PATH.
func TestTheScriptRunsOnTheNodeThisMachineHas(t *testing.T) {
	open := func(path string) (io.ReadCloser, error) { return os.Open(path) }
	binaries := probe.Binaries(open, nil, filepath.SplitList(os.Getenv("PATH")), "node.exe", "node")
	if len(binaries) == 0 {
		t.Skip("no node on PATH, so there is nothing to ask")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, why := ask(ctx, probe.Without(withheld...), binaries[0], nil)
	if why != "" {
		t.Fatalf("%s did not answer: %s", binaries[0], why)
	}
	if !strings.HasPrefix(a.Node, "v") {
		t.Errorf("the version is %q", a.Node)
	}
	if a.Lists != nil && len(a.Lists.Default) == 0 && !a.CertStore {
		t.Errorf("%s %s listed no certificate it trusts", binaries[0], a.Node)
	}
	t.Logf("%s %s: %d certificates, cert_store %v", binaries[0], a.Node, len(a.PEM), a.CertStore)
}
