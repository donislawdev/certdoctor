package python

import (
	"crypto/x509"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// onTruststore is pip 26.2.2 with truststore, nothing named, and certifi at
// certifi - truststore having loaded OpenSSL's defaults.
func onTruststore(certifi string) *pipAnswer {
	return &pipAnswer{Version: "26.2.2", Certifi: certifi, Deprecated: []string{}, Features: []string{},
		LegacyFlags: flags(0x88020), Truststore: true, TruststoreLoads: []*string{nil}}
}

// onCertifi is pip 23.0.1, which has no truststore, on a Python whose urllib3
// sets no flags of its own.
func onCertifi(certifi string) *pipAnswer {
	return &pipAnswer{Version: "23.0.1", Certifi: certifi, Deprecated: []string{}, Features: []string{},
		LegacyFlags: flags(0x8000)}
}

// both runs the probe over one interpreter answering a, and returns its python
// row and its pip row.
func both(t *testing.T, platform string, a answer, chain [][]byte, set func(w *world)) (report.TrustStore, report.TrustStore) {
	t.Helper()
	w := newWorld(platform)
	interpreter := filepath.Join(abs("/usr/bin"), "python3")
	if platform == "windows" {
		interpreter = filepath.Join(abs("/Python314"), "python.exe")
	}
	w.path = []string{filepath.Dir(interpreter)}
	w.disk.put(interpreter, "ELF")
	w.replies[interpreter] = replyOf(t, a)
	if set != nil {
		set(w)
	}
	stores := w.rows(t, chain)
	if len(stores) != 2 {
		t.Fatalf("got %d rows for one interpreter with pip: %+v", len(stores), stores)
	}
	if stores[0].Runtime != report.RuntimePython || stores[1].Runtime != report.RuntimePip {
		t.Fatalf("the rows are %q and %q", stores[0].Runtime, stores[1].Runtime)
	}
	if stores[1].Instance != stores[0].Instance || !slices.Equal(stores[1].SelectedBy[:len(stores[0].SelectedBy)],
		stores[0].SelectedBy) {
		t.Errorf("pip is %s %v and its python %s %v", stores[1].Instance, stores[1].SelectedBy, stores[0].Instance,
			stores[0].SelectedBy)
	}
	return stores[0], stores[1]
}

// pip HAS ANOTHER RULE THAN ITS OWN INTERPRETER - ADR112 part 5, measured with
// probe S28: Python 3.13 and later end a chain at an intermediate on the list,
// and pip on the same file does not. So one machine gets two answers, and the
// pip row reads the very file the python row does, spelled the same way.
func TestPipJudgesTheSameFileByItsOwnRule(t *testing.T) {
	b := newBench(t)
	bundle, certifi := abs("/etc/ssl/certs/ca-certificates.crt"), abs("/usr/lib/python3/pip/cacert.pem")
	a := listing(0x88020, b.inter)
	a.CAFile = text(bundle)
	a.Pip = onTruststore(certifi)
	python, pip := both(t, "linux", a, b.chain(), func(w *world) {
		w.disk.put(bundle, pemOf(b.inter))
		w.disk.put(certifi, pemOf(b.other))
	})
	if got := trustOf(python); got != "trusted" {
		t.Errorf("python on 3.13 is %s", got)
	}
	if got := trustOf(pip); got != "refused unknown_authority" {
		t.Errorf("pip is %s, and its context takes no intermediate as an anchor", got)
	}
	if pip.Variant != report.PipTruststore || pip.StoreForm != report.StoreFile || pip.StorePath != bundle ||
		pip.FileEnd != report.FileEndLineBreak {
		t.Errorf("pip is %q on %s %q ending %v", pip.Variant, pip.StoreForm, pip.StorePath, pip.FileEnd)
	}

	// THE POSITIVE TWIN: the root in certifi closes it for pip and not for python.
	_, pip = both(t, "linux", a, b.chain(), func(w *world) {
		w.disk.put(bundle, pemOf(b.inter))
		w.disk.put(certifi, pemOf(b.root))
	})
	if got := trustOf(pip); got != "trusted" {
		t.Errorf("pip with the root in its certifi is %s", got)
	}

	// AND IN OpenSSL'S DIRECTORY, which truststore loads with the defaults.
	certs := abs("/usr/lib/ssl/certs")
	a.DirDefault = certs
	_, pip = both(t, "linux", a, b.chain(), func(w *world) {
		w.disk.put(bundle, pemOf(b.inter))
		w.disk.put(certifi, pemOf(b.other))
		w.disk.entry(certs, "0a1b2c3d.0", pemOf(b.root))
	})
	if got := trustOf(pip); got != "trusted" {
		t.Errorf("pip with the root in OpenSSL's directory is %s", got)
	}
}

// 24.2 IS THE FIRST pip ON TRUSTSTORE - the twin of every release before it.
func TestPip242IsTheFirstOnTruststore(t *testing.T) {
	b := newBench(t)
	certifi := abs("/pip/cacert.pem")
	a := listing(0x8000)
	a.Pip = onTruststore(certifi)
	a.Pip.Version = "24.2"
	_, pip := both(t, "linux", a, b.chain(), func(w *world) { w.disk.put(certifi, pemOf(b.root)) })
	if pip.Variant != report.PipTruststore {
		t.Errorf("pip 24.2 is on %q", pip.Variant)
	}
}

// THE FILE NAMED FOR VERIFICATION JOINS THE LIST AND BECOMES THE ROW'S FILE, and
// the name that set it is said - decided by the owner 2026-10-27.
func TestAFileNamedForVerificationJoinsTheListAndIsNamed(t *testing.T) {
	b := newBench(t)
	bundle, certifi, company := abs("/etc/ssl/certs/ca-certificates.crt"), abs("/pip/cacert.pem"), abs("/etc/company.pem")
	a := listing(0x8000)
	a.CAFile = text(bundle)
	a.Pip = onTruststore(certifi)
	a.Pip.RequestsCABundle = text(company)
	_, pip := both(t, "linux", a, b.chain(), func(w *world) {
		w.disk.put(bundle, pemOf(b.other))
		w.disk.put(certifi, pemOf(b.other))
		w.disk.put(company, pemOf(b.root))
	})
	if got := trustOf(pip); got != "trusted" {
		t.Errorf("pip with the root in REQUESTS_CA_BUNDLE is %s", got)
	}
	if pip.StorePath != company || pip.SelectedBy[len(pip.SelectedBy)-1] != report.PipRequestsCABundle {
		t.Errorf("pip reads %q, selected by %v", pip.StorePath, pip.SelectedBy)
	}
}

// ONE FILE, IN THE ORDER requests AND pip TAKE IT - REQUESTS_CA_BUNDLE, then
// CURL_CA_BUNDLE, then cert - and from 24.2 on a proxy, or --no-proxy-env, turns
// the two variables off, so cert is what is left. Before 24.2 a proxy changes
// nothing - measured with probe S28 on pip 23.0.1.
func TestTheFileForVerificationIsTakenInPipsOrder(t *testing.T) {
	cases := []struct {
		name     string
		p        pipAnswer
		path, by string
	}{
		{"nothing", pipAnswer{}, "", ""},
		{"requests first", pipAnswer{RequestsCABundle: text("r"), CurlCABundle: text("c"), Cert: text("p")}, "r",
			report.PipRequestsCABundle},
		{"an empty variable counts as unset", pipAnswer{RequestsCABundle: text(""), CurlCABundle: text("c")}, "c",
			report.PipCurlCABundle},
		{"cert from the configuration", pipAnswer{Cert: text("p")}, "p", report.PipCertSetting},
		{"cert from PIP_CERT", pipAnswer{Cert: text("p"), PipCert: text("p")}, "p", report.PipCertVariable},
		{"an empty PIP_CERT leaves the configuration's", pipAnswer{Cert: text("p"), PipCert: text("")}, "p",
			report.PipCertSetting},
		{"a proxy turns the variables off", pipAnswer{Version: "24.2", Proxy: true, RequestsCABundle: text("r"),
			CurlCABundle: text("c"), Cert: text("p")}, "p", report.PipCertSetting},
		{"so does --no-proxy-env", pipAnswer{Version: "26.2.2", NoProxyEnv: true, RequestsCABundle: text("r")}, "", ""},
		{"but not before 24.2", pipAnswer{Version: "24.1.2", Proxy: true, RequestsCABundle: text("r")}, "r",
			report.PipRequestsCABundle},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.p.Version == "" {
				c.p.Version = "26.2.2"
			}
			if path, by := verifyOf(c.p); path != c.path || by != c.by {
				t.Errorf("got %q from %q, want %q from %q", path, by, c.path, c.by)
			}
		})
	}
}

// ON WINDOWS pip ASKS WINDOWS FIRST - so a list that refuses defers to this
// account's store, with no file and no verdict of its own, and a list that
// closes the chain is the answer, on the file named for verification.
func TestPipOnWindowsDefersWhenItsListRefuses(t *testing.T) {
	b := newBench(t)
	certifi, company := abs("/Python314/pip/cacert.pem"), abs("/company.pem")
	a := listing(0x88020)
	a.Pip = onTruststore(certifi)
	a.Pip.TruststoreLoads = nil
	_, pip := both(t, "windows", a, b.chain(), func(w *world) { w.disk.put(certifi, pemOf(b.other)) })
	if pip.DefersTo == nil || *pip.DefersTo != (report.StoreRef{Runtime: report.RuntimeSystemStore,
		Instance: report.InstanceCurrentUser}) {
		t.Fatalf("a refusing list on Windows defers to %+v", pip.DefersTo)
	}
	if pip.TrustsPresentedChain != nil || pip.StoreForm != report.StoreSystem || pip.StorePath != "" ||
		pip.Variant != report.PipTruststore || pip.NotAssessed == "" {
		t.Errorf("the deferring row is %+v", pip)
	}

	a.Pip.RequestsCABundle = text(company)
	_, pip = both(t, "windows", a, b.chain(), func(w *world) {
		w.disk.put(certifi, pemOf(b.other))
		w.disk.put(company, pemOf(b.root))
	})
	if got := trustOf(pip); got != "trusted" || pip.DefersTo != nil || pip.StorePath != company {
		t.Errorf("a list closing the chain on Windows is %s, defers to %+v, reads %q", got, pip.DefersTo, pip.StorePath)
	}

	// A LIST WITH AN INTERMEDIATE AND NO ROOT ENDS NO CHAIN, so it defers too -
	// measured with probe S28: an intermediate alone in PIP_CERT was refused.
	a.Pip.RequestsCABundle = nil
	_, pip = both(t, "windows", a, b.chain(), func(w *world) { w.disk.put(certifi, pemOf(b.inter)) })
	if pip.DefersTo == nil {
		t.Errorf("a list of one intermediate on Windows is %s and does not defer: %q", trustOf(pip), pip.NotAssessed)
	}
}

// A SERVER'S OWN CERTIFICATE PINNED IN THE FILE IS A ROOT TO OpenSSL AND NONE TO
// pip ON WINDOWS - truststore hands Windows what get_ca_certs lists, and that
// list holds authorities only.
func TestAPinnedServerCertificateIsNoRootForPipOnWindows(t *testing.T) {
	pinned, _ := mint(t, "pinned.test", 9, nil, nil, false)
	certifi, pin := abs("/pip/cacert.pem"), abs("/pin.pem")
	a := listing(0x8000)
	a.Pip = onTruststore(certifi)
	a.Pip.Cert = text(pin)

	_, pip := both(t, "linux", a, [][]byte{pinned}, func(w *world) {
		w.disk.put(certifi, "")
		w.disk.put(pin, pemOf(pinned))
	})
	if got := trustOf(pip); got != "trusted" {
		t.Errorf("on Linux the pinned certificate is %s", got)
	}

	a.Pip.TruststoreLoads = nil
	_, pip = both(t, "windows", a, [][]byte{pinned}, func(w *world) {
		w.disk.put(certifi, "")
		w.disk.put(pin, pemOf(pinned))
	})
	if pip.DefersTo == nil {
		t.Errorf("on Windows the pinned certificate closed pip's own list: %s", trustOf(pip))
	}
}

// authority IS check_ca - an authority by its basic constraints, and never one
// whose key usage leaves out signing certificates.
func TestOnlyAnAuthorityIsHandedToWindows(t *testing.T) {
	b := newBench(t)
	cases := []struct {
		name string
		der  []byte
		want bool
	}{
		{"a root", b.root, true},
		{"an intermediate", b.inter, true},
		{"a server's certificate", b.leaf, false},
	}
	strayCA, _ := mint(t, "a CA that may not sign certificates", 10, nil, nil, true, func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageDigitalSignature
	})
	// basic constraints alone say "not an authority" when no key usage says anything.
	bare, _ := mint(t, "bare.test", 11, nil, nil, false, func(c *x509.Certificate) { c.KeyUsage = 0 })
	cases = append(cases, []struct {
		name string
		der  []byte
		want bool
	}{{"a CA whose key usage leaves out signing", strayCA, false},
		{"a server's certificate with no key usage", bare, false}}...)
	for _, c := range cases {
		certificate, err := x509.ParseCertificate(c.der)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := authority(certificate); got != c.want {
			t.Errorf("%s: authority says %v", c.name, got)
		}
	}
	if kept := authoritiesOnly([]byte(pemOf(b.root, b.leaf, b.inter))); string(kept) != pemOf(b.root, b.inter) {
		t.Errorf("the bundle kept %q", kept)
	}
}

// A pip WITHOUT TRUSTSTORE READS ONE FILE: the one named for verification takes
// certifi's place rather than joining it - requests, read - and the rule is
// urllib3's flags.
func TestPipWithoutTruststoreReadsOneFile(t *testing.T) {
	b := newBench(t)
	certifi, company := abs("/pip/cacert.pem"), abs("/company.pem")
	// The standard library's own list holds the root, and pip without
	// truststore does not read it.
	a := listing(0x8000, b.root)
	a.Pip = onCertifi(certifi)
	_, pip := both(t, "linux", a, b.chain(), func(w *world) { w.disk.put(certifi, pemOf(b.root)) })
	if got := trustOf(pip); got != "trusted" || pip.Variant != report.PipCertifi || pip.StorePath != certifi {
		t.Errorf("pip 23 with the root in certifi is %s, %q on %q", got, pip.Variant, pip.StorePath)
	}

	a.Pip.Cert = text(company)
	_, pip = both(t, "linux", a, b.chain(), func(w *world) {
		w.disk.put(certifi, pemOf(b.root))
		w.disk.put(company, pemOf(b.other))
	})
	if got := trustOf(pip); got != "refused unknown_authority" || pip.StorePath != company {
		t.Errorf("certifi stayed in the list beside the named file: %s on %q", got, pip.StorePath)
	}
}

// legacy-certs AND A truststore THAT WILL NOT IMPORT both take a new pip back to
// certifi, and there urllib3's flags rule - with PARTIAL_CHAIN an intermediate
// ends the chain.
func TestANewPipCanGoBackToCertifi(t *testing.T) {
	b := newBench(t)
	certifi := abs("/pip/cacert.pem")
	for name, spoil := range map[string]func(p *pipAnswer){
		"legacy-certs":                func(p *pipAnswer) { p.Deprecated = []string{"legacy-certs"} },
		"truststore will not import":  func(p *pipAnswer) { p.Truststore = false },
		"a release before 24.2":       func(p *pipAnswer) { p.Version = "24.1.2" },
		"a release candidate of 24.1": func(p *pipAnswer) { p.Version = "24.1rc1" },
	} {
		t.Run(name, func(t *testing.T) {
			a := listing(0x8000)
			a.Pip = onTruststore(certifi)
			spoil(a.Pip)
			_, pip := both(t, "linux", a, b.chain(), func(w *world) { w.disk.put(certifi, pemOf(b.inter)) })
			if got := trustOf(pip); got != "trusted" || pip.Variant != report.PipCertifi {
				t.Errorf("pip is %s on %q", got, pip.Variant)
			}
		})
	}
}

// STRICT UNDER ANOTHER OpenSSL IS NOT PROVEN for pip either - the rule the python
// row keeps, said about pip.
func TestStrictUnderAnotherOpenSSLIsNotProvenForPip(t *testing.T) {
	b := newBench(t)
	certifi := abs("/pip/cacert.pem")
	a := listing(0x8000)
	a.OpenSSL = []int{1, 1, 1, 20, 0}
	a.Pip = onCertifi(certifi)
	a.Pip.LegacyFlags = flags(0x88020)
	_, pip := both(t, "linux", a, b.chain(), func(w *world) { w.disk.put(certifi, pemOf(b.root)) })
	if pip.TrustsPresentedChain != nil || !strings.Contains(pip.NotAssessed, "this pip checks a chain against the strict") {
		t.Errorf("pip is %s: %q", trustOf(pip), pip.NotAssessed)
	}
}

// WHAT TRUSTSTORE LOADED IS WHAT THE ROW READS - a candidate file when OpenSSL's
// defaults are empty, and nothing at all, which leaves the row on the platform's
// store with no file to name.
func TestPipReadsWhatTruststoreLoaded(t *testing.T) {
	b := newBench(t)
	certifi, candidate := abs("/pip/cacert.pem"), abs("/etc/ssl/cert.pem")
	a := listing(0x8000)
	a.Pip = onTruststore(certifi)
	a.Pip.TruststoreLoads = []*string{text(candidate)}
	_, pip := both(t, "linux", a, b.chain(), func(w *world) {
		w.disk.put(certifi, pemOf(b.other))
		w.disk.put(candidate, pemOf(b.root))
	})
	if got := trustOf(pip); got != "trusted" || pip.StorePath != candidate {
		t.Errorf("pip on truststore's candidate is %s on %q", got, pip.StorePath)
	}

	a.Pip.TruststoreLoads = []*string{}
	_, pip = both(t, "linux", a, b.chain(), func(w *world) { w.disk.put(certifi, pemOf(b.root)) })
	if got := trustOf(pip); got != "trusted" || pip.StoreForm != report.StoreSystem || pip.StorePath != "" {
		t.Errorf("pip with nothing from truststore is %s on %s %q", got, pip.StoreForm, pip.StorePath)
	}
}

// WHAT CANNOT BE TOLD IS SAID - a step of pip's code that raised, a version
// that cannot be placed, a truststore asked for by --use-feature, a relative or
// missing file, and macOS.
func TestWhatCannotBeToldAboutPipIsSaid(t *testing.T) {
	b := newBench(t)
	certifi := abs("/pip/cacert.pem")
	cases := []struct {
		name     string
		platform string
		spoil    func(p *pipAnswer)
		says     string
	}{
		{"a step that raised", "linux", func(p *pipAnswer) { p.Failed = "settings: SystemExit" }, "settings: SystemExit"},
		{"a version with no number", "linux", func(p *pipAnswer) { p.Version = "unknown" }, "cannot place"},
		{"truststore by --use-feature", "linux", func(p *pipAnswer) {
			p.Version, p.Features = "23.0.1", []string{"truststore"}
		}, "--use-feature=truststore"},
		{"a relative file", "linux", func(p *pipAnswer) { p.Cert = text("company.pem") }, "relative path"},
		{"a missing file", "linux", func(p *pipAnswer) { p.Cert = text(abs("/missing.pem")) }, "could not be read"},
		{"no flags from urllib3", "linux", func(p *pipAnswer) { p.Version, p.LegacyFlags = "23.0.1", nil }, "flags"},
		{"truststore said nothing", "linux", func(p *pipAnswer) { p.TruststoreLoads = nil }, "did not say"},
		{"macOS", "darwin", func(p *pipAnswer) {}, "macOS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := listing(0x8000)
			a.Pip = onTruststore(certifi)
			c.spoil(a.Pip)
			_, pip := both(t, c.platform, a, b.chain(), func(w *world) { w.disk.put(certifi, pemOf(b.root)) })
			if pip.TrustsPresentedChain != nil || !strings.Contains(pip.NotAssessed, c.says) {
				t.Errorf("pip is %s: %q", trustOf(pip), pip.NotAssessed)
			}
		})
	}
}

// NO pip IS NO pip ROW, and a python that could not be asked says nothing of a
// pip either.
func TestNoPipIsNoPipRow(t *testing.T) {
	b := newBench(t)
	if store := one(t, "linux", listing(0x8000, b.root), b.chain(), nil); store.Runtime != report.RuntimePython {
		t.Errorf("the one row is %q", store.Runtime)
	}
	a := listing(0x8000, b.root)
	a.Pip = onTruststore(abs("/pip/cacert.pem"))
	store := one(t, "linux", a, b.chain(), func(w *world) {
		for binary := range w.replies {
			reply := replyOf(t, a)
			reply.ExitCode = 1
			w.replies[binary] = reply
		}
	})
	if store.TrustsPresentedChain != nil {
		t.Errorf("a python that exited with 1 is %s", trustOf(store))
	}
}
