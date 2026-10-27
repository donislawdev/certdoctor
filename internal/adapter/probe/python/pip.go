package python

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// pipStore is what one interpreter's pip trusts - ADR112 part 5, decided by the
// owner 2026-10-21, and how the row says so, decided 2026-10-27.
//
// pip HAS ANOTHER RULE THAN THE STANDARD LIBRARY OF THE SAME INTERPRETER, which
// is why it is a row of its own. Measured with probe S28: its context sets
// neither PARTIAL_CHAIN nor STRICT, so an intermediate alone was refused on every
// Python, while 3.13 and later trusted it through urllib. And from 24.2 on it
// reads this machine's store through truststore beside the certifi it carries,
// while before 24.2, and under --use-deprecated=legacy-certs, it reads one file.
// Variant says which, and the command depends on it.
func (m machine) pipStore(in interpreter, a answer, chain [][]byte, now time.Time) report.TrustStore {
	p := *a.Pip
	store := report.TrustStore{
		Runtime: report.RuntimePip,
		// THE INTERPRETER IS THE IDENTITY - the pip a person types belongs to the
		// interpreter its first line names, and is reached through the same
		// commands.
		Instance:   in.path,
		SelectedBy: slices.Clone(in.selectedBy),
		StoreForm:  report.StoreSystem,
	}
	if p.Failed != "" {
		store.NotAssessed = fmt.Sprintf("this interpreter has pip, and pip's own code could not say what it reads - "+
			"the step %s", p.Failed)
		return store
	}
	variant, why := variantOf(p)
	if why != "" {
		store.NotAssessed = why
		return store
	}
	store.Variant = variant
	verify, by := verifyOf(p)
	if by != "" {
		store.SelectedBy = append(store.SelectedBy, by)
		if !filepath.IsAbs(verify) {
			store.NotAssessed = fmt.Sprintf("%s names %s, a relative path pip looks up from wherever it starts, so what "+
				"this pip makes of the chain is undetermined", by, verify)
			return store
		}
	}
	if why := addressRefused(m.addressed, variant, p.Urllib3); why != "" {
		store.NotAssessed = why
		return store
	}
	switch {
	case variant == report.PipCertifi:
		return m.onCertifi(store, a, p, verify, chain, now)
	case m.platform == "windows":
		return m.onWindows(store, a, p, verify, chain, now)
	case m.platform == "darwin":
		store.NotAssessed = "this pip asks macOS through truststore, which this program does not read, so what it " +
			"makes of the chain is undetermined"
		return store
	}
	return m.onTruststore(store, a, p, verify, chain, now)
}

// truststoreRelease is the pip that reads this machine's store unless told not
// to: "truststore", "always on since 24.2" in the list of --use-feature values,
// src/pip/_internal/cli/cmdoptions.py of pip 26.2.2, read 2026-10-27 on the
// owner's machine. Measured with probe S28: pip 21.3.1 and 23.0.1 did not read
// it, every pip from 25.1.1 did.
var truststoreRelease = [2]int{24, 2}

// variantOf is which of its two lists this pip trusts, or the sentence saying it
// cannot be told.
//
// A pip FROM 24.2 ON GOES BACK TO certifi IN TWO CASES, and both are pip's own:
// --use-deprecated=legacy-certs, and truststore failing to import, which pip
// answers with a warning and no truststore - _create_truststore_ssl_context in
// src/pip/_internal/cli/index_command.py of pip 26.2.2, read the same day.
// truststore imports on Python 3.10 and later only. A pip BEFORE 24.2 asked for
// truststore with --use-feature was not measured.
func variantOf(p pipAnswer) (string, string) {
	release, placed := releaseOf(p.Version)
	switch {
	case !placed:
		return "", fmt.Sprintf("this pip reports the version %q, which this program cannot place before or after 24.2, "+
			"where pip began to read this machine's store", p.Version)
	case beforeTruststore(release):
		if slices.Contains(p.Features, "truststore") {
			return "", "this pip reads this machine's store only because --use-feature=truststore asks it to, which this " +
				"program has not measured"
		}
		return report.PipCertifi, ""
	case slices.Contains(p.Deprecated, "legacy-certs") || !p.Truststore:
		return report.PipCertifi, ""
	}
	return report.PipTruststore, ""
}

// namesAnAddressFrom is the first major version of urllib3 that hands TLS the
// server's name when the target is an IP address - addressRefused has the source.
const namesAnAddressFrom = 2

// addressRefused is the sentence of a pip that cannot open https to an IP
// address at all, or empty - OBS202, decided by the owner 2026-10-27: UNKNOWN
// with the way out, rather than a verdict on a list pip never gets to use.
//
// URLLIB3 BEFORE 2 SENDS NO SERVER NAME TO AN ADDRESS, AND TRUSTSTORE REFUSES A
// CONNECTION WITHOUT ONE before any certificate is read: ssl_wrap_socket in
// urllib3 1.26.20's util/ssl_.py leaves server_hostname out for an IP address,
// and truststore's context keeps check_hostname on, so Python's ssl module
// raises "check_hostname requires server_hostname". Read 2026-10-27 on GitHub,
// and measured with probe S28 the same day: pip 25.0.1, 25.1.1 and 26.0.1, each
// on urllib3 1.26.20, failed that way against the bench's address with a root
// they trusted through its name, while 26.1.2 on urllib3 2.6.3 and 26.2.1 on
// 2.7.0 reached it. pip carries urllib3 2 from 26.1 - src/pip/_vendor/vendor.txt
// of each tag. Without truststore urllib3 makes its own context and checks the
// name itself, and --use-deprecated=legacy-certs reached the address on 25.0.1.
func addressRefused(addressed bool, variant string, urllib3 *string) string {
	if !addressed || variant != report.PipTruststore {
		return ""
	}
	if urllib3 == nil {
		return "this pip runs on truststore and did not say which urllib3 it connects through, and before urllib3 2 " +
			"an https connection to an IP address is refused before any certificate is read, so what this pip makes " +
			"of this target is undetermined"
	}
	release, placed := releaseOf(*urllib3)
	switch {
	case !placed:
		return fmt.Sprintf("this pip connects through urllib3 %q, which this program cannot place before or after 2, "+
			"and before 2 an https connection to an IP address is refused before any certificate is read, so what "+
			"this pip makes of this target is undetermined", *urllib3)
	case release[0] < namesAnAddressFrom:
		return fmt.Sprintf("this pip runs on truststore with urllib3 %s, which opens https to an IP address without "+
			"the server's name, and truststore refuses that before any certificate is read - so this pip cannot reach "+
			"this target whatever it trusts. pip 26.1 or later, a host name in place of the address, or "+
			"--use-deprecated=legacy-certs reaches it", *urllib3)
	}
	return ""
}

// beforeTruststore says a release came before 24.2.
func beforeTruststore(release [2]int) bool {
	return release[0] < truststoreRelease[0] || release[0] == truststoreRelease[0] && release[1] < truststoreRelease[1]
}

// releaseOf is the first two numbers of a pip version - "24.2", "25.1.1",
// "24.3.dev0", "24.2rc1" - each read up to its first character that is not a
// digit, and false when either has no digit to start with.
func releaseOf(version string) ([2]int, bool) {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return [2]int{}, false
	}
	var release [2]int
	for i := range release {
		digits := parts[i]
		if end := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
			digits = digits[:end]
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return [2]int{}, false
		}
		release[i] = n
	}
	return release, true
}

// verifyOf is the one file pip verifies with beside its list, and the name that
// set it, or two empty strings.
//
// REQUESTS_CA_BUNDLE FIRST, THEN CURL_CA_BUNDLE, THEN pip's cert - measured with
// probe S28 on every pip from 21.3.1 to 26.2.2, and read in requests 2.34.2:
// merge_environment_settings in sessions.py takes the two variables, the first
// that is not empty, in place of a verify left at True, and pip puts cert in the
// session's verify, which the request's own setting overrides. But only while
// trust_env holds, and from 24.2 on pip turns it off for a proxy, and from 26.2
// for --no-proxy-env too - _build_session in src/pip/_internal/cli/
// index_command.py, where the line arrived with the file in tag 24.2, read
// 2026-10-27 on GitHub with every tag up to 26.2, while req_command.py of 22.3 to
// 24.1 sets only the proxies. Measured the same day with probe S28 (pip.ps1):
// with PIP_PROXY on the bench's own tunnel and REQUESTS_CA_BUNDLE on its root,
// pip 26.2.2 refused and pip 23.0.1 trusted, both through the tunnel. So a proxy
// in pip's configuration leaves cert as the file and the variables unread.
//
// cert came from PIP_CERT when that variable is set, since pip's parser takes the
// environment last - _get_ordered_configuration_items in parser.py - and from a
// configuration file otherwise.
func verifyOf(p pipAnswer) (string, string) {
	release, _ := releaseOf(p.Version)
	trustEnv := beforeTruststore(release) || !p.Proxy && !p.NoProxyEnv
	switch {
	case trustEnv && set(p.RequestsCABundle):
		return *p.RequestsCABundle, report.PipRequestsCABundle
	case trustEnv && set(p.CurlCABundle):
		return *p.CurlCABundle, report.PipCurlCABundle
	case set(p.Cert) && set(p.PipCert):
		return *p.Cert, report.PipCertVariable
	case set(p.Cert):
		return *p.Cert, report.PipCertSetting
	}
	return "", ""
}

func set(s *string) bool { return s != nil && *s != "" }

// onCertifi judges a pip without truststore: the file named for verification,
// or else certifi, by the flags urllib3 gives its context.
//
// ONE FILE, NOT TWO. requests hands urllib3 the named path in place of certifi's -
// HTTPAdapter.cert_verify in adapters.py of requests 2.34.2 - so certifi drops
// out the moment a file is named. Read, not measured: the bench serves no
// publicly trusted chain to show certifi gone.
func (m machine) onCertifi(store report.TrustStore, a answer, p pipAnswer, verify string, chain [][]byte,
	now time.Time) report.TrustStore {
	if p.LegacyFlags == nil {
		store.NotAssessed = "this pip did not report the flags its connections verify with, so what it makes of the " +
			"chain is undetermined"
		return store
	}
	file := verify
	if file == "" {
		file = p.Certifi
	}
	list, err := m.fileOf(file)
	if err != nil {
		store.NotAssessed = fmt.Sprintf("this pip reads %s, which could not be read (%v), so what it makes of the "+
			"chain is undetermined", file, err)
		return store
	}
	store.StoreForm = report.StoreFile
	store.StorePath = m.spelled(file)
	store.FileEnd = probe.ReadEndOf(m.source, store.StorePath)
	view := a
	view.DER, view.Flags = nil, p.LegacyFlags
	judge(&store, view, view.bundle(list), chain, now)
	return undecided(store, view, "", "", nil)
}

// noFlags are the flags of truststore's context: ssl.SSLContext with neither
// PARTIAL_CHAIN nor STRICT - measured with probe S28, where an intermediate alone
// was refused and a chain breaking either strict rule measured was trusted on
// every Python. So only a self-signed certificate ends a chain.
const noFlags int64 = 0

// onWindows judges pip on truststore on Windows - ADR112 part 5.
//
// WINDOWS FIRST, THE LIST AFTER, so the row judges the list and defers to this
// account's store when the list refuses: _verify_peercerts_impl in truststore
// 0.10.4's _windows.py, read 2026-10-27, builds the chain with the default
// engine, and only when that fails, with an engine trusting nothing but the
// list - certifi and the file named for verification - as its exclusive roots.
// Measured with probe S28: SSL_CERT_FILE did not reach pip there, and a root in
// any of the files named for verification did. The default engine was seen
// only refusing, because a root in that store needs the owner at the machine.
//
// THE COMMAND OF A REFUSING ROW IS THE STORE'S - decided by the owner 2026-10-27,
// even with a file named for verification: the row takes the answer of the store
// it defers to, and that store is the one pip asks first.
func (m machine) onWindows(store report.TrustStore, a answer, p pipAnswer, verify string, chain [][]byte,
	now time.Time) report.TrustStore {
	files := []string{p.Certifi}
	if verify != "" {
		files = append(files, verify)
	}
	lists := make([][]byte, 0, len(files))
	for _, file := range files {
		list, err := m.fileOf(file)
		if err != nil {
			store.NotAssessed = fmt.Sprintf("this pip reads %s, which could not be read (%v), so what it makes of the "+
				"chain is undetermined", file, err)
			return store
		}
		lists = append(lists, list)
	}
	view := a
	flags := noFlags
	view.DER, view.Flags = nil, &flags
	roots := authoritiesOnly(view.bundle(lists...))
	judge(&store, view, roots, chain, now)
	// A LIST WITH NOTHING TO END A CHAIN IS A LIST THAT CANNOT CLOSE IT - with no
	// authority truststore raises Windows' own error, and with no self-signed one
	// the exclusive engine refuses - so both defer, as a refusal does.
	switch {
	case trusted(store):
		store.StoreForm = report.StoreFile
		store.StorePath = files[len(files)-1]
	case store.TrustsPresentedChain != nil || !endsAChain(roots):
		probe.Undetermined(&store, "its own list does not close the chain, and pip then takes the answer of Windows, "+
			"which judges by system-store CurrentUser")
		store.DefersTo = &report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: report.InstanceCurrentUser}
	}
	return store
}

// endsAChain says a PEM bundle holds a self-signed certificate, the only kind
// that ends a chain on truststore's exclusive engine - measured with probe S28,
// where an intermediate alone in PIP_CERT was refused on Windows.
func endsAChain(bundle []byte) bool {
	for rest := bundle; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return false
		}
		if certificate, err := x509.ParseCertificate(block.Bytes); err == nil && probe.SelfSigned(certificate) {
			return true
		}
	}
}

// onTruststore judges pip on truststore off Windows and macOS: what truststore
// loaded, certifi, and the file named for verification, in one context.
//
// WHAT TRUSTSTORE LOADS IS WHAT IT SAID - the script hands it a recorder. OpenSSL's
// defaults are the file and the directory the python row reads, named in the
// same answer, and here the file is read whole, as OpenSSL loads it, rather than
// through the list Python prints, which holds authorities only. The command adds
// to the file named for verification, or to the one truststore loads, which is
// the platform's on a distribution - ADR112 part 5. With neither, the row is on
// the platform's store and has no file to name, as the python row on Fedora.
func (m machine) onTruststore(store report.TrustStore, a answer, p pipAnswer, verify string, chain [][]byte,
	now time.Time) report.TrustStore {
	if p.TruststoreLoads == nil {
		store.NotAssessed = "this pip's truststore did not say which files it loads, so what it makes of the chain is " +
			"undetermined"
		return store
	}
	view := a
	flags := noFlags
	view.DER, view.Flags = nil, &flags
	var lists [][]byte
	var dirs probe.CADirectories
	relative, loaded := "", ""
	for _, load := range p.TruststoreLoads {
		switch {
		case load != nil:
			loaded = *load
		case a.CAFile != nil:
			loaded = *a.CAFile
			fallthrough
		default:
			dirs, relative = m.directories(a)
		}
	}
	for _, file := range []string{loaded, p.Certifi, verify} {
		if file == "" {
			continue
		}
		list, err := m.fileOf(file)
		if err != nil {
			store.NotAssessed = fmt.Sprintf("this pip reads %s, which could not be read (%v), so what it makes of the "+
				"chain is undetermined", file, err)
			return store
		}
		lists = append(lists, list)
	}
	directory, stopped, err := probe.HashedAnchors(m.source, m.files, dirs)
	judge(&store, view, view.bundle(append(lists, directory)...), chain, now)
	store = undecided(store, view, relative, stopped, err)
	file := verify
	if file == "" {
		file = loaded
	}
	if file != "" {
		store.StoreForm = report.StoreFile
		store.StorePath = m.spelled(file)
		store.FileEnd = probe.ReadEndOf(m.source, store.StorePath)
	}
	return store
}

// fileOf reads one file pip loads. Only an absolute path names one file - a
// relative one is looked up from wherever pip starts.
func (m machine) fileOf(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%q is not an absolute path", path)
	}
	reader, err := m.source(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

// keyUsage is the object identifier of the key usage extension, RFC 5280
// section 4.2.1.3.
var keyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// authoritiesOnly keeps the certificates of a PEM bundle that Python would hand
// Windows as roots.
//
// truststore PASSES get_ca_certs, AND THAT LIST HOLDS AUTHORITIES ONLY: the
// function skips every certificate X509_check_ca turns down - Modules/_ssl.c of
// CPython's 3.15 branch, read 2026-10-27 - and check_ca in
// crypto/x509/v3_purp.c of OpenSSL's openssl-3.5 branch, read the same day, says
// which: none whose key usage leaves out certificate signing, one whose basic
// constraints say CA, and without basic constraints a self-issued version 1
// certificate or one with a key usage that allows signing. So a server's own
// certificate pinned in the file named for verification is a root to OpenSSL on
// Linux, and none to pip on Windows.
//
// WHAT IS LEFT OUT, NAMED: OpenSSL calls a version 1 certificate self-signed by
// its names, its key identifiers and the algorithm of its signature, and only
// the names are compared here; and a Netscape certificate type marking a CA,
// which Go does not read, is not taken as one.
func authoritiesOnly(bundle []byte) []byte {
	var kept bytes.Buffer
	for rest := bundle; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !authority(certificate) {
			continue
		}
		_ = pem.Encode(&kept, block)
	}
	return kept.Bytes()
}

// authority is check_ca's answer for one certificate - authoritiesOnly has the
// source.
func authority(c *x509.Certificate) bool {
	usage := slices.ContainsFunc(c.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(keyUsage) })
	switch {
	case usage && c.KeyUsage&x509.KeyUsageCertSign == 0:
		return false
	case c.BasicConstraintsValid:
		return c.IsCA
	case c.Version == 1:
		return bytes.Equal(c.RawSubject, c.RawIssuer)
	}
	return usage
}
