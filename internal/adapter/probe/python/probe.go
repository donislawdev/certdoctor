// Package python is the L5 probe for Python - ADR112, decided by the owner
// 2026-10-21 after probe S28.
//
// IT JUDGES THE LIST THE INTERPRETER NAMES, BY THE RULE ITS OWN FLAGS SET. What
// Python's ssl module trusts by default is a file or the Windows stores, which it
// lists, and a hashed directory, which it does not - and from 3.13 on every
// certificate on the list ends a chain, while before only a self-signed one did.
// S28 measured both on sixteen interpreters, so each interpreter on PATH is asked
// once, with a constant script and no network, and the chain is judged here, in
// Go, by the rule that interpreter's flags name.
package python

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// withheld are the variables every interpreter this probe starts goes without -
// ADR112 part 6, the list curl's probe keeps (OBS189). SSLKEYLOGFILE names a
// file create_default_context opens for appending - Lib/ssl.py of CPython 3.15.0,
// read 2026-10-21, which -I already stops, so withholding it is a second wall -
// and OPENSSL_CONF names a configuration OpenSSL loads as it starts, which can
// name a module of native code.
var withheld = []string{"SSLKEYLOGFILE", "OPENSSL_CONF"}

// Probe builds the L5 probe for python.
//
// start makes the runner from the variables to withhold, and this package names
// them, as for curl and node. platform decides the names on PATH, the form of the
// store and the separator SSL_CERT_DIR is split by. files lists the hashed
// directory, and alias reads Windows' app execution aliases.
func Probe(source file.Source, resolve file.Resolve, alias file.AppAlias, files file.List,
	start func(withheld ...string) probe.Runner, pathDirs []string, platform string,
	now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		host := machine{source: source, resolve: resolve, alias: alias, files: files, run: start(withheld...), platform: platform}
		found := host.interpreters(ctx, pathDirs)
		if len(found) == 0 {
			// NOT AN ERROR - docs/20 rule 1. No Python is not a fact about trust.
			return nil, nil
		}
		stores := make([]report.TrustStore, 0, len(found))
		for _, in := range found {
			stores = append(stores, host.storesFor(ctx, in, chain, now())...)
		}
		return stores, nil
	}
}

// storesFor asks one interpreter once and turns its answer into rows - python
// always, and pip beside it when the interpreter has a pip - ADR112 part 1.
func (m machine) storesFor(ctx context.Context, in interpreter, chain [][]byte, now time.Time) []report.TrustStore {
	a, why := in.reply, in.why
	if !in.asked {
		a, why = ask(ctx, m.run, in.path)
	}
	python := m.storeFor(in, a, why, chain, now)
	// An interpreter that could not be asked has an empty answer, so no pip.
	if a.Pip == nil {
		return []report.TrustStore{python}
	}
	return []report.TrustStore{python, m.pipStore(in, a, chain, now)}
}

// machine is what one run of the probe reads this machine through.
type machine struct {
	source   file.Source
	resolve  file.Resolve
	alias    file.AppAlias
	files    file.List
	run      probe.Runner
	platform string
}

// storeFor turns one interpreter's answer, or the sentence saying there is none,
// into its python row.
func (m machine) storeFor(in interpreter, a answer, why string, chain [][]byte, now time.Time) report.TrustStore {
	store := report.TrustStore{
		Runtime: report.RuntimePython,
		// THE PATH IS THE IDENTITY, as for node and curl - two interpreters differ
		// by nothing else a person could tell them apart by.
		Instance:   in.path,
		SelectedBy: in.selectedBy,
		StoreForm:  report.StoreSystem,
	}
	if why != "" {
		store.NotAssessed = why
		return store
	}
	m.place(&store, a)
	if store.StoreForm == report.StoreFile {
		// THE INTERPRETER READ THE FILE AND HANDED BACK ITS CERTIFICATES, not its
		// bytes, so the end the append command depends on is read here - ADR114
		// B13.
		store.FileEnd = probe.ReadEndOf(m.source, store.StorePath)
	}
	dirs, relative := m.directories(a)
	directory, stopped, err := probe.HashedAnchors(m.source, m.files, dirs)
	judge(&store, a, a.bundle(directory), chain, now)
	return undecided(store, a, relative, stopped, err)
}

// undecided takes back a verdict the row cannot stand behind, and says why - for
// the python row and for pip's, whose flags a carries. relative is a directory
// named relatively, and stopped and err the directory that could not be read.
func undecided(store report.TrustStore, a answer, relative, stopped string, err error) report.TrustStore {
	// A DIRECTORY ADDS SIGNERS AND NEVER TAKES ONE AWAY, so one this program could
	// not read matters only where what it did read did not close the chain.
	switch {
	case relative != "" && !trusted(store):
		probe.Undetermined(&store, fmt.Sprintf("SSL_CERT_DIR names %s, a relative directory each program looks up from "+
			"wherever it starts, so what this %s makes of the chain is undetermined", relative, store.Runtime))
	case err != nil && !trusted(store):
		probe.Undetermined(&store, fmt.Sprintf("this %s also reads the directory %s, which could not be read in full "+
			"(%v), so what it makes of the chain is undetermined", store.Runtime, stopped, err))
	case a.flags().Strict() && !a.openSSL3() && trusted(store):
		// STRICT ONLY TAKES AWAY - ADR112 part 3. Its rules are applied here as
		// OpenSSL 3 has them, and OpenSSL 1.1.1 has far fewer, so a trust under
		// any other OpenSSL is not proven, and a refusal stands as it is.
		probe.Undetermined(&store, fmt.Sprintf("this %s checks a chain against the strict rules (VERIFY_X509_STRICT) of "+
			"%s, and this program applies those of OpenSSL 3 alone", store.Runtime, openSSLName(a.OpenSSL)))
	}
	return store
}

// judge applies the anchor rule this interpreter's flags name - ADR112 part 2 -
// and with OpenSSL 3 the strict rules they name - part 3. A flag and not a
// version number, because the flag is what is seen.
func judge(store *report.TrustStore, a answer, anchors []byte, chain [][]byte, now time.Time) {
	switch flags := a.flags(); {
	case flags.Strict() && a.openSSL3():
		probe.VerifyStrictly(store, anchors, chain, now, flags)
	case flags.PartialChain():
		probe.Verify(store, anchors, chain, now)
	default:
		probe.VerifySelfSignedAnchors(store, anchors, chain, now)
	}
}

// openSSLName names the OpenSSL the interpreter reported, by the five numbers it
// reported - spelled as they came, since OpenSSL 3 puts its patch fourth and
// LibreSSL reports a 2 of its own.
func openSSLName(version []int) string {
	if len(version) == 0 {
		return "an OpenSSL whose version it did not report"
	}
	numbers := make([]string, len(version))
	for i, n := range version {
		numbers[i] = strconv.Itoa(n)
	}
	return "an OpenSSL reporting version " + strings.Join(numbers, ".")
}

// place writes the form of the store this interpreter reads - ADR112 part 2.
//
// ON WINDOWS IT IS THE PLATFORM'S STORES, CA and ROOT, and a file OpenSSL loaded
// sits BESIDE them - SSL_CERT_FILE added to the stores on all seven interpreters
// S28 measured. So such a row names that file as well, and is counted as a store
// of its own rather than as this account's: measured with this program's binary
// on 2026-10-21, a Python trusting the bench's root through SSL_CERT_FILE was
// counted under the account's store that refused it, and the line about who
// holds the signer said nobody did.
//
// ELSEWHERE IT IS THE FILE OpenSSL LOADED, when it loaded one, spelled as the
// platform store's row spells it when it is that file - so the two rows are
// counted as one store and hand a person one command. A Python reading no file -
// Fedora 44 measured by S28, only the hashed directory - is on the platform's
// store, with no path to name.
func (m machine) place(store *report.TrustStore, a answer) {
	if a.CAFile == nil || *a.CAFile == "" {
		return
	}
	store.StorePath = *a.CAFile
	if m.platform == "windows" {
		return
	}
	store.StoreForm = report.StoreFile
	store.StorePath = m.spelled(*a.CAFile)
}

// spelled is a file this interpreter reads, written as the platform store's row
// writes it when it is that row's file after links - so the rows are counted as
// one store, and hand a person one command.
func (m machine) spelled(path string) string {
	if m.platform != "linux" {
		return path
	}
	if platform, _, _ := probe.FirstBundle(m.source, probe.LinuxBundles); platform != "" &&
		probe.IdentityKey(m.resolve, platform) == probe.IdentityKey(m.resolve, path) {
		return platform
	}
	return path
}

// directories are the hashed directories this interpreter's OpenSSL looks in -
// SSL_CERT_DIR split by the platform's separator when it is set, even to nothing,
// and the default directory when it is not - answer.go has the source - with the
// first relative one named apart, since it is no one directory. The ceilings are
// the measured ones the platform store reads its directories with.
func (m machine) directories(a answer) (probe.CADirectories, string) {
	dirs := probe.CADirectories{
		EntryCeiling: probe.LinuxCADirectories.EntryCeiling,
		ByteCeiling:  probe.LinuxCADirectories.ByteCeiling,
	}
	listed := []string{a.DirDefault}
	if a.DirEnv != nil {
		separator := ":"
		if m.platform == "windows" {
			separator = ";"
		}
		listed = strings.Split(*a.DirEnv, separator)
	}
	relative := ""
	for _, dir := range listed {
		switch {
		case dir == "":
		case filepath.IsAbs(dir):
			dirs.Paths = append(dirs.Paths, dir)
		case relative == "":
			relative = dir
		}
	}
	return dirs, relative
}

// trusted says the row closed the chain.
func trusted(store report.TrustStore) bool {
	return store.TrustsPresentedChain != nil && *store.TrustsPresentedChain
}
