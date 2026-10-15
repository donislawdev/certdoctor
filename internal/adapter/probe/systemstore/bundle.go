package systemstore

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// This file is the platform store where the platform keeps it as FILES - Linux,
// ADR104. It carries no build tag, so every rule in it is tested on every
// platform the tests run on, and probe_linux.go only wires it.
//
// THERE IS NO PLATFORM API TO ASK, SO THE STORE IS WHAT THE PROGRAMS READ. Go
// reads the first bundle on a fixed list, and OpenSSL's own default bundle led
// to that same file in every image probe S24 opened on 2026-10-15 - Debian,
// Ubuntu, Alpine and RHEL. So the row reads the first bundle on that list,
// through the same guarded port every other probe reads through, and judges the
// chain with the verifier git and java share.
//
// SSL_CERT_FILE AND SSL_CERT_DIR ARE NOT FOLLOWED, decided by the owner
// 2026-10-15. They point a program AWAY from the platform store, L0 already
// reports both, and the openssl slice of M2 is where a row for the file they
// name belongs - this probe reads no environment at all.

// layout is where a platform keeps the store its programs read from disk.
type layout struct {
	// bundles are the candidates in the order they are asked, and the first one
	// that exists is the store.
	bundles []string
	// directories are read only when the bundle refused for want of a signer.
	directories []string
	// releases name the distribution, in precedence order.
	releases []string
	// entryCeiling and byteCeiling bound the directory pass - how many entries
	// one directory may hold, and how many bytes the pass may read in all.
	entryCeiling, byteCeiling int
}

// linuxLayout is Go's own list, so the row reads exactly what a Go program on
// the machine reads.
//
// SOURCE, inviolable rule 18: src/crypto/x509/root_linux.go of Go 1.27.2, read
// 2026-10-15 - certFiles ("stop after finding one") and certDirectories ("all
// will be read"), in that order. The two release files and their precedence are
// os-release(5): "/etc/os-release takes precedence over /usr/lib/os-release",
// read the same day at https://man7.org/linux/man-pages/man5/os-release.5.html
var linuxLayout = layout{
	bundles: []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/cert.pem",
	},
	directories:  []string{"/etc/ssl/certs", "/etc/pki/tls/certs"},
	releases:     []string{"/etc/os-release", "/usr/lib/os-release"},
	entryCeiling: directoryEntryCeiling,
	byteCeiling:  directoryByteCeiling,
}

// The two ceilings on the directory pass. Measured by S24 on 2026-10-15: the
// largest directory held 301 entries, and everything read from both came to
// well under a megabyte. Each ceiling is more than ten times that and still
// finite, which is the only property that matters - past it the row says it did
// not look rather than pretending it did.
const (
	directoryEntryCeiling = 4096
	directoryByteCeiling  = 64 << 20
)

// fallbackDistribution is the instance when nothing names the distribution. It
// is os-release(5)'s own default: "If not set, a default of ID=linux may be
// used."
const fallbackDistribution = "linux"

// noBundle is the row on a machine with no bundle anywhere. Measured by S24:
// debian:trixie-slim and ubuntu:24.04 hold none, and Go's own pool there is
// empty - the ca-certificates package is the thing not installed, measured there on
// 2026-08-05 and 2026-09-23.
//
// IT IS UNDETERMINED RATHER THAN A REFUSAL, the same answer the shared verifier
// gives an empty store. A refusal would feed the count of stores that do not
// hold the signer, and every sentence built on that count is about who SIGNED
// the chain - here the fault is that nothing is installed to trust anybody.
const noBundle = "there is no CA bundle at any of the places Go and the common distributions keep one, so this " +
	"platform has no store to judge the chain with - on Debian and Ubuntu the ca-certificates package is what installs it"

// bundleProbe builds the probe that reads a platform store kept as files.
func bundleProbe(source file.Source, files file.List, l layout, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		store := report.TrustStore{
			Runtime:   report.RuntimeSystemStore,
			Instance:  fallbackDistribution,
			StoreForm: report.StoreSystem,
			// NOTHING SELECTS A PLATFORM STORE, the same answer the Windows rows
			// give - SSL_CERT_FILE selects something ELSE, and is not followed.
			SelectedBy: []string{},
		}
		// The context is asked once, before anything is read - every read below
		// is a local file of a few hundred kilobytes.
		if err := ctx.Err(); err != nil {
			store.NotAssessed = fmt.Sprintf("this store was not asked: %v", err)
			return []report.TrustStore{store}, nil
		}
		if source == nil || files == nil {
			// A FORGOTTEN PORT IS OUR DEFECT AND IS SAID AS ONE, never read as a
			// machine with nothing installed.
			store.NotAssessed = "this program was built without a way to read files here, so the store was not read"
			return []report.TrustStore{store}, nil
		}
		store.Instance = distribution(source, l.releases)
		assess(&store, source, files, l, chain, now())
		return []report.TrustStore{store}, nil
	}
}

// assess fills in what the first bundle - and, when it refuses, the
// directories beside it - make of the chain.
func assess(store *report.TrustStore, source file.Source, files file.List, l layout, chain [][]byte, at time.Time) {
	path, bundle, err := firstBundle(source, l.bundles)
	if path == "" {
		store.NotAssessed = noBundle
		return
	}
	// THE PATH IS THE ONE ON GO'S LIST, NOT WHERE ITS LINKS LEAD. It is the name
	// a person and their tools use, and appending through a link appends to
	// whatever it leads to - measured on RHEL, where it is a link.
	store.StoreForm, store.StorePath = report.StoreFile, path
	if err != nil {
		// A BUNDLE THAT EXISTS AND CANNOT BE READ IS NOT SKIPPED, and that is a
		// deliberate difference from Go, which moves on to the next file. OpenSSL
		// does not move on, so the next file would be a store some programs here
		// never read, reported as the one they do.
		store.NotAssessed = fmt.Sprintf("the CA bundle at %s could not be read: %v", path, err)
		return
	}
	probe.Verify(store, bundle, chain, at)
	if refusedForWantOfASigner(store) {
		weighDirectories(store, source, files, l, bundle, chain, at)
	}
}

// firstBundle returns the first candidate that exists, with its bytes or the
// reason they could not be read, and an empty path when none exists.
func firstBundle(source file.Source, candidates []string) (string, []byte, error) {
	for _, path := range candidates {
		data, err := readAll(source, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return path, data, err
	}
	return "", nil, nil
}

// refusedForWantOfASigner is the one refusal a directory could overturn.
func refusedForWantOfASigner(store *report.TrustStore) bool {
	return store.TrustsPresentedChain != nil && !*store.TrustsPresentedChain &&
		store.TrustFailure == report.UnknownAuthority
}

// The sentences a row carries when the directories stop a refusal from being
// proven - decided by the owner 2026-10-15.
const (
	directoryCloses = "the bundle does not close this chain and a certificate in %s does - programs that read that " +
		"directory trust it and programs that read only the bundle do not, so what this store makes of the chain " +
		"depends on the program asking"
	directoryUnreadable = "the bundle does not close this chain and %s could not be read in full (%v), so whether a " +
		"certificate there closes it is undetermined"
	directoryTooLarge = "the bundle does not close this chain and %s holds more than this program reads, so whether a " +
		"certificate there closes it is undetermined"
)

// weighDirectories reads the directories the way Go does and turns the
// refusal into undetermined when they close what the bundle did not.
//
// MEASURED, IN ORDINARY USE THEY ADD NOTHING - S24, eight images out of eight
// with a store: the directories held no certificate the bundle lacked. What
// they CAN add is a certificate copied in by hand without the distribution's
// tool, which Go reads and OpenSSL reads through its hashed links while every
// program reading only the bundle refuses. A FAIL there would be true of the
// file this row names and false of half the programs on the machine.
//
// IT RUNS ONLY ON A REFUSAL, because a directory can add a signer and never take
// one away - so a bundle that trusts the chain is already the answer.
func weighDirectories(store *report.TrustStore, source file.Source, files file.List, l layout,
	bundle []byte, chain [][]byte, at time.Time) {
	anchors := bytes.Clone(bundle)
	for _, directory := range l.directories {
		names, err := files(directory)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			undetermined(store, fmt.Sprintf(directoryUnreadable, directory, err))
			return
		case len(names) > l.entryCeiling:
			undetermined(store, fmt.Sprintf(directoryTooLarge, directory))
			return
		}
		for _, name := range names {
			data, err := readAll(source, name)
			if errors.Is(err, fs.ErrNotExist) {
				// A dangling link is an ordinary leftover there and holds nothing.
				continue
			}
			if err != nil {
				undetermined(store, fmt.Sprintf(directoryUnreadable, directory, err))
				return
			}
			if len(anchors)+1+len(data) > l.byteCeiling {
				undetermined(store, fmt.Sprintf(directoryTooLarge, directory))
				return
			}
			anchors = append(append(anchors, '\n'), data...)
		}
		var trial report.TrustStore
		probe.Verify(&trial, anchors, chain, at)
		if trial.TrustsPresentedChain != nil && *trial.TrustsPresentedChain {
			undetermined(store, fmt.Sprintf(directoryCloses, directory))
			return
		}
	}
}

// undetermined turns a row into one without a verdict. The count goes with the
// verdict - the contract refuses a row that could not assess a store and still
// counts what is in it.
func undetermined(store *report.TrustStore, why string) {
	store.TrustsPresentedChain = nil
	store.TrustFailure = ""
	store.TrustAnchorCount = 0
	store.NotAssessed = why
}

// distribution is the ID os-release gives, or the fallback.
//
// THE FIRST RELEASE FILE THAT EXISTS IS THE ONLY ONE READ - os-release(5): use
// its data "exclusively ... if it exists". A file that exists and names no ID
// gets the default, not the next file.
func distribution(source file.Source, releases []string) string {
	for _, path := range releases {
		data, err := readAll(source, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fallbackDistribution
		}
		return idFrom(data)
	}
	return fallbackDistribution
}

// idFrom reads ID out of an os-release file.
//
// THE VALUE IS CHECKED AGAINST THE SPECIFICATION BEFORE IT IS PRINTED, because
// it is text from the machine being diagnosed and it lands in every surface of
// the report. os-release(5): "A lower-case string (no spaces or other characters
// outside of 0-9, a-z, ".", "_" and "-")". Anything else is not an ID and gets
// the default - a value that needed escaping cannot be a valid one. The last
// assignment wins, the way the shell that may source this file would read it.
func idFrom(data []byte) string {
	id := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		key, value, found := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if found && key == "ID" {
			id = unquoted(value)
		}
	}
	if !validID(id) {
		return fallbackDistribution
	}
	return id
}

// unquoted takes off one pair of matching quotes, which os-release(5) allows
// around any value.
func unquoted(value string) string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}

// validID reports whether a value is an ID as os-release(5) defines one. The
// length bound is ours - an ID is a word, and a report should not carry a page.
func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// readAll is the one place this file turns the port into bytes.
func readAll(source file.Source, path string) ([]byte, error) {
	reader, err := source(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}
