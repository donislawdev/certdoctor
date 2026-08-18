package git

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Probe builds the L5 probe for git.
//
// globalConfigs are the user-level config files, in git's precedence order. They
// are passed in rather than derived here because this package must not read the
// environment: the same rule redact follows, and for the same reason - an
// assessment has to be reproducible from its input.
func Probe(source file.Source, globalConfigs []string) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(_ context.Context, chain [][]byte) ([]report.TrustStore, error) {
		installs := find(source, systemConfigs)
		if len(installs) == 0 {
			// NOT AN ERROR. docs/20 rule 1: a runtime that is not here sits
			// outside the matrix, and "git is not installed" is not a fact about
			// trust.
			return nil, nil
		}

		stores := make([]report.TrustStore, 0, len(installs))
		for _, install := range installs {
			paths := append([]string{install.SystemConfig}, globalConfigs...)
			stores = append(stores, storeFor(source, install, readSettings(source, paths), chain))
		}
		return stores, nil
	}
}

// storeFor turns one installation into one row of the matrix.
func storeFor(source file.Source, install Install, settings Settings, chain [][]byte) report.TrustStore {
	store := report.TrustStore{
		Runtime:      "git",
		Instance:     install.Root,
		Architecture: install.Architecture,
		Backend:      settings.Backend,
		SelectedBy:   []string{},
	}

	switch settings.Backend {
	case "openssl":
		store.StoreForm = report.StoreFile
		store.StorePath = filepath.Clean(settings.CAInfo)
		if settings.CAInfo == "" {
			// openssl with no bundle named means git falls back to its build-time
			// default, which is not something this program can read off disk.
			store.StorePath = ""
			store.StoreForm = report.StoreSystem
			store.NotAssessed = "git is set to use openssl and names no http.sslCAInfo, so the bundle it would read is its build-time default"
			return store
		}
		assess(source, &store, chain)
	case "schannel":
		// THE ANSWER BELONGS TO ANOTHER PROBE AND SAYING SO IS THE HONEST ROW.
		// Reporting "trusted" here would mean this probe silently answered a
		// question about the Windows store, which is system-store's job. Claiming
		// failure would be worse.
		store.StoreForm = report.StoreSystem
		store.NotAssessed = "this install is configured to use the platform store, which the system-store probe answers"
	default:
		store.StoreForm = report.StoreSystem
		store.NotAssessed = fmt.Sprintf(
			"http.sslBackend is %q at the %s level, which this program does not know how to follow",
			settings.Backend, level(settings.BackendLevel))
	}
	return store
}

func level(l string) string {
	if l == "" {
		return "default"
	}
	return l
}

// assess reads the bundle and asks whether the presented chain builds a path in
// it.
//
// THE NAME IS NOT CHECKED, DELIBERATELY. This asks "does this store contain an
// anchor that closes this chain", which is L5's question. Whether the certificate
// is valid FOR THE HOST is a different question with a different answer, and
// folding them together would report a trust failure for a name mismatch.
func assess(source file.Source, store *report.TrustStore, chain [][]byte) {
	bundle, err := readAll(source, store.StorePath)
	if err != nil {
		// A bundle that cannot be read is UNKNOWN with a reason, never a failure
		// to trust - inviolable rule 15. It is also a real diagnosis on its own:
		// the file port refuses a path that would leave this machine, so "your
		// bundle is on a file server" arrives here as this sentence.
		store.NotAssessed = fmt.Sprintf("the bundle named by http.sslCAInfo could not be read: %v", err)
		return
	}

	roots := x509.NewCertPool()
	anchors := 0
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		anchor, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			// One unreadable entry in somebody's bundle is not a reason to
			// discard the rest of it.
			continue
		}
		roots.AddCert(anchor)
		anchors++
	}
	store.TrustAnchorCount = anchors

	if anchors == 0 {
		store.NotAssessed = "the file named by http.sslCAInfo holds no certificate this program could read"
		return
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the presented leaf could not be parsed: %v", err)
		return
	}
	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		if certificate, parseErr := x509.ParseCertificate(der); parseErr == nil {
			intermediates.AddCert(certificate)
		}
	}

	_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
	trusts := verifyErr == nil
	store.TrustsPresentedChain = &trusts
}
