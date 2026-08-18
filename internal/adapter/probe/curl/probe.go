package curl

import (
	"context"
	"fmt"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Probe builds the L5 probe for curl.
//
// bundleFromEnv is the value of CURL_CA_BUNDLE, read at the entry point and
// handed in so this package touches no environment of its own. It is used ONLY
// for backends that honour it - which is the whole point of reading the backend
// first.
func Probe(source file.Source, run probe.Runner, pathDirs []string, bundleFromEnv string) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		installs := find(source, pathDirs)
		if len(installs) == 0 {
			return nil, nil
		}

		stores := make([]report.TrustStore, 0, len(installs))
		for _, install := range installs {
			stores = append(stores, storeFor(ctx, run, source, install, chain, bundleFromEnv))
		}
		return stores, nil
	}
}

func storeFor(ctx context.Context, run probe.Runner, source file.Source, install Install, chain [][]byte, bundleFromEnv string) report.TrustStore {
	store := report.TrustStore{
		Runtime:  "curl",
		Instance: install.Path,
		// THE PATH IS THE IDENTITY HERE, unlike java where it is a version. Two
		// curl binaries differ by nothing else a person could use to tell them
		// apart, which is why masking treats Instance as a path - ADR48.
		SelectedBy: []string{"PATH"},
		StoreForm:  report.StoreSystem,
	}

	backend, err := backendOf(ctx, run, install)
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the backend could not be established: %v", err)
		return store
	}
	if backend == "" {
		// AN UNRECOGNISED BACKEND IS UNKNOWN, NEVER A GUESS. Picking the
		// commonest one and generating a fix for it is how somebody ends up
		// running a command that does nothing.
		store.NotAssessed = "this build reports a TLS backend this program does not recognise, so which store it reads is undetermined"
		return store
	}
	store.Backend = backend

	if backend != "openssl" && backend != "libressl" && backend != "boringssl" {
		// SCHANNEL AND FRIENDS ASK THE PLATFORM, AND THE PLATFORM STORE IS
		// system-store's QUESTION. Answering it here would mean this probe
		// quietly claimed a verdict about a store it never opened.
		store.NotAssessed = fmt.Sprintf(
			"this build uses %s, which reads the platform store rather than a file - the system-store probe answers for it", backend)
		return store
	}

	if bundleFromEnv == "" {
		// An OpenSSL build with no bundle named falls back to whatever it was
		// compiled with, and that is not something this program can read off
		// disk without guessing.
		store.NotAssessed = "this build uses a file store and CURL_CA_BUNDLE is not set, so the bundle it would read is its build-time default"
		return store
	}

	store.StoreForm = report.StoreFile
	store.StorePath = bundleFromEnv
	bundle, err := readAll(source, bundleFromEnv)
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the bundle named by CURL_CA_BUNDLE could not be read: %v", err)
		return store
	}
	probe.Verify(&store, bundle, chain)
	return store
}
