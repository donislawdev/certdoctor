package curl

import (
	"context"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Probe builds the L5 probe for curl.
//
// env is read at the entry point and handed in, so this package touches no
// environment of its own. CABundle is used ONLY for backends that honour it -
// which is the whole point of reading the backend first - and Homes only to find
// the configuration file a Schannel build would read.
func Probe(source file.Source, resolve file.Resolve, run probe.Runner, pathDirs []string, env Environment, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		installs := find(source, resolve, pathDirs)
		if len(installs) == 0 {
			return nil, nil
		}

		stores := make([]report.TrustStore, 0, len(installs))
		for _, install := range installs {
			stores = append(stores, storeFor(ctx, run, source, install, chain, env, now()))
		}
		return stores, nil
	}
}

func storeFor(ctx context.Context, run probe.Runner, source file.Source, install Install, chain [][]byte, env Environment, now time.Time) report.TrustStore {
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

	if backend == "schannel" {
		return judgedByThisAccount(store, source, install, chain, env.Homes)
	}

	if backend != "openssl" && backend != "libressl" && backend != "boringssl" {
		// THE OTHER PLATFORM BACKENDS ASK THE PLATFORM TOO, and nothing here has
		// measured which store any of them reads - so no row is named as their
		// answer, and this one says it has none.
		store.NotAssessed = fmt.Sprintf(
			"this build uses %s, which reads the platform store rather than a file - the system-store probe answers for it", backend)
		return store
	}

	if env.CABundle == "" {
		// An OpenSSL build with no bundle named falls back to whatever it was
		// compiled with, and that is not something this program can read off
		// disk without guessing.
		store.NotAssessed = "this build uses a file store and CURL_CA_BUNDLE is not set, so the bundle it would read is its build-time default"
		return store
	}

	store.StoreForm = report.StoreFile
	store.StorePath = env.CABundle
	bundle, err := readAll(source, env.CABundle)
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the bundle named by CURL_CA_BUNDLE could not be read: %v", err)
		return store
	}
	probe.Verify(&store, bundle, chain, now)
	return store
}

// judgedByThisAccount writes the row of a Schannel build - ADR108 part 4.
//
// THE ANSWER IS NOT THIS PROBE'S TO GIVE, AND IT IS NOT LEFT BLANK EITHER. Measured
// with probe S25 on 2026-10-20, both builds on the owner's machine: a root held
// in this account's Root store and not in the machine's was trusted, so Schannel
// judges with the engine the system-store row for CurrentUser was judged with.
// The row names that row, and the trust layer hands it that row's answer once
// every probe has been asked.
//
// WHAT ONLY THIS PROBE KNOWS IS SETTLED HERE: whether a configuration file could
// change all of that, and whether the server's certificate names anywhere to
// check its revocation - without which curl refuses it whatever the store says.
func judgedByThisAccount(store report.TrustStore, source file.Source, install Install, chain [][]byte, homes map[string]string) report.TrustStore {
	found, unreadable := configFile(source, configCandidates(homes, install.Path))
	switch {
	case unreadable != "":
		store.NotAssessed = unreadable
		return store
	case found != "":
		store.NotAssessed = fmt.Sprintf("curl reads the configuration file %s on every run, and it can name a CA file "+
			"or turn revocation checks off - this program does not read it", found)
		return store
	case len(chain) == 0 || len(chain[0]) == 0:
		store.NotAssessed = "no chain was presented, so there was nothing for this build to judge"
		return store
	}
	named, err := namesRevocation(chain[0])
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the server's certificate could not be read to see whether it names a revocation address: %v", err)
		return store
	}
	store.DefersTo = &report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: report.InstanceCurrentUser}
	if !named {
		refused := false
		store.TrustsPresentedChain = &refused
		store.TrustFailure = report.NoRevocationInfo
		return store
	}
	store.NotAssessed = "this build uses schannel, which judges by system-store CurrentUser"
	return store
}
