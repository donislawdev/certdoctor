package curl

import (
	"context"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// withheld are the variables every process this probe starts goes without -
// OBS189, decided by the owner 2026-10-20, the rule ADR111 part 2 keeps for
// node. Each one, from curl 8.21.0, read 2026-10-20 at
// https://github.com/curl/curl/tree/curl-8_21_0/lib/vtls
//   - SSLKEYLOGFILE names a file libcurl opens for appending as its OpenSSL
//     backend starts - Curl_tls_keylog_open in keylog.c, called from ossl_init
//     in openssl.c - so curl --version alone creates it. Measured the same day
//     with curl 8.21.0 on OpenSSL 3.5.7 in an Alpine image: an empty file
//     appeared, against inviolable rule 14. Both Schannel builds on the owner's
//     machine left no file.
//   - OPENSSL_CONF names the configuration OpenSSL loads when ossl_init asks it
//     to, with OPENSSL_INIT_LOAD_CONFIG, and that file can name a provider
//     module, native code inside the process this program started. That curl
//     loads it was NOT measured - OpenSSL outside node passes over a missing
//     module silently - so this one rests on the source alone.
//
// The deferral's rpm runs through the same runner and loses the same two,
// which a child may always do.
var withheld = []string{"SSLKEYLOGFILE", "OPENSSL_CONF"}

// Probe builds the L5 probe for curl.
//
// env is read at the entry point and handed in, so this package touches no
// environment of its own. The CA variables are used ONLY for backends that
// honour them - which is the whole point of reading the backend first - and the
// home variables only to find the configuration file the tool would read. files
// lists the directories a build may read beside its CA file.
//
// start makes the runner from the variables to withhold, and this package names
// them - probe.Without is what the entry point hands in, as for node.
func Probe(source file.Source, resolve file.Resolve, files file.List, start func(withheld ...string) probe.Runner, pathDirs []string, env Environment, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		installs := find(source, resolve, pathDirs)
		if len(installs) == 0 {
			return nil, nil
		}

		ports := probe.Ports{Source: source, Resolve: resolve, Run: start(withheld...)}
		stores := make([]report.TrustStore, 0, len(installs))
		for _, install := range installs {
			stores = append(stores, storeFor(ctx, ports, files, install, chain, env, now()))
		}
		return stores, nil
	}
}

func storeFor(ctx context.Context, ports probe.Ports, files file.List, install Install, chain [][]byte, env Environment, now time.Time) report.TrustStore {
	store := report.TrustStore{
		Runtime:  "curl",
		Instance: install.Path,
		// THE PATH IS THE IDENTITY HERE, unlike java where it is a version. Two
		// curl binaries differ by nothing else a person could use to tell them
		// apart, which is why masking treats Instance as a path - ADR48.
		SelectedBy: []string{"PATH"},
		StoreForm:  report.StoreSystem,
	}

	backend, err := backendOf(ctx, ports.Run, install)
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
		return judgedByThisAccount(store, ports.Source, install, chain, env)
	}

	if backend != "openssl" && backend != "libressl" && backend != "boringssl" {
		// THE OTHER PLATFORM BACKENDS ASK THE PLATFORM TOO, and nothing here has
		// measured which store any of them reads - so no row is named as their
		// answer, and this one says it has none.
		store.NotAssessed = fmt.Sprintf(
			"this build uses %s, which reads the platform store rather than a file - the system-store probe answers for it", backend)
		return store
	}
	return judgedByAFile(ctx, store, ports, files, install, chain, env, now)
}

// judgedByAFile writes the row of a build that reads a CA file - ADR110 part 1.
//
// THE FILE IS THE ONE curl'S TOOL WOULD HAND ITS LIBRARY, in the tool's own
// order: the configuration file first, because a line in it wins over every
// variable, then the variables as caNamed reads them.
//
// A REFUSAL IS WEIGHED AGAINST THE DIRECTORIES THE BUILD MAY ALSO READ, decided
// by the owner 2026-10-20 on the measurement under probe.CADirectoriesOn: the
// Debian, Ubuntu and Alpine packages trusted a root kept only in /etc/ssl/certs
// while the named file lacked it, so a FAIL there would be false.
func judgedByAFile(ctx context.Context, store report.TrustStore, ports probe.Ports, files file.List, install Install, chain [][]byte,
	env Environment, now time.Time) report.TrustStore {
	if stopped := configFileStops(&store, ports.Source, configOrderOn(env.Platform), install, env); stopped {
		return store
	}
	variable, path := caNamed(env)
	switch variable {
	case "":
		// Nothing named falls back to whatever the build was compiled with,
		// and that is not something this program can read off disk without
		// guessing.
		//
		// ON LINUX THE DISTRIBUTION'S OWN BUILD IS ANSWERED BY THE PLATFORM
		// STORE - ADR110, measured by S26 on 2026-10-20 with curl from the
		// Debian, Ubuntu, Alpine and RHEL packages. Nothing curl's tool
		// honours names another file by now: the configuration file and all
		// three variables were ruled out above, which is condition 4.
		const compiledIn = "this build reads a CA file and none of CURL_CA_BUNDLE, SSL_CERT_FILE and SSL_CERT_DIR is " +
			"set, so the bundle it reads is its build-time default"
		if env.Platform == "linux" {
			return probe.DeferToThePlatform(ctx, store, ports, install.Path, "curl", compiledIn)
		}
		store.NotAssessed = compiledIn
		return store
	case "SSL_CERT_DIR":
		// MEASURED BY S26 ON 2026-10-20: a root in that directory counted only
		// under its hashed file name, and the same root under any other name did
		// not. Which names a directory holds is not something this program
		// checks, so the row says what it would have to know.
		store.NotAssessed = fmt.Sprintf("SSL_CERT_DIR names the directory %s, which this build reads beside its CA file, "+
			"and whether a certificate there counts depends on its hashed file name, which this program does not check", path)
		return store
	}

	store.StoreForm = report.StoreFile
	store.StorePath = path
	bundle, err := readAll(ports.Source, path)
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the bundle named by %s could not be read: %v", variable, err)
		return store
	}
	probe.Verify(&store, bundle, chain, now)
	probe.WeighDirectories(&store, ports.Source, files, probe.CADirectoriesOn(env.Platform), bundle, chain, now,
		probe.LibcurlDirectorySentences(variable, "curl"))
	return store
}

// configFileStops writes the row of a build whose configuration file this
// program could not rule out, and reports whether it did.
func configFileStops(store *report.TrustStore, source file.Source, order configOrder, install Install, env Environment) bool {
	found, unreadable := configFile(source, configCandidates(order, env.Homes, env.Account, install.Path))
	switch {
	case unreadable != "":
		store.NotAssessed = unreadable
		return true
	case found != "":
		store.NotAssessed = fmt.Sprintf("curl reads the configuration file %s on every run, and a line in it can name "+
			"a CA file or switch a certificate check off - this program does not read it", found)
		return true
	}
	return false
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
//
// THE CONFIGURATION FILE IS LOOKED FOR IN THE WINDOWS ORDER WHATEVER THE
// PLATFORM, because Schannel exists only there.
func judgedByThisAccount(store report.TrustStore, source file.Source, install Install, chain [][]byte, env Environment) report.TrustStore {
	if stopped := configFileStops(&store, source, windowsConfigOrder, install, env); stopped {
		return store
	}
	if len(chain) == 0 || len(chain[0]) == 0 {
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
