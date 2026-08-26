package git

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Probe builds the L5 probe for git.
//
// globalConfigs are the user-level config files, in git's precedence order. They
// are passed in rather than derived here because this package must not read the
// environment: the same rule redact follows, and for the same reason - an
// assessment has to be reproducible from its input.
func Probe(source file.Source, globalConfigs []string, pathDirs []string, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
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
			store := storeFor(source, install, readSettings(source, paths), chain, now())
			store.SelectedBy = selectedBy(install, pathDirs)
			stores = append(stores, store)
		}
		return stores, nil
	}
}

// storeFor turns one installation into one row of the matrix.
func storeFor(source file.Source, install Install, settings Settings, chain [][]byte, now time.Time) report.TrustStore {
	store := report.TrustStore{
		Runtime:      "git",
		Instance:     install.Root,
		Architecture: install.Architecture,
		Backend:      settings.Backend,
		SelectedBy:   []string{},
	}

	// A CONFIG THIS PROGRAM COULD NOT READ TO THE END DECIDES NOTHING - P3-1.
	// Every branch below concludes something from what the settings DO or do not
	// say, and a read that stopped halfway makes "does not say" meaningless. This
	// is inviolable rule 15 at the one place where the alternative is a
	// confident row built out of half a file.
	if settings.Unreadable != "" {
		store.StoreForm = report.StoreSystem
		store.NotAssessed = "this install's configuration could not be read in full, so what it points at is unknown: " +
			settings.Unreadable
		return store
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
		bundle, err := readAll(source, store.StorePath)
		if err != nil {
			// A bundle that cannot be read is UNKNOWN with a reason, never a
			// failure to trust - inviolable rule 15. It is also a real diagnosis:
			// the file port refuses a path that would leave this machine, so "your
			// bundle is on a file server" arrives here as this sentence.
			store.NotAssessed = fmt.Sprintf("the bundle named by http.sslCAInfo could not be read: %v", err)
			return store
		}
		probe.Verify(&store, bundle, chain, now)
	case "schannel":
		// THE ANSWER BELONGS TO ANOTHER PROBE AND SAYING SO IS THE HONEST ROW.
		// Reporting "trusted" here would mean this probe silently answered a
		// question about the Windows store, which is system-store's job. Claiming
		// failure would be worse.
		store.StoreForm = report.StoreSystem
		store.NotAssessed = "this install is configured to use the platform store, which the system-store probe answers"
	case "":
		// NAMING NO BACKEND IS THE ORDINARY CASE, NOT AN ODD ONE, and saying
		// otherwise was reporting our ignorance as news about somebody's machine
		// - the shape OBS67 records, where a rule written to catch OUR mistake
		// rejected data that was perfectly correct.
		//
		// git-config, Documentation/config/http.adoc, read 2026-08-19 at
		// https://git-scm.com/docs/git-config: http.sslBackend is the "Name of
		// the SSL backend to use", and it is simply absent on the many
		// installations that were built with one backend and never asked. Git
		// then uses whichever libcurl it was linked against, and which bundle
		// that reads is compiled in - not something this program can read off
		// disk without guessing.
		store.StoreForm = report.StoreSystem
		store.NotAssessed = "git names no http.sslBackend, so it uses the one libcurl was built with, and the store that build reads is compiled into it"
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

// selectedBy names what points at THIS installation, and an empty slice is an
// answer rather than a gap.
//
// IT ANSWERS "WHICH ONE DOES A TYPED COMMAND USE" AND NOTHING ELSE - ADR48 part
// 4. It is never a detection mechanism: measured on this machine, PATH names one
// of two curl binaries and JAVA_HOME one of six Java installs, so an install
// nothing selects is perfectly real and simply gets an empty list.
//
// THE MATCH IS ON A PATH SEGMENT, NOT A TEXT PREFIX, and that is the bug this
// function is written to avoid: "C:\Program Files\Git2\cmd" starts with
// "C:\Program Files\Git" as text, and reporting it as this install would credit
// one installation with another one's presence on PATH.
func selectedBy(install Install, pathDirs []string) []string {
	// AND IT FOLDS CASE WHERE THE PLATFORM DOES - P3-2, the half that was
	// missing. The rule lives in probe.SameOrInside so that the java probe asks
	// the same function rather than a copy of it.
	for _, dir := range pathDirs {
		if probe.SameOrInside(dir, install.Root) {
			return []string{"PATH"}
		}
	}
	return []string{}
}
