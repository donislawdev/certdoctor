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
// and env are passed in rather than derived here because this package must not
// read the environment: the same rule redact follows, and for the same reason -
// an assessment has to be reproducible from its input. files lists the
// directories a build may read beside its CA file.
func Probe(source file.Source, resolve file.Resolve, files file.List, globalConfigs []string, pathDirs []string, env Environment, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(_ context.Context, chain [][]byte) ([]report.TrustStore, error) {
		installs := find(source, resolve, systemConfigs, pathDirs)
		if len(installs) == 0 {
			// NOT AN ERROR. docs/20 rule 1: a runtime that is not here sits
			// outside the matrix, and "git is not installed" is not a fact about
			// trust.
			return nil, nil
		}

		stores := make([]report.TrustStore, 0, len(installs))
		for _, install := range installs {
			store := storeFor(source, files, install, readSettings(source, install.SystemConfig, globalConfigs), env, chain, now())
			store.SelectedBy = selectedBy(install, pathDirs)
			stores = append(stores, store)
		}
		return stores, nil
	}
}

// storeFor turns one installation into one row of the matrix.
func storeFor(source file.Source, files file.List, install Install, settings Settings, env Environment, chain [][]byte, now time.Time) report.TrustStore {
	store := report.TrustStore{
		Runtime:      "git",
		Instance:     install.Instance,
		Architecture: install.Architecture,
		Backend:      settings.Backend,
		SelectedBy:   []string{},
		StoreForm:    report.StoreSystem,
	}

	// A CONFIG THIS PROGRAM COULD NOT READ TO THE END DECIDES NOTHING - P3-1.
	// Every branch below concludes something from what the settings DO or do not
	// say, and a read that stopped halfway makes "does not say" meaningless. This
	// is inviolable rule 15 at the one place where the alternative is a
	// confident row built out of half a file.
	if settings.Unreadable != "" {
		store.NotAssessed = "this install's configuration could not be read in full, so what it points at is unknown: " +
			settings.Unreadable
		return store
	}
	// A GIT THAT DOES NOT VERIFY ASKS NO STORE, whichever backend it names -
	// ADR110 part 1. Any store's answer here would be about a check git skips.
	if why := verificationOff(settings, env); why != "" {
		store.NotAssessed = why
		return store
	}

	switch settings.Backend {
	case "openssl":
		return judgedByAFile(store, source, files, settings, env, chain, now,
			"git is set to use openssl and neither http.sslCAInfo nor GIT_SSL_CAINFO names a file, so the bundle it would "+
				"read is its build-time default")
	case "schannel":
		// THE ANSWER BELONGS TO ANOTHER PROBE AND SAYING SO IS THE HONEST ROW.
		// Reporting "trusted" here would mean this probe silently answered a
		// question about the Windows store, which is system-store's job. Claiming
		// failure would be worse.
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
		//
		// A FILE NAMED ON LINUX IS READ, because that is measured - S26 on
		// 2026-10-20: git from the Debian package (libcurl on GnuTLS) and from
		// the Alpine one (libcurl on OpenSSL) trusted a root that GIT_SSL_CAINFO
		// or http.sslCAInfo named, with no backend named. Elsewhere nothing was
		// measured, and the row stays as it was.
		const compiledIn = "git names no http.sslBackend, so it uses the one libcurl was built with, and the store that " +
			"build reads is compiled into it"
		if env.Platform == "linux" {
			return judgedByAFile(store, source, files, settings, env, chain, now, compiledIn)
		}
		store.NotAssessed = compiledIn
	default:
		store.NotAssessed = fmt.Sprintf(
			"http.sslBackend is %q at the %s level, which this program does not know how to follow",
			settings.Backend, level(settings.BackendLevel))
	}
	return store
}

// verificationOff names what switched git's certificate check off, or returns
// the empty string when nothing did. The sources are on EnvironmentFrom and on
// boolean.
func verificationOff(settings Settings, env Environment) string {
	if env.NoVerify {
		return "GIT_SSL_NO_VERIFY is set, so git does not verify the server's certificate at all and no store decides " +
			"what it makes of the chain"
	}
	if settings.VerifyLevel == "" {
		return ""
	}
	on, read := boolean(settings.Verify)
	switch {
	case !read:
		return fmt.Sprintf("http.sslVerify is %q at the %s level, which this program does not read as true or false",
			settings.Verify, level(settings.VerifyLevel))
	case !on:
		return fmt.Sprintf("http.sslVerify is false at the %s level, so git does not verify the server's certificate "+
			"at all and no store decides what it makes of the chain", level(settings.VerifyLevel))
	}
	return ""
}

// judgedByAFile writes the row of a git whose libcurl reads a CA file.
//
// THE ENVIRONMENT WINS OVER THE CONFIGURATION, and a directory beside the file
// leaves the row without a verdict - http.c of git 2.54.0, where GIT_SSL_CAINFO
// and GIT_SSL_CAPATH are read after the configuration, and a directory is handed
// to libcurl on its own. Which certificates in a directory count depends on the
// TLS library: S26 measured git on GnuTLS taking a root under any file name and
// git on OpenSSL only under its hashed one.
//
// A REFUSAL IS WEIGHED AGAINST THE DIRECTORIES THE BUILD MAY ALSO READ, decided
// by the owner 2026-10-20 on the measurement under probe.CADirectoriesOn.
func judgedByAFile(store report.TrustStore, source file.Source, files file.List, settings Settings, env Environment,
	chain [][]byte, now time.Time, nothingNamed string) report.TrustStore {
	if named, directory := caDirectory(settings, env); named != "" {
		store.NotAssessed = fmt.Sprintf("%s names the directory %s, which git hands its libcurl beside any CA file, and "+
			"which certificates there count depends on the TLS library it was built with, which this program does not check",
			named, directory)
		return store
	}
	named, path := caFile(settings, env)
	switch {
	case named == "":
		store.NotAssessed = nothingNamed
		return store
	case path == "":
		store.NotAssessed = "GIT_SSL_CAINFO is set and empty, which git hands its libcurl as the name of a file, and " +
			"what the library then reads was not established"
		return store
	}

	store.StoreForm = report.StoreFile
	store.StorePath = filepath.Clean(path)
	bundle, err := readAll(source, store.StorePath)
	if err != nil {
		// A bundle that cannot be read is UNKNOWN with a reason, never a
		// failure to trust - inviolable rule 15. It is also a real diagnosis:
		// the file port refuses a path that would leave this machine, so "your
		// bundle is on a file server" arrives here as this sentence.
		store.NotAssessed = fmt.Sprintf("the bundle named by %s could not be read: %v", named, err)
		return store
	}
	probe.Verify(&store, bundle, chain, now)
	probe.WeighDirectories(&store, source, files, probe.CADirectoriesOn(env.Platform), bundle, chain, now,
		probe.LibcurlDirectorySentences(named, "git"))
	return store
}

// caFile is the file git hands its libcurl, and what named it.
func caFile(settings Settings, env Environment) (named, path string) {
	switch {
	case env.CAInfo.Set:
		return "GIT_SSL_CAINFO", env.CAInfo.Value
	case settings.CAInfo != "":
		return "http.sslCAInfo", settings.CAInfo
	}
	return "", ""
}

// caDirectory is the directory git hands its libcurl, and what named it.
func caDirectory(settings Settings, env Environment) (named, path string) {
	switch {
	case env.CAPath.Set:
		return "GIT_SSL_CAPATH", env.CAPath.Value
	case settings.CAPath != "":
		return "http.sslCAPath", settings.CAPath
	}
	return "", ""
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
//
// AN INSTALLATION FOUND ON PATH ANSWERS THIS WITHOUT LOOKING AGAIN, and saying
// so is not the thing ADR48 part 4 bans. That ban is on letting PATH pick ONE
// installation; this walked all of them, and reporting afterwards that a typed
// command reaches this one is a property of the row, not the way it was found.
func selectedBy(install Install, pathDirs []string) []string {
	if install.OnPath {
		return []string{"PATH"}
	}
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
