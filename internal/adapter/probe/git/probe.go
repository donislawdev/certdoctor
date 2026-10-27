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
// env is passed in rather than read here because this package must not read the
// environment: the same rule redact follows, and for the same reason - an
// assessment has to be reproducible from its input. Which configuration files
// git reads is worked out from it, OBS179. files lists the directories a build
// may read beside its CA file, and run asks the package database on a Linux that
// keeps it out of reach of a plain file read - ADR110.
func Probe(source file.Source, resolve file.Resolve, files file.List, run probe.Runner, pathDirs []string, env Environment,
	now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		installs := find(source, resolve, systemConfigs, pathDirs)
		if len(installs) == 0 {
			// NOT AN ERROR. docs/20 rule 1: a runtime that is not here sits
			// outside the matrix, and "git is not installed" is not a fact about
			// trust.
			return nil, nil
		}

		ports := probe.Ports{Source: source, Resolve: resolve, Run: run}
		stores := make([]report.TrustStore, 0, len(installs))
		for _, install := range installs {
			store := storeFor(ctx, ports, files, install, readSettings(source, install.SystemConfig, env), env, chain, now())
			store.SelectedBy = selectedBy(install, pathDirs)
			stores = append(stores, store)
		}
		return stores, nil
	}
}

// storeFor turns one installation into one row of the matrix.
func storeFor(ctx context.Context, ports probe.Ports, files file.List, install Install, settings Settings, env Environment,
	chain [][]byte, now time.Time) report.TrustStore {
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
	// A KEY SET UNDER A CONDITION THIS PROGRAM DOES NOT EVALUATE DECIDES
	// NOTHING EITHER - OBS179, decided by the owner 2026-10-20. Whether an
	// [includeIf] holds depends on a repository and whether an [http "<url>"]
	// section applies depends on the address, so the general value beside it is
	// not known to be the one git uses.
	if why := conditional(settings, env); why != "" {
		store.NotAssessed = why
		return store
	}
	// A GIT THAT DOES NOT VERIFY ASKS NO STORE, whichever backend it names -
	// ADR110 part 1. Any store's answer here would be about a check git skips.
	if why := verificationOff(settings, env); why != "" {
		store.NotAssessed = why
		return store
	}

	switch {
	case settings.Backend == "openssl":
		if namesNothing(settings, env) {
			store.NotAssessed = "git is set to use openssl and neither http.sslCAInfo nor GIT_SSL_CAINFO names a file, " +
				"so the bundle it would read is its build-time default"
			return store
		}
		return judgedByAFile(store, ports.Source, files, settings, env, chain, now)
	case settings.Backend == "schannel":
		// THE ANSWER BELONGS TO ANOTHER PROBE AND SAYING SO IS THE HONEST ROW.
		// Reporting "trusted" here would mean this probe silently answered a
		// question about the Windows store, which is system-store's job. Claiming
		// failure would be worse.
		store.NotAssessed = "this install is configured to use the platform store, which the system-store probe answers"
	case settings.BackendLevel == "":
		return noBackendNamed(ctx, store, ports, files, install, settings, env, chain, now)
	default:
		// AN EMPTY BACKEND IS NAMED TOO - http.c hands it to
		// curl_global_sslset, which knows no backend called that, and git stops.
		store.NotAssessed = fmt.Sprintf(
			"http.sslBackend is %q at the %s level, which this program does not know how to follow",
			settings.Backend, settings.BackendLevel)
	}
	return store
}

// noBackendNamed writes the row of a git that names no http.sslBackend.
//
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
//
// AND NOTHING NAMED ON LINUX IS ANSWERED BY THE PLATFORM STORE when this
// is the distribution's own git - ADR110, measured by S26 the same day
// with the same two packages. Condition 4 holds by the time a row gets
// here: storeFor has already sent away an unreadable or conditional
// configuration, a check switched off and a named backend, and a
// variable or key naming a file or a directory goes to judgedByAFile
// below. A NAMED BACKEND NEVER DEFERS:
// condition 4 lists http.sslBackend, and OBS184 records a libcurl built
// with one backend refusing another one by name.
func noBackendNamed(ctx context.Context, store report.TrustStore, ports probe.Ports, files file.List, install Install,
	settings Settings, env Environment, chain [][]byte, now time.Time) report.TrustStore {
	const compiledIn = "git names no http.sslBackend, so it uses the one libcurl was built with, and the store that " +
		"build reads is compiled into it"
	switch {
	case env.Platform != "linux":
		store.NotAssessed = compiledIn
	case namesNothing(settings, env):
		return probe.DeferToThePlatform(ctx, store, ports, probe.LibcurlBuilds, binaryOf(install), "git", compiledIn)
	default:
		return judgedByAFile(store, ports.Source, files, settings, env, chain, now)
	}
	return store
}

// conditional names the first key set under a condition that would change what
// this row says, or returns the empty string when none would. A git that does
// not verify asks no store whatever the condition, and a variable git reads
// after its configuration makes the configured key beside it irrelevant.
func conditional(settings Settings, env Environment) string {
	if env.NoVerify || len(settings.Conditional) == 0 {
		return ""
	}
	overridden := map[string]bool{keyCAInfo: env.CAInfo.Set, keyCAPath: env.CAPath.Set}
	for _, key := range decisiveKeys {
		if why, present := settings.Conditional[key]; present && !overridden[key] {
			return why
		}
	}
	return settings.Conditional[""]
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
			settings.Verify, settings.VerifyLevel)
	case !on:
		return fmt.Sprintf("http.sslVerify is false at the %s level, so git does not verify the server's certificate "+
			"at all and no store decides what it makes of the chain", settings.VerifyLevel)
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
//
// IT IS ASKED ONLY WHEN SOMETHING NAMES A FILE OR A DIRECTORY - namesNothing is
// the caller's question, because what nothing named means depends on the
// backend and the platform.
func judgedByAFile(store report.TrustStore, source file.Source, files file.List, settings Settings, env Environment,
	chain [][]byte, now time.Time) report.TrustStore {
	if named, directory := caDirectory(settings, env); named != "" {
		if directory == "" {
			store.NotAssessed = fmt.Sprintf("%s is set and empty, which git hands its libcurl as the name of a "+
				"directory, and what the library then reads was not established", named)
			return store
		}
		store.NotAssessed = fmt.Sprintf("%s names the directory %s, which git hands its libcurl beside any CA file, and "+
			"which certificates there count depends on the TLS library it was built with, which this program does not check",
			named, directory)
		return store
	}
	named, path := caFile(settings, env)
	if path == "" {
		store.NotAssessed = fmt.Sprintf("%s is set and empty, which git hands its libcurl as the name of a file, and "+
			"what the library then reads was not established", named)
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
	store.FileEnd = probe.EndOf(bundle)
	probe.Verify(&store, bundle, chain, now)
	probe.WeighDirectories(&store, source, files, probe.CADirectoriesOn(env.Platform), bundle, chain, now,
		probe.LibcurlDirectorySentences(named, "git"))
	return store
}

// caFile is the file git hands its libcurl, and what named it. A key written
// with an empty value is set - git hands libcurl the empty name - so the level
// says whether it was written, not the value.
func caFile(settings Settings, env Environment) (named, path string) {
	switch {
	case env.CAInfo.Set:
		return "GIT_SSL_CAINFO", env.CAInfo.Value
	case settings.CAInfoLevel != "":
		return "http.sslCAInfo", settings.CAInfo
	}
	return "", ""
}

// namesNothing says whether neither a variable nor the configuration names a CA
// file or a directory for git's libcurl.
func namesNothing(settings Settings, env Environment) bool {
	file, _ := caFile(settings, env)
	directory, _ := caDirectory(settings, env)
	return file == "" && directory == ""
}

// binaryOf is the git binary of an install, or nothing for one found only by its
// configuration - there is no binary to ask a package database about.
func binaryOf(install Install) string {
	if !install.OnPath {
		return ""
	}
	return install.Instance
}

// caDirectory is the directory git hands its libcurl, and what named it.
func caDirectory(settings Settings, env Environment) (named, path string) {
	switch {
	case env.CAPath.Set:
		return "GIT_SSL_CAPATH", env.CAPath.Value
	case settings.CAPathLevel != "":
		return "http.sslCAPath", settings.CAPath
	}
	return "", ""
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
