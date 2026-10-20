// Package git answers what git on this machine makes of a presented chain.
//
// IT RUNS NO PROCESS, and that is measured rather than preferred. On 2026-08-18
// the two values that decide everything here - http.sslBackend and
// http.sslCAInfo - were read straight out of C:/Program Files/Git/etc/gitconfig,
// which is plain INI. ADR49 keeps process execution to one file for good
// reasons; a probe that does not need it does not get it.
//
// WHY GIT IS THE TEXTBOOK CASE FOR THIS WHOLE PRODUCT, measured on the same day:
// git reports sslbackend=openssl and reads its OWN bundle, while the
// curl.exe sitting in the same install directory is built on Schannel and asks
// Windows. Adding a company CA to the Windows store fixes one and not the other,
// and no other tool will tell somebody that.
package git

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
)

// Install is one git installation found on this machine.
type Install struct {
	// Instance is the identity a person reads and what tells two installations
	// apart: the binary where one was found, and the install directory where
	// only a config was.
	Instance string
	// OnPath says this installation was found by walking PATH, so a command
	// somebody types reaches it.
	OnPath bool
	// Root is the install directory. It answers selected_by for an installation
	// found by its config rather than by its binary, and nothing else.
	Root string
	// SystemConfig is the gitconfig this installation reads, and EMPTY IS AN
	// ORDINARY ANSWER rather than a gap - OBS72. Measured 2026-08-19 and again
	// 2026-09-02 in the bench image: git 2.54.0 there has no config file at any
	// level, and "git config --list --show-origin" prints nothing at all.
	SystemConfig string
	// Architecture is x86 where the path says so, and x64 otherwise. Measured on
	// this machine for Java: two installs differing ONLY by "(x86)" have separate
	// stores and therefore separate answers.
	Architecture string
}

// systemConfigs are the places a git installation keeps its system-level config
// when no binary on PATH claimed one.
//
// IT IS A FALLBACK AND NO LONGER THE PROOF - OBS72. Git for Windows can be
// installed without putting anything on PATH, and that install still has this
// file and still reads a store; dropping the list would swap one false negative
// for another. What it must not do again is decide whether git EXISTS.
var systemConfigs = []string{
	`C:\Program Files\Git\etc\gitconfig`,
	`C:\Program Files (x86)\Git\etc\gitconfig`,
	"/etc/gitconfig",
	"/usr/local/etc/gitconfig",
	"/opt/homebrew/etc/gitconfig",
}

// Settings are the values in git's configuration that decide which store git
// uses and whether it asks one at all, plus where each came from.
//
// LEVEL IS CARRIED BECAUSE IT CHANGES THE ADVICE. Measured: on this machine both
// values come from the SYSTEM level, chosen when git was installed - so on a
// colleague's machine the backend may be schannel and the correct fix is the
// opposite one. A report that says "openssl" without saying who said so invites
// a fix that the next machine will not need.
type Settings struct {
	Backend      string
	BackendLevel string
	CAInfo       string
	CAInfoLevel  string
	// CAPath is http.sslCAPath - a directory git hands its libcurl beside the
	// file, ADR110 part 1.
	CAPath      string
	CAPathLevel string
	// Verify is http.sslVerify as written, and VerifyLevel says it was written at
	// all - an empty value is an answer here, because git reads it as false.
	Verify      string
	VerifyLevel string
	// Unreadable names a config file this program could not read to the end -
	// P3-1. bufio.Scanner stops on a line longer than its buffer and reports it
	// only if somebody asks, and nobody did: a config whose reading stopped
	// halfway came out as a config that simply does not set anything. The store
	// path would then be missing, the row would say git uses its built-in
	// default, and a remediation command could name the wrong file - all from a
	// read that never finished. Empty means every file was read to the end.
	Unreadable string
}

// Environment is what this package is handed by the entry point, so the package
// reads nothing of its own - ADR110 part 1.
type Environment struct {
	// Platform is the platform this program runs on, as runtime.GOOS spells it.
	Platform string
	// CAInfo and CAPath are GIT_SSL_CAINFO and GIT_SSL_CAPATH, and they win over
	// the configuration whenever they are SET - an empty value included.
	CAInfo, CAPath Variable
	// NoVerify is GIT_SSL_NO_VERIFY being set at all, whatever its value.
	NoVerify bool
}

// Variable is one environment variable, where being set is an answer of its own.
type Variable struct {
	Value string
	Set   bool
}

// EnvironmentFrom reads every variable this package needs, through lookup.
//
// SOURCE, inviolable rule 18: http.c of git 2.54.0, http_init and set_from_env,
// read 2026-10-20 at https://github.com/git/git/blob/v2.54.0/http.c - the three
// are read after the configuration and override it, and each acts on getenv
// returning anything at all. Measured by S26 the same day in three images: an
// empty GIT_SSL_NO_VERIFY switched verification off, and GIT_SSL_CAINFO and
// GIT_SSL_CAPATH were followed while curl's own variables were not. Which is why
// the port is a lookup and not a getter - a getter cannot tell empty from unset.
func EnvironmentFrom(lookup func(string) (string, bool), platform string) Environment {
	variable := func(name string) Variable {
		value, set := lookup(name)
		return Variable{Value: value, Set: set}
	}
	_, noVerify := lookup("GIT_SSL_NO_VERIFY")
	return Environment{
		Platform: platform,
		CAInfo:   variable("GIT_SSL_CAINFO"),
		CAPath:   variable("GIT_SSL_CAPATH"),
		NoVerify: noVerify,
	}
}

// find returns every git installation this machine has.
//
// THE BINARY IS WHAT PROVES ONE, AND THE CONFIGURATION PROVES NOTHING - OBS72,
// and this is the line that used to be the other way round. A git config file
// is OPTIONAL: measured in the bench image, git 2.54.0 has none at any level
// while /usr/bin/git sits there reading some store. Requiring one meant git
// dropped out of the matrix beside the runtimes that are genuinely absent -
// silence about somebody's machine, where inviolable rule 15 asks for an
// UNKNOWN carrying a reason.
//
// IT IS A SEARCH OF PATH AND NOT A SELECTION FROM IT - ADR50. The ban in ADR48
// part 4 is on taking the ONE binary PATH puts first; walking every directory
// and keeping every hit produces the matrix rather than a favourite. Measured
// 2026-09-02: this machine has git.exe in two PATH directories.
//
// AND THE FALLBACK RUNS SECOND SO IT CANNOT DOUBLE-COUNT. A config already
// claimed by a binary is not a second installation - on this machine both
// binaries name C:\Program Files\Git\etc\gitconfig, which is also in the list
// above, and without this the matrix would report three gits where there are
// two.
func find(source file.Source, resolve file.Resolve, candidates []string, pathDirs []string) []Install {
	var found []Install
	claimed := map[string]bool{}

	for _, binary := range probe.Binaries(source, resolve, pathDirs, "git.exe", "git") {
		config := systemConfigNear(source, binary)
		if config != "" {
			claimed[probe.PathKey(config)] = true
		}
		found = append(found, Install{
			Instance:     binary,
			OnPath:       true,
			Root:         filepath.Dir(binary),
			SystemConfig: config,
			Architecture: architectureOf(binary),
		})
	}

	for _, config := range candidates {
		if claimed[probe.PathKey(config)] {
			continue
		}
		reader, err := source(config)
		if err != nil {
			continue
		}
		_ = reader.Close()
		root := filepath.Dir(filepath.Dir(config))
		found = append(found, Install{
			Instance:     root,
			Root:         root,
			SystemConfig: config,
			Architecture: architectureOf(config),
		})
	}
	return found
}

// systemConfigNear finds the system config belonging to one git binary.
//
// THE CANDIDATES ARE MEASURED BY ASKING THE BINARIES THEMSELVES, 2026-09-02,
// which is the only honest way to claim where somebody else's program looks -
// inviolable rule 18. Both git.exe on this machine answered
// "git config --list --show-origin --system" with C:/Program Files/Git/etc/
// gitconfig: one directory up for C:\Program Files\Git\cmd\git.exe, two for
// C:\Program Files\Git\mingw64\bin\git.exe, whose own mingw64\etc\gitconfig
// does not exist. Two up is also what reaches /etc/gitconfig from /usr/bin/git,
// and one up is what reaches /usr/local/etc/gitconfig and the homebrew prefix.
//
// FINDING NOTHING IS AN ANSWER AND NOT A FAILURE. The row then says git uses
// whatever libcurl it was built with, which is a true sentence about a machine
// with no git configuration on it.
func systemConfigNear(source file.Source, binary string) string {
	dir := filepath.Dir(binary)
	for _, candidate := range []string{
		filepath.Join(dir, "..", "etc", "gitconfig"),
		filepath.Join(dir, "..", "..", "etc", "gitconfig"),
	} {
		candidate = filepath.Clean(candidate)
		reader, err := source(candidate)
		if err != nil {
			continue
		}
		_ = reader.Close()
		return candidate
	}
	return ""
}

// architectureOf reads the bitness off a path, because two installs differing
// ONLY by "(x86)" have separate stores and separate answers.
func architectureOf(path string) string {
	if strings.Contains(path, "(x86)") {
		return "x86"
	}
	return "x64"
}

// readSettings applies the config files in git's own precedence order.
//
// SYSTEM FIRST, THEN GLOBAL, and later wins - which is git's documented order
// and the reason the level travels with the value. Measured on this machine:
// system sets sslBackend and sslCAInfo, the user's ~/.gitconfig sets only
// http.postBuffer, so system is what actually decides.
//
// WHAT THIS DOES NOT READ, said here rather than discovered later. Repository
// level config, because a probe answers about the MACHINE and there is no
// repository in the question. Conditional includes and [http "<url>"] subsection
// overrides, which can both change the answer for one specific remote - the
// report says what the general setting is, and a subsection aimed at one host
// would not show up. Neither is silent: both are named in the descriptor.
// THE SYSTEM CONFIG ARRIVES NAMED RATHER THAN RECOGNISED, and that is a defect
// removed rather than a tidier signature. The level used to be decided by
// asking whether a path was in systemConfigs, which stopped being true the
// moment a config could be found NEXT TO A BINARY: C:\Program Files\Git\mingw64
// \etc\gitconfig is a system config that list has never heard of, and it would
// have been reported at global level - in the one field that decides whether a
// colleague needs the same fix or the opposite one.
func readSettings(source file.Source, systemConfig string, globals []string) Settings {
	var s Settings
	if systemConfig != "" {
		s.apply(source, systemConfig, "system")
	}
	for _, path := range globals {
		s.apply(source, path, "global")
	}
	return s
}

// apply folds one config file into the settings, at the level it was read from.
func (s *Settings) apply(source file.Source, path, level string) {
	values, err := parse(source, path)
	if err != nil && s.Unreadable == "" {
		// THE FIRST ONE, AND IT DOES NOT STOP THE WALK. The later files may
		// still be readable, and what they set is worth reading - what is not
		// worth doing is concluding anything from what was NOT found.
		s.Unreadable = fmt.Sprintf("%s could not be read to the end: %v", path, err)
	}
	for key, value := range values {
		switch key {
		case "http.sslbackend":
			s.Backend, s.BackendLevel = value, level
		case "http.sslcainfo":
			s.CAInfo, s.CAInfoLevel = value, level
		case "http.sslcapath":
			s.CAPath, s.CAPathLevel = value, level
		case "http.sslverify":
			s.Verify, s.VerifyLevel = value, level
		}
	}
}

// boolean reads a value the way git reads a boolean, and says whether git reads
// it at all.
//
// SOURCE, inviolable rule 18: parse.c of git 2.54.0, git_parse_maybe_bool_text
// and git_parse_maybe_bool, read 2026-10-20 at
// https://github.com/git/git/blob/v2.54.0/parse.c - true, yes and on are true,
// false, no, off and the empty string are false, in any case, and an integer is
// true unless it is zero. Anything else stops git with an error. git also takes
// an integer with a k, m or g after it, and that one this program does not read -
// the row says so rather than guessing which way it goes.
func boolean(value string) (on, read bool) {
	switch strings.ToLower(value) {
	case "true", "yes", "on":
		return true, true
	case "", "false", "no", "off":
		return false, true
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return false, false
	}
	return n != 0, true
}

// parse reads the [http] section of one config file into lower-cased keys.
//
// IT READS ONLY WHAT IT UNDERSTANDS AND SAYS SO. git's config format has more in
// it than this - subsections, includes, multi-valued keys - and a parser that
// guessed at the rest would produce a confident wrong answer, which is worse
// here than no answer. The keys this needs are plain scalars in the [http]
// section on every machine measured.
func parse(source file.Source, path string) (map[string]string, error) {
	values := map[string]string{}
	reader, err := source(path)
	if err != nil {
		// A FILE THAT IS NOT THERE IS NOT A FAILURE TO READ ONE. Absence is the
		// ordinary state of a global gitconfig, and it says nothing was set.
		return values, nil
	}
	defer func() { _ = reader.Close() }()

	section := ""
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		if section == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			// A KEY STANDING ALONE IS TRUE TO GIT - parse.c of 2.54.0 reads a
			// value that is not there as true. Skipping it would let an earlier
			// "sslVerify = false" stand where git verifies again.
			value = "true"
		}
		values[section+"."+strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	// P3-1. Scan returning false means "no more lines" OR "I stopped" - a line
	// longer than the buffer, or a read that failed - and the two are told apart
	// only by asking. Unasked, a config read halfway looks like a config that
	// sets nothing.
	return values, scanner.Err()
}

// readAll is the one place this package turns a port into bytes.
func readAll(source file.Source, path string) ([]byte, error) {
	reader, err := source(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}
