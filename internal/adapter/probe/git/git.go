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
	// Unreadable says where git stops reading its configuration, or where this
	// program cannot follow it - P3-1 and OBS179. A config whose reading stopped
	// halfway once came out as a config that simply does not set anything: the
	// store path was then missing, the row said git uses its built-in default,
	// and a remediation command could name the wrong file - all from a read
	// that never finished. Empty means everything git reads was read.
	Unreadable string
	// Conditional names, per key, the first place that sets it under a condition
	// this program does not evaluate - an [includeIf] or an [http "<url>"]
	// section, OBS179. The empty key stands for every key at once.
	Conditional map[string]string
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

	// The variables that decide WHICH configuration git reads - OBS179, sources
	// on readSettings and gitHome. HomeDrive, HomePath, UserProfile and
	// SystemRoot matter on Windows alone, where git computes its HOME from them.
	Home, HomeDrive, HomePath, UserProfile, SystemRoot Variable
	// XDGConfigHome counts only when it is not empty, as in path.c.
	XDGConfigHome string
	// GlobalConfig, SystemConfig and NoSystem are GIT_CONFIG_GLOBAL,
	// GIT_CONFIG_SYSTEM and GIT_CONFIG_NOSYSTEM.
	GlobalConfig, SystemConfig, NoSystem Variable
	// Commands are the GIT_CONFIG_COUNT pairs in git's order, and CommandsBroken
	// says where git stops reading them.
	Commands       []Command
	CommandsBroken string
	// Parameters is GIT_CONFIG_PARAMETERS.
	Parameters string
}

// Variable is one environment variable, where being set is an answer of its own.
type Variable struct {
	Value string
	Set   bool
}

// Command is one GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n> pair, as written.
type Command struct {
	Key, Value string
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
	xdg, _ := lookup("XDG_CONFIG_HOME")
	parameters, _ := lookup("GIT_CONFIG_PARAMETERS")
	commands, broken := commandsFrom(lookup)
	return Environment{
		Platform:       platform,
		CAInfo:         variable("GIT_SSL_CAINFO"),
		CAPath:         variable("GIT_SSL_CAPATH"),
		NoVerify:       noVerify,
		Home:           variable("HOME"),
		HomeDrive:      variable("HOMEDRIVE"),
		HomePath:       variable("HOMEPATH"),
		UserProfile:    variable("USERPROFILE"),
		SystemRoot:     variable("SystemRoot"),
		XDGConfigHome:  xdg,
		GlobalConfig:   variable("GIT_CONFIG_GLOBAL"),
		SystemConfig:   variable("GIT_CONFIG_SYSTEM"),
		NoSystem:       variable("GIT_CONFIG_NOSYSTEM"),
		Commands:       commands,
		CommandsBroken: broken,
		Parameters:     parameters,
	}
}

// commandsFrom reads the GIT_CONFIG_COUNT pairs the way
// git_config_from_parameters does, in config.c of git 2.54.0: the count is a
// decimal number no larger than INT_MAX, and a pair missing its key or its value
// stops git - S26 measured a count of two with one pair stopping git before it
// connected. The walk ends at the first missing variable, so it is bounded by
// the environment, whatever the count says.
//
// A count this program reads differently from strtoul - a sign other than a
// plus, white space after the digits - is reported as stopping git, which
// costs a verdict and never invents one.
func commandsFrom(lookup func(string) (string, bool)) ([]Command, string) {
	raw, set := lookup("GIT_CONFIG_COUNT")
	if !set {
		return nil, ""
	}
	digits := strings.TrimPrefix(strings.TrimLeft(raw, " \t\n\v\f\r"), "+")
	count := uint64(0)
	if raw != "" {
		var err error
		if count, err = strconv.ParseUint(digits, 10, 31); err != nil {
			return nil, fmt.Sprintf("GIT_CONFIG_COUNT is %q, which git does not read as a count, and it stops there", raw)
		}
	}
	var commands []Command
	for i := uint64(0); i < count; i++ {
		key, hasKey := lookup(fmt.Sprintf("GIT_CONFIG_KEY_%d", i))
		value, hasValue := lookup(fmt.Sprintf("GIT_CONFIG_VALUE_%d", i))
		if !hasKey || !hasValue {
			return nil, fmt.Sprintf("GIT_CONFIG_COUNT is %d and pair %d of it is not set, and git stops there", count, i)
		}
		commands = append(commands, Command{Key: key, Value: value})
	}
	return commands, ""
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

// readAll is the one place this package turns a port into bytes.
func readAll(source file.Source, path string) ([]byte, error) {
	reader, err := source(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}
