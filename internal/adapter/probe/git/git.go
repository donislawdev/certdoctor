// Package git answers what git on this machine makes of a presented chain.
//
// IT RUNS NO PROCESS, and that is measured rather than preferred. On 2026-08-18
// the two values that decide everything here - http.sslBackend and
// http.sslCAInfo - were read straight out of C:/Program Files/Git/etc/gitconfig,
// which is plain INI. ADR49 keeps process execution to one file for good
// reasons; a probe that does not need it does not get it.
//
// WHY GIT IS THE TEXTBOOK CASE FOR THIS WHOLE PRODUCT, measured on the same day:
// git reports sslbackend=openssl and reads its OWN 229042-byte bundle, while the
// curl.exe sitting in the same install directory is built on Schannel and asks
// Windows. Adding a company CA to the Windows store fixes one and not the other,
// and no other tool will tell somebody that.
package git

import (
	"bufio"
	"io"
	"path/filepath"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
)

// Install is one git installation found on this machine.
type Install struct {
	// Root is the install directory - the identity a person reads, and what
	// tells two installations apart when both are present.
	Root string
	// SystemConfig is the gitconfig belonging to this install.
	SystemConfig string
	// Architecture is x86 where the path says so, and x64 otherwise. Measured on
	// this machine for Java: two installs differing ONLY by "(x86)" have separate
	// stores and therefore separate answers.
	Architecture string
}

// systemConfigs are the places a git installation keeps its system-level config.
//
// THE LIST IS SEARCHED, NOT DERIVED FROM PATH - ADR48 part 4. PATH names one
// installation, and this machine proves the difference elsewhere: six Java
// installs with JAVA_HOME naming one, two curl binaries with PATH naming one.
// PATH is used below to ENRICH a row, never to find it.
var systemConfigs = []string{
	`C:\Program Files\Git\etc\gitconfig`,
	`C:\Program Files (x86)\Git\etc\gitconfig`,
	"/etc/gitconfig",
	"/usr/local/etc/gitconfig",
	"/opt/homebrew/etc/gitconfig",
}

// Settings are the two values that decide which store git uses, plus where each
// came from.
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
}

// find returns every installation whose system config is readable.
//
// A PATH THAT IS NOT THERE IS NOT AN INSTALLATION. The same rule ADR48 part 2
// states for Java stores, and for the same measured reason: this machine has two
// C:\Program Files\Java\latest directories with no store inside, and a row
// invented from a directory name would be a claim about a store nobody has.
func find(source file.Source, candidates []string) []Install {
	var found []Install
	for _, config := range candidates {
		reader, err := source(config)
		if err != nil {
			continue
		}
		_ = reader.Close()

		root := filepath.Dir(filepath.Dir(config))
		architecture := "x64"
		if strings.Contains(config, "(x86)") {
			architecture = "x86"
		}
		found = append(found, Install{Root: root, SystemConfig: config, Architecture: architecture})
	}
	return found
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
func readSettings(source file.Source, paths []string) Settings {
	var s Settings
	for _, path := range paths {
		level := "global"
		if isSystem(path) {
			level = "system"
		}
		for key, value := range parse(source, path) {
			switch key {
			case "http.sslbackend":
				s.Backend, s.BackendLevel = value, level
			case "http.sslcainfo":
				s.CAInfo, s.CAInfoLevel = value, level
			}
		}
	}
	return s
}

func isSystem(path string) bool {
	for _, candidate := range systemConfigs {
		if candidate == path {
			return true
		}
	}
	return false
}

// parse reads the [http] section of one config file into lower-cased keys.
//
// IT READS ONLY WHAT IT UNDERSTANDS AND SAYS SO. git's config format has more in
// it than this - subsections, includes, multi-valued keys - and a parser that
// guessed at the rest would produce a confident wrong answer, which is worse
// here than no answer. The two keys this needs are plain scalars in the [http]
// section on every machine measured.
func parse(source file.Source, path string) map[string]string {
	values := map[string]string{}
	reader, err := source(path)
	if err != nil {
		return values
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
		key, value, found := strings.Cut(line, "=")
		if !found || section == "" {
			continue
		}
		values[section+"."+strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return values
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
