package git

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
)

// WHICH CONFIGURATION GIT READS, IN WHICH ORDER, AND HOW IT READS IT - OBS179.
//
// SOURCE, inviolable rule 18: config.c, path.c and parse.c of git 2.54.0 at
// https://github.com/git/git/tree/v2.54.0 and compat/mingw.c of Git for Windows
// 2.55.0.windows.5 at https://github.com/git-for-windows/git/tree/v2.55.0.windows.5,
// read 2026-10-20 - Git for Windows reads its configuration in the same order
// as git, function for function. MEASURED the same day by S26 round 3: thirty
// steps in git 2.47.3 from Debian and git 2.54.0 from Alpine, every one of them
// as the source predicted. Among them: ~/.gitconfig is read AFTER the XDG file
// and wins over it, a syntax error stops git before it connects, an include
// applies where it stands, and a section for one URL beats the general one
// wherever it is written.

// The http keys that decide which store git asks, lower-cased as git
// canonicalises them.
const (
	keyBackend = "sslbackend"
	keyCAInfo  = "sslcainfo"
	keyCAPath  = "sslcapath"
	keyVerify  = "sslverify"
)

// decisiveKeys are those keys in the order a sentence about one is chosen.
var decisiveKeys = []string{keyBackend, keyVerify, keyCAInfo, keyCAPath}

// keyNames are the spellings a person reads, the ones git's documentation uses.
var keyNames = map[string]string{
	keyBackend: "http.sslBackend",
	keyCAInfo:  "http.sslCAInfo",
	keyCAPath:  "http.sslCAPath",
	keyVerify:  "http.sslVerify",
}

// maxIncludeDepth is MAX_INCLUDE_DEPTH in config.c - one include deeper and git
// stops.
const maxIncludeDepth = 10

// commandLevel is the scope git gives the GIT_CONFIG_COUNT pairs, the word
// "git config --show-scope" prints for them.
const commandLevel = "command"

// configReader walks git's configuration in git's own order and folds what
// decides trust into one Settings.
type configReader struct {
	source   file.Source
	env      Environment
	home     string
	hasHome  bool
	homeWhy  string
	settings *Settings
}

// readSettings is git's configuration for one installation, read in the order
// do_git_config_sequence reads it: the system file, the XDG file, ~/.gitconfig,
// then the GIT_CONFIG_COUNT pairs - and later wins. The level travels with each
// value because it changes the advice: measured on the owner's machine, the
// deciding values sit at SYSTEM level, so a colleague whose install chose
// schannel needs the opposite fix.
//
// WHAT THIS DOES NOT READ, said here and in the row rather than discovered later.
// Repository level config, because a probe answers about the MACHINE and there
// is no repository in the question. GIT_CONFIG_PARAMETERS, the quoted list git
// hands the processes it starts from "git -c" - when it is set the row says so.
// And a condition: an [includeIf] or an [http "<url>"] section that touches one
// of the four keys leaves the row without a verdict, because which repository or
// which address it applies to is not something this program evaluates.
func readSettings(source file.Source, systemConfig string, env Environment) Settings {
	var s Settings
	r := &configReader{source: source, env: env, settings: &s}
	r.home, r.hasHome, r.homeWhy = gitHome(env)

	system, why := systemPath(systemConfig, env)
	if why != "" {
		r.stop(why)
	}
	r.top(system, "system")
	for _, path := range r.globalPaths() {
		r.top(path, "global")
	}
	r.commands()
	if env.Parameters != "" {
		r.stop("GIT_CONFIG_PARAMETERS is set, which carries configuration git was given with -c, and this program " +
			"does not read it")
	}
	return s
}

// systemPath is the system file git reads, or empty when it reads none.
//
// GIT_CONFIG_NOSYSTEM is a boolean read as parse.c reads one, empty included -
// S26 measured an empty one leaving the system file read and a word that is
// not a boolean stopping git. GIT_CONFIG_SYSTEM replaces the file for every installation at once.
func systemPath(found string, env Environment) (path, why string) {
	if env.NoSystem.Set {
		on, read := boolean(env.NoSystem.Value)
		if !read {
			return "", fmt.Sprintf("GIT_CONFIG_NOSYSTEM is %q, which this program does not read as true or false",
				env.NoSystem.Value)
		}
		if on {
			return "", ""
		}
	}
	if env.SystemConfig.Set {
		return env.SystemConfig.Value, ""
	}
	return found, ""
}

// globalPaths are the user-level files in the order git reads them - the XDG
// file first and ~/.gitconfig after it, so ~/.gitconfig wins. GIT_CONFIG_GLOBAL
// replaces both, and an empty one means none.
func (r *configReader) globalPaths() []string {
	if r.env.GlobalConfig.Set {
		return []string{r.env.GlobalConfig.Value}
	}
	if r.homeWhy != "" {
		r.stop(r.homeWhy)
		return nil
	}
	var paths []string
	switch {
	case r.env.XDGConfigHome != "":
		paths = append(paths, under(r.env.XDGConfigHome, "git/config"))
	case r.hasHome:
		paths = append(paths, under(r.home, ".config/git/config"))
	}
	if r.hasHome {
		paths = append(paths, under(r.home, ".gitconfig"))
	}
	return paths
}

// under joins a path the way git's mkpathdup does - text and a slash, with no
// cleaning - spelled with this platform's separator.
func under(dir, rel string) string {
	return filepath.FromSlash(dir + "/" + rel)
}

// gitHome is the HOME git runs with, whether it has one, and why it could not be
// established.
//
// OUTSIDE WINDOWS IT IS THE VARIABLE, and with none git reads no ~/.gitconfig -
// S26 measured that. ON WINDOWS Git for Windows computes it when it is unset
// (setup_windows_environment): HOMEDRIVE and HOMEPATH when that is a directory
// and not the system directory, USERPROFILE otherwise - and HOMEDRIVE set with
// no HOMEPATH leaves HOME unset. Go's own home is USERPROFILE, which is why this
// is not os.UserHomeDir.
//
// WHEN THE TWO DIFFER THIS PROGRAM DOES NOT LOOK WHICH ONE GIT TAKES. That needs
// a look at a directory a company typically maps to a network share, and
// inviolable rule 16 keeps this program off any machine nobody named. The row
// then says which two places it could be. The system directory is compared as
// %SystemRoot%\System32, which is where GetSystemDirectoryW points on a standard
// installation - an ASSESSMENT, not a source.
func gitHome(env Environment) (home string, has bool, why string) {
	if env.Home.Set {
		return env.Home.Value, true, ""
	}
	if env.Platform != "windows" {
		return "", false, ""
	}
	if env.HomeDrive.Set {
		if !env.HomePath.Set {
			return "", false, ""
		}
		candidate := env.HomeDrive.Value + env.HomePath.Value
		switch {
		case env.SystemRoot.Set && sameWindowsPath(candidate, env.SystemRoot.Value+`\System32`):
		case env.UserProfile.Set && sameWindowsPath(candidate, env.UserProfile.Value):
			return candidate, true, ""
		default:
			otherwise := "nothing"
			if env.UserProfile.Set {
				otherwise = env.UserProfile.Value
			}
			return "", false, fmt.Sprintf("git's home directory is %s when that is a directory and %s otherwise, and "+
				"this program does not look which - the first may be on a network share", candidate, otherwise)
		}
	}
	if env.UserProfile.Set {
		return env.UserProfile.Value, true, ""
	}
	return "", false, ""
}

// sameWindowsPath compares two Windows paths as Windows does: either slash, any
// case, a trailing separator ignored.
func sameWindowsPath(a, b string) bool {
	norm := func(p string) string {
		return strings.TrimRight(strings.ReplaceAll(p, "/", `\`), `\`)
	}
	return strings.EqualFold(norm(a), norm(b))
}

// commands applies the GIT_CONFIG_COUNT pairs after every file, at the command
// level, and stops where git stops.
func (r *configReader) commands() {
	if r.env.CommandsBroken != "" {
		r.stop(r.env.CommandsBroken)
		return
	}
	for i, command := range r.env.Commands {
		key, why := canonicalKey(command.Key)
		if why != "" {
			r.stop(fmt.Sprintf("GIT_CONFIG_KEY_%d is %q, which %s, and git stops there", i, command.Key, why))
			return
		}
		r.apply(entry{key: key, value: command.Value, hasValue: true}, fmt.Sprintf("GIT_CONFIG_KEY_%d", i), "",
			commandLevel, 0, "")
	}
}

// canonicalKey is git_config_parse_key: the section and the variable name are
// lower-cased and checked, and what lies between them is kept as written.
func canonicalKey(key string) (string, string) {
	last := strings.LastIndexByte(key, '.')
	switch {
	case key == "":
		return "", "is empty"
	case last <= 0:
		return "", "has no section"
	case last == len(key)-1:
		return "", "has no variable name"
	}
	first := strings.IndexByte(key, '.')
	out := []byte(key)
	for i := 0; i < len(key); i++ {
		c := key[i]
		if i < first || i > last {
			if !isKeyChar(c) || (i == last+1 && !isAlpha(c)) {
				return "", "is not a valid key"
			}
			out[i] = toLower(c)
		} else if c == '\n' {
			return "", "is not a valid key"
		}
	}
	return string(out), ""
}

// splitKey divides a canonical key into git's three parts, the way
// parse_config_key does: the section up to the first dot, the variable name
// after the last, and a subsection only when the two dots differ.
func splitKey(key string) (section, subsection, name string, hasSubsection bool) {
	first, last := strings.IndexByte(key, '.'), strings.LastIndexByte(key, '.')
	if first < 0 {
		return key, "", "", false
	}
	if first == last {
		return key[:first], "", key[last+1:], false
	}
	return key[:first], key[first+1 : last], key[last+1:], true
}

// top reads one of the files git reads on its own - not through an include.
// git passes over a USER file it may not read (ACCESS_EACCES_OK in
// do_git_config_sequence), and stops on a system file it may not read, because
// the ordinary read of the configuration leaves system_gently unset.
func (r *configReader) top(path, level string) {
	r.file(path, path, level, 0, "", level == "global")
}

// file reads one config file and applies what is in it.
//
// condition is empty for a file git reads unconditionally, and otherwise says
// under which condition git reads it. lenient says git passes over this file
// when it may not read it - see top - where an included file it may not read
// stops it.
//
// A FILE THAT IS NOT THERE IS NOT A FAILURE TO READ ONE. Absence is the
// ordinary state of a global gitconfig, and git passes over a missing include in
// silence - S26 measured that. Any other failure to read is NOT absence: a
// config that could not be read says nothing about what it would have set.
func (r *configReader) file(path, where, level string, depth int, condition string, lenient bool) {
	if r.settings.Unreadable != "" || path == "" {
		return
	}
	data, err := readAll(r.source, path)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return
	case lenient && errors.Is(err, fs.ErrPermission):
		return
	default:
		// P3-1. A read that stopped halfway is not a file that sets nothing.
		r.refuse(condition, fmt.Sprintf("%s could not be read to the end: %v", where, err))
		return
	}
	if depth > maxIncludeDepth {
		r.refuse(condition, fmt.Sprintf("%s is included more than %d deep, and git stops there", where, maxIncludeDepth))
		return
	}
	entries, line, err := parseConfig(data)
	if err != nil {
		r.refuse(condition, fmt.Sprintf("line %d of %s is not configuration git can read, and git stops there", line, where))
		return
	}
	for _, e := range entries {
		if r.settings.Unreadable != "" {
			return
		}
		r.apply(e, where, path, level, depth, condition)
	}
}

// apply folds one key into the settings.
//
// where names the key's origin for a person, and from is the file it stands in,
// or empty for a pair from the environment - a relative include is resolved
// against it, and git refuses one with nothing to resolve against.
func (r *configReader) apply(e entry, where, from, level string, depth int, condition string) {
	section, subsection, name, hasSubsection := splitKey(e.key)
	switch {
	case section == "http" && keyNames[name] != "":
		switch {
		case condition != "":
			r.mark(name, fmt.Sprintf("%s, and %s sets %s there", condition, where, keyNames[name]))
		case hasSubsection:
			// http.<url>.<key> - urlmatch in http.c. S26 measured one for the
			// target winning over the general key written after it, and one for
			// another host changing nothing.
			r.mark(name, fmt.Sprintf("%s sets %s for %s only, and whether that is the address being diagnosed is "+
				"not checked here", where, keyNames[name], subsection))
		default:
			r.set(name, e, where, level)
		}
	case section == "include" && !hasSubsection && name == "path":
		r.include(e, where, from, level, depth, condition, "")
	case section == "includeif" && hasSubsection && name == "path":
		r.include(e, where, from, level, depth, condition, subsection)
	}
}

// set records one decisive key read unconditionally.
//
// THE THREE KEYS DO NOT TREAT A MISSING VALUE ALIKE, and each follows http.c of
// git 2.54.0. sslVerify standing alone is true (git_config_bool). sslBackend
// standing alone puts the backend back to none (xstrdup_or_null). sslCAInfo and
// sslCAPath standing alone stop git (git_config_pathname) - S26 measured that.
func (r *configReader) set(name string, e entry, where, level string) {
	s := r.settings
	switch name {
	case keyVerify:
		s.Verify, s.VerifyLevel = e.value, level
		if !e.hasValue {
			s.Verify = "true"
		}
	case keyBackend:
		s.Backend, s.BackendLevel = e.value, level
		if !e.hasValue {
			s.Backend, s.BackendLevel = "", ""
		}
	default:
		if !e.hasValue {
			r.stop(fmt.Sprintf("%s sets %s with no value, and git stops there", where, keyNames[name]))
			return
		}
		path, present, why := r.pathname(e.value)
		if why != "" {
			r.stop(fmt.Sprintf("%s sets %s to %q, and %s", where, keyNames[name], e.value, why))
			return
		}
		if !present {
			path, level = "", ""
		}
		if name == keyCAInfo {
			s.CAInfo, s.CAInfoLevel = path, level
		} else {
			s.CAPath, s.CAPathLevel = path, level
		}
	}
}

// pathname reads a path value the way git_config_pathname does: a leading
// ":(optional)" makes a file that is not there unset the key, and the rest is
// expanded as interpolate_path expands it.
func (r *configReader) pathname(value string) (path string, present bool, why string) {
	rest, optional := strings.CutPrefix(value, ":(optional)")
	path, why = r.interpolate(rest)
	if why != "" {
		return "", false, why
	}
	if optional && r.missing(path) {
		return "", false, ""
	}
	return path, true, ""
}

// missing is is_missing_file - a file that is not there, and nothing else.
func (r *configReader) missing(path string) bool {
	if path == "" {
		return true
	}
	reader, err := r.source(path)
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	_ = reader.Close()
	return false
}

// interpolate expands a path the way interpolate_path does: "~" and "~/" are
// git's HOME, and the two forms this program cannot follow say so.
func (r *configReader) interpolate(value string) (string, string) {
	if strings.HasPrefix(value, "%(prefix)/") {
		return "", "that is under git's install prefix, which this program does not follow"
	}
	rest, tilde := strings.CutPrefix(value, "~")
	if !tilde {
		return value, ""
	}
	if account, _, _ := strings.Cut(rest, "/"); account != "" {
		return "", "that names another account's home directory, which this program does not look up"
	}
	switch {
	case r.homeWhy != "":
		return "", r.homeWhy
	case !r.hasHome:
		return "", "git has no home directory to expand ~ with, and it stops there"
	}
	return filepath.FromSlash(r.home + rest), ""
}

// include follows one include the way handle_path_include does: the path is
// expanded, a relative one is taken from the directory of the file that names
// it, and the file is read in place, at the level of the file that includes it -
// S26 measured an include written before a key losing to it and one written
// after it winning.
//
// when is the condition of an [includeIf], and empty for a plain [include].
// A FILE INCLUDED UNDER A CONDITION IS READ ONLY TO LEARN WHETHER IT TOUCHES ONE
// OF THE FOUR KEYS - decided by the owner 2026-10-20 (OBS179). Whether the
// condition holds depends on a repository, and a probe answers about the
// machine, so a touch leaves the row without a verdict and no touch changes
// nothing.
func (r *configReader) include(e entry, where, from, level string, depth int, condition, when string) {
	if when != "" && condition == "" {
		condition = fmt.Sprintf("%s includes %q only when %q holds", where, e.value, when)
	}
	if !e.hasValue {
		r.refuse(condition, fmt.Sprintf("%s names an include with no path, and git stops there", where))
		return
	}
	path, why := r.interpolate(e.value)
	if why != "" {
		r.refuse(condition, fmt.Sprintf("%s includes %q, and %s", where, e.value, why))
		return
	}
	if !absolute(r.env.Platform, path) {
		if from == "" {
			r.refuse(condition, fmt.Sprintf("%s includes the relative path %q, which git refuses outside a file", where,
				e.value))
			return
		}
		path = directoryOf(r.env.Platform, from) + path
	}
	r.file(path, path, level, depth+1, condition, false)
}

// absolute is is_absolute_path: on Windows a drive letter or a leading
// separator of either kind, elsewhere a leading slash.
func absolute(platform, path string) bool {
	if platform == "windows" {
		return strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) ||
			(len(path) >= 2 && isAlpha(path[0]) && path[1] == ':')
	}
	return strings.HasPrefix(path, "/")
}

// directoryOf is the including file's directory with its separator, the way
// handle_path_include cuts at find_last_dir_sep - and empty with none.
func directoryOf(platform, path string) string {
	separators := "/"
	if platform == "windows" {
		separators = `/\`
	}
	return path[:strings.LastIndexAny(path, separators)+1]
}

// stop records where git stops reading its configuration, or where this program
// cannot follow it. The first one is kept and nothing after it is read.
func (r *configReader) stop(why string) {
	if r.settings.Unreadable == "" {
		r.settings.Unreadable = why
	}
}

// refuse is stop for a file git reads unconditionally, and a mark on every key
// for one it reads under a condition - git stops there only if the condition
// holds, and whether it does is not evaluated here.
func (r *configReader) refuse(condition, why string) {
	if condition == "" {
		r.stop(why)
		return
	}
	r.mark("", condition+", and "+why)
}

// mark records the first place a key is set under a condition. The empty key
// stands for every key at once - a conditional file nobody could read may set
// any of them.
func (r *configReader) mark(key, why string) {
	if r.settings.Conditional == nil {
		r.settings.Conditional = map[string]string{}
	}
	if _, seen := r.settings.Conditional[key]; !seen {
		r.settings.Conditional[key] = why
	}
}

// entry is one key git reads from one file, in the order it reads it. key is
// section, subsection and name joined with dots, the section and the name
// lower-cased, the subsection as written.
type entry struct {
	key      string
	value    string
	hasValue bool
}

// configScanner hands out a file one character at a time the way get_next_char
// does: CR LF is LF, and the end of the file reads as one more LF, for ever.
type configScanner struct {
	data []byte
	pos  int
	line int
	eof  bool
}

func (s *configScanner) next() byte {
	if s.pos >= len(s.data) {
		s.eof = true
		return '\n'
	}
	c := s.data[s.pos]
	s.pos++
	if c == '\r' && s.pos < len(s.data) && s.data[s.pos] == '\n' {
		c = '\n'
		s.pos++
	}
	if c == '\n' {
		s.line++
	}
	return c
}

// utf8BOM is skipped at the very start of a file, and a part of it is an error.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// parseConfig reads one config file the way git_parse_source does, and on a
// line git stops on returns that line's number with the error.
//
// IT IS GIT'S PARSER RATHER THAN A LOOK-ALIKE, because a look-alike that is
// wrong does not fail - it reads a path with a comment on the end of it, finds
// no such file and says nothing was set. S26 measured git reading a key on the
// line of its section header, a comment after a value and a quoted value, and
// stopping on a header with no closing bracket. A key before any section is read
// without one, as git reads it, and matches nothing here.
func parseConfig(data []byte) ([]entry, int, error) {
	s := &configScanner{data: data, line: 1}
	matched := 0
	for matched < len(utf8BOM) && matched < len(data) && data[matched] == utf8BOM[matched] {
		matched++
	}
	switch matched {
	case len(utf8BOM):
		s.pos = matched
	case 0:
	default:
		return nil, 1, errors.New("a partial byte order mark")
	}

	var entries []entry
	stem := ""
	comment := false
	for {
		start := s.line
		c := s.next()
		switch {
		case c == '\n':
			if s.eof {
				return entries, 0, nil
			}
			comment = false
		case comment, isSpace(c):
		case c == '#' || c == ';':
			comment = true
		case c == '[':
			name, ok := s.section()
			if !ok || name == "" {
				return nil, start, errors.New("a section header git cannot read")
			}
			stem = name + "."
		case isAlpha(c):
			e, ok := s.variable(stem, c)
			if !ok {
				return nil, start, errors.New("a key git cannot read")
			}
			entries = append(entries, e)
		default:
			return nil, start, errors.New("a line git cannot read")
		}
	}
}

// section is get_base_var and get_extended_base_var: a name of key characters
// and dots, lower-cased, or a name, white space and a quoted subsection kept as
// written, with a backslash escaping the character after it.
func (s *configScanner) section() (string, bool) {
	var name []byte
	for {
		c := s.next()
		switch {
		case s.eof:
			return "", false
		case c == ']':
			return string(name), true
		case isSpace(c):
			return s.subsection(name, c)
		case !isKeyChar(c) && c != '.':
			return "", false
		}
		name = append(name, toLower(c))
	}
}

func (s *configScanner) subsection(name []byte, c byte) (string, bool) {
	for {
		if c == '\n' {
			return "", false
		}
		if c = s.next(); !isSpace(c) {
			break
		}
	}
	if c != '"' {
		return "", false
	}
	name = append(name, '.')
	for {
		c = s.next()
		if c == '\n' {
			return "", false
		}
		if c == '"' {
			break
		}
		if c == '\\' {
			if c = s.next(); c == '\n' {
				return "", false
			}
		}
		name = append(name, c)
	}
	return string(name), s.next() == ']'
}

// variable is get_value: a name of key characters, lower-cased, then white
// space, then either the end of the line - a key with no value - or "=" and a
// value.
func (s *configScanner) variable(stem string, first byte) (entry, bool) {
	name := append([]byte(stem), toLower(first))
	var c byte
	for {
		c = s.next()
		if s.eof || !isKeyChar(c) {
			break
		}
		name = append(name, toLower(c))
	}
	for c == ' ' || c == '\t' {
		c = s.next()
	}
	if c == '\n' {
		return entry{key: string(name)}, true
	}
	if c != '=' {
		return entry{}, false
	}
	value, ok := s.value()
	return entry{key: string(name), value: value, hasValue: true}, ok
}

// value is parse_value: white space at either end is dropped, "#" and ";"
// outside quotes start a comment, double quotes group without being kept, and a
// backslash escapes a newline, t, b, n, a backslash or a quote - any other
// escape, and a quote left open at the end of the line, stop git.
func (s *configScanner) value() (string, bool) {
	var out []byte
	quote, comment := false, false
	trim := 0
	for {
		c := s.next()
		if c == '\n' {
			if quote {
				return "", false
			}
			if trim != 0 {
				out = out[:trim]
			}
			return string(out), true
		}
		switch {
		case comment:
			continue
		case isSpace(c) && !quote:
			if trim == 0 {
				trim = len(out)
			}
			if len(out) != 0 {
				out = append(out, c)
			}
			continue
		case !quote && (c == ';' || c == '#'):
			comment = true
			continue
		}
		trim = 0
		switch c {
		case '\\':
			escaped, continued, ok := s.escape()
			if !ok {
				return "", false
			}
			if !continued {
				out = append(out, escaped)
			}
		case '"':
			quote = !quote
		default:
			out = append(out, c)
		}
	}
}

// escape reads the character after a backslash in a value: a line end carries
// the value on to the next line, and t, b, n, a backslash and a quote stand for
// what parse_value makes of them. Anything else stops git.
func (s *configScanner) escape() (c byte, continued, ok bool) {
	switch c = s.next(); c {
	case '\n':
		return 0, true, true
	case 't':
		return '\t', false, true
	case 'b':
		return '\b', false, true
	case 'n':
		return '\n', false, true
	case '\\', '"':
		return c, false, true
	}
	return 0, false, false
}

// The character classes git's parser uses - sane_ctype, ASCII alone.
func isSpace(c byte) bool   { return c == ' ' || (c >= '\t' && c <= '\r') }
func isAlpha(c byte) bool   { return (c|0x20) >= 'a' && (c|0x20) <= 'z' }
func isKeyChar(c byte) bool { return isAlpha(c) || (c >= '0' && c <= '9') || c == '-' }
func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
