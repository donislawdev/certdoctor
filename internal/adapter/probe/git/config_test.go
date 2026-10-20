package git

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
)

// These tests pin git's own reading of its configuration - config.c, path.c and
// parse.c of git 2.54.0, compat/mingw.c of Git for Windows - and the steps of S26
// round 3 that measured it are named where a test stands on one.

// home is an invented account's home, from the list in personal_test.go, on the
// platform these tests run on - a relative include is cut at this platform's
// separators, and production reads the platform it runs on.
var home = Environment{Platform: runtime.GOOS, Home: Variable{Value: "/home/jdoe", Set: true}}

// withHome is the home environment with changes on top.
func withHome(change func(*Environment)) Environment {
	env := home
	change(&env)
	return env
}

// deny is a file port that refuses the named paths for want of permission and
// hands the rest to inner.
func deny(inner func(string) (io.ReadCloser, error), paths ...string) func(string) (io.ReadCloser, error) {
	return func(path string) (io.ReadCloser, error) {
		for _, denied := range paths {
			if filepath.Clean(path) == filepath.Clean(denied) {
				return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
			}
		}
		return inner(path)
	}
}

// userConfig reads one ~/.gitconfig and nothing else.
func userConfig(t *testing.T, config string, files map[string]string) Settings {
	t.Helper()
	all := map[string]string{"/home/jdoe/.gitconfig": config}
	for path, body := range files {
		all[path] = body
	}
	return readSettings(sourceOf(all), "", home)
}

func TestTheParserReadsGitsSyntax(t *testing.T) {
	cases := []struct {
		name, config, key, value string
		hasValue                 bool
	}{
		{"a key on its section's line (S26)", "[http] sslCAInfo = /a\n", "http.sslcainfo", "/a", true},
		{"a comment after the value (S26)", "[http]\nsslCAInfo = /a # corp\n", "http.sslcainfo", "/a", true},
		{"a semicolon comment", "[http]\nsslCAInfo = /a ; corp\n", "http.sslcainfo", "/a", true},
		{"a quoted value keeps what a comment would take (S26)", "[http]\nsslCAInfo = \"/a #b\"\n", "http.sslcainfo", "/a #b", true},
		{"escapes", "[x]\nv = a\\tb\\\\c\\\"d\\ne\\bf\n", "x.v", "a\tb\\c\"d\ne\bf", true},
		{"a line continued", "[x]\nv = a\\\nb\n", "x.v", "ab", true},
		{"white space at the ends dropped and inside kept", "[x]\nv =  a b  \n", "x.v", "a b", true},
		{"quoted white space kept", "[x]\nv = \" a \"\n", "x.v", " a ", true},
		{"CR LF line ends", "[http]\r\nsslCAInfo = /a\r\n", "http.sslcainfo", "/a", true},
		{"a byte order mark", "\xEF\xBB\xBF[x]\nv = 1\n", "x.v", "1", true},
		{"a URL section keeps its case", "[http \"https://X.example/\"]\nsslCAInfo = /a\n", "http.https://X.example/.sslcainfo", "/a", true},
		{"an escaped quote in a section name", "[http \"a\\\"b\"]\nv = 1\n", "http.a\"b.v", "1", true},
		{"the old dotted section form is lower-cased whole", "[Http.Example.COM]\nV = 1\n", "http.example.com.v", "1", true},
		{"a key standing alone", "[http]\nsslVerify\n", "http.sslverify", "", false},
		{"a key standing alone at the end of the file", "[http]\nsslVerify", "http.sslverify", "", false},
		{"a key standing alone before a tab", "[http]\nsslVerify\t\n", "http.sslverify", "", false},
		{"an empty value", "[http]\nsslCAInfo =\n", "http.sslcainfo", "", true},
		{"a key before any section", "v = 1\n", "v", "1", true},
		{"dashes and digits in a key", "[x]\nSsl-Ver1fy = 1\n", "x.ssl-ver1fy", "1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries, _, err := parseConfig([]byte(c.config))
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("got %d entries %+v, want one", len(entries), entries)
			}
			if got := entries[0]; got.key != c.key || got.value != c.value || got.hasValue != c.hasValue {
				t.Errorf("got %+v, want key %q value %q set %v", got, c.key, c.value, c.hasValue)
			}
		})
	}
}

// WHERE GIT STOPS, THIS PARSER STOPS, and it names the line - S26 measured git
// stopping before it connects on the third case here.
func TestTheParserStopsWhereGitStops(t *testing.T) {
	cases := []struct {
		name, config string
		line         int
	}{
		{"a header with no closing bracket", "[http\n", 1},
		{"a header cut by the end of the file", "[http", 1},
		{"a broken header after a key", "[http]\nsslCAInfo = /a\n[http", 3},
		{"a space in a header with no quote after it", "[ht tp]\n", 1},
		{"a header ending in white space", "[http \n", 1},
		{"a subsection left open", "[http \"x]\n", 1},
		{"a subsection with an escaped line end", "[http \"x\\\n\"]\n", 1},
		{"a subsection not closed by a bracket", "[http \"x\" ]\n", 1},
		{"an empty header", "[]\n", 1},
		{"a bad character in a header", "[ht@tp]\n", 1},
		{"a key starting with a digit", "[http]\n1abc = x\n", 2},
		{"a key with no equals sign", "[http]\nkey x\n", 2},
		{"a bad character in a key", "[http]\nv@ = 1\n", 2},
		{"a quote left open", "[http]\nv = \"open\n", 2},
		{"an unknown escape", "[http]\nv = a\\q\n", 2},
		{"part of a byte order mark", "\xEF\xBBx\n", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries, line, err := parseConfig([]byte(c.config))
			if err == nil {
				t.Fatalf("accepted as %+v", entries)
			}
			if line != c.line || entries != nil {
				t.Errorf("stopped on line %d with %v, want line %d and nothing", line, entries, c.line)
			}
		})
	}
}

// A FILE GIT STOPS ON LEAVES THE ROW WITHOUT A VERDICT, naming the file and the
// line, and nothing in it or after it is applied.
func TestAFileGitStopsOnIsNotReadAsEmpty(t *testing.T) {
	settings := userConfig(t, "[http]\n\tsslVerify = false\n[http\n", nil)
	if !strings.Contains(settings.Unreadable, "line 3 of "+filepath.FromSlash("/home/jdoe/.gitconfig")) ||
		settings.VerifyLevel != "" {
		t.Errorf("got %+v, want the file named at line 3 and nothing applied", settings)
	}
}

// ~/.gitconfig IS READ AFTER THE XDG FILE AND WINS - the order this probe had
// the wrong way round before OBS179, and S26 measured both directions.
func TestTheUserFilesAreReadInGitsOrder(t *testing.T) {
	both := map[string]string{
		"/home/jdoe/.config/git/config": "[http]\n\tsslCAInfo = /xdg.crt\n\tsslBackend = openssl\n",
		"/home/jdoe/.gitconfig":         "[http]\n\tsslCAInfo = /user.crt\n",
	}
	settings := readSettings(sourceOf(both), "", home)
	if settings.CAInfo != "/user.crt" || settings.CAInfoLevel != "global" || settings.Backend != "openssl" {
		t.Errorf("got %+v, want ~/.gitconfig over the XDG file and both read", settings)
	}

	xdg := map[string]string{
		"/xdg/git/config":               "[http]\n\tsslCAInfo = /moved.crt\n",
		"/home/jdoe/.config/git/config": "[http]\n\tsslCAInfo = /xdg.crt\n",
	}
	settings = readSettings(sourceOf(xdg), "", withHome(func(e *Environment) { e.XDGConfigHome = "/xdg" }))
	if settings.CAInfo != "/moved.crt" {
		t.Errorf("XDG_CONFIG_HOME set: got %q, want the file under it", settings.CAInfo)
	}
	settings = readSettings(sourceOf(xdg), "", home)
	if settings.CAInfo != "/xdg.crt" {
		t.Errorf("XDG_CONFIG_HOME unset or empty: got %q, want ~/.config/git/config", settings.CAInfo)
	}
}

// WITH NO HOME GIT READS NO ~/.gitconfig (S26), and XDG_CONFIG_HOME still names
// its file.
func TestWithNoHomeOnlyXDGConfigHomeNamesAUserFile(t *testing.T) {
	files := sourceOf(map[string]string{
		"/home/jdoe/.gitconfig": "[http]\n\tsslCAInfo = /user.crt\n",
		"/xdg/git/config":       "[http]\n\tsslVerify = false\n",
	})
	settings := readSettings(files, "", Environment{Platform: "linux"})
	if settings.CAInfoLevel != "" || settings.VerifyLevel != "" || settings.Unreadable != "" {
		t.Errorf("no HOME and no XDG_CONFIG_HOME read %+v", settings)
	}
	settings = readSettings(files, "", Environment{Platform: "linux", XDGConfigHome: "/xdg"})
	if settings.Verify != "false" || settings.CAInfoLevel != "" {
		t.Errorf("no HOME with XDG_CONFIG_HOME read %+v, want the XDG file alone", settings)
	}
}

// GIT_CONFIG_GLOBAL REPLACES BOTH USER FILES, and an empty one means none (S26).
func TestGitConfigGlobalReplacesBothUserFiles(t *testing.T) {
	files := sourceOf(map[string]string{
		"/elsewhere":                    "[http]\n\tsslCAInfo = /named.crt\n",
		"/home/jdoe/.gitconfig":         "[http]\n\tsslCAInfo = /user.crt\n",
		"/home/jdoe/.config/git/config": "[http]\n\tsslVerify = false\n",
	})
	settings := readSettings(files, "", withHome(func(e *Environment) {
		e.GlobalConfig = Variable{Value: "/elsewhere", Set: true}
	}))
	if settings.CAInfo != "/named.crt" || settings.VerifyLevel != "" {
		t.Errorf("got %+v, want the named file alone", settings)
	}
	settings = readSettings(files, "", withHome(func(e *Environment) { e.GlobalConfig = Variable{Set: true} }))
	if settings.CAInfoLevel != "" || settings.VerifyLevel != "" || settings.Unreadable != "" {
		t.Errorf("an empty GIT_CONFIG_GLOBAL read %+v, want no user file at all", settings)
	}
}

// GIT_CONFIG_SYSTEM NAMES THE SYSTEM FILE AND GIT_CONFIG_NOSYSTEM SKIPS IT - a
// boolean read as parse.c reads one, so an empty one reads the file and one git
// cannot read leaves the row without a verdict (S26).
func TestTheSystemFileFollowsTheTwoVariables(t *testing.T) {
	files := sourceOf(map[string]string{
		"/install/gitconfig": "[http]\n\tsslCAInfo = /install.crt\n",
		"/named/gitconfig":   "[http]\n\tsslCAInfo = /named.crt\n",
	})
	named := Variable{Value: "/named/gitconfig", Set: true}
	cases := []struct {
		name       string
		env        Environment
		want       string
		unreadable bool
	}{
		{"neither", Environment{}, "/install.crt", false},
		{"GIT_CONFIG_SYSTEM", Environment{SystemConfig: named}, "/named.crt", false},
		{"GIT_CONFIG_SYSTEM empty", Environment{SystemConfig: Variable{Set: true}}, "", false},
		{"GIT_CONFIG_NOSYSTEM=1", Environment{SystemConfig: named, NoSystem: Variable{Value: "1", Set: true}}, "", false},
		{"GIT_CONFIG_NOSYSTEM empty", Environment{NoSystem: Variable{Set: true}}, "/install.crt", false},
		{"GIT_CONFIG_NOSYSTEM=false", Environment{NoSystem: Variable{Value: "false", Set: true}}, "/install.crt", false},
		{"GIT_CONFIG_NOSYSTEM unreadable", Environment{NoSystem: Variable{Value: "maybe", Set: true}}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := readSettings(files, "/install/gitconfig", c.env)
			if settings.CAInfo != c.want || (settings.Unreadable != "") != c.unreadable {
				t.Errorf("got %+v, want %q", settings, c.want)
			}
			if c.want != "" && settings.CAInfoLevel != "system" {
				t.Errorf("level %q, want system", settings.CAInfoLevel)
			}
		})
	}
}

// GIT'S HOME ON WINDOWS IS NOT GO'S - compat/mingw.c computes it from HOMEDRIVE
// and HOMEPATH before USERPROFILE, and where the two differ this program does
// not look which one a directory test would pick.
func TestGitsHomeOnWindows(t *testing.T) {
	set := func(value string) Variable { return Variable{Value: value, Set: true} }
	cases := []struct {
		name string
		env  Environment
		home string
		has  bool
		why  bool
	}{
		{"HOME wins", Environment{Platform: "windows", Home: set(`D:\h`), UserProfile: set(`C:\Users\jdoe`)}, `D:\h`, true, false},
		{"the drive and path are the profile", Environment{Platform: "windows", HomeDrive: set("C:"),
			HomePath: set(`\Users\jdoe`), UserProfile: set(`c:/users/jdoe/`)}, `C:\Users\jdoe`, true, false},
		{"the drive and path differ from the profile", Environment{Platform: "windows", HomeDrive: set("H:"),
			HomePath: set(`\`), UserProfile: set(`C:\Users\jdoe`)}, "", false, true},
		{"the drive and path with no profile", Environment{Platform: "windows", HomeDrive: set("H:"),
			HomePath: set(`\`)}, "", false, true},
		{"the system directory falls to the profile", Environment{Platform: "windows", HomeDrive: set("C:"),
			HomePath: set(`\Windows\system32`), SystemRoot: set(`C:\WINDOWS`), UserProfile: set(`C:\Users\jdoe`)},
			`C:\Users\jdoe`, true, false},
		{"a drive with no path leaves none", Environment{Platform: "windows", HomeDrive: set("C:"),
			UserProfile: set(`C:\Users\jdoe`)}, "", false, false},
		{"the profile alone", Environment{Platform: "windows", UserProfile: set(`C:\Users\jdoe`)}, `C:\Users\jdoe`, true, false},
		{"nothing at all", Environment{Platform: "windows"}, "", false, false},
		{"elsewhere the profile is not asked", Environment{Platform: "linux", UserProfile: set("/x")}, "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, has, why := gitHome(c.env)
			if got != c.home || has != c.has || (why != "") != c.why {
				t.Errorf("got %q %v %q, want %q %v and a reason %v", got, has, why, c.home, c.has, c.why)
			}
		})
	}
}

// A HOME THIS PROGRAM DID NOT ESTABLISH LEAVES THE ROW WITHOUT A VERDICT, and
// only where git would need it: GIT_CONFIG_GLOBAL takes the user files away.
func TestAnUndeterminedHomeMattersOnlyWhereGitNeedsIt(t *testing.T) {
	split := Environment{Platform: "windows", HomeDrive: Variable{Value: "H:", Set: true},
		HomePath: Variable{Value: `\`, Set: true}, UserProfile: Variable{Value: `C:\Users\jdoe`, Set: true}}
	settings := readSettings(sourceOf(nil), "", split)
	if !strings.Contains(settings.Unreadable, `H:\`) || !strings.Contains(settings.Unreadable, `C:\Users\jdoe`) {
		t.Errorf("got %q, want both places named", settings.Unreadable)
	}
	split.GlobalConfig = Variable{Set: true}
	if settings = readSettings(sourceOf(nil), "", split); settings.Unreadable != "" {
		t.Errorf("with GIT_CONFIG_GLOBAL the home is not needed, got %q", settings.Unreadable)
	}
}

// THE GIT_CONFIG_COUNT PAIRS ARE READ AFTER EVERY FILE, at the command level -
// S26 measured one winning over ~/.gitconfig.
func TestCommandPairsWinOverEveryFile(t *testing.T) {
	files := sourceOf(map[string]string{"/home/jdoe/.gitconfig": "[http]\n\tsslCAInfo = /user.crt\n"})
	settings := readSettings(files, "", withHome(func(e *Environment) {
		e.Commands = []Command{{Key: "core.editor", Value: "vi"}, {Key: "HTTP.SSLCAInfo", Value: "/command.crt"}}
	}))
	if settings.CAInfo != "/command.crt" || settings.CAInfoLevel != commandLevel {
		t.Errorf("got %+v, want the pair at the command level", settings)
	}

	for name, env := range map[string]Environment{
		"a key git refuses":     withHome(func(e *Environment) { e.Commands = []Command{{Key: "nosection", Value: "x"}} }),
		"a broken count":        withHome(func(e *Environment) { e.CommandsBroken = "GIT_CONFIG_COUNT is broken" }),
		"GIT_CONFIG_PARAMETERS": withHome(func(e *Environment) { e.Parameters = "'http.sslcainfo'='/x'" }),
	} {
		if settings := readSettings(files, "", env); settings.Unreadable == "" {
			t.Errorf("%s: got %+v, want the row left without a verdict", name, settings)
		}
	}
}

// THE COUNT IS READ AS git_config_from_parameters READS IT, and a missing pair
// stops git (S26) - so it stops here.
func TestTheCountIsReadAsGitReadsIt(t *testing.T) {
	cases := []struct {
		name   string
		vars   map[string]string
		pairs  int
		broken bool
	}{
		{"unset", map[string]string{}, 0, false},
		{"empty", map[string]string{"GIT_CONFIG_COUNT": ""}, 0, false},
		{"two pairs", map[string]string{"GIT_CONFIG_COUNT": " +2", "GIT_CONFIG_KEY_0": "a.b", "GIT_CONFIG_VALUE_0": "1",
			"GIT_CONFIG_KEY_1": "c.d", "GIT_CONFIG_VALUE_1": ""}, 2, false},
		{"not a number", map[string]string{"GIT_CONFIG_COUNT": "x"}, 0, true},
		{"negative", map[string]string{"GIT_CONFIG_COUNT": "-1"}, 0, true},
		{"past INT_MAX", map[string]string{"GIT_CONFIG_COUNT": "2147483648"}, 0, true},
		{"a key missing", map[string]string{"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_VALUE_0": "1"}, 0, true},
		{"a value missing", map[string]string{"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "a.b"}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := EnvironmentFrom(func(name string) (string, bool) {
				value, set := c.vars[name]
				return value, set
			}, "linux")
			if len(env.Commands) != c.pairs || (env.CommandsBroken != "") != c.broken {
				t.Errorf("got %+v and %q", env.Commands, env.CommandsBroken)
			}
		})
	}
}

// canonicalKey is git_config_parse_key: section and name lower-cased and
// checked, the subsection kept as written.
func TestAKeyFromTheEnvironmentIsCheckedAsGitChecksIt(t *testing.T) {
	cases := map[string]string{
		"http.sslCAInfo":            "http.sslcainfo",
		"Http.https://X.SSLCAInfo":  "http.https://X.sslcainfo",
		"":                          "",
		"nodot":                     "",
		".x":                        "",
		"http.":                     "",
		"http.1x":                   "",
		"ht tp.x":                   "",
		"http.a\nb.x":               "",
		"include.path":              "include.path",
		"includeIf.gitdir:/x/.path": "includeif.gitdir:/x/.path",
	}
	for key, want := range cases {
		got, why := canonicalKey(key)
		if got != want || (want == "") != (why != "") {
			t.Errorf("%q: got %q %q, want %q", key, got, why, want)
		}
	}
}

// AN INCLUDE APPLIES WHERE IT STANDS - S26 measured it losing to a key written
// after it and winning over one written before it - and a relative path is taken
// from the directory of the file that names it.
func TestAnIncludeAppliesWhereItStands(t *testing.T) {
	inc := map[string]string{"/home/jdoe/inc": "[http]\n\tsslCAInfo = /included.crt\n"}
	settings := userConfig(t, "[include]\n\tpath = inc\n[http]\n\tsslCAInfo = /after.crt\n", inc)
	if settings.CAInfo != "/after.crt" {
		t.Errorf("include before the key: got %q, want the key after it", settings.CAInfo)
	}
	settings = userConfig(t, "[http]\n\tsslCAInfo = /before.crt\n[include]\n\tpath = inc\n", inc)
	if settings.CAInfo != "/included.crt" || settings.CAInfoLevel != "global" {
		t.Errorf("include after the key: got %+v, want the included one at the includer's level", settings)
	}
	settings = userConfig(t, "[include]\n\tpath = ~/inc\n", inc)
	if settings.CAInfo != "/included.crt" {
		t.Errorf("include through ~/: got %+v", settings)
	}
	settings = userConfig(t, "[include]\n\tpath = /home/jdoe/inc\n", inc)
	if settings.CAInfo != "/included.crt" {
		t.Errorf("an absolute include: got %+v", settings)
	}
	// S26: an include of a file that is not there is passed over in silence.
	settings = userConfig(t, "[include]\n\tpath = missing\n[http]\n\tsslCAInfo = /kept.crt\n", nil)
	if settings.CAInfo != "/kept.crt" || settings.Unreadable != "" {
		t.Errorf("a missing include: got %+v", settings)
	}
	// A key that only looks like an include is not one.
	settings = userConfig(t, "[include \"x\"]\n\tpath = inc\n", inc)
	if settings.CAInfoLevel != "" {
		t.Errorf("include.<x>.path was followed: %+v", settings)
	}
}

// WHERE GIT STOPS ON AN INCLUDE, THE ROW HAS NO VERDICT - and a user file git may
// not read is passed over the way git passes over it, where an included one it
// may not read stops it.
func TestAnIncludeGitStopsOnLeavesTheRowWithoutAVerdict(t *testing.T) {
	cases := map[string]string{
		"no path":                     "[include]\n\tpath\n",
		"git's install prefix":        "[include]\n\tpath = %(prefix)/etc/x\n",
		"another account's home":      "[include]\n\tpath = ~bob/x\n",
		"a file that includes itself": "[include]\n\tpath = .gitconfig\n",
	}
	for name, config := range cases {
		settings := userConfig(t, config, nil)
		if settings.Unreadable == "" {
			t.Errorf("%s: got %+v, want the row without a verdict", name, settings)
		}
	}

	files := sourceOf(map[string]string{
		"/home/jdoe/.gitconfig": "[include]\n\tpath = denied\n",
		"/home/jdoe/denied":     "",
	})
	settings := readSettings(deny(files, "/home/jdoe/denied"), "", home)
	if !strings.Contains(settings.Unreadable, "denied") {
		t.Errorf("an include git may not read: got %+v", settings)
	}
	settings = readSettings(deny(files, "/home/jdoe/.gitconfig"), "", home)
	if settings.Unreadable != "" {
		t.Errorf("a user file git may not read is passed over by git, got %+v", settings)
	}
	settings = readSettings(deny(files, "/etc/gitconfig"), "/etc/gitconfig", home)
	if settings.Unreadable == "" {
		t.Errorf("a system file git may not read stops it, got %+v", settings)
	}
}

// TEN INCLUDES DEEP IS READ AND ELEVEN STOP GIT - MAX_INCLUDE_DEPTH.
func TestIncludesStopPastTenDeep(t *testing.T) {
	chain := func(length int) map[string]string {
		files := map[string]string{"/home/jdoe/.gitconfig": "[include]\n\tpath = inc1\n"}
		for i := 1; i < length; i++ {
			files[fmt.Sprintf("/home/jdoe/inc%d", i)] = fmt.Sprintf("[include]\n\tpath = inc%d\n", i+1)
		}
		files[fmt.Sprintf("/home/jdoe/inc%d", length)] = "[http]\n\tsslCAInfo = /deep.crt\n"
		return files
	}
	if settings := readSettings(sourceOf(chain(maxIncludeDepth)), "", home); settings.CAInfo != "/deep.crt" {
		t.Errorf("ten deep: got %+v", settings)
	}
	if settings := readSettings(sourceOf(chain(maxIncludeDepth+1)), "", home); settings.Unreadable == "" {
		t.Errorf("eleven deep: got %+v, want git stopping", settings)
	}
}

// A RELATIVE INCLUDE FROM THE ENVIRONMENT IS REFUSED BY GIT, and an absolute one
// is read at the command level.
func TestAnIncludeFromTheEnvironment(t *testing.T) {
	files := sourceOf(map[string]string{"/inc": "[http]\n\tsslCAInfo = /from-env.crt\n"})
	settings := readSettings(files, "", withHome(func(e *Environment) {
		e.Commands = []Command{{Key: "include.path", Value: "/inc"}}
	}))
	if settings.CAInfo != "/from-env.crt" || settings.CAInfoLevel != commandLevel {
		t.Errorf("an absolute include: got %+v", settings)
	}
	settings = readSettings(files, "", withHome(func(e *Environment) {
		e.Commands = []Command{{Key: "include.path", Value: "inc"}}
	}))
	if settings.Unreadable == "" {
		t.Errorf("a relative include from the environment: got %+v", settings)
	}
}

// A FILE INCLUDED UNDER A CONDITION IS READ ONLY FOR WHAT IT TOUCHES - decided
// by the owner 2026-10-20. S26 measured a gitdir condition left unapplied
// outside a repository, which is one answer of many, so a touch is a condition
// this program does not evaluate.
func TestAConditionalIncludeIsReadOnlyForWhatItTouches(t *testing.T) {
	const when = "[includeIf \"gitdir:~/work/\"]\n\tpath = work\n"
	settings := userConfig(t, when, map[string]string{"/home/jdoe/work": "[http]\n\tsslCAInfo = /work.crt\n"})
	why := settings.Conditional[keyCAInfo]
	if !strings.Contains(why, "gitdir:~/work/") || !strings.Contains(why, "http.sslCAInfo") || settings.CAInfoLevel != "" {
		t.Errorf("a touching include: got %+v", settings)
	}
	settings = userConfig(t, when, map[string]string{"/home/jdoe/work": "[user]\n\temail = jdoe@example.com\n"})
	if len(settings.Conditional) != 0 || settings.Unreadable != "" {
		t.Errorf("an include that sets only an address: got %+v", settings)
	}
	settings = userConfig(t, when, nil)
	if len(settings.Conditional) != 0 {
		t.Errorf("an include of a file that is not there: got %+v", settings)
	}
	// Nested: a plain include inside a conditional one is just as conditional.
	settings = userConfig(t, when, map[string]string{
		"/home/jdoe/work":   "[include]\n\tpath = deeper\n",
		"/home/jdoe/deeper": "[http]\n\tsslVerify = false\n",
	})
	if settings.Conditional[keyVerify] == "" || settings.VerifyLevel != "" {
		t.Errorf("nested in a conditional include: got %+v", settings)
	}
	// What git would stop on only if the condition held is a condition too.
	for name, files := range map[string]map[string]string{
		"a syntax error":               {"/home/jdoe/work": "[http\n"},
		"no path at all":               {"/home/jdoe/.gitconfig": "[includeIf \"gitdir:~/work/\"]\n\tpath\n"},
		"a relative path from nowhere": nil,
	} {
		var settings Settings
		if files == nil {
			settings = readSettings(sourceOf(nil), "", withHome(func(e *Environment) {
				e.Commands = []Command{{Key: "includeIf.gitdir:/x/.path", Value: "rel"}}
			}))
		} else {
			all := map[string]string{"/home/jdoe/.gitconfig": when}
			for path, body := range files {
				all[path] = body
			}
			settings = readSettings(sourceOf(all), "", home)
		}
		if settings.Conditional[""] == "" || settings.Unreadable != "" {
			t.Errorf("%s: got %+v, want a condition on every key", name, settings)
		}
	}
	settings = readSettings(deny(sourceOf(map[string]string{"/home/jdoe/.gitconfig": when, "/home/jdoe/work": ""}),
		"/home/jdoe/work"), "", home)
	if settings.Conditional[""] == "" {
		t.Errorf("a conditional include nobody could read: got %+v", settings)
	}
}

// A SECTION FOR ONE URL IS A CONDITION - S26 measured one for the target winning
// over the general key and one for another host changing nothing, and which
// address is diagnosed is not this probe's question.
func TestAURLSectionTouchingAKeyIsACondition(t *testing.T) {
	settings := userConfig(t, "[http \"https://corp.example\"]\n\tsslVerify = false\n\tproxy = http://p:8080\n", nil)
	why := settings.Conditional[keyVerify]
	if !strings.Contains(why, "https://corp.example") || settings.VerifyLevel != "" || len(settings.Conditional) != 1 {
		t.Errorf("got %+v, want one condition naming the URL", settings)
	}
	settings = readSettings(sourceOf(nil), "", withHome(func(e *Environment) {
		e.Commands = []Command{{Key: "http.https://corp.example.sslCAInfo", Value: "/x"}}
	}))
	if settings.Conditional[keyCAInfo] == "" {
		t.Errorf("a URL key from the environment: got %+v", settings)
	}
}

// THE FOUR KEYS TREAT A MISSING VALUE AS http.c DOES - sslVerify alone is true,
// sslBackend alone puts the backend back to none, and the two path keys alone
// stop git (S26).
func TestTheKeysTreatAMissingValueAsGitDoes(t *testing.T) {
	settings := userConfig(t, "[http]\n\tsslBackend = schannel\n\tsslBackend\n", nil)
	if settings.Backend != "" || settings.BackendLevel != "" {
		t.Errorf("sslBackend alone: got %+v, want no backend", settings)
	}
	for _, key := range []string{"sslCAInfo", "sslCAPath"} {
		if settings := userConfig(t, "[http]\n\t"+key+"\n", nil); settings.Unreadable == "" {
			t.Errorf("%s alone: got %+v, want git stopping", key, settings)
		}
	}
	settings = userConfig(t, "[http]\n\tsslCAInfo =\n\tsslCAPath =\n", nil)
	if settings.CAInfoLevel != "global" || settings.CAInfo != "" || settings.CAPathLevel != "global" {
		t.Errorf("empty values: got %+v, want both set and empty", settings)
	}
}

// A PATH VALUE IS EXPANDED AS git_config_pathname EXPANDS IT - ~/ is git's
// home, and ":(optional)" makes a file that is not there unset the key, even one
// set before it.
func TestPathValuesAreExpandedAsGitExpandsThem(t *testing.T) {
	settings := userConfig(t, "[http]\n\tsslCAInfo = ~/ca.pem\n", nil)
	if settings.CAInfo != filepath.FromSlash("/home/jdoe/ca.pem") {
		t.Errorf("~/: got %q", settings.CAInfo)
	}
	settings = userConfig(t, "[http]\n\tsslCAInfo = /set.crt\n\tsslCAInfo = :(optional)/missing.crt\n", nil)
	if settings.CAInfoLevel != "" || settings.CAInfo != "" {
		t.Errorf(":(optional) and missing: got %+v, want the key unset", settings)
	}
	settings = userConfig(t, "[http]\n\tsslCAPath = :(optional)/there\n", map[string]string{"/there": ""})
	if settings.CAPath != "/there" {
		t.Errorf(":(optional) and present: got %+v", settings)
	}
	settings = userConfig(t, "[http]\n\tsslCAInfo = :(optional)\n", nil)
	if settings.CAInfoLevel != "" {
		t.Errorf(":(optional) and empty: got %+v, want the key unset", settings)
	}
	settings = readSettings(deny(sourceOf(map[string]string{"/home/jdoe/.gitconfig": "[http]\n\tsslCAInfo = :(optional)/d\n"}),
		"/d"), "", home)
	if settings.CAInfo != "/d" {
		t.Errorf(":(optional) and unreadable is not missing: got %+v", settings)
	}
	for _, value := range []string{"%(prefix)/etc/ca.pem", "~bob/ca.pem"} {
		if settings := userConfig(t, "[http]\n\tsslCAInfo = "+value+"\n", nil); settings.Unreadable == "" {
			t.Errorf("%s: got %+v, want the row without a verdict", value, settings)
		}
	}
	noHome := Environment{Platform: "linux", Commands: []Command{{Key: "http.sslCAInfo", Value: "~/ca.pem"}}}
	if settings := readSettings(sourceOf(nil), "", noHome); settings.Unreadable == "" {
		t.Errorf("~/ with no home: got %+v", settings)
	}
	split := Environment{Platform: "windows", HomeDrive: Variable{Value: "H:", Set: true}, HomePath: Variable{Value: `\`, Set: true},
		GlobalConfig: Variable{Set: true}, Commands: []Command{{Key: "http.sslCAInfo", Value: "~/ca.pem"}}}
	if settings := readSettings(sourceOf(nil), "", split); !strings.Contains(settings.Unreadable, `H:\`) {
		t.Errorf("~/ with an undetermined home: got %+v", settings)
	}
}

// is_absolute_path and find_last_dir_sep, per platform.
func TestPathsAreCutAsGitCutsThem(t *testing.T) {
	absolutes := []struct {
		platform, path string
		want           bool
	}{
		{"windows", `C:\x`, true}, {"windows", "c:x", true}, {"windows", "/x", true}, {"windows", `\x`, true},
		{"windows", "x", false}, {"windows", "1:x", false}, {"linux", "/x", true}, {"linux", `C:\x`, false},
	}
	for _, c := range absolutes {
		if got := absolute(c.platform, c.path); got != c.want {
			t.Errorf("absolute(%q, %q) = %v", c.platform, c.path, got)
		}
	}
	directories := map[[2]string]string{
		{"windows", `C:\a/b\c`}: `C:\a/b\`, {"linux", `/a\b/c`}: `/a\b/`, {"linux", "c"}: "",
	}
	for in, want := range directories {
		if got := directoryOf(in[0], in[1]); got != want {
			t.Errorf("directoryOf(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
	if section, sub, name, has := splitKey("loose"); section != "loose" || sub != "" || name != "" || has {
		t.Errorf("a key with no dot split as %q %q %q %v", section, sub, name, has)
	}
}

// A KEY SET UNDER A CONDITION LEAVES THE ROW WITHOUT A VERDICT - unless git
// would not ask a store at all, or a variable git reads later makes the key
// beside it irrelevant.
func TestAConditionLeavesTheRowWithoutAVerdict(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/bundle.crt": string(anchorPEM), "/env.crt": string(anchorPEM)})
	install := Install{Instance: "/usr/bin/git", Root: "/usr/bin"}
	settings := settingsFor("/bundle.crt")
	settings.Conditional = map[string]string{keyCAInfo: "a condition on the file"}

	store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, Environment{}, [][]byte{leafDER}, atNoon())
	if store.NotAssessed != "a condition on the file" || store.TrustsPresentedChain != nil {
		t.Errorf("got %+v, want the condition", store)
	}
	env := Environment{CAInfo: Variable{Value: "/env.crt", Set: true}}
	store = storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, env, [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		t.Errorf("GIT_SSL_CAINFO set: got %+v, want the file it names judged", store)
	}
	store = storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, Environment{NoVerify: true}, [][]byte{leafDER}, atNoon())
	if !strings.Contains(store.NotAssessed, "GIT_SSL_NO_VERIFY") {
		t.Errorf("GIT_SSL_NO_VERIFY set: got %+v, want verification off", store)
	}
	settings.Conditional = map[string]string{keyCAPath: "a condition on the directory"}
	store = storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, Environment{CAPath: Variable{Value: "/d", Set: true}}, [][]byte{leafDER}, atNoon())
	if !strings.Contains(store.NotAssessed, "GIT_SSL_CAPATH") {
		t.Errorf("GIT_SSL_CAPATH set: got %+v, want the variable's directory, not the condition", store)
	}
	settings.Conditional = map[string]string{"": "a condition on anything"}
	store = storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, env, [][]byte{leafDER}, atNoon())
	if store.NotAssessed != "a condition on anything" {
		t.Errorf("a condition on every key: got %+v", store)
	}
}

// A KEY WRITTEN EMPTY IS SET - git hands libcurl the empty name - and an empty
// backend is a name git stops on rather than none.
func TestAnEmptyConfiguredValueIsNamedAsEmpty(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	install := Install{Instance: "/usr/bin/git", Root: "/usr/bin"}
	cases := map[string]struct {
		settings Settings
		says     string
	}{
		"file":      {Settings{Backend: "openssl", BackendLevel: "system", CAInfoLevel: "global"}, "http.sslCAInfo is set and empty"},
		"directory": {Settings{Backend: "openssl", BackendLevel: "system", CAPathLevel: "global"}, "http.sslCAPath is set and empty"},
		"backend":   {Settings{BackendLevel: "global"}, `http.sslBackend is "" at the global level`},
	}
	for name, c := range cases {
		store := storeFor(t.Context(), probe.Ports{Source: sourceOf(nil)}, noFiles, install, c.settings, Environment{Platform: "linux"}, [][]byte{leafDER}, atNoon())
		if !strings.Contains(store.NotAssessed, c.says) {
			t.Errorf("%s: got %q, want %q", name, store.NotAssessed, c.says)
		}
	}
}

// WHERE GIT STOPS, THE ROW SAYS SO - the whole way from the environment through
// Probe, and a key after the one git stops on is not read.
func TestWhereGitStopsTheRowSaysWhy(t *testing.T) {
	source := sourceOf(map[string]string{
		gitCmdExe:               "MZ",
		gitSysConfig:            "[http]\n\tsslBackend = openssl\n",
		"/home/jdoe/.gitconfig": "[http]\n\tsslCAInfo\n\tsslVerify = false\n",
	})
	env := withHome(func(e *Environment) { e.Platform = "linux" })
	stores, err := Probe(source, noLinks, noFiles, nil, []string{gitCmdDir}, env, atNoon)(t.Context(), [][]byte{{0x30}})
	if err != nil || len(stores) != 1 {
		t.Fatalf("got %d rows and %v", len(stores), err)
	}
	if !strings.Contains(stores[0].NotAssessed, "sets http.sslCAInfo with no value") ||
		strings.Contains(stores[0].NotAssessed, "does not verify") {
		t.Errorf("got %q, want the key git stops on named and nothing after it read", stores[0].NotAssessed)
	}
}
