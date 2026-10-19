package curl

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
)

// WHY A SCHANNEL ROW LOOKS FOR curl'S CONFIGURATION FILE AT ALL. The tool reads
// one on every run unless told not to, and a line in it can switch the build to
// a CA file of its own or turn revocation checks off - cacert, ssl-no-revoke,
// ssl-revoke-best-effort, insecure. Any of those makes "this build judges by the
// Windows store" untrue, and this program does not read the file to find out
// which. So a row that finds one says so, and takes no store's answer -
// inviolable rule 15.
//
// WHERE IT LOOKS IS curl'S OWN ORDER, ON WINDOWS - curl 8.21.0, src/tool_findfile.c
// (conf_list and findfile), src/tool_findfile.h (CURLRC_DOTSCORE) and
// src/tool_parsecfg.c, read 2026-10-20 at
// https://github.com/curl/curl/tree/curl-8_21_0/src . Windows alone, because only
// a Schannel build asks this question and Schannel is only on Windows.
var homeVariables = []string{"CURL_HOME", "XDG_CONFIG_HOME", "HOME", "USERPROFILE", "APPDATA"}

// configPlace is one row of curl's conf_list.
type configPlace struct {
	variable string
	// below is appended to the variable's value before the file name.
	below string
	// withoutDot is a place that holds "curlrc" rather than ".curlrc".
	withoutDot bool
}

var configPlaces = []configPlace{
	{variable: "CURL_HOME"},
	{variable: "XDG_CONFIG_HOME", withoutDot: true},
	{variable: "HOME"},
	{variable: "USERPROFILE"},
	{variable: "APPDATA"},
	{variable: "USERPROFILE", below: "Application Data"},
	{variable: "CURL_HOME", below: ".config", withoutDot: true},
	{variable: "HOME", below: ".config", withoutDot: true},
}

// configCandidates lists, in curl's order, every file curl would try to open as
// its configuration file, the first one that opens being the one it reads.
//
// THE UNDERSCORE STOPS AT THE FIRST PLACE WITHOUT A DOT, AND THAT IS curl'S LOOP
// RATHER THAN A SIMPLIFICATION HERE. findfile starts asking for ".curlrc" and
// "_curlrc" in each place, and the first place holding "curlrc" sets that to
// zero for the rest of the loop: every later place is asked for ".curlrc" alone,
// and every later place without a dot is skipped. A variable that is unset or
// empty is skipped before any of that happens.
//
// THE BINARY'S OWN DIRECTORY COMES LAST, and only when nothing above opened -
// tool_parsecfg.c, ".curlrc" and then "_curlrc".
func configCandidates(homes map[string]string, binary string) []string {
	var out []string
	underscoreToo := true
	for _, p := range configPlaces {
		home := homes[p.variable]
		if home == "" {
			continue
		}
		dir := home
		if p.below != "" {
			dir = filepath.Join(home, p.below)
		}
		if p.withoutDot {
			if !underscoreToo {
				continue
			}
			underscoreToo = false
			out = append(out, filepath.Join(dir, "curlrc"))
			continue
		}
		out = append(out, filepath.Join(dir, ".curlrc"))
		if underscoreToo {
			out = append(out, filepath.Join(dir, "_curlrc"))
		}
	}
	beside := filepath.Dir(binary)
	return append(out, filepath.Join(beside, ".curlrc"), filepath.Join(beside, "_curlrc"))
}

// configFile returns the first of the candidates curl would read, or a sentence
// when a place it would look in is one this program will not open.
//
// A FILE THAT DOES NOT OPEN IS PASSED OVER, AS curl PASSES IT. The tool opens
// each candidate read-only and moves on when that fails, whatever the reason.
// A directory opens here and fails at the first read, where curl's open fails
// outright - so it is passed over by both. An empty file is a file: curl reads
// it and stops looking.
//
// A PLACE ON ANOTHER MACHINE IS NOT OPENED - the file port refuses it, and
// inviolable rule 16 is why. Whether a configuration file waits there is then
// unknown, and the row says so rather than looking past it.
func configFile(source file.Source, candidates []string) (found, unreadable string) {
	for _, path := range candidates {
		reader, err := source(path)
		if err != nil {
			var remote *file.RemotePath
			if errors.As(err, &remote) {
				return "", fmt.Sprintf("curl would look for its configuration file at %s, which is not on this machine, "+
					"so whether one waits there was not read", path)
			}
			continue
		}
		_, readErr := reader.Read(make([]byte, 1))
		_ = reader.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			continue
		}
		return path, ""
	}
	return "", ""
}
