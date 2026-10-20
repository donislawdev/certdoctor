package curl

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
)

// WHY A ROW LOOKS FOR curl'S CONFIGURATION FILE AT ALL. The tool reads one on
// every run unless told not to, and a line in it can switch the build to a CA
// file or directory of its own or turn a check off - cacert, capath,
// ssl-no-revoke, ssl-revoke-best-effort, insecure. Any of those makes "this build
// judges by the Windows store" or "this build reads the file CURL_CA_BUNDLE
// names" untrue, and this program does not read the file to find out which. So a
// row that finds one says so, and takes no store's answer - inviolable rule 15.
//
// WHERE IT LOOKS IS curl'S OWN ORDER, AND THE ORDER DEPENDS ON THE PLATFORM -
// curl 8.21.0, src/tool_findfile.c (conf_list, checkhome and findfile),
// src/tool_findfile.h (CURLRC_DOTSCORE) and src/tool_parsecfg.c, read 2026-10-20
// at https://github.com/curl/curl/tree/curl-8_21_0/src . Windows adds three
// places, asks for "_curlrc" beside ".curlrc" and ends in the binary's own
// directory. Everywhere else the tool asks for ".curlrc" alone and ends in the
// home directory the user database gives the account it runs as.
//
// homeVariables are every variable either order reads, so the entry point hands
// over all of them and the order picks.
var homeVariables = []string{"CURL_HOME", "XDG_CONFIG_HOME", "HOME", "USERPROFILE", "APPDATA"}

// configPlace is one row of curl's conf_list.
type configPlace struct {
	variable string
	// below is appended to the variable's value before the file name.
	below string
	// withoutDot is a place that holds "curlrc" rather than ".curlrc".
	withoutDot bool
}

// configOrder is where curl's tool looks for its configuration file on one
// platform.
type configOrder struct {
	places []configPlace
	// dotscore is CURLRC_DOTSCORE: 2 asks for "_curlrc" after ".curlrc" in each
	// place, 1 asks for ".curlrc" alone.
	dotscore int
	// besideBinary asks the binary's own directory when nothing above opened -
	// tool_parsecfg.c, on Windows alone.
	besideBinary bool
	// account asks the home directory of getpwuid(geteuid()) last - findfile,
	// everywhere but Windows.
	account bool
}

var windowsConfigOrder = configOrder{
	places: []configPlace{
		{variable: "CURL_HOME"},
		{variable: "XDG_CONFIG_HOME", withoutDot: true},
		{variable: "HOME"},
		{variable: "USERPROFILE"},
		{variable: "APPDATA"},
		{variable: "USERPROFILE", below: "Application Data"},
		{variable: "CURL_HOME", below: ".config", withoutDot: true},
		{variable: "HOME", below: ".config", withoutDot: true},
	},
	dotscore:     2,
	besideBinary: true,
}

var otherConfigOrder = configOrder{
	places: []configPlace{
		{variable: "CURL_HOME"},
		{variable: "XDG_CONFIG_HOME", withoutDot: true},
		{variable: "HOME"},
		{variable: "CURL_HOME", below: ".config", withoutDot: true},
		{variable: "HOME", below: ".config", withoutDot: true},
	},
	dotscore: 1,
	account:  true,
}

// configOrderOn returns the order curl's tool follows on a platform.
func configOrderOn(platform string) configOrder {
	if platform == "windows" {
		return windowsConfigOrder
	}
	return otherConfigOrder
}

// configCandidates lists, in curl's order, every file curl would try to open as
// its configuration file, the first one that opens being the one it reads.
//
// THE FIRST PLACE WITHOUT A DOT ENDS BOTH THE UNDERSCORE AND EVERY LATER PLACE
// WITHOUT A DOT, and that is curl's loop rather than a simplification here.
// findfile asks with the dotscore it started with until a place holding "curlrc"
// sets it to zero for the rest of the loop: every later place is asked for
// ".curlrc" alone, and every later place without a dot is skipped. A variable
// that is unset or empty is skipped before any of that happens.
func configCandidates(order configOrder, homes map[string]string, account, binary string) []string {
	var out []string
	dotscore := order.dotscore
	for _, p := range order.places {
		home := homes[p.variable]
		if home == "" {
			continue
		}
		dir := home
		if p.below != "" {
			dir = filepath.Join(home, p.below)
		}
		if p.withoutDot {
			if dotscore == 0 {
				continue
			}
			dotscore = 0
			out = append(out, filepath.Join(dir, "curlrc"))
			continue
		}
		out = append(out, filepath.Join(dir, ".curlrc"))
		if dotscore == 2 {
			out = append(out, filepath.Join(dir, "_curlrc"))
		}
	}
	if order.account && account != "" {
		out = append(out, filepath.Join(account, ".curlrc"))
	}
	if order.besideBinary {
		beside := filepath.Dir(binary)
		out = append(out, filepath.Join(beside, ".curlrc"), filepath.Join(beside, "_curlrc"))
	}
	return out
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
