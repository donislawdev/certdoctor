package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// ADDRESSES WRITTEN INTO THE PROGRAM (2026-11-11, beside notelemetry_test.go).
// This program connects to what the person asked about and to nothing else, so
// a place it could connect to that nobody asked about has to be written down
// somewhere first - and the likeliest somewhere is a string. An update check,
// a crash report, a counter of runs: each starts as an address in a literal.
//
// The registry is by FILE AND HOST, the owner's decision of the same day: each
// file names the hosts it may write into an address, each with the reason. A
// new link to a source a file already cites costs nothing, a new host always
// costs a line. Two kinds of address need no line at all, because neither
// names a place anybody could be listening on our behalf: a scheme with no host
// (the words "an http:// address" in a sentence), and a host kept for examples
// by RFC 2606 - example.com, example.net, example.org and the top level domains
// example and invalid. A name merely LIKE them (example.com.evil.net) is not one.
//
// It reads string literals in the files a shipped binary is built from, every
// build tag. What it cannot see: an address put together at run time ("https://"
// + host), a host written without a scheme - notelemetry_test.go refuses that
// one where it would matter, as an argument that widens the allowed set - and
// text a file embeds rather than spells.

// addressHosts are the hosts each shipped file may name in an address, and why.
var addressHosts = map[string]map[string]string{
	"internal/adapter/proxyauth/challenge.go": {
		"%s": "the request line of the question put to a proxy - the host is the target's, filled in at run time",
	},
	"internal/core/trust/descriptor.go": {
		"learn.microsoft.com": "the source of a claim about certutil, quoted in the report (inviolable rule 18) and never opened",
		"github.com":          "sources of claims about git, curl and node, quoted in the report and never opened",
		"git-scm.com":         "the source of a claim about git config, quoted in the report and never opened",
		"docs.oracle.com":     "the source of a claim about keytool, quoted in the report and never opened",
		"curl.se":             "the source of a claim about curl, quoted in the report and never opened",
	},
	"internal/core/trust/inspection.go": {
		"github.com":        "the source of the mitmproxy entry on the list of inspection products, never opened",
		"docs.umbrella.com": "the source of the Cisco Umbrella entry on the list of inspection products, never opened",
	},
	"internal/gui/catalogue/parts.go": {
		"untrusted-root.badssl.com": "text typed into a field of the catalogue of the window's parts - the catalogue runs nothing",
	},
	"internal/gui/parts/heart.go": {"www.w3.org": "the SVG namespace of a drawn picture, an identifier and not an address"},
	"internal/gui/parts/mark.go":  {"www.w3.org": "the SVG namespace of a drawn picture, an identifier and not an address"},
	"internal/gui/words/words.go": {
		"github.com":      "this project's repository, handed to the browser on a press of GitHub (ADR122)",
		"donislawdev.com": "the support page, handed to the browser on a press of Donate (ADR122)",
	},
}

// addressSchemes are the ones worth finding, each a way of naming somewhere else.
var addressSchemes = []string{"https://", "http://", "ftp://", "wss://", "ws://", "ldaps://", "ldap://"}

// addressesIn pulls every address out of a string, wherever in it they sit -
// TestingFilesGenerator measured why: its first version asked whether a literal
// STARTED with a scheme, and an address inside an SVG namespace walked past.
func addressesIn(text string) []string {
	var found []string
	for i := 0; i < len(text); i++ {
		for _, scheme := range addressSchemes {
			if !strings.HasPrefix(text[i:], scheme) {
				continue
			}
			end := strings.IndexAny(text[i:], "\"'`<>, \t\r\n\\")
			if end < 0 {
				end = len(text) - i
			}
			found = append(found, text[i:i+end])
			i += end - 1
			break
		}
	}
	return found
}

// hostOf is the host an address names, in lower case, without the user, the
// port or a closing dot.
func hostOf(address string) string {
	rest := address[strings.Index(address, "://")+3:]
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end >= 0 {
			return strings.ToLower(rest[:end+1])
		}
	}
	if colon := strings.LastIndex(rest, ":"); colon >= 0 {
		rest = rest[:colon]
	}
	return strings.ToLower(strings.TrimSuffix(rest, "."))
}

// namesNoPlace reports whether a host is no place anybody could listen on: no
// host at all, or one RFC 2606 keeps for examples.
func namesNoPlace(host string) bool {
	if host == "" {
		return true
	}
	for _, kept := range []string{"example.com", "example.net", "example.org"} {
		if host == kept || strings.HasSuffix(host, "."+kept) {
			return true
		}
	}
	top := host[strings.LastIndex(host, ".")+1:]
	return top == "example" || top == "invalid"
}

// addressUse is one address in a literal of a file.
type addressUse struct {
	address, host string
	line          int
}

// addressUses are the addresses a file writes into its string literals.
func addressUses(sf sourceFile) []addressUse {
	var uses []addressUse
	ast.Inspect(sf.file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		for _, address := range addressesIn(literalValue(lit)) {
			uses = append(uses, addressUse{address, hostOf(address), sf.fset.Position(lit.Pos()).Line})
		}
		return true
	})
	return uses
}

// checkAddresses reports every address naming a host its file is not allowed.
func checkAddresses(files []sourceFile) []Violation {
	var violations []Violation
	for _, sf := range files {
		for _, use := range addressUses(sf) {
			if namesNoPlace(use.host) || addressHosts[sf.rel][use.host] != "" {
				continue
			}
			violations = append(violations, Violation{sf.rel, use.line, fmt.Sprintf(
				"%s names the host %s in %q, which addressHosts in addresses_test.go does not allow for it - an "+
					"address written into the program is where a connection nobody asked for would go, so a new "+
					"one is a decision, written there with the reason", sf.rel, use.host, use.address)})
		}
	}
	return sortViolations(violations)
}

// TestNoShippedFileNamesAHostNobodyAllowed is the guard on the tree.
func TestNoShippedFileNamesAHostNobodyAllowed(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkAddresses(shippedFiles(t, tr)), "an address nobody allowed")
}

// TestEveryAllowedHostIsStillNamed - a line for a host its file no longer
// names forgives the next address that arrives there.
func TestEveryAllowedHostIsStillNamed(t *testing.T) {
	tr := mustLoadModule(t)
	for rel, hosts := range addressHosts {
		sf, ok := fileOf(tr, rel)
		if !ok {
			t.Errorf("addressHosts names %s, which is not in the tree", rel)
			continue
		}
		named := map[string]bool{}
		for _, use := range addressUses(sf) {
			named[use.host] = true
		}
		for host, why := range hosts {
			if !named[host] {
				t.Errorf("addressHosts lets %s name %s, and it names it nowhere - delete the line", rel, host)
			}
			if strings.TrimSpace(why) == "" {
				t.Errorf("addressHosts lets %s name %s without saying why", rel, host)
			}
		}
	}
}

// The canary: every shape an address can take in a literal, each its own case.
func TestTheAddressScannerRefusesWhatItMustRefuse(t *testing.T) {
	const elsewhere = "internal/core/report/planted.go"
	for _, c := range []struct{ label, src, host string }{
		{"an endpoint alone", "\"https://metrics.telemetry-net.org/v1\"", "metrics.telemetry-net.org"},
		{"an endpoint inside a longer string", "\"POST https://metrics.telemetry-net.org/v1 HTTP/1.1\"", "metrics.telemetry-net.org"},
		{"an endpoint in a raw string", "`<ping to=\"https://metrics.telemetry-net.org/v1\"/>`", "metrics.telemetry-net.org"},
		{"an endpoint in a format string", "\"https://metrics.telemetry-net.org/v1?id=%s\"", "metrics.telemetry-net.org"},
		{"a websocket", "\"wss://metrics.telemetry-net.org\"", "metrics.telemetry-net.org"},
		{"a user and a port", "\"https://key@Metrics.Telemetry-Net.org:8443/v1\"", "metrics.telemetry-net.org"},
		{"an address by number", "\"http://203.0.113.9:8080/\"", "203.0.113.9"},
		{"an address by number, version 6", "\"http://[2001:db8::9]:8080/\"", "[2001:db8::9]"},
		{"a name that only starts like an example", "\"https://example.com.telemetry-net.org/\"", "example.com.telemetry-net.org"},
		{"a host allowed in another file", "\"https://github.com/donislawdev/certdoctor\"", "github.com"},
	} {
		sf := sourceFrom(t, elsewhere, "package p\n\nvar v = "+c.src+"\n")
		got := checkAddresses([]sourceFile{sf})
		if len(got) != 1 || !strings.Contains(got[0].Detail, "the host "+c.host+" ") {
			t.Errorf("%s: wanted one violation naming %s, got %v", c.label, c.host, got)
		}
	}
}

// And it does not get there by refusing every address.
func TestTheAddressScannerLeavesWhatItMustLeave(t *testing.T) {
	for _, c := range []struct{ label, rel, src string }{
		{"a scheme in a sentence", "cmd/certdoctor/planted.go", "\"give an http:// or https:// address\""},
		{"a scheme joined to a value", "cmd/certdoctor/planted.go", "\"https://\" + x"},
		{"an example of RFC 2606", "cmd/certdoctor/planted.go", "\"https://example.com:8080/path\""},
		{"an example below one", "cmd/certdoctor/planted.go", "\"http://www.example.org/\""},
		{"a top level domain kept for examples", "cmd/certdoctor/planted.go", "\"http://proxy.example/proxy.pac\""},
		{"a name that cannot resolve", "cmd/certdoctor/planted.go", "\"https://target.invalid/\""},
		{"a word that is no address", "cmd/certdoctor/planted.go", "\"the https scheme\""},
	} {
		sf := sourceFrom(t, c.rel, "package p\n\nvar v = "+c.src+"\n")
		if got := checkAddresses([]sourceFile{sf}); len(got) != 0 {
			t.Errorf("%s: wanted nothing, got %v", c.label, got)
		}
	}
}
