// Package curl answers what each curl on this machine makes of a presented
// chain, and which trust store it would even look at.
//
// TWO curl.exe ON PATH HERE, MEASURED 2026-08-18 - the system one and the one
// shipped inside the Git installation - and BOTH are built on Schannel. The
// second was expected to be OpenSSL and was not, which is why the backend is
// read from the program rather than assumed from where it sits.
//
// WHY THE BACKEND DECIDES EVERYTHING. Schannel asks Windows and IGNORES
// CURL_CA_BUNDLE - measured on this machine by pointing that variable at a path
// that does not exist and still getting a 200. A fix generated without reading
// the backend is a command that does nothing while a person waits for it to
// work, which docs/20 marks as the most expensive trap in the whole registry.
package curl

import (
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
)

// backends are the TLS implementations curl reports in its version line.
//
// RECOGNISED BY A TECHNICAL NAME AND THIS IS A DELIBERATE, NAMED EXCEPTION to
// inviolable rule 19 - docs/20 section 3 rule 2 grants it and says why: these
// are library names, not localised sentences, so they do not change with the
// language of the machine. The exception stops here: everything else about
// curl is read from an exit code.
var backends = []string{
	"Schannel", "OpenSSL", "LibreSSL", "BoringSSL", "GnuTLS",
	"NSS", "SecureTransport", "wolfSSL", "mbedTLS", "rustls",
}

// Install is one curl binary found on this machine.
type Install struct {
	Path    string
	Backend string
	OnPath  bool
}

// find walks EVERY directory on PATH and returns EVERY curl it finds.
//
// THIS IS A SEARCH AND NOT A SELECTION - ADR50. Taking the first hit would be
// naming a favourite, which is what ADR48 part 4 forbids and what would have
// hidden the second curl on this machine. Walking all of them produces the
// matrix instead.
//
// IT LOOKS FOR A FILE AND NOT FOR A NAME, which docs/20 flags at this
// descriptor: on Windows "curl" is also a PowerShell alias for
// Invoke-WebRequest, so a name that resolves proves nothing about a binary.
func find(source file.Source, pathDirs []string) []Install {
	var found []Install
	seen := map[string]bool{}

	for _, dir := range pathDirs {
		for _, name := range []string{"curl.exe", "curl"} {
			path := filepath.Join(dir, name)
			cleaned := filepath.Clean(path)
			// DEDUPLICATED CASE-INSENSITIVELY, AND THIS WAS A MEASURED DEFECT rather
			// than a precaution. PATH on this machine carries system32 in two
			// spellings - Windows and WINDOWS - and filepath.Clean does not fold
			// case, so the first run of this probe reported ONE binary as TWO stores
			// and the verdict counted ten where there are nine.
			//
			// THE COST, NAMED: on a case-sensitive filesystem two genuinely different
			// files whose names differ only by case would be folded into one. That is
			// a pathology nobody ships, while counting one binary twice is measured
			// and here.
			key := strings.ToLower(cleaned)
			if seen[key] {
				continue
			}
			reader, err := source(path)
			if err != nil {
				continue
			}
			_ = reader.Close()
			seen[key] = true
			found = append(found, Install{Path: cleaned, OnPath: true})
		}
	}
	return found
}

// backendOf asks the binary which TLS library it was built against.
func backendOf(ctx context.Context, run probe.Runner, install Install) (string, error) {
	out, err := run(ctx, install.Path, "--version")
	if err != nil {
		return "", err
	}
	if out.ExitCode != 0 {
		return "", errExitedNonZero
	}
	first := out.Stdout
	if line, _, found := strings.Cut(out.Stdout, "\n"); found {
		first = line
	}
	for _, backend := range backends {
		if strings.Contains(first, backend) {
			return strings.ToLower(backend), nil
		}
	}
	return "", nil
}

// errExitedNonZero is the one failure this package names for itself.
//
// THE CODE, NEVER THE MESSAGE. Why curl refused to print its version is a
// sentence in somebody else's language, and branching on it is exactly what
// inviolable rule 19 forbids.
var errExitedNonZero = curlError("curl did not report its version")

type curlError string

func (e curlError) Error() string { return string(e) }

// readAll is the one place this package turns a port into bytes.
func readAll(source file.Source, path string) ([]byte, error) {
	reader, err := source(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}
