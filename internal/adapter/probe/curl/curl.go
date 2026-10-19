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

// find returns EVERY curl this machine has on PATH.
//
// THE WALK ITSELF IS CONSUMED RATHER THAN WRITTEN HERE - probe.Binaries. It is
// the same question the git probe asks, and a second copy of it is the shape
// OBS50 has taken four times in this tree: an entry aimed at one copy stops
// proving anything about the other, and the two drift the first time one of
// them gains a case. Why the walk searches instead of selecting, why it looks
// for a file rather than a name, and why one byte has to come back, are all
// recorded there.
func find(source file.Source, resolve file.Resolve, pathDirs []string) []Install {
	var found []Install
	for _, path := range probe.Binaries(source, resolve, pathDirs, "curl.exe", "curl") {
		found = append(found, Install{Path: path, OnPath: true})
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
	selected := withoutBracketed(first)
	for _, backend := range backends {
		if strings.Contains(selected, backend) {
			return strings.ToLower(backend), nil
		}
	}
	return "", nil
}

// withoutBracketed drops everything the version line puts in brackets.
//
// A BUILD WITH SEVERAL BACKENDS BRACKETS EVERY ONE IT DID NOT SELECT - curl
// 8.21.0, lib/vtls/vtls.c, multissl_version, read 2026-10-20 at
// https://github.com/curl/curl/blob/curl-8_21_0/lib/vtls/vtls.c . Before this,
// "OpenSSL/3.5.7 (Schannel)" read as Schannel, because Schannel is the name asked
// first - harmless while a Schannel row only said it could not be assessed, and a
// verdict about the wrong store once that row takes the Windows store's answer
// (ADR108 part 4). The platform in brackets after the version goes too, and no
// backend is ever spelled there.
func withoutBracketed(line string) string {
	var b strings.Builder
	depth := 0
	for _, r := range line {
		switch {
		case r == '(':
			depth++
		case r == ')' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Environment is what this package reads from the environment, handed in by the
// entry point so the package reads none of its own.
type Environment struct {
	// CABundle is CURL_CA_BUNDLE, which only a build reading a file honours.
	CABundle string
	// Homes holds the variables curl's own tool reads to find its configuration
	// file, by name - homeVariables lists them.
	Homes map[string]string
}

// EnvironmentFrom reads every variable this package needs, through getenv.
func EnvironmentFrom(getenv func(string) string) Environment {
	env := Environment{CABundle: getenv("CURL_CA_BUNDLE"), Homes: map[string]string{}}
	for _, name := range homeVariables {
		env.Homes[name] = getenv(name)
	}
	return env
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
