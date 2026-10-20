package probe

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"strings"
)

// This file is how a Linux machine names its distribution and where it keeps its
// CA bundle - the two facts the platform store's row is built on (ADR104), and
// the two facts curl and git need to defer to that row (ADR110).
//
// THEY LIVE HERE AND NOT WITH THE PLATFORM STORE because three rows ask them,
// and a copy in each is the shape OBS50 has taken in this tree four times: an
// entry aimed at one copy stops proving anything about the others.

// LinuxBundles are the CA bundles a Linux distribution may keep, in the order
// they are asked, and the first one that exists is the platform's own store.
//
// SOURCE, inviolable rule 18: src/crypto/x509/root_linux.go of Go 1.27.2, read
// 2026-10-15 - certFiles ("stop after finding one"), in that order. It is Go's
// own list, so the row reads exactly what a Go program on the machine reads.
var LinuxBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// LinuxReleases name the distribution, in precedence order - os-release(5):
// "/etc/os-release takes precedence over /usr/lib/os-release", read 2026-10-15
// at https://man7.org/linux/man-pages/man5/os-release.5.html
var LinuxReleases = []string{"/etc/os-release", "/usr/lib/os-release"}

// FallbackDistribution is the distribution when nothing names one. It is
// os-release(5)'s own default: "If not set, a default of ID=linux may be used."
const FallbackDistribution = "linux"

// FirstBundle returns the first candidate that exists, with its bytes or the
// reason they could not be read, and an empty path when none exists.
//
// A BUNDLE THAT EXISTS AND CANNOT BE READ ENDS THE SEARCH, and that is a
// deliberate difference from Go, which moves on to the next file. OpenSSL does
// not move on, so the next file would be a store some programs here never read,
// reported as the one they do.
func FirstBundle(source func(string) (io.ReadCloser, error), candidates []string) (string, []byte, error) {
	for _, path := range candidates {
		data, err := readAll(source, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return path, data, err
	}
	return "", nil, nil
}

// Distribution is the ID os-release gives, or the fallback.
//
// THE FIRST RELEASE FILE THAT EXISTS IS THE ONLY ONE READ - os-release(5): use
// its data "exclusively ... if it exists". A file that exists and names no ID
// gets the default, not the next file.
func Distribution(source func(string) (io.ReadCloser, error), releases []string) string {
	for _, path := range releases {
		data, err := readAll(source, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return FallbackDistribution
		}
		return idFrom(data)
	}
	return FallbackDistribution
}

// idFrom reads ID out of an os-release file.
//
// THE VALUE IS CHECKED AGAINST THE SPECIFICATION BEFORE IT IS PRINTED, because
// it is text from the machine being diagnosed and it lands in every surface of
// the report. os-release(5): "A lower-case string (no spaces or other characters
// outside of 0-9, a-z, ".", "_" and "-")". Anything else is not an ID and gets
// the default - a value that needed escaping cannot be a valid one. The last
// assignment wins, the way the shell that may source this file would read it.
func idFrom(data []byte) string {
	id := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		key, value, found := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if found && key == "ID" {
			id = unquoted(value)
		}
	}
	if !validID(id) {
		return FallbackDistribution
	}
	return id
}

// unquoted takes off one pair of matching quotes, which os-release(5) allows
// around any value.
func unquoted(value string) string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}

// validID reports whether a value is an ID as os-release(5) defines one. The
// length bound is ours - an ID is a word, and a report should not carry a page.
func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
