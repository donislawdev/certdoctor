package probe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// CADirectories are the directories a TLS library may read certificates from
// beside its CA file, with the bounds on reading them.
type CADirectories struct {
	// Paths are read in this order, and every one of them is read.
	Paths []string
	// EntryCeiling and ByteCeiling bound the pass - how many entries one
	// directory may hold, and how many bytes the pass may read in all.
	EntryCeiling, ByteCeiling int
}

// LinuxCADirectories are Go's own directories on Linux.
//
// SOURCE, inviolable rule 18: src/crypto/x509/root_linux.go of Go 1.27.2, read
// 2026-10-15 - certDirectories ("all will be read"), in that order.
//
// THE CEILINGS ARE MEASURED BOUNDS, NOT GUESSES. S24 on 2026-10-15: the largest
// directory held 301 entries, and everything read from both came to well under a
// megabyte. Each ceiling is more than ten times that and still finite, which is
// the only property that matters - past it the row says it did not look rather
// than pretending it did.
var LinuxCADirectories = CADirectories{
	Paths:        []string{"/etc/ssl/certs", "/etc/pki/tls/certs"},
	EntryCeiling: 4096,
	ByteCeiling:  64 << 20,
}

// CADirectoriesOn returns the directories a TLS library on this platform may read
// beside its CA file, and none where no such directory was measured.
//
// ONLY LINUX, because only Linux was measured. S26, round two, 2026-10-20: curl
// and git from the Debian, Ubuntu and Alpine packages trusted a root kept only as
// a hashed link in /etc/ssl/certs while CURL_CA_BUNDLE, SSL_CERT_FILE,
// GIT_SSL_CAINFO or http.sslCAInfo named a file without it. libcurl keeps the
// directory it was built with unless a directory is named - curl 8.21.0,
// lib/vtls/vtls_config.c, Curl_ssl_easy_config_complete, read 2026-10-20 at
// https://github.com/curl/curl/blob/curl-8_21_0/lib/vtls/vtls_config.c
func CADirectoriesOn(platform string) CADirectories {
	if platform == "linux" {
		return LinuxCADirectories
	}
	return CADirectories{}
}

// DirectorySentences are what a row says when the directories stop a refusal
// from being proven. Each is a format taking the directory, and Unreadable the
// error after it.
//
// THE RULE IS SHARED AND THE WORDS ARE NOT. The platform store answers for every
// program on the machine, and a curl row answers for one build - the same
// directory means a different thing in each sentence.
type DirectorySentences struct {
	Closes, Unreadable, TooLarge string
}

// LibcurlDirectorySentences are the words for a tool on libcurl whose CA file
// was named and refused the chain. named is what named the file - a variable or
// a configuration key - and tool is the program. Both come from this program's
// own code, never from the machine, so neither can carry a formatting verb in.
//
// THE DIRECTORY IS THE BUILD'S, NOT THE PERSON'S. Naming a file does not switch
// off the directory libcurl was built with - measured by S26 on 2026-10-20, with
// the source under CADirectoriesOn - so a certificate there leaves the answer to
// how this build was made, which nothing here can read.
func LibcurlDirectorySentences(named, tool string) DirectorySentences {
	refused := "the file " + named + " names does not close this chain and "
	return DirectorySentences{
		Closes: refused + "a certificate in %s does - a " + tool + " built to read that directory as well trusts it, " +
			"so what this one makes of the chain is undetermined",
		Unreadable: refused + "%s could not be read in full (%v), so whether a certificate there closes it is undetermined",
		TooLarge:   refused + "%s holds more than this program reads, so whether a certificate there closes it is undetermined",
	}
}

// WeighDirectories reads the directories the way Go does when the bundle refused
// a chain for want of a signer, and turns the refusal into a row without a
// verdict when they close what the bundle did not.
//
// BESIDE THE PLATFORM'S OWN BUNDLE THEY ADD NOTHING IN ORDINARY USE - S24, eight
// images out of eight with a store: the directories held no certificate the
// bundle lacked. What they CAN add there is a certificate copied in by hand
// without the distribution's tool, which Go reads and OpenSSL reads through its
// hashed links while every program reading only the bundle refuses. Beside a
// file somebody NAMED they can add the whole platform store - S26, the case curl
// and git meet. Either way a FAIL would be true of the file the row names and
// false of the programs that read the directory too.
//
// IT RUNS ONLY ON A REFUSAL FOR WANT OF A SIGNER, and that check lives here so no
// caller can forget it. A directory can add a signer and never take one away, so
// a bundle that trusts the chain is already the answer - and an expired chain is
// refused whatever the directories hold.
//
// ONE RULE FOR EVERY ROW THAT READS A BUNDLE - the platform store, and curl and
// git when a file is named. Three copies of it would be the shape OBS50 has
// taken in this tree four times.
//
// THE PORTS ARRIVE AS PLAIN FUNCTIONS, the way Binaries takes them, because this
// package may not import the file adapter - the layer guard holds adapters to
// their own lane, and file.Source and file.List are these two shapes.
func WeighDirectories(store *report.TrustStore, source func(string) (io.ReadCloser, error),
	files func(string) ([]string, error), dirs CADirectories, bundle []byte, chain [][]byte, at time.Time,
	say DirectorySentences) {
	if !refusedForWantOfASigner(store) {
		return
	}
	anchors := bytes.Clone(bundle)
	for _, directory := range dirs.Paths {
		more, err := readDirectory(source, files, directory, dirs, everyFile, anchors)
		switch {
		case errors.Is(err, ErrDirectoryTooLarge):
			Undetermined(store, fmt.Sprintf(say.TooLarge, directory))
			return
		case err != nil:
			Undetermined(store, fmt.Sprintf(say.Unreadable, directory, err))
			return
		}
		anchors = more
		var trial report.TrustStore
		Verify(&trial, anchors, chain, at)
		if trial.TrustsPresentedChain != nil && *trial.TrustsPresentedChain {
			Undetermined(store, fmt.Sprintf(say.Closes, directory))
			return
		}
	}
}

// ErrDirectoryTooLarge says a directory holds more than CADirectories lets this
// program read.
var ErrDirectoryTooLarge = errors.New("it holds more than this program reads")

// HashedAnchors reads every certificate OpenSSL's directory lookup could find in
// dirs, as one PEM bundle, or names the directory that stopped it and why.
//
// IT IS NOT WeighDirectories, AND THE DIFFERENCE IS WHAT IS KNOWN. There a
// directory is one a build MAY also read, so a certificate in it leaves the
// answer undetermined. Here the program asked - Python said which directory its
// OpenSSL reads - so what is in it is part of the store, and goes into the
// verdict like the rest - ADR112 part 2.
//
// ONLY A FILE NAMED BY A SUBJECT HASH IS READ, because that is the only name
// OpenSSL opens: eight lowercase hex digits, a dot and a number counted from 0 -
// "%s%c%08lx.%s%d" with an empty postfix in get_cert_by_subject_ex,
// crypto/x509/by_dir.c of OpenSSL's openssl-3.5 branch, read 2026-10-21 at
// https://github.com/openssl/openssl/blob/openssl-3.5/crypto/x509/by_dir.c - so a
// certificate under any other name is one OpenSSL never finds, and counting it
// would be a false PASS. A revocation list carries an "r" before the number.
//
// WHAT IS NOT CHECKED, NAMED: that the hash in the name is the hash of the
// subject inside, and that the numbers run on from 0 without a gap - OpenSSL
// looks up one hash and stops at the first number missing. The tools that write
// these directories get both right, and a hand-made one that does not would be
// counted here and missed there.
func HashedAnchors(source func(string) (io.ReadCloser, error), files func(string) ([]string, error),
	dirs CADirectories) ([]byte, string, error) {
	var anchors []byte
	for _, directory := range dirs.Paths {
		more, err := readDirectory(source, files, directory, dirs, hashedName, anchors)
		if err != nil {
			return nil, directory, err
		}
		anchors = more
	}
	return anchors, "", nil
}

// readDirectory appends to anchors every file of one directory that keep takes,
// within the ceilings of dirs, and says why it stopped when it did. A directory
// that is not there adds nothing and is no error.
//
// BOTH READERS ABOVE GO THROUGH IT, so the ceilings and what a leftover link means
// are one rule in one place - OBS50.
func readDirectory(source func(string) (io.ReadCloser, error), files func(string) ([]string, error), directory string,
	dirs CADirectories, keep func(string) bool, anchors []byte) ([]byte, error) {
	names, err := files(directory)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return anchors, nil
	case err != nil:
		return nil, err
	case len(names) > dirs.EntryCeiling:
		return nil, ErrDirectoryTooLarge
	}
	for _, name := range names {
		if !keep(name) {
			continue
		}
		data, err := readAll(source, name)
		if errors.Is(err, fs.ErrNotExist) {
			// A dangling link is an ordinary leftover there and holds nothing.
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(anchors)+1+len(data) > dirs.ByteCeiling {
			return nil, ErrDirectoryTooLarge
		}
		anchors = append(append(anchors, '\n'), data...)
	}
	return anchors, nil
}

// everyFile is what Go reads from a certificate directory - every file in it.
func everyFile(string) bool { return true }

// hashedName says a path names a file OpenSSL's directory lookup opens for a
// certificate - HashedAnchors has the source.
func hashedName(path string) bool {
	hash, number, found := strings.Cut(filepath.Base(path), ".")
	if !found || len(hash) != 8 || number == "" {
		return false
	}
	for _, r := range hash {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	for _, r := range number {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// refusedForWantOfASigner is the one refusal a directory could overturn.
func refusedForWantOfASigner(store *report.TrustStore) bool {
	return store.TrustsPresentedChain != nil && !*store.TrustsPresentedChain &&
		store.TrustFailure == report.UnknownAuthority
}

// Undetermined turns a row into one without a verdict, for every probe - one
// rule in one place, which the python probe's own copy was not.
//
// EVERYTHING THAT DESCRIBED THE VERDICT GOES WITH IT. The contract refuses a row
// that could not assess a store and still counts what is in it, or still says
// why it refused - and the orchestrator drops a whole layer over one row it
// refuses. A strict refusal followed by a directory that could not be read did
// exactly that until ADR114: the detail of the refusal stayed, and the matrix
// went.
func Undetermined(store *report.TrustStore, why string) {
	store.TrustsPresentedChain = nil
	store.TrustFailure = ""
	store.RefusalDetail = ""
	store.TrustAnchorCount = 0
	store.NotAssessed = why
}

// readAll is the one place this file turns the port into bytes.
func readAll(source func(string) (io.ReadCloser, error), path string) ([]byte, error) {
	reader, err := source(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}
