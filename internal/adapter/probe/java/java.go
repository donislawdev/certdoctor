// Package java answers what each Java installation on this machine makes of a
// presented chain.
//
// SIX STORES ON THE OWNER'S MACHINE, MEASURED 2026-08-18 - four JDKs and a JRE 8
// in both bitnesses, each with its own lib/security/cacerts. This is the runtime
// ADR48 was written for: one row per STORE, never one per runtime, because a fix
// applied to one of six leaves five untouched and the report has to say so.
//
// IT RUNS keytool, WHICH IS WHY internal/adapter/probe/exec.go EXISTS. Measured:
// the stores here are PKCS12 in the JDKs and JKS in the JRE, so reading them
// directly means two parsers or a dependency, while keytool -list -rfc hands
// back PEM in one call - 113 blocks from one JDK, 563 ms. That PEM goes through
// the SAME verifier git uses.
package java

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
)

// storePassword is the documented default for a Java trust store.
//
// A STORE THAT WILL NOT OPEN WITH IT IS UNKNOWN WITH A REASON, NEVER A FAILURE
// TO TRUST - docs/20 says so at this descriptor, and inviolable rule 15 says it
// generally: "we could not read this" is not a fact about trust, and reporting
// it as one would send somebody to fix a store that is fine.
// IT TRAVELS IN THE CHILD'S ARGUMENT LIST AND THAT IS A DECISION - P3-5 from the
// external review, left as it is rather than fixed. An argument list is readable
// by anyone who can list processes on this machine, which is a real property and
// the reason the review raised it. What it would reveal here is the string
// "changeit": the value Oracle documents as the initial password of every cacerts
// file, quoted in this program's own descriptor and in its own README. Hiding a
// published default costs something real - the only alternatives are a temporary
// file, which inviolable rule 14 forbids outright, or keytool's interactive
// prompt, which a diagnostic tool cannot answer.
const storePassword = "changeit"

// Install is one Java installation with a store we can name.
type Install struct {
	Root         string
	Store        string
	Keytool      string
	Variant      string
	Architecture string
}

// find turns candidate directories into the installations that actually have a
// store AND a keytool to read it with.
//
// A DIRECTORY IS NOT AN INSTALLATION - ADR48 part 2, and this is the runtime that
// proved it: measured 2026-08-18, C:\Program Files\Java\latest exists in BOTH
// bitnesses with no cacerts inside. Detection by directory name would have
// invented two rows about stores nobody has.
//
// THE VARIANT IS READ FROM STRUCTURE AND NOT FROM THE NAME. javac is present in a
// JDK and absent from a JRE - measured on both - so the row says which one it is
// without parsing a directory name, which is inviolable rule 19 applied to our
// own filesystem rather than to somebody's output.
//
// ONE INSTALLATION REACHED TWICE IS ONE ROW - the directory scan and PATH can
// both name it, and on Debian /usr/bin/java is a link ending inside the
// /usr/lib/jvm directory the scan already listed. The root is told apart by
// probe.IdentityKey, after the store has opened, for the same reason Binaries
// opens before it resolves.
func find(source file.Source, resolve file.Resolve, candidates []string) []Install {
	var found []Install
	seen := map[string]bool{}
	for _, root := range candidates {
		store := filepath.Join(root, "lib", "security", "cacerts")
		if !readable(source, store) {
			continue
		}
		keytool := binaryIn(source, root, "keytool")
		if keytool == "" {
			continue
		}
		key := probe.IdentityKey(resolve, root)
		if seen[key] {
			continue
		}
		seen[key] = true

		variant := "jre"
		if binaryIn(source, root, "javac") != "" {
			variant = "jdk"
		}
		architecture := "x64"
		if strings.Contains(root, "(x86)") {
			architecture = "x86"
		}
		found = append(found, Install{
			Root: root, Store: store, Keytool: keytool,
			Variant: variant, Architecture: architecture,
		})
	}
	return found
}

// installations is every Java installation this probe can name: the
// directories handed in, then the installation behind every java binary on
// PATH.
//
// PATH IS SEARCHED, NEVER ASKED - ADR50. Every directory on it is walked and
// every java there counts, so this can find more than one installation, which
// is what makes it a search rather than a favourite. JAVA_HOME is still never
// asked where Java is, and TestJavaHomeAloneFindsNothing holds that.
//
// OBS168, measured 2026-10-19 in eclipse-temurin:21-jre: Java lives in
// /opt/java/openjdk, its bin is on PATH, nothing is under /usr/lib/jvm, and the
// matrix had no java row while its note said java had been asked.
//
// THE BINARY IS RESOLVED BEFORE ITS ROOT IS TAKEN, because on Debian
// /usr/bin/java is a link through /etc/alternatives, and two directories up
// from the link is /usr, which is not an installation. A root that is not one
// is refused by find exactly like any other candidate - no store, no row.
func installations(source file.Source, resolve file.Resolve, candidates []string, pathDirs []string) []Install {
	roots := append([]string{}, candidates...)
	for _, binary := range probe.Binaries(source, resolve, pathDirs, "java.exe", "java") {
		roots = append(roots, filepath.Dir(filepath.Dir(probe.Resolved(resolve, binary))))
	}
	return find(source, resolve, roots)
}

// readable answers whether the port can open this path at all.
func readable(source file.Source, path string) bool {
	reader, err := source(path)
	if err != nil {
		return false
	}
	_ = reader.Close()
	return true
}

// anchorsOf asks keytool for every anchor in one store, as PEM.
//
// -rfc IS THE WHOLE REASON THIS WORKS WITHOUT A SECOND PARSER. Without it keytool
// prints a human listing that we would have to read by TEXT, which inviolable
// rule 19 forbids for exactly the reason it exists: that listing is translated on
// a machine whose language we do not choose. With it the output is PEM, which is
// a format rather than a message.
func anchorsOf(ctx context.Context, run probe.Runner, install Install) ([]byte, error) {
	out, err := run(ctx, install.Keytool,
		"-list", "-rfc", "-keystore", install.Store, "-storepass", storePassword)
	if err != nil {
		return nil, err
	}
	if out.ExitCode != 0 {
		// THE CODE, NEVER THE MESSAGE. A wrong password, a locked file and a
		// corrupt store all arrive as a non-zero exit, and which one it was is
		// somebody else's sentence in somebody else's language.
		return nil, fmt.Errorf("keytool exited with %d", out.ExitCode)
	}
	return []byte(out.Stdout), nil
}

// binaryIn finds a tool under bin, trying both spellings rather than asking
// which platform this is. A probe that branches on the operating system gets one
// more thing to be wrong about, and the answer is on disk either way.
func binaryIn(source file.Source, root, name string) string {
	for _, candidate := range []string{name + ".exe", name} {
		path := filepath.Join(root, "bin", candidate)
		if readable(source, path) {
			return path
		}
	}
	return ""
}
