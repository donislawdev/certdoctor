// Command probe-macos-truststore answers one open question: can certdoctor
// list the macOS trust anchors with cgo disabled?
//
// WHY IT DECIDES SOMETHING. Cross-compiling without a C toolchain is the second
// reason this project is written in Go rather than Rust. If listing the macOS
// anchors turns out to need cgo, that reason weakens - building for macOS stops
// being free - and the decision has to be revisited rather than quietly carried.
//
// WHY IT LIVES HERE AND NOT WITH THE OTHER PROBES. The rest of them sit outside
// the repository, where a person runs them on the owner's machine. This one
// cannot be run there at all: it needs macOS. CI has a macOS runner and CI only
// sees what is committed, so this is the one probe that has to be public.
//
// IT IS A SEPARATE MODULE ON PURPOSE. Inside the main module it would join
// `go build ./...`, demand a coverage floor, and need a rule in the layer guard
// - all for a program that is never released and never imported.
//
// THE EXPECTATION, WRITTEN DOWN BEFORE THE MEASUREMENT, so the result can
// contradict it: the `security` route works and is enough. The standard library
// route probably does NOT enumerate anything, because it can build a trust pool
// without being able to show what is in it, and a list is what a trust matrix
// needs. Being wrong about either half is worth more than being right.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// systemRoots is the keychain holding the anchors Apple ships. It is not in the
// default search list, so asking without naming it answers a different question
// than the one being asked.
//
// OCENA, NOT A SOURCE: this path is conventional rather than read out of Apple's
// documentation. The probe is built so that being wrong here is visible instead
// of silent - a keychain that is not there reports zero and says which path it
// tried, and the default search list is printed beside it.
const systemRoots = "/System/Library/Keychains/SystemRootCertificates.keychain"

func main() {
	fmt.Printf("platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("cgo at build time: %s\n", cgoSetting())

	if runtime.GOOS != "darwin" {
		fmt.Println("NOT APPLICABLE: this probe only answers anything on macOS.")
		return
	}

	stdlib := viaStandardLibrary()
	securityDefault := viaSecurity("the default search list")
	securityRoots := viaSecurity("the system roots keychain", systemRoots)

	fmt.Println()
	fmt.Println("--- what the search list actually is ---")
	fmt.Println(run("security", "list-keychains"))

	fmt.Println()
	fmt.Println("--- verdict ---")
	best := max(stdlib, max(securityDefault, securityRoots))
	if best == 0 {
		fmt.Println("NO ROUTE ENUMERATED ANYTHING.")
		fmt.Println("This contradicts the expectation and weakens reason 2 of the")
		fmt.Println("language decision. It is a result, not a broken probe - read the")
		fmt.Println("output above before treating it as a failure of this program.")
		os.Exit(1)
	}
	fmt.Printf("at least one route listed anchors without cgo, best count: %d\n", best)
}

// viaStandardLibrary asks the standard library for the platform pool and then
// tries to enumerate it.
//
// The enumeration call is deprecated precisely because it cannot answer on
// platforms where the pool is supplied by the operating system. That is the
// measurement: a pool we can verify against but cannot list is not enough for a
// trust matrix, which has to show WHICH anchors are present.
func viaStandardLibrary() int {
	fmt.Println()
	fmt.Println("--- route 1: crypto/x509.SystemCertPool ---")

	pool, err := x509.SystemCertPool()
	if err != nil {
		fmt.Printf("refused outright: %v\n", err)
		return 0
	}

	subjects := pool.Subjects()
	fmt.Printf("pool obtained, enumerable subjects: %d\n", len(subjects))
	if len(subjects) == 0 {
		fmt.Println("the pool exists and cannot be listed - usable for verifying, useless for a matrix")
	}
	return len(subjects)
}

// viaSecurity shells out to the system tool.
//
// THE TRAP THIS IS WRITTEN AGAINST, recorded before the probe was built: asking
// without -a returns exactly ONE certificate and looks like success. So this
// counts and prints the count rather than reporting that the call worked.
func viaSecurity(what string, keychain ...string) int {
	fmt.Println()
	fmt.Printf("--- route 2: security find-certificate over %s ---\n", what)

	args := append([]string{"find-certificate", "-a", "-p"}, keychain...)
	out := run("security", args...)
	if strings.HasPrefix(out, "FAILED") {
		fmt.Println(out)
		return 0
	}

	count, first := countPEM(out)
	fmt.Printf("certificates: %d\n", count)
	if first != "" {
		fmt.Printf("first fingerprint (sha256, truncated): %s\n", first)
	}
	return count
}

// countPEM walks every PEM block and returns how many parsed as certificates,
// plus a fingerprint of the first one.
//
// Anything that fails to parse is counted as not present rather than assumed to
// be a certificate, because a count inflated by junk would answer the question
// with a number that means nothing.
func countPEM(text string) (int, string) {
	rest := []byte(text)
	count := 0
	first := ""

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return count, first
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		count++
		if first == "" {
			sum := sha256.Sum256(certificate.Raw)
			first = hex.EncodeToString(sum[:])[:16]
		}
	}
}

func run(name string, args ...string) string {
	output, err := exec.Command(name, args...).Output()
	if err != nil {
		return fmt.Sprintf("FAILED: %s %s: %v", name, strings.Join(args, " "), err)
	}
	return string(output)
}

// cgoSetting reports what the compiler was told, read from the environment the
// build ran in rather than assumed. The whole question is about cgo being off,
// so a probe that did not say which way it was built would prove nothing.
func cgoSetting() string {
	if value, present := os.LookupEnv("CGO_ENABLED"); present {
		return value
	}
	return "not set at run time - check the build step"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
