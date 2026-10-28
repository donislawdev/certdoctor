// Command sbom writes the bill of materials of a certdoctor release, as an
// SPDX 2.3 document on standard output.
//
// It is a build tool and never ships. The release builds ./cmd/certdoctor by
// name, and a main package cannot be imported, so nothing in here reaches a
// binary that a person downloads.
//
// WHAT IT READS. Standard input is what "go version -m" prints for the built
// binaries, so the document describes the artefacts rather than the tree they
// came from: the toolchain, the target, the commit and every module with the
// version the compiler recorded in each binary. What a build cannot know - the
// licence of each component and its copyright lines - comes from
// THIRD-PARTY-NOTICES.md, compiled into this command from the same tree. The
// two are compared before anything is written, and a build that links a module
// or a version the notices do not name is refused rather than described. A bill
// of materials that leaves out what it cannot see still claims to be complete.
//
// IT OPENS NO FILE AND WRITES NONE. The input arrives on a pipe and the
// document leaves on one, so neither the list of files allowed to write nor the
// list of files allowed to read grew for a tool that is not the product.
//
// Usage:
//
//	go version -m dist/* | go run ./cmd/sbom > certdoctor.spdx.json
//
// Exit codes: 0 when the document was written, 1 when the builds and the
// notices disagree or the notices cannot describe a build, 2 when standard
// input is not a listing of builds at all.
package main

import (
	"fmt"
	"io"
	"os"

	certdoctor "github.com/donislawdev/certdoctor"
)

// inputCeiling is how much of standard input is read. A listing of five
// binaries is under four kilobytes, and anything near a megabyte is something
// other than a listing.
const inputCeiling = 1 << 20

// A tree is what this command knows about the source the builds came from: the
// notices and the version, both compiled in from the module root.
type tree struct {
	notices string
	version string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, tree{notices: certdoctor.Notices, version: certdoctor.Version}))
}

// run is the command without the process around it, so that a test can call it
// with notices of its own.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, from tree) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: go version -m <binary>... | sbom > certdoctor.spdx.json")
		return 2
	}
	input, err := io.ReadAll(io.LimitReader(stdin, inputCeiling+1))
	if err != nil {
		fmt.Fprintf(stderr, "sbom: reading standard input: %v\n", err)
		return 2
	}
	if len(input) > inputCeiling {
		fmt.Fprintf(stderr, "sbom: standard input is over %d bytes, which no listing of builds is\n", inputCeiling)
		return 2
	}
	builds, err := parseBuilds(string(input))
	if err != nil {
		fmt.Fprintf(stderr, "sbom: %v\n", err)
		return 2
	}
	notes, err := parseNotices(from.notices)
	if err != nil {
		fmt.Fprintf(stderr, "sbom: THIRD-PARTY-NOTICES.md cannot describe a build: %v\n", err)
		return 1
	}
	if problems := reconcile(builds, notes); len(problems) > 0 {
		fmt.Fprintln(stderr, "sbom: the builds and THIRD-PARTY-NOTICES.md disagree, so no document was written:")
		for _, p := range problems {
			fmt.Fprintf(stderr, "  %s\n", p)
		}
		return 1
	}
	document, err := render(from.version, builds, notes)
	if err != nil {
		fmt.Fprintf(stderr, "sbom: %v\n", err)
		return 1
	}
	if _, err := stdout.Write(document); err != nil {
		fmt.Fprintf(stderr, "sbom: writing the document: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "sbom: %s\n", summary(from.version, builds, notes))
	return 0
}
