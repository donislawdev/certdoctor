// Command certdoctor diagnoses why this machine or this container cannot reach a
// given URL.
//
// Nothing is diagnosed yet. This entry point exists so that the release build
// produces an artefact CI can prove is statically linked - a check that cannot
// be written against a build that emits no binary.
//
// What it does today it does honestly: it assesses nothing and says so, on the
// log channel, and ends with the code that means "could not assess". There is no
// point at which this program claims to have checked something it has not.
package main

import (
	"fmt"
	"os"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

func main() {
	// Standard output is the report channel and it stays empty. A script that
	// redirected it must end up with an empty file rather than half a report.
	// Standard error is the log channel.
	fmt.Fprintln(os.Stderr, "certdoctor: nothing is implemented yet, so nothing about this machine has been assessed")
	os.Exit(exitcode.Inconclusive.Int())
}
