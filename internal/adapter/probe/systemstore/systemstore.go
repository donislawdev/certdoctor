// Package systemstore answers what the platform's OWN trust store makes of a
// presented chain - the question every row that defers to the platform points
// at, curl on Schannel first among them.
//
// ON WINDOWS IT ASKS crypt32 ITSELF, WITH THE NETWORK SWITCHED OFF - ADR101.
// The verifier in crypto/x509 would ask the same library with none of the flags
// that stop it fetching, and the address it would fetch from is written into the
// certificate by the server under diagnosis. Inviolable rule 16 forbids exactly
// that connection.
//
// THE PRICE OF SWITCHING IT OFF IS ONE AMBIGUITY, AND THIS PACKAGE SETTLES IT
// LOCALLY. Measured 2026-09-23: a root in Microsoft's root program that this
// machine has not downloaded yet fails as a partial chain, exactly like an
// inspection authority nobody installed - and the second one is the scenario
// this product exists for. The local copy of the program's list tells them
// apart without the network, measured 2026-10-13 - judge.go is where.
//
// ON LINUX THERE IS NO SUCH LIBRARY, AND THE STORE IS A FILE - ADR104. The row
// reads the bundle Go itself reads, and bundle.go is where.
//
// WINDOWS AND LINUX - ADR103 and ADR104. macOS is M3.
package systemstore

import (
	"context"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Probe builds the L5 probe for the platform's own store, or returns nil on a
// platform whose store this package does not read yet.
//
// THE TWO PORTS ARE HOW LINUX IS READ - a source for files and a listing of the
// files in a directory, both guarded the way every other probe's are. Windows
// asks crypt32 and does not use them.
//
// NIL RATHER THAN A PROBE THAT FINDS NOTHING. Every probe in this tree answers
// "zero instances" when a runtime is not installed, and the layer reads that as
// a runtime absent from the machine - but the platform store is never absent.
// Saying it was would turn a gap in this program into a claim about somebody's
// machine, so on those platforms the probe is simply not wired, and the
// coverage note says which families were asked.
func Probe(source file.Source, files file.List, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return platformProbe(source, files, now)
}
