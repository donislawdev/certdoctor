// Package dial is the only way this program is allowed to open a connection.
//
// IT EXISTS SO THAT INVIOLABLE RULE 16 CAN BE CHECKED RATHER THAN PROMISED. A
// Dialer is a seam: the real one is supplied from the entry point, a recording
// one is supplied by a test, and Guarded sits in front of either and refuses
// anything the run did not derive from the user's own question.
//
// NOTHING HERE IMPORTS net, AND THAT IS DELIBERATE. This package holds the
// rule, not the plumbing. The function that actually opens a socket arrives as
// a parameter and lives in the one file named on the dial allowlist in
// reach_test.go - so the number of places in this program able to start a
// connection stays countable, and this is not one of them.
package dial

import (
	"context"
	"fmt"
	"io"

	"github.com/donislawdev/certdoctor/internal/core/allowed"
)

// Dialer opens a connection to one address.
//
// The address is a string rather than a parsed structure because that is what
// the allowed set stores and compares. Handing this function something richer
// would mean the set and the dialler could disagree about what "the same
// address" is, and then the guard passes while the connection goes elsewhere.
type Dialer func(ctx context.Context, address string) (io.ReadWriteCloser, error)

// Record is told about every address a guarded dialler was ASKED for, whether
// or not it was permitted.
//
// The refusals are the interesting half. A run that tried to reach somewhere it
// should not is a finding about this program, and a recorder that only saw the
// permitted attempts would show a clean sheet in exactly the case worth seeing.
type Record func(address string, permitted bool)

// Refusal is returned when an address is not in the allowed set.
//
// It is a type rather than a bare error so a layer can tell "we were not
// allowed to look" apart from "we looked and it failed" - those are a defect on
// our side and a fact about the user's machine, and reporting the first as the
// second would accuse a working network of being broken.
type Refusal struct {
	Address string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("connecting to %s was refused: it is not one of the places this run derived from the target, "+
		"the addresses it resolved to, this machine's resolvers, the proxy, or the PAC file", r.Address)
}

// Guarded puts the allowed set in front of a dialler.
//
// A nil recorder is allowed and means nobody is watching; a nil set is not, and
// comes back as a refusal of everything. THAT DIRECTION IS CHOSEN: a forgotten
// set must not read as an empty set of restrictions. It reads as a program that
// cannot connect at all, which is loud, wrong in the safe direction, and
// impossible to mistake for working.
func Guarded(inner Dialer, targets *allowed.Targets, record Record) Dialer {
	return func(ctx context.Context, address string) (io.ReadWriteCloser, error) {
		permitted := false
		if targets != nil {
			_, permitted = targets.Permits(address)
		}
		if record != nil {
			record(address, permitted)
		}
		if !permitted {
			return nil, &Refusal{Address: address}
		}
		if inner == nil {
			return nil, fmt.Errorf("no dialler was supplied, so %s could not be reached", address)
		}
		return inner(ctx, address)
	}
}
