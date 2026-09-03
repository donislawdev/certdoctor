package planted

// A planted violation: a file outside the entry point adds a target to the set
// of places this run may reach.
//
// This is the shape the guard exists for - a LAYER permitting itself, which
// turns the allowed set from a rule about what may happen into a description of
// what did.
import "github.com/donislawdev/certdoctor/internal/core/allowed"

func plant(targets *allowed.Targets) {
	_ = targets.Allow("example.invalid", allowed.ReasonTarget)
}
