// Package tcp is layer L3: can this machine open a connection to the addresses
// the name resolved to.
//
// IT ANSWERS A NARROWER QUESTION THAN IT LOOKS. A connection that opens says
// nothing about what is listening there - whether it speaks TLS, whether the
// certificate verifies, whether a proxy is in the way. Those are L4's and L2's
// questions. This layer establishes reachability and the SHAPE of unreachability,
// which is the part a person cannot get from a browser saying "cannot connect".
package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Connect opens one connection to one address and hands back something that can
// be closed.
//
// THE PORT TRAVELS BESIDE THE ADDRESS RATHER THAN GLUED TO IT, and that is not
// cosmetic. The set of places this run may reach compares STRINGS, so the address
// dialled and the address permitted have to be spelled identically - and the one
// function that joins them lives in the adapter, next to the dialler, where both
// sides of that comparison can use it. Joining them here would put a second
// spelling in the core, which is how a guard starts refusing addresses on a
// working machine. Measured the hard way: the first version passed a bare address
// and every connection came back refused_by_rule.
//
// IT RETURNS AN io.Closer AND THE LAYER CLOSES IT IMMEDIATELY. This layer's
// question is whether the connection opens, so holding it any longer would be
// holding somebody else's socket for no measurement. L4 will open its own, and
// it will want the connection rather than the fact.
//
// It is declared here rather than imported from the adapter for the same reason
// resolve.Exchange is: the core may not name a type from internal/adapter.
type Connect func(ctx context.Context, address string, port int) (io.Closer, error)

// The failures a caller of Connect has to be able to tell apart.
//
// THEY ARE SENTINELS RATHER THAN TYPES FROM THE ADAPTER, and the adapter maps
// whatever the operating system said onto them - so the decision "which word does
// the report show" is made in one place, in the core, where it can be tested
// without a network.
//
// ANYTHING ELSE IS A TIMEOUT ONLY IF THE CONTEXT SAYS SO, and otherwise a reset:
// the deliberate default is the one that describes the wire rather than one that
// claims to know why.
var (
	// ErrRefusedByRule - the allowed set refused this address, so nothing was
	// sent. A fact about us, never about their network.
	ErrRefusedByRule = errors.New("this address is not in the set of places this run may connect to")
	// ErrRefused - something answered and refused the connection.
	ErrRefused = errors.New("the connection was refused")
	// ErrTimeout - nothing answered before the deadline.
	ErrTimeout = errors.New("nothing answered before the deadline")
	// ErrReset - the connection was torn down rather than refused or accepted.
	ErrReset = errors.New("the connection was reset")
	// ErrUnreachable - the network reported no route.
	ErrUnreachable = errors.New("there is no route to this address")
)

// Input is everything one walk of L3 was handed.
type Input struct {
	// Addresses is where to connect, asked for AT WALK TIME rather than handed
	// over as a list.
	//
	// IT IS A FUNCTION AND THAT IS THE WHOLE SEAM BETWEEN TWO LAYERS. Everything
	// else any layer needs is assembled by the entry point before the walk
	// starts. These addresses do not exist yet at that moment: L1 produces them,
	// and it runs first because the registry says so. Taking them as a function
	// makes the dependency visible in this type instead of hiding it in a closure
	// somebody has to go and find.
	//
	// A nil one means the layer was given no way to know, which is our defect and
	// is reported as one - not as a machine with nothing to connect to.
	Addresses func() []string
	// Port is the port to try, taken from the target URL.
	Port int
	// Connect is how a connection is opened. A nil one refuses everything, the
	// same direction every other port in this program chose: a forgotten port
	// must read as a program that cannot ask.
	Connect Connect
	// Now is the clock, taken as a port so the budget arithmetic is testable
	// without waiting for real time.
	Now func() time.Time
	// PerAddress is the longest one attempt may take, capped by whatever is left
	// of the layer's own deadline - ADR36, decided for L1 and binding here for
	// the same reason: one silent address must not spend the whole layer.
	PerAddress time.Duration
}

// Result is what this layer establishes.
type Result struct {
	Status   status.Status
	Reason   status.Reason
	Detail   string
	Findings []report.Finding
}

// Sentences for the cases where the layer establishes nothing.
const (
	noConnect   = "no way to open a connection was supplied, so nothing about reachability was established"
	noClock     = "no clock was supplied, so the time each attempt took could not be established"
	noAddresses = "no way to learn the addresses was supplied, so this layer could not know what to connect to"
	nothingToDo = "the name resolved to no address, so there was nothing to connect to"
)

// Ask tries every address once and reports what happened to each.
//
// ONE ATTEMPT PER ADDRESS, NEVER FOLDED. A name behind four addresses where one
// is unreachable is the "hangs, then works" class of fault, and a single folded
// row would report it as working or as broken - both wrong, and the wrong one is
// the one a person acts on.
func Ask(ctx context.Context, in Input) Result {
	if broken := in.unusable(); broken != "" {
		return Result{Status: status.Unknown, Reason: status.ReasonProbeError, Detail: broken}
	}
	addresses := in.Addresses()
	if len(addresses) == 0 {
		// NOT A FAILURE OF THIS LAYER. The name resolving nowhere is L1's finding
		// and L1 has already reported it - saying FAIL again here would count one
		// fault twice in the verdict.
		return Result{Status: status.Unknown, Reason: status.ReasonNothingToCheck, Detail: nothingToDo}
	}

	findings := make([]report.Finding, 0, len(addresses))
	reached := 0
	for i, address := range addresses {
		finding := in.tryOne(ctx, address, len(addresses)-i)
		if finding.TCPConnect.Outcome == report.OutcomeConnected {
			reached++
		}
		findings = append(findings, finding)
	}

	if reached == 0 {
		return Result{Status: status.Fail, Detail: detailFor(reached, addresses), Findings: findings}
	}
	return Result{Status: status.Pass, Detail: detailFor(reached, addresses), Findings: findings}
}

// unusable names the port this layer was not given, or returns empty.
//
// A MISSING PORT IS OUR DEFECT AND SAYS SO. Reporting it as a machine that
// cannot connect would accuse somebody's network of our own omission - inviolable
// rule 15.
func (in Input) unusable() string {
	switch {
	case in.Connect == nil:
		return noConnect
	case in.Now == nil:
		return noClock
	case in.Addresses == nil:
		return noAddresses
	}
	return ""
}

// tryOne makes one attempt and turns whatever happened into one finding.
//
// IT ALWAYS PRODUCES A ROW, including for an address that was never tried,
// because a report with fewer rows reads as a name with fewer addresses.
func (in Input) tryOne(ctx context.Context, address string, left int) report.Finding {
	remaining := in.limitFor(ctx, left)
	if remaining <= 0 {
		// NOT A TIMEOUT. Nothing was sent, so nothing failed to answer - this row
		// is about our budget, not about their network.
		return in.finding(address, report.OutcomeNotAttempted, 0)
	}

	attemptCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()

	started := in.Now()
	conn, err := in.Connect(attemptCtx, address, in.Port)
	elapsed := in.Now().Sub(started)

	// CLOSED BEFORE ANYTHING IS DECIDED, AND WITHOUT ASKING WHETHER err IS NIL.
	// A port may hand back a connection TOGETHER with an error - the io contract
	// permits exactly that, and this project has already paid for the assumption
	// once, in L1, where a reply arriving beside io.EOF was thrown away. Here the
	// same assumption leaks a socket instead of losing an answer, on the path
	// where something already went wrong, which is where leaks live.
	//
	// This layer's question is only whether the connection opens, so holding one
	// any longer would be holding a stranger's socket for no measurement.
	if conn != nil {
		_ = conn.Close()
	}

	if err != nil {
		outcome := outcomeFor(err)
		if !outcome.Reached() {
			// Nothing left this machine, so there is nothing whose duration this
			// could be - and the contract refuses a time here.
			return in.finding(address, outcome, 0)
		}
		return in.finding(address, outcome, elapsed)
	}
	return in.finding(address, report.OutcomeConnected, elapsed)
}

// limitFor is the share of what is left that this attempt may spend - ADR36.
//
// The same arithmetic L1 uses, and for the same measured reason: with a fixed
// per-attempt limit, one address that never answers spends the whole layer and
// the working ones are never tried.
func (in Input) limitFor(ctx context.Context, addressesLeft int) time.Duration {
	deadline, set := ctx.Deadline()
	if !set {
		// No layer deadline at all: there is nothing to divide, and the attempt's
		// own limit is the only thing left.
		return in.PerAddress
	}
	// THE CLOCK IS THE PORT AND NEVER time.Until. Reading the real clock here
	// while the rest of the layer reads the injected one would make the budget
	// untestable and, worse, would make it behave differently under test than in
	// production - the one place a wrong measurement is invisible.
	left := deadline.Sub(in.Now())
	if left <= 0 {
		return 0
	}
	share := left
	if addressesLeft > 1 {
		share = left / time.Duration(addressesLeft)
	}
	if in.PerAddress > 0 && in.PerAddress < share {
		return in.PerAddress
	}
	return share
}

// outcomeFor turns one of the sentinels into the word the report shows.
//
// AN UNRECOGNISED ERROR BECOMES reset RATHER THAN connected, and the direction is
// the point: a failure we did not anticipate must never read as a success.
func outcomeFor(err error) report.ConnectOutcome {
	switch {
	case errors.Is(err, ErrRefusedByRule):
		return report.OutcomeRefusedByRule
	case errors.Is(err, ErrRefused):
		return report.OutcomeRefused
	case errors.Is(err, ErrTimeout):
		return report.OutcomeTimeout
	case errors.Is(err, ErrUnreachable):
		return report.OutcomeUnreachable
	}
	return report.OutcomeReset
}

func (in Input) finding(address string, outcome report.ConnectOutcome, elapsed time.Duration) report.Finding {
	milliseconds := elapsed.Milliseconds()
	if milliseconds < 0 || !outcome.Reached() {
		milliseconds = 0
	}
	return report.Finding{
		Kind:    report.FindingTCPConnect,
		Summary: fmt.Sprintf("%s on port %d: %s", address, in.Port, outcome.Meaning()),
		Source:  report.SourceDetected,
		TCPConnect: &report.TCPConnect{
			Address:    address,
			Port:       in.Port,
			Outcome:    outcome,
			DurationMS: milliseconds,
		},
	}
}

// detailFor is the layer's one line.
//
// IT NAMES THE FAMILY THAT FAILED RATHER THAN JUST COUNTING, and that is the
// difference between a sentence and arithmetic. Every IPv6 address failing on a
// machine with no IPv6 is a fact about the machine and reads as one; the same
// count without the family reads as a broken destination.
func detailFor(reached int, addresses []string) string {
	if reached == 0 {
		return fmt.Sprintf("none of the %d address(es) this name resolved to accepted a connection%s",
			len(addresses), familyNote(addresses))
	}
	return fmt.Sprintf("%d of %d address(es) accepted a connection%s",
		reached, len(addresses), familyNote(addresses))
}

// familyNote says which families were tried, when there is more than one.
//
// IT NEVER NAMES AN ADDRESS, only a family and a count. This sentence goes
// through the same masking as everything else, and a sentence built out of counts
// cannot leak one by being written before somebody thought about it.
func familyNote(addresses []string) string {
	four, six := 0, 0
	for _, address := range addresses {
		parsed, err := netip.ParseAddr(address)
		switch {
		case err != nil:
			continue
		case parsed.Is4():
			four++
		default:
			six++
		}
	}
	if four == 0 || six == 0 {
		return ""
	}
	return fmt.Sprintf(", across %d IPv4 and %d IPv6", four, six)
}
