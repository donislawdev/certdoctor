package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// WHAT THIS FILE DELIBERATELY DOES NOT TEST, AND WHY IT WOULD BE WORSE THAN NO
// TEST AT ALL. Whether our dialler is called - the fact that decides detected
// against derived - depends on the machine the test runs on. Probe S10 measured
// it: Windows never calls it, Linux always does. An assertion about it would
// pass on one runner and fail on the other, so the mutation register would
// report ZLAPANE or PRZEZYLA depending on where somebody happened to run it.
// That is the trap OBS28 and OBS1 both name. The platform half is measured by
// running the real binary on both systems and written down; what is checked here
// is everything that is true on every machine.

// TestEachWayTheSystemViewFailsKeepsItsOwnReason is the mapping onto the closed
// list, and each row is a different place to go and look.
//
// A REFUSAL BY OUR OWN RULE MUST NEVER READ AS A NETWORK FAILURE. That is the
// same distinction dial.Refusal exists for one floor down: "we were not allowed
// to ask" is a defect on our side, "the wire said no" is a fact about the
// machine, and reporting the first as the second sends somebody to inspect a
// firewall that is working.
func TestEachWayTheSystemViewFailsKeepsItsOwnReason(t *testing.T) {
	refusal := errors.New("refused by the allowed set")

	cases := []struct {
		name    string
		err     error
		refused error
		want    report.NoAnswer
	}{
		{"it worked", nil, nil, ""},
		{"our own rule refused it", errors.New("dial refused"), refusal, report.NoAnswerRefusedByRule},
		{"the deadline passed", &net.DNSError{Err: "timeout", IsTimeout: true}, nil, report.NoAnswerTimeout},
		{"the context ran out", fmt.Errorf("lookup: %w", context.DeadlineExceeded), nil, report.NoAnswerTimeout},
		// A NAME THAT DOES NOT EXIST IS AN ANSWER. The platform told us it does
		// not resolve - it cannot tell us whether that was NXDOMAIN or an empty
		// record set, which is the distinction the direct view exists to make.
		{"the name does not exist", &net.DNSError{Err: "no such host", IsNotFound: true}, nil, ""},
		{"anything else", errors.New("network is unreachable"), nil, report.NoAnswerTransportError},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := systemNoAnswer(c.err, c.refused); got != c.want {
				t.Errorf("%v with refusal %v came back as %q, want %q", c.err, c.refused, got, c.want)
			}
		})
	}
}

// TestTheFactsSurviveBeingWrittenFromEveryDirectionAtOnce is point (b) of the
// stability run from docs/22 section 6a, aimed at the one piece of shared state
// this adapter owns.
//
// IT IS HERE BECAUSE THE PARALLELISM IS MEASURED, NOT SUSPECTED. net.Resolver
// calls the dialler we hand it from its own goroutines - in alpine, three runs
// of three, the A and the AAAA query overlapped in time. Nothing in this program
// starts those goroutines, which is exactly why this state is the only thing we
// can defend: they arrive whenever the standard library decides, and the race
// detector is the only witness that would ever notice.
func TestTheFactsSurviveBeingWrittenFromEveryDirectionAtOnce(t *testing.T) {
	const writers = 32

	facts := &dialFacts{}
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// Released together rather than one after another, so they land on an
			// untouched struct at the same moment instead of politely queueing.
			<-start
			facts.ourResolverIsDoingTheWork()
			facts.refusedBy(fmt.Errorf("refusal %d", n))
			_ = facts.wentThroughThePlatform()
			_ = facts.refusal()
		}(i)
	}
	close(start)
	wg.Wait()

	if facts.wentThroughThePlatform() {
		t.Error("our dialler was called and the facts still say the platform did the work")
	}
	if facts.refusal() == nil {
		t.Error("every writer recorded a refusal and none of them survived")
	}
}

// TestTheDiallerRecordsItselfBeforeItAsksPermission covers the seam on every
// platform, which is the whole reason it is a named function.
//
// THE ORDER OF THE TWO IS THE ASSERTION. Being called at all decides detected
// against derived, and it is true even when the address is then refused - the
// question went through our own resolver either way. Recording after the check
// would label a refused run as one the platform handled, which is the opposite
// of what happened.
func TestTheDiallerRecordsItselfBeforeItAsksPermission(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		seen := &dialFacts{}
		refusal := errors.New("not in the allowed set")
		_, err := guardedDial(seen, func(string) error { return refusal })(context.Background(), "udp", "192.0.2.53:53")

		if !errors.Is(err, refusal) {
			t.Errorf("the dialler answered %v where the rule refused", err)
		}
		if seen.wentThroughThePlatform() {
			t.Error("our dialler was called and refused, and the facts still say the platform did the work")
		}
		if !errors.Is(seen.refusal(), refusal) {
			t.Errorf("the refusal was not kept: %v", seen.refusal())
		}
	})

	t.Run("no rule at all", func(t *testing.T) {
		seen := &dialFacts{}
		conn, err := guardedDial(seen, nil)(context.Background(), "udp", "192.0.2.53:53")

		if err == nil {
			t.Error("a dialler with no permission rule opened something")
			if conn != nil {
				_ = conn.Close()
			}
		}
		if seen.refusal() == nil {
			t.Error("a missing rule refused nothing that anybody could see afterwards")
		}
	})
}

// TestTheFirstRefusalIsTheOneReported keeps the answer stable.
//
// A lookup is refused once per address it tries, and the reader needs one
// sentence rather than the last one to arrive. Keeping the first also makes the
// answer independent of which goroutine won, which is the only version of this
// that can be checked at all.
func TestTheFirstRefusalIsTheOneReported(t *testing.T) {
	facts := &dialFacts{}
	first := errors.New("the first one")

	facts.refusedBy(first)
	facts.refusedBy(errors.New("the second one"))

	if !errors.Is(facts.refusal(), first) {
		t.Errorf("the refusal reported is %v, and the first one was %v", facts.refusal(), first)
	}
}

// TestAMissingPermissionRuleRefusesRatherThanAsking is the direction this
// project does not get wrong on purpose.
//
// dial.Guarded answers a nil allowed set by refusing everything, and this has to
// answer a nil rule the same way. A forgotten wire must read as a program that
// cannot connect - loud, wrong in the safe direction, impossible to mistake for
// working - never as one with no restrictions.
func TestAMissingPermissionRuleRefusesRatherThanAsking(t *testing.T) {
	lookup := System(nil)

	// A name under .invalid can never be delegated, so on a machine where our
	// dialler IS called this asks nothing of anybody's network, and on a machine
	// where it is not called this test says nothing at all - which is why the
	// assertion below is about the shape of the answer rather than its content.
	answer := lookup(context.Background(), "certdoctor-nil-rule.invalid")

	if len(answer.Addresses) != 0 {
		t.Errorf("a lookup with no permission rule came back with addresses: %v", answer.Addresses)
	}
	if answer.NoAnswer != "" && answer.NoAnswer != report.NoAnswerRefusedByRule &&
		answer.NoAnswer != report.NoAnswerTransportError && answer.NoAnswer != report.NoAnswerTimeout {
		t.Errorf("the reason %q is outside what this can honestly report", answer.NoAnswer)
	}
}
