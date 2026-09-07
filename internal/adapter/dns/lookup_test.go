package dns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/dnsmsg"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
)

// The two failure directions this function has to keep apart, and why every test
// below is really about one of them.
//
// pac.Ports says an empty list means the name did not resolve and an error means
// nobody could be asked. The sandbox turns the first into the browser-shaped "no"
// a PAC file expects and the second into a state the layer refuses to build a
// verdict on. A stand-in that could not tell the two apart would let this whole
// file pass while the program reported a route worked out from a question it
// never got to ask.

// answering is a stand-in exchange that reads the identifier and the type out of
// the query, for the reason the same helper in internal/core/resolve gives: a
// fixture that ignored them could not tell a matched reply from a stray one.
func answering(reply func(resolver string, id uint16, recordType dnsmsg.Type) ([]byte, error)) resolve.Exchange {
	return func(_ context.Context, resolver string, query []byte) ([]byte, error) {
		id := uint16(query[0])<<8 | uint16(query[1])
		asked := dnsmsg.Type(uint16(query[len(query)-4])<<8 | uint16(query[len(query)-3]))
		return reply(resolver, id, asked)
	}
}

// replyFor assembles an answer to the question the caller actually asked. The
// question section spells example.com, so every test below asks about that name.
func replyFor(id uint16, recordType dnsmsg.Type, flags byte, addresses ...[]byte) []byte {
	msg := []byte{byte(id >> 8), byte(id), flags, 0, 0, 1, byte(len(addresses) >> 8), byte(len(addresses)), 0, 0, 0, 0}
	msg = append(msg, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	msg = append(msg, byte(uint16(recordType)>>8), byte(recordType), 0, 1)
	for _, address := range addresses {
		msg = append(msg, 0xc0, 0x0c)
		msg = append(msg, byte(uint16(recordType)>>8), byte(recordType), 0, 1, 0, 0, 0, 60)
		msg = append(msg, byte(len(address)>>8), byte(len(address)))
		msg = append(msg, address...)
	}
	return msg
}

const (
	answered  = byte(0x81) // QR set, no truncation
	truncated = byte(0x83) // QR set, TC set
)

func addressOf(recordType dnsmsg.Type) []byte {
	if recordType == dnsmsg.TypeAAAA {
		return []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	}
	return []byte{192, 0, 2, 10}
}

func identifiers() func() uint16 {
	var next uint16
	return func() uint16 { next += 7; return next }
}

func lookupWith(exchange resolve.Exchange, resolvers ...string) func(string) ([]string, error) {
	if len(resolvers) == 0 {
		resolvers = []string{"192.0.2.53"}
	}
	return Lookup(exchange, resolvers, identifiers(), time.Second)
}

// TestLookupRefusesWhenItWasGivenNoWayToAsk covers every missing port, and each
// refusal has to be an ERROR rather than an empty list. A build that cannot ask
// anybody has not learned that a name does not resolve, and answering as though
// it had is exactly the quiet no inviolable rule 15 forbids.
func TestLookupRefusesWhenItWasGivenNoWayToAsk(t *testing.T) {
	working := answering(func(_ string, id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyFor(id, recordType, answered, addressOf(recordType)), nil
	})

	cases := []struct {
		name   string
		lookup func(string) ([]string, error)
	}{
		{"no exchange", Lookup(nil, []string{"192.0.2.53"}, identifiers(), time.Second)},
		{"no identifiers", Lookup(working, []string{"192.0.2.53"}, nil, time.Second)},
		{"no resolvers", Lookup(working, nil, identifiers(), time.Second)},
	}

	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			addresses, err := one.lookup("example.com")
			if err == nil {
				t.Fatalf("a build that could not ask answered %v with no error, which reads as a name that does not resolve", addresses)
			}
			if len(addresses) != 0 {
				t.Errorf("a refusal carried addresses: %v", addresses)
			}
		})
	}
}

// TestAnAddressRecordEndsTheSearch pins the order A before AAAA and the fact that
// finding one stops the other being asked. The order is not cosmetic: DNSResolve
// hands a PAC file the first IPv4 it can find, so asking A first makes the common
// case cost one query rather than two.
func TestAnAddressRecordEndsTheSearch(t *testing.T) {
	var asked []dnsmsg.Type
	lookup := lookupWith(answering(func(_ string, id uint16, recordType dnsmsg.Type) ([]byte, error) {
		asked = append(asked, recordType)
		return replyFor(id, recordType, answered, addressOf(recordType)), nil
	}))

	addresses, err := lookup("example.com")
	if err != nil {
		t.Fatalf("a resolver that answered produced an error: %v", err)
	}
	if len(addresses) != 1 || addresses[0] != "192.0.2.10" {
		t.Errorf("the lookup answered %v, want the one A record", addresses)
	}
	if len(asked) != 1 || asked[0] != dnsmsg.TypeA {
		t.Errorf("the lookup asked for %v, want A alone once it had an answer", asked)
	}
}

// TestAAAAIsAskedOnlyWhenThereIsNoIPv4 is the other half of the order. A name
// with no IPv4 at all still has an answer worth giving a PAC file.
func TestAAAAIsAskedOnlyWhenThereIsNoIPv4(t *testing.T) {
	lookup := lookupWith(answering(func(_ string, id uint16, recordType dnsmsg.Type) ([]byte, error) {
		if recordType == dnsmsg.TypeA {
			return replyFor(id, recordType, answered), nil
		}
		return replyFor(id, recordType, answered, addressOf(recordType)), nil
	}))

	addresses, err := lookup("example.com")
	if err != nil {
		t.Fatalf("a name with only IPv6 produced an error: %v", err)
	}
	if len(addresses) != 1 || addresses[0] != "2001:db8::10" {
		t.Errorf("the lookup answered %v, want the AAAA record", addresses)
	}
}

// TestANameNobodyHasARecordForIsEmptyRatherThanAnError is the distinction the
// whole file turns on. Every resolver answered in full and none had a record,
// which is a name that does not resolve - a fact about the name, not a gap in
// this run.
func TestANameNobodyHasARecordForIsEmptyRatherThanAnError(t *testing.T) {
	lookup := lookupWith(answering(func(_ string, id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyFor(id, recordType, answered), nil
	}))

	addresses, err := lookup("example.com")
	if err != nil {
		t.Fatalf("a name with no records came back as a failure to ask: %v", err)
	}
	if len(addresses) != 0 {
		t.Errorf("a name with no records answered %v", addresses)
	}
}

// TestNobodyReachableIsAnErrorRatherThanEmpty is the same distinction from the
// other side, and it is the one that protects a verdict. Reporting this as "the
// name does not resolve" would let a PAC file take a browser-shaped branch on a
// question this run never managed to put.
func TestNobodyReachableIsAnErrorRatherThanEmpty(t *testing.T) {
	// A SENTINEL RATHER THAN A SUBSTRING, so the test asserts the cause is still
	// REACHABLE and not merely that its words landed in a sentence. A caller
	// deciding what to do about a refusal reads the chain, not the prose.
	refused := errors.New("the socket was refused")
	lookup := lookupWith(answering(func(string, uint16, dnsmsg.Type) ([]byte, error) {
		return nil, refused
	}), "192.0.2.53", "198.51.100.53")

	addresses, err := lookup("example.com")
	if err == nil {
		t.Fatalf("every resolver refusing answered %v with no error", addresses)
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Errorf("the failure does not name what was being asked about: %v", err)
	}
	if !errors.Is(err, refused) {
		t.Errorf("the failure dropped the cause instead of wrapping it: %v", err)
	}
}

// TestASecondResolverIsAskedAfterTheFirstFails pins that the list is a list. A
// machine names several resolvers because the first may not answer, and a lookup
// that gave up on the first would report failures its own machine does not have.
func TestASecondResolverIsAskedAfterTheFirstFails(t *testing.T) {
	lookup := lookupWith(answering(func(resolver string, id uint16, recordType dnsmsg.Type) ([]byte, error) {
		if resolver == "192.0.2.53" {
			return nil, errors.New("no route")
		}
		return replyFor(id, recordType, answered, addressOf(recordType)), nil
	}), "192.0.2.53", "198.51.100.53")

	addresses, err := lookup("example.com")
	if err != nil {
		t.Fatalf("the second resolver answered and the lookup still failed: %v", err)
	}
	if len(addresses) != 1 {
		t.Errorf("the lookup answered %v, want the second resolver's record", addresses)
	}
}

// TestATruncatedAnswerIsRefusedRatherThanUsed is the sharpest of these, and it is
// sharper here than in L1. isInNet asks whether an address falls inside a subnet,
// and the address that would have matched may be one of the ones that did not
// fit. Using what arrived would send somebody's PAC file down a branch chosen by
// a shortened list.
func TestATruncatedAnswerIsRefusedRatherThanUsed(t *testing.T) {
	lookup := lookupWith(answering(func(_ string, id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyFor(id, recordType, truncated, addressOf(recordType)), nil
	}))

	addresses, err := lookup("example.com")
	if err == nil {
		t.Fatalf("a truncated answer was used: %v", addresses)
	}
	if len(addresses) != 0 {
		t.Errorf("a refused answer still carried addresses: %v", addresses)
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("the failure does not say the answer was cut short: %v", err)
	}
}

// TestAReplyThatCannotBeReadIsNotAnAnswer keeps an unreadable reply out of the
// "this name does not resolve" bucket. Something was reachable, but nothing about
// the name was established, and only an error says that.
func TestAReplyThatCannotBeReadIsNotAnAnswer(t *testing.T) {
	lookup := lookupWith(answering(func(string, uint16, dnsmsg.Type) ([]byte, error) {
		return []byte{0, 1, 2}, nil
	}))

	if addresses, err := lookup("example.com"); err == nil {
		t.Fatalf("an unreadable reply was treated as a name that does not resolve: %v", addresses)
	}
}

// TestANameThatCannotGoOnTheWireDoesNotResolveAndIsNotAFailure is the one case
// where nothing is asked and the answer is still empty rather than an error. The
// name cannot be encoded for ANY resolver, so this is a fact about the name that
// somebody else's PAC file supplied - not a gap in this run.
func TestANameThatCannotGoOnTheWireDoesNotResolveAndIsNotAFailure(t *testing.T) {
	var asked int
	lookup := lookupWith(answering(func(_ string, id uint16, recordType dnsmsg.Type) ([]byte, error) {
		asked++
		return replyFor(id, recordType, answered, addressOf(recordType)), nil
	}))

	addresses, err := lookup(strings.Repeat("a", 64) + ".example.com")
	if err != nil {
		t.Fatalf("an unencodable name was reported as a failure to ask: %v", err)
	}
	if len(addresses) != 0 {
		t.Errorf("an unencodable name answered %v", addresses)
	}
	if asked != 0 {
		t.Errorf("an unencodable name still put %d question(s) on the wire", asked)
	}
}

// TestTheBudgetCoversTheWholeCallAndNotOneQuery pins what probe S16 made load
// bearing: the sandbox stopwatch cannot interrupt a native call that is running,
// so the amount a PAC evaluation can overrun by is the longest single call into
// here. A per-query deadline would make that resolvers times types times the
// number while still looking bounded.
func TestTheBudgetCoversTheWholeCallAndNotOneQuery(t *testing.T) {
	var deadlines []time.Time
	exchange := func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("a query was sent with no deadline on it at all")
		}
		deadlines = append(deadlines, deadline)
		return nil, errors.New("no answer")
	}

	lookup := Lookup(exchange, []string{"192.0.2.53", "198.51.100.53"}, identifiers(), time.Second)
	if _, err := lookup("example.com"); err == nil {
		t.Fatal("a lookup where nothing answered came back without an error")
	}

	if len(deadlines) < 2 {
		t.Fatalf("only %d question(s) were put, so there is nothing to compare", len(deadlines))
	}
	for i, deadline := range deadlines[1:] {
		if !deadline.Equal(deadlines[0]) {
			t.Errorf("query %d carried its own deadline, so the budget grows with the number of queries", i+2)
		}
	}
}
