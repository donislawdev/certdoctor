package dnsmsg

import (
	"errors"
	"strings"
	"testing"
)

// answer builds a well formed response so that each test can break exactly one
// thing about it.
//
// IT IS A BUILDER RATHER THAN A CONSTANT FOR THE REASON OBS43 RECORDS. A fixture
// that cannot produce both sides of a difference silences the test that depends
// on it, and every rule in this file is about telling two packets apart.
type answer struct {
	id        uint16
	rcode     byte
	truncated bool
	question  Type
	records   []record
}

type record struct {
	kind  Type
	class uint16
	data  []byte
}

func (a answer) bytes() []byte {
	flags := uint16(0x8000) | uint16(a.rcode)
	if a.truncated {
		flags |= 0x0200
	}

	msg := []byte{byte(a.id >> 8), byte(a.id), byte(flags >> 8), byte(flags)}
	msg = append(msg, 0, 1)                                          // one question
	msg = append(msg, byte(len(a.records)>>8), byte(len(a.records))) // answers
	msg = append(msg, 0, 0, 0, 0)                                    // no authority, no additional

	name, err := encodeName("example.com")
	if err != nil {
		panic(err)
	}
	msg = append(msg, name...)
	msg = append(msg, byte(a.question>>8), byte(a.question), 0, 1)

	for _, r := range a.records {
		// A compression pointer back to the question's name, which is the shape
		// every real resolver sends and the shape a hand written fixture would
		// skip.
		msg = append(msg, 0xc0, headerLen)
		msg = append(msg, byte(r.kind>>8), byte(r.kind))
		msg = append(msg, byte(r.class>>8), byte(r.class))
		msg = append(msg, 0, 0, 0, 60) // time to live
		msg = append(msg, byte(len(r.data)>>8), byte(len(r.data)))
		msg = append(msg, r.data...)
	}
	return msg
}

func recordA(a, b, c, d byte) record {
	return record{kind: TypeA, class: 1, data: []byte{a, b, c, d}}
}

func recordAAAA(last byte) record {
	data := make([]byte, 16)
	data[0], data[1] = 0x20, 0x01
	data[15] = last
	return record{kind: TypeAAAA, class: 1, data: data}
}

// TestTheFourAnswersAreToldApart is the whole reason this package exists rather
// than a call to net.Resolver - ADR24.
//
// The standard library collapses the middle two into one "no such host". A person
// reading "the name does not exist" goes and checks their spelling; a person
// reading "resolving it failed" goes and looks at their resolver. Handing them
// the same sentence for both sends half of them to the wrong place.
func TestTheFourAnswersAreToldApart(t *testing.T) {
	cases := []struct {
		name string
		msg  answer
		want string
	}{
		{"an address came back", answer{id: 7, question: TypeA, records: []record{recordA(192, 0, 2, 1)}}, NOERROR},
		{"the name does not exist", answer{id: 7, rcode: 3, question: TypeA}, NXDOMAIN},
		{"resolving failed", answer{id: 7, rcode: 2, question: TypeA}, SERVFAIL},
		{"the name exists with no record of that type", answer{id: 7, question: TypeAAAA}, NODATA},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.msg.bytes(), 7, c.msg.question)
			if err != nil {
				t.Fatalf("a well formed answer was refused: %v", err)
			}
			if got.ResponseCode != c.want {
				t.Errorf("the answer reads as %s and it is %s", got.ResponseCode, c.want)
			}
		})
	}
}

// TestNoDataIsDecidedByRecordsOfTheRequestedType is the defect the probe found
// before any of this was product code, and it would have shipped.
//
// A name with no AAAA record answers with a CNAME sitting in the answer section.
// Counting records in that section says something arrived, so the answer reads as
// an ordinary NOERROR carrying no addresses - which is a different fact from "this
// name has no IPv6 address" and is the fact L1 was built to establish.
func TestNoDataIsDecidedByRecordsOfTheRequestedType(t *testing.T) {
	cname := record{kind: 5, class: 1, data: []byte{0xc0, headerLen}}
	msg := answer{id: 9, question: TypeAAAA, records: []record{cname}}.bytes()

	got, err := Parse(msg, 9, TypeAAAA)
	if err != nil {
		t.Fatalf("an answer carrying a CNAME was refused: %v", err)
	}
	if got.ResponseCode != NODATA {
		t.Errorf("an answer section holding only a CNAME reads as %s, and the name has no AAAA record at all",
			got.ResponseCode)
	}
	if len(got.Addresses) != 0 {
		t.Errorf("a CNAME was read as an address: %v", got.Addresses)
	}
}

// TestAddressesComeBackInTheOrderTheyArrived pins both halves of reading a
// record: the bytes become the right text, and the order is not sorted behind
// the caller's back. D13 forbids comparing two views' timings, and comparing
// their addresses is the thing it leaves standing - which needs the order to be
// the resolver's, not ours.
func TestAddressesComeBackInTheOrderTheyArrived(t *testing.T) {
	four := answer{id: 1, question: TypeA, records: []record{
		recordA(203, 0, 113, 9), recordA(192, 0, 2, 1),
	}}
	got, err := Parse(four.bytes(), 1, TypeA)
	if err != nil {
		t.Fatalf("a well formed answer was refused: %v", err)
	}
	if len(got.Addresses) != 2 || got.Addresses[0] != "203.0.113.9" || got.Addresses[1] != "192.0.2.1" {
		t.Errorf("the addresses came back as %v", got.Addresses)
	}

	six := answer{id: 2, question: TypeAAAA, records: []record{recordAAAA(1)}}
	got, err = Parse(six.bytes(), 2, TypeAAAA)
	if err != nil {
		t.Fatalf("a well formed answer was refused: %v", err)
	}
	// The canonical form, with the run of zeros compressed. Written out here
	// rather than built, so that a change in how addresses are rendered is a red
	// test and not a quietly different report.
	if len(got.Addresses) != 1 || got.Addresses[0] != "2001::1" {
		t.Errorf("an IPv6 address came back as %v", got.Addresses)
	}
}

// TestARecordOfAnotherClassIsNotCounted covers the branch that decides NODATA.
// A record in the CHAOS class answers a question this program never asks, and
// counting it would turn "no address of that type" into "an address arrived".
func TestARecordOfAnotherClassIsNotCounted(t *testing.T) {
	chaos := record{kind: TypeA, class: 3, data: []byte{192, 0, 2, 1}}
	got, err := Parse(answer{id: 3, question: TypeA, records: []record{chaos}}.bytes(), 3, TypeA)
	if err != nil {
		t.Fatalf("an answer carrying another class was refused: %v", err)
	}
	if got.ResponseCode != NODATA {
		t.Errorf("a record outside class IN was counted, giving %s", got.ResponseCode)
	}
}

// TestTruncationIsReportedRatherThanHidden covers the bit that decides whether a
// list of addresses is complete. Reading past it would hand back a short list
// that looks whole.
func TestTruncationIsReportedRatherThanHidden(t *testing.T) {
	msg := answer{id: 4, truncated: true, question: TypeA, records: []record{recordA(192, 0, 2, 1)}}
	got, err := Parse(msg.bytes(), 4, TypeA)
	if err != nil {
		t.Fatalf("a truncated answer was refused rather than reported: %v", err)
	}
	if !got.Truncated {
		t.Error("an answer that did not fit came back saying it was complete")
	}

	whole := answer{id: 4, question: TypeA, records: []record{recordA(192, 0, 2, 1)}}
	got, err = Parse(whole.bytes(), 4, TypeA)
	if err != nil {
		t.Fatalf("a well formed answer was refused: %v", err)
	}
	if got.Truncated {
		t.Error("a complete answer reported itself as truncated, which would send every run looking for a missing address")
	}
}

// TestAnAnswerToSomebodyElsesQuestionIsRefusedByName covers the one refusal a
// caller has to be able to tell from the others. A stray or forged datagram is
// not a broken resolver, and the real answer may still be on its way.
func TestAnAnswerToSomebodyElsesQuestionIsRefusedByName(t *testing.T) {
	msg := answer{id: 1000, question: TypeA, records: []record{recordA(192, 0, 2, 1)}}.bytes()

	_, err := Parse(msg, 1001, TypeA)
	if err == nil {
		t.Fatal("an answer carrying a different identifier was accepted")
	}
	if !errors.Is(err, ErrNotOurs) {
		t.Errorf("a stray answer is indistinguishable from a malformed one: %v", err)
	}
}

// TestAQuestionIsNotAnAnswer covers the QR bit. A query echoed back is not an
// answer, and reading one as an answer produces NODATA out of a packet nobody
// answered.
func TestAQuestionIsNotAnAnswer(t *testing.T) {
	query, err := Query(11, "example.com", TypeA)
	if err != nil {
		t.Fatalf("a query for an ordinary name could not be built: %v", err)
	}
	if _, err := Parse(query, 11, TypeA); err == nil {
		t.Error("a query was read as an answer to itself")
	}
}

// TestTheHostileShapesAreRefusedWithoutPanicking is the list the probe was run
// against before any of this was product code.
//
// SIX HAND WRITTEN CASES ARE NOT A PROOF and this test does not claim to be one -
// the fuzz target beside it is what covers the shapes nobody thought of. What
// this pins is that each NAMED shape is refused, so a rewrite cannot quietly lose
// one of them and stay green on the fuzzer's luck.
func TestTheHostileShapesAreRefusedWithoutPanicking(t *testing.T) {
	valid := answer{id: 5, question: TypeA, records: []record{recordA(192, 0, 2, 1)}}.bytes()

	cases := []struct {
		name string
		msg  []byte
	}{
		{"an empty packet", nil},
		{"a header cut in half", valid[:6]},
		{"a header promising an answer that is not there", func() []byte {
			short := append([]byte{}, valid[:headerLen]...)
			short[6], short[7] = 0, 4
			return short
		}()},
		{"a label longer than the packet", []byte{0, 5, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 60, 'x'}},
		{"a compression pointer at the very end", []byte{0, 5, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0}},
		{"a record claiming more data than is left", func() []byte {
			over := append([]byte{}, valid...)
			over[len(over)-5] = 0xff
			return over
		}()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.msg, 5, TypeA); err == nil {
				t.Error("a malformed packet was read as an answer")
			}
		})
	}
}

// TestASectionCutShortIsRefusedRatherThanWalkedPast covers the two bounds checks
// that stand between a short packet and reading whatever memory follows it.
//
// Both are reachable from the wire: a datagram can be truncated anywhere, and the
// counts in the header are the sender's claim rather than a fact.
func TestASectionCutShortIsRefusedRatherThanWalkedPast(t *testing.T) {
	// A question whose name is complete and whose type and class are not. The
	// name ends exactly at the end of the packet, so only the four bytes after it
	// are missing - the case a reader who checks the name and forgets the rest
	// walks straight past.
	name, err := encodeName("example.com")
	if err != nil {
		t.Fatalf("an ordinary name could not be encoded: %v", err)
	}
	question := append([]byte{0, 5, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0}, name...)
	if _, err := Parse(question, 5, TypeA); err == nil {
		t.Error("a question with no type or class was walked past")
	}

	// An answer whose name is complete and whose ten byte header is not.
	answer := append(append([]byte{0, 5, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0}, name...), 0, 1, 0, 1)
	if _, err := Parse(answer, 5, TypeA); err == nil {
		t.Error("an answer record with a header cut in half was walked past")
	}

	// An answer whose own NAME runs off the end. It is a separate branch from the
	// question's name above and would be reached by a resolver that answered a
	// question we never sent - which is the case with nothing else guarding it.
	nameless := []byte{0, 5, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, 60, 'x'}
	if _, err := Parse(nameless, 5, TypeA); err == nil {
		t.Error("an answer record whose name runs past the end of the packet was read")
	}
}

// TestAQueryCarriesWhatWasAsked pins the bytes that go out. It is the half of
// this package a fuzz target cannot reach: nothing hostile arrives on this side,
// and a query built wrongly comes back as a timeout rather than as an error.
func TestAQueryCarriesWhatWasAsked(t *testing.T) {
	got, err := Query(0xbeef, "example.com", TypeAAAA)
	if err != nil {
		t.Fatalf("a query for an ordinary name could not be built: %v", err)
	}

	want := []byte{
		0xbe, 0xef, // identifier, echoed back so a stray answer can be spotted
		0x01, 0x00, // recursion desired
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x1c, // AAAA
		0x00, 0x01, // class IN
	}
	if string(got) != string(want) {
		t.Errorf("the query on the wire is not the one this package documents\n  got:  % x\n  want: % x", got, want)
	}
}

// TestANameThatCannotBeAskedIsRefusedHere keeps a fact about the user's input out
// of the timeout path. A name over the limit would otherwise be sent, ignored, and
// reported as a resolver that did not answer.
func TestANameThatCannotBeAskedIsRefusedHere(t *testing.T) {
	cases := map[string]string{
		"an empty name":            "",
		"a name that is only dots": "..",
		"an empty label inside":    "a..b",
		"a label over the limit":   strings.Repeat("a", 64) + ".example",
		"a name over the limit":    strings.Repeat("abcdefgh.", 30) + "example",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Query(1, value, TypeA); err == nil {
				t.Errorf("%q was encoded into a query", value)
			}
		})
	}

	// The other side of the limits, without which they could be written to refuse
	// everything and every case above would still pass.
	for _, value := range []string{"example.com", "example.com.", "a", strings.Repeat("a", 63) + ".example"} {
		if _, err := Query(1, value, TypeA); err != nil {
			t.Errorf("%q is a name a resolver would accept and it was refused: %v", value, err)
		}
	}
}

// TestAnUnknownResponseCodeIsReportedAsItself covers the rule that keeps this
// package from having an opinion about a list that is not ours. A code we do not
// recognise is a fact about the resolver, and refusing it would hide it.
func TestAnUnknownResponseCodeIsReportedAsItself(t *testing.T) {
	got, err := Parse(answer{id: 6, rcode: 11, question: TypeA}.bytes(), 6, TypeA)
	if err != nil {
		t.Fatalf("an unrecognised response code was refused: %v", err)
	}
	if got.ResponseCode != "RCODE11" {
		t.Errorf("an unrecognised response code reads as %q", got.ResponseCode)
	}
}

// TestARecordOfTheRightTypeWithTheWrongLengthIsRefused covers the branch that
// separates a malformed packet from an absent record. Guessing at four bytes that
// should have been sixteen would put an invented address in a report.
func TestARecordOfTheRightTypeWithTheWrongLengthIsRefused(t *testing.T) {
	short := record{kind: TypeAAAA, class: 1, data: []byte{0x20, 0x01}}
	if _, err := Parse(answer{id: 8, question: TypeAAAA, records: []record{short}}.bytes(), 8, TypeAAAA); err == nil {
		t.Error("an AAAA record carrying two bytes was read as an address")
	}
}

// TestAskingForATypeNothingCanReadIsRefused covers the closed half of Type. The
// list is open in the report because record types will grow, and closed here
// because a query nothing can read back produces a silent NODATA.
func TestAskingForATypeNothingCanReadIsRefused(t *testing.T) {
	if _, err := Query(1, "example.com", Type(16)); err == nil {
		t.Error("a query was built for a record type nothing knows how to read")
	}
	if got := Type(16).String(); got != "TYPE16" {
		t.Errorf("a type outside the list prints as %q rather than as its number", got)
	}
}
