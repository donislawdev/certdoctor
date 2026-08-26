package dnsmsg

import (
	"strings"
	"testing"
)

// FuzzParsingAnAnswerNeverPanics is the target position 3 of the standard of
// code has been waiting for.
//
// THAT ROW STOOD AT "NONE" FOR A REASON THAT HAS NOW EXPIRED: there was not a
// single parser in this program to point it at. This is the first, and it is the
// worst case of the kind - the bytes arrive over UDP from whatever answered on
// port 53, so they can be anything at all, including something sent by a machine
// that was not asked.
//
// WHAT IT ASSERTS, and it is deliberately narrow. Not that parsing succeeds -
// almost every input here is nonsense and refusing it is the right answer. What
// it asserts is that refusing is how this ends: no panic, and no answer that
// contradicts itself. A panic in a layer is caught at the entry point and mapped
// to an internal failure, which means a malformed packet from anywhere on the
// path would end the run with no report at all.
func FuzzParsingAnAnswerNeverPanics(f *testing.F) {
	valid := answer{id: 5, question: TypeA, records: []record{recordA(192, 0, 2, 1)}}.bytes()
	sixRecords := answer{id: 5, question: TypeAAAA, records: []record{
		recordAAAA(1), recordAAAA(2), {kind: 5, class: 1, data: []byte{0xc0, headerLen}},
	}}.bytes()

	// The six shapes the probe was run against before any of this was product
	// code, plus the two that are meant to succeed. A corpus of only hostile
	// inputs would let the target pass with a Parse that refuses everything.
	seeds := [][]byte{
		valid,
		sixRecords,
		nil,
		valid[:6],
		{0, 5, 0x80, 0, 0, 1, 0, 4, 0, 0, 0, 0},
		{0, 5, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 60, 'x'},
		{0, 5, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0},
		{0, 5, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0xff, 0xff},
		// A label announcing a reserved type, which is neither a length nor a
		// pointer and is the branch a reader is most likely to leave out.
		{0, 5, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x80},
	}
	for _, seed := range seeds {
		f.Add(seed, uint16(5), uint16(TypeA))
	}

	f.Fuzz(func(t *testing.T, msg []byte, wantID, recordType uint16) {
		want := Type(recordType)
		if !want.Valid() {
			// Nothing asks for a type it cannot read back - Query refuses to build
			// one - so parsing for it is a state this program cannot reach.
			return
		}

		got, err := Parse(msg, wantID, "example.com", want)
		if err != nil {
			return
		}

		// A parse that succeeded has to say something, and what it says has to
		// agree with itself. Every one of these is a shape that would render as an
		// ordinary row in a report and be believed.
		if got.ResponseCode == "" {
			t.Fatalf("an answer was accepted with no response code: % x", msg)
		}
		if got.ResponseCode == NODATA && len(got.Addresses) != 0 {
			t.Fatalf("an answer says there is no record of that type and carries %d: % x", len(got.Addresses), msg)
		}
		for _, address := range got.Addresses {
			if address == "" {
				t.Fatalf("an empty address came out of a parsed answer: % x", msg)
			}
		}
	})
}

// FuzzAQueryIsEitherRefusedOrWithinTheProtocolLimits covers the side a hostile
// packet cannot reach, and it matters for a reason that is easy to miss: a query
// built wrongly does not fail, it goes out and IS IGNORED. The resolver says
// nothing, the layer reports a timeout, and the report blames the user's network
// for a defect of ours.
//
// The name comes from a URL somebody typed, so it can be anything a URL can hold.
func FuzzAQueryIsEitherRefusedOrWithinTheProtocolLimits(f *testing.F) {
	for _, seed := range []string{
		"example.com",
		"example.com.",
		"a",
		"",
		"..",
		"a..b",
		strings.Repeat("a", 63) + ".example",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("abcdefgh.", 30) + "example",
		"xn--bcher-kva.example",
		// Written as escapes because the source of this repository is ASCII and a
		// guard enforces it. The bytes are what matter here: a name typed in a
		// browser and pasted into a ticket arrives like this, unconverted.
		"\u017a\u00f3\u0142w.example",
		"host_with_underscore.example",
		"192.0.2.1",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		for _, kind := range AllTypes {
			msg, err := Query(1, name, kind)
			if err != nil {
				continue
			}

			if len(msg) < headerLen+1+4 {
				t.Fatalf("a query for %q is %d bytes, which is shorter than a header and a root label", name, len(msg))
			}
			// The name sits between the header and the trailing type and class.
			// Both limits are the protocol's, and a query breaking either is one
			// the resolver drops in silence.
			encoded := msg[headerLen : len(msg)-4]
			if len(encoded) > 255 {
				t.Fatalf("a query for %q encodes its name in %d bytes, over the 255 the protocol allows", name, len(encoded))
			}
			for at := 0; at < len(encoded); {
				length := int(encoded[at])
				if length > 63 {
					t.Fatalf("a query for %q carries a label of %d bytes, over the 63 the protocol allows", name, length)
				}
				if length == 0 {
					if at != len(encoded)-1 {
						t.Fatalf("a query for %q has a root label %d bytes before the end of the name", name, len(encoded)-1-at)
					}
					break
				}
				at += 1 + length
				if at > len(encoded) {
					t.Fatalf("a query for %q has a label running past the end of its own name", name)
				}
			}
		}
	})
}
