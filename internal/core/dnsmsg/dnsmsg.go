// Package dnsmsg builds DNS queries and reads the answers to them.
//
// IT IS THE ONLY PLACE IN THIS PROGRAM THAT PARSES BYTES ARRIVING FROM THE
// NETWORK, which is why it is a package of its own rather than a file inside the
// layer that uses it. Everything else certdoctor reads is either its own command
// line or a local file under a size cap. This is somebody else's packet, from
// whoever answered on port 53, and hostile input is the normal case rather than
// the accident. A package boundary buys it a coverage floor of its own, a fuzz
// target of its own, and the property that nothing else in the tree can quietly
// grow a second way of reading a packet.
//
// WHY WE WRITE THIS AT ALL INSTEAD OF USING net.Resolver - ADR24. The resolver in
// the standard library collapses NXDOMAIN and SERVFAIL into one "no such host",
// and telling those apart is the whole reason L1 has a second view: "the name
// does not exist" and "resolving it failed" send a person to two different
// places. NODATA is a third fact it cannot express, and "the name exists but has
// no AAAA record" is half of the hangs-thirty-seconds-then-works class this tool
// is for.
//
// IT OPENS NOTHING. The bytes arrive as a slice and leave as a structure. Sending
// them is the caller's business, through the one guarded port that may reach the
// network - so the rule about where this program is allowed to connect stays
// checkable in one place.
package dnsmsg

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Type is a record type this program knows how to ask for.
//
// The list is closed HERE and deliberately open in the report: which types we
// ask for will grow, and a closed vocabulary in a public contract is a promise
// to break. Inside this package it is closed so that a query cannot be built for
// something nothing knows how to read back.
type Type uint16

const (
	// TypeA is an IPv4 address record.
	TypeA Type = 1
	// TypeAAAA is an IPv6 address record.
	TypeAAAA Type = 28
)

var typeNames = map[Type]string{TypeA: "A", TypeAAAA: "AAAA"}

// AllTypes lists every type this package can ask for, in declaration order.
var AllTypes = []Type{TypeA, TypeAAAA}

// Valid reports whether t is one of the declared types.
func (t Type) Valid() bool {
	_, ok := typeNames[t]
	return ok
}

// String is the name that goes in the report. A type outside the list prints as
// its number rather than as an invented name.
func (t Type) String() string {
	if name, ok := typeNames[t]; ok {
		return name
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// Response codes this package names. They are strings rather than a closed type
// because they come off the wire and the list is not ours to close - an
// unrecognised code is reported as itself.
const (
	// NOERROR - the resolver answered and had something to say.
	NOERROR = "NOERROR"
	// NXDOMAIN - the name does not exist.
	NXDOMAIN = "NXDOMAIN"
	// SERVFAIL - resolving failed, which is not the same as not existing.
	SERVFAIL = "SERVFAIL"
	// NODATA is NOT a response code and that is the point of naming it here. It
	// is NOERROR carrying no record OF THE TYPE THAT WAS ASKED FOR, and it is a
	// separate fact: the name exists, this record type does not.
	NODATA = "NODATA"
)

var codeNames = map[byte]string{
	0: NOERROR,
	1: "FORMERR",
	2: SERVFAIL,
	3: NXDOMAIN,
	4: "NOTIMP",
	5: "REFUSED",
}

// Message is one answer, read.
type Message struct {
	// ResponseCode is what the resolver said, or NODATA - see the constant.
	ResponseCode string
	// Truncated is the TC bit: the answer did not fit and the resolver expects
	// the question to be asked again over TCP.
	//
	// IT IS REPORTED RATHER THAN ACTED ON, and that is a decision. Retrying over
	// TCP is work this program does not do yet, and the alternative to reporting
	// the bit is handing back a SHORTENED LIST OF ADDRESSES that looks complete -
	// a confident wrong answer about somebody's DNS, which is the failure this
	// whole tool exists to prevent.
	Truncated bool
	// Addresses are the records of the requested type, in the order they arrived.
	Addresses []string
}

// ErrNotOurs is returned for a packet that answers a different question than the
// one that was asked.
//
// It is a named error rather than a parse failure because the two mean different
// things to a caller: a malformed packet says the resolver or the path is broken,
// while a packet with somebody else's identifier says a stray or forged datagram
// arrived and the real answer may still be coming.
var ErrNotOurs = errors.New("this answer belongs to a different question")

const headerLen = 12

// Query builds a query for one name and one record type.
//
// The identifier is a parameter rather than something generated here, because
// this package has no clock and no source of randomness - it is a pure function
// of what it is handed, which is what lets a test check a byte sequence against a
// known one. Picking an unpredictable identifier is the caller's job and matters:
// it is what makes an off-path answer detectable at all.
func Query(id uint16, name string, t Type) ([]byte, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("%s is not a record type this program knows how to read back, so it will not ask for it", t)
	}
	encoded, err := encodeName(name)
	if err != nil {
		return nil, err
	}

	msg := make([]byte, 0, headerLen+len(encoded)+4)
	msg = appendUint16(msg, id)
	// Recursion desired, and nothing else. No EDNS0, so the answer is capped at
	// 512 bytes by the protocol and a bigger one comes back with the TC bit -
	// which is reported. No DNSSEC bit: we are asking what the resolver hands the
	// user's runtime, not what is cryptographically true.
	msg = appendUint16(msg, 0x0100)
	msg = appendUint16(msg, 1) // one question
	msg = appendUint16(msg, 0) // no answers
	msg = appendUint16(msg, 0) // no authority records
	msg = appendUint16(msg, 0) // no additional records
	msg = append(msg, encoded...)
	msg = appendUint16(msg, uint16(t))
	msg = appendUint16(msg, 1) // class IN
	return msg, nil
}

// Parse reads an answer to a question that was asked.
//
// IT REFUSES RATHER THAN SALVAGING, and that is the same rule the file port
// follows when a file runs over its size limit. A packet that stops making sense
// half way through has already told us the only thing that matters - it cannot be
// believed - and handing back the records read so far would produce a confident,
// short and wrong answer about somebody's DNS.
//
// wantID and want are what was asked. Both are checked rather than trusted: an
// answer carrying a different identifier is not ours, and NODATA can only be
// decided by counting records OF THE REQUESTED TYPE.
func Parse(msg []byte, wantID uint16, wantName string, want Type) (Message, error) {
	if len(msg) < headerLen {
		return Message{}, fmt.Errorf("an answer of %d bytes is shorter than a DNS header", len(msg))
	}
	if id := uint16(msg[0])<<8 | uint16(msg[1]); id != wantID {
		return Message{}, fmt.Errorf("%w: it carries id %d and %d was asked", ErrNotOurs, id, wantID)
	}
	if msg[2]&0x80 == 0 {
		return Message{}, errors.New("this packet is a question, not an answer")
	}

	at, err := readQuestions(msg, int(uint16(msg[4])<<8|uint16(msg[5])), wantName, want)
	if err != nil {
		return Message{}, err
	}
	addresses, matched, err := readAnswers(msg, at, int(uint16(msg[6])<<8|uint16(msg[7])), want)
	if err != nil {
		return Message{}, err
	}

	return Message{
		ResponseCode: responseCode(msg[3]&0x0f, matched),
		// The high byte of the flags word holds QR, then four bits of opcode,
		// then AA, TC and RD. TC is therefore 0x02 and not 0x20 - the first
		// version had the latter, which is a bit of the OPCODE field, so every
		// truncated answer reported itself as complete and every ordinary answer
		// to a non-standard query reported itself as truncated.
		Truncated: msg[2]&0x02 != 0,
		Addresses: addresses,
	}, nil
}

// responseCode turns the four bits into the word that goes in the report, and
// separates NODATA out of NOERROR.
//
// THE COUNT IS OF RECORDS OF THE REQUESTED TYPE AND NOTHING ELSE. The first
// version of this rule, in the probe that measured whether any of this was
// possible, counted records in the answer section - and ipv4.google.com asked for
// AAAA came back as an ordinary NOERROR, because a CNAME was sitting in there.
// The name has no AAAA record, the section was not empty, and the general counter
// said something had arrived.
func responseCode(rcode byte, matched int) string {
	name, known := codeNames[rcode]
	if !known {
		return "RCODE" + strconv.Itoa(int(rcode))
	}
	if name == NOERROR && matched == 0 {
		return NODATA
	}
	return name
}

// skipQuestions walks past the question section to the first answer.
func readQuestions(msg []byte, questions int, wantName string, want Type) (int, error) {
	at := headerLen
	for i := 0; i < questions; i++ {
		next, err := skipName(msg, at)
		if err != nil {
			return 0, fmt.Errorf("reading question %d of %d: %w", i+1, questions, err)
		}
		// THE FIRST QUESTION IS COMPARED WITH WHAT WAS ASKED - P3-3 in the review,
		// and it is the second half of the defence the unpredictable identifier
		// is the first half of. An identifier is sixteen bits: an off-path answer
		// only has to guess those, and until now it did not have to match the
		// question at all. RFC 5452 section 9.1 names both checks together.
		//
		// THE COMPARISON IS CASE INSENSITIVE, WHICH IS WHY IT WAS SKIPPED BEFORE.
		// A resolver may echo the question in any case and stays correct - RFC
		// 4343 - so a byte comparison would refuse working resolvers. Folding
		// case is the whole difference between refusing them and refusing the
		// answers that are genuinely not ours.
		// THE BOUND IS ON next AND NOT ON at, and getting that wrong panicked on
		// a truncated packet - caught by the test for a section cut short, which
		// is what that test is for. The type sits AFTER the name, so it is the
		// end of the name that has to be inside the message.
		if i == 0 && next+2 <= len(msg) {
			if !sameName(msg, at, wantName) {
				return 0, fmt.Errorf("%w: it answers a different name than the one that was asked", ErrNotOurs)
			}
			if asked := Type(uint16(msg[next])<<8 | uint16(msg[next+1])); asked != want {
				return 0, fmt.Errorf("%w: it answers a question about %s and %s was asked", ErrNotOurs, asked, want)
			}
		}
		at = next + 4
		if at > len(msg) {
			return 0, fmt.Errorf("question %d of %d runs past the end of a %d byte answer", i+1, questions, len(msg))
		}
	}
	return at, nil
}

// sameName reports whether the name encoded at "at" is the one that was asked,
// comparing label by label and folding case - RFC 4343.
//
// A COMPRESSION POINTER ANSWERS false RATHER THAN BEING FOLLOWED. The question
// section is the first thing in a message, so there is nothing before it to
// point at, and a pointer there is either a malformed packet or somebody being
// clever. Neither is an answer to our question.
func sameName(msg []byte, at int, want string) bool {
	want = strings.TrimSuffix(want, ".")
	for _, label := range strings.Split(want, ".") {
		if at >= len(msg) {
			return false
		}
		length := int(msg[at])
		if length == 0 || length&0xc0 != 0 || at+1+length > len(msg) {
			return false
		}
		if !strings.EqualFold(string(msg[at+1:at+1+length]), label) {
			return false
		}
		at += 1 + length
	}
	return at < len(msg) && msg[at] == 0
}

// readAnswers collects the addresses of the requested type and counts how many
// records of that type were there.
//
// The count is returned separately from the addresses because they are different
// questions. A record of the right type whose length is wrong makes the packet
// malformed, so it never reaches the count - but if it ever did, a caller reading
// len(addresses) would read NODATA where the truth is "this answer is broken".
func readAnswers(msg []byte, at, answers int, want Type) ([]string, int, error) {
	var addresses []string
	matched := 0

	for i := 0; i < answers; i++ {
		next, err := skipName(msg, at)
		if err != nil {
			return nil, 0, fmt.Errorf("reading answer %d of %d: %w", i+1, answers, err)
		}
		at = next
		if at+10 > len(msg) {
			return nil, 0, fmt.Errorf("answer %d of %d has no room for its own header in a %d byte packet",
				i+1, answers, len(msg))
		}

		recordType := Type(uint16(msg[at])<<8 | uint16(msg[at+1]))
		class := uint16(msg[at+2])<<8 | uint16(msg[at+3])
		// Time to live is skipped: it says how long an answer may be cached, and
		// this program asks once and reports what came back.
		length := int(uint16(msg[at+8])<<8 | uint16(msg[at+9]))
		at += 10
		if at+length > len(msg) {
			return nil, 0, fmt.Errorf("answer %d of %d claims %d bytes of data and %d are left",
				i+1, answers, length, len(msg)-at)
		}

		// Class IN only. A record in another class answers a question nobody in
		// this program asks, and counting it would put a CHAOS TXT record into
		// the tally that decides NODATA.
		if recordType == want && class == 1 {
			address, err := addressOf(want, msg[at:at+length])
			if err != nil {
				return nil, 0, fmt.Errorf("answer %d of %d: %w", i+1, answers, err)
			}
			addresses = append(addresses, address)
			matched++
		}
		at += length
	}
	return addresses, matched, nil
}

// addressOf turns the data of an address record into text.
//
// A record of the right type with the wrong length is a malformed packet rather
// than an address to guess at, so it comes back as an error.
func addressOf(t Type, data []byte) (string, error) {
	switch {
	case t == TypeA && len(data) == 4:
		return netip.AddrFrom4([4]byte(data)).String(), nil
	case t == TypeAAAA && len(data) == 16:
		return netip.AddrFrom16([16]byte(data)).String(), nil
	}
	return "", fmt.Errorf("a %s record carries %d bytes of address", t, len(data))
}

// skipName walks past one name and returns where it ends.
//
// IT DOES NOT FOLLOW COMPRESSION POINTERS, AND THAT IS WHY IT CANNOT LOOP. A
// pointer is where the name ends for the purpose of walking forward, so the two
// bytes are stepped over and nothing is chased. The classic failure of a DNS
// parser - a pointer to itself, or two pointers to each other, spinning until
// something runs out - is not defended against here, it is absent. Nothing this
// program does needs the text of a name that arrived, only the addresses.
//
// Everything else moves the position strictly forward and is bounded by the
// packet, so there is no step counter either. A counter here would be a branch
// nothing can reach, which is the shape the mutation register has already caught
// twice in this tree.
//
// THERE IS ALSO NO CHECK FOR A POINTER CUT IN HALF BY THE END OF THE PACKET, AND
// THERE WAS ONE UNTIL THE REGISTER LOOKED AT IT. It read as caution and decided
// nothing: neither byte of the pointer is dereferenced here, so a pointer sitting
// on the last byte cannot read past the end - it only returns a position that is
// past it, and EVERY CALLER bounds-checks the position it gets back before using
// it. The mutation deleting that branch survived a full run with the hostile
// shapes still refused, which is what "this line does not decide anything" looks
// like. All it changed was the wording of a refusal that happens either way, and a
// branch kept for wording will be believed to be doing more than it is.
func skipName(msg []byte, at int) (int, error) {
	for {
		if at >= len(msg) {
			return 0, fmt.Errorf("a name runs past the end of a %d byte answer", len(msg))
		}
		length := int(msg[at])
		switch {
		case length == 0:
			return at + 1, nil
		case length&0xc0 == 0xc0:
			return at + 2, nil
		case length&0xc0 != 0:
			return 0, fmt.Errorf("a label announces the reserved type %d, so this is not a name", length>>6)
		}
		at += 1 + length
		if at > len(msg) {
			return 0, fmt.Errorf("a label of %d bytes runs past the end of a %d byte answer", length, len(msg))
		}
	}
}

// encodeName turns a host name into the wire form.
//
// The limits are the protocol's and they are checked here rather than left to
// the resolver to complain about, because a name that cannot be asked is a fact
// about the user's input and belongs in the report as one - not as a timeout.
// EncodableName reports whether name can be put on the wire as a question, and
// says why not when it cannot.
//
// IT IS A THIN WRAPPER ON PURPOSE AND THAT IS THE WHOLE VALUE OF IT. The rule
// has exactly one implementation, below, and two callers: this package when it
// builds a query, and the entry point when it reads what a person typed. A
// second copy of "is this a name a resolver would accept" is the measured shape
// of OBS50 - one copy gains a case, the other does not, and the mutation entry
// aimed at one of them stops proving anything about the other.
//
// WHY THE ENTRY POINT ASKS AT ALL - ADR60's doctrine, applied to a name instead
// of to a port. Measured 2026-09-03 on the binary: https://a..b produced L1 FAIL
// and exit 4 - a verdict about somebody's DNS - for a name no resolver could
// ever have been asked about, and a row naming this machine's own router as
// having sent an unreadable reply when no query had left. A typing mistake has
// to be named where it is still a typing mistake.
func EncodableName(name string) error {
	_, err := encodeName(name)
	return err
}

func encodeName(name string) ([]byte, error) {
	// A trailing dot means the name is already absolute and is not an empty
	// label. Everything this program resolves is treated as absolute anyway.
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return nil, errors.New("an empty name cannot be asked about")
	}

	out := make([]byte, 0, len(trimmed)+2)
	for _, label := range strings.Split(trimmed, ".") {
		switch {
		case label == "":
			return nil, fmt.Errorf("%q has an empty label, so it is not a name a resolver would accept", name)
		case len(label) > 63:
			return nil, fmt.Errorf("%q has a label of %d bytes and 63 is the most a name may carry", name, len(label))
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)

	if len(out) > 255 {
		return nil, fmt.Errorf("%q encodes to %d bytes and 255 is the most a name may carry", name, len(out))
	}
	return out, nil
}

func appendUint16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
