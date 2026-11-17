package derinput

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// things is a kind that reads THING blocks, for the reader's own tests - no
// tool's rules, so a test here proves the reader and nothing else.
var things = Kind{
	Thing:  "thing",
	Header: "-----BEGIN THING-----",
	Reads: func(block int, b *pem.Block) ([]byte, string, bool) {
		if b.Type != "THING" {
			return nil, "", false
		}
		if len(b.Bytes) > 0 && b.Bytes[0] == 'n' {
			return b.Bytes, "a note from the tool", true
		}
		return b.Bytes, "", true
	},
}

func block(blockType, body string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: []byte(body)}))
}

// TestTheReaderFindsTheObjectsAndSaysWhatItDid holds every way an input is
// read, the notes each one leaves, and that objects keep their order.
func TestTheReaderFindsTheObjectsAndSaysWhatItDid(t *testing.T) {
	two := block("THING", "\x30one") + block("THING", "\x30two")
	for _, tc := range []struct {
		name    string
		input   string
		form    string
		objects []string
		notes   []string
		skipped []Skipped
	}{
		{"two blocks", two, FormPEM, []string{"\x30one", "\x30two"}, nil, nil},
		{"text before and after", "said before\n" + two + "said after\n", FormPEM, []string{"\x30one", "\x30two"},
			[]string{"Text outside the PEM blocks was not read."}, nil},
		{"a broken block after a good one", block("THING", "\x30one") + "-----BEGIN THING-----\n!!\n", FormPEM,
			[]string{"\x30one"}, []string{"1 block that starts like PEM could not be read: an END line is missing or " +
				"the base64 inside is broken."}, nil},
		{"a note from the tool", block("THING", "note"), FormPEM, []string{"note"},
			[]string{"a note from the tool"}, nil},
		{"a key, a request and an odd block beside it", block("THING", "\x30") + block("EC PRIVATE KEY", "k") +
			block("CERTIFICATE REQUEST", "r") + block("ODD", "o"), FormPEM, []string{"\x30"}, []string{
			"Block 2 of the input, a private key, was not read and is not shown.",
			"Block 3 of the input, a certificate request (CSR), was not read - certdoctor tool csr reads it.",
			"Block 4 of the input, a block of a kind this tool does not read, was not read.",
		}, []Skipped{{2, "EC PRIVATE KEY"}, {3, "CERTIFICATE REQUEST"}, {4, "ODD"}}},
		{"PEM written into JSON", strings.ReplaceAll(two, "\n", `\n`), FormPEM, []string{"\x30one", "\x30two"},
			[]string{`Read each \n written in the text as a line break.`}, nil},
		{"base64", base64.StdEncoding.EncodeToString([]byte("\x30abc")), FormBase64, []string{"\x30abc"}, nil, nil},
		{"base64 in the URL alphabet, unpadded, in lines", "MGFi\nYw", FormBase64, []string{"\x30abc"}, nil, nil},
		{"quoted base64", `"MGFiYw=="`, FormBase64, []string{"\x30abc"}, []string{"Took off the quotes around the input."},
			nil},
		{"DER", "\x30\x01\xff", FormDER, []string{"\x30\x01\xff"}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, err := things.Read([]byte(tc.input))
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			var objects []string
			for _, o := range in.Objects {
				objects = append(objects, string(o))
			}
			if in.Form != tc.form || !slices.Equal(objects, tc.objects) || !slices.Equal(in.Notes, tc.notes) ||
				!slices.Equal(in.Skipped, tc.skipped) {
				t.Errorf("got %s %q %q %v\nwant %s %q %q %v", in.Form, objects, in.Notes, in.Skipped, tc.form,
					tc.objects, tc.notes, tc.skipped)
			}
		})
	}
}

// TestWhatHoldsNothingIsRefusedByKind holds ADR141 point 9: a refusal names
// what was found by kind and position, never by content, and sends an object
// another tool reads to that tool.
func TestWhatHoldsNothingIsRefusedByKind(t *testing.T) {
	const marker = "SECRETMARKER"
	for _, tc := range []struct {
		name   string
		input  string
		saying string
	}{
		{"nothing", " \n", "The input is empty - give it a thing in PEM, base64 or DER."},
		{"words", "hello " + marker, "The input is not a thing: it has no PEM block (-----BEGIN THING-----), " +
			"it is not base64 and it is not DER."},
		{"letters that are not base64", marker + "x", "has no PEM block (-----BEGIN THING-----) and does not decode"},
		{"a broken block alone", "-----BEGIN THING-----\n" + marker + "!\n", "The input has 1 block that starts " +
			"like PEM, and none could be read"},
		{"two broken blocks", "-----BEGIN THING-----\n!\n-----BEGIN THING-----\n!\n", "2 blocks that start like PEM"},
		{"a certificate and a key", block("CERTIFICATE", marker) + block("PRIVATE KEY", marker),
			"The input holds no thing - its PEM blocks are a certificate and a private key. certdoctor tool cert " +
				"reads a certificate."},
		{"a request", block("NEW CERTIFICATE REQUEST", marker), "its PEM block is a certificate request (CSR). " +
			"certdoctor tool csr reads a certificate request (CSR)."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := things.Read([]byte(tc.input))
			var refusal *spec.Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("not a refusal: %v", err)
			}
			if !strings.Contains(refusal.Reason, tc.saying) || strings.Contains(refusal.Reason, marker) {
				t.Errorf("reason %q - want it to say %q and never the input", refusal.Reason, tc.saying)
			}
		})
	}
}

// TestBareTextGoesToTheToolFirst holds the hook a tool reads its own form
// through, and that a refusal from it stands.
func TestBareTextGoesToTheToolFirst(t *testing.T) {
	k := things
	k.Bare = func(text []byte) (Input, bool, error) {
		switch text[0] {
		case '[':
			return Input{Form: "own", Objects: [][]byte{text}}, true, nil
		case '!':
			return Input{}, true, Refuse("the tool's own refusal")
		}
		return Input{}, false, nil
	}
	if in, err := k.Read([]byte(` "[1]" `)); err != nil || in.Form != "own" ||
		!slices.Equal(in.Notes, []string{"Took off the quotes around the input."}) {
		t.Errorf("own form: %+v %v", in, err)
	}
	if _, err := k.Read([]byte("!")); err == nil || err.Error() != "the tool's own refusal" {
		t.Errorf("own refusal: %v", err)
	}
	if in, err := k.Read([]byte("MGFiYw==")); err != nil || in.Form != FormBase64 {
		t.Errorf("past the hook: %+v %v", in, err)
	}
}

// TestAPrivateKeyIsNamedByBlockAndNeverMore holds the private_key check both
// tools of this shape give.
func TestAPrivateKeyIsNamedByBlockAndNeverMore(t *testing.T) {
	if _, ok := PrivateKeyCheck([]Skipped{{1, "CERTIFICATE REQUEST"}}); ok {
		t.Error("a check without a private key")
	}
	for _, tc := range []struct {
		skipped []Skipped
		saying  string
	}{
		{[]Skipped{{2, "PRIVATE KEY"}}, "Block 2 of the input is a private key. It was not read"},
		{[]Skipped{{1, "RSA PRIVATE KEY"}, {3, "ENCRYPTED PRIVATE KEY"}}, "Blocks 1 and 3 of the input are each a " +
			"private key."},
	} {
		c, ok := PrivateKeyCheck(tc.skipped)
		if !ok || c.ID != "private_key" || c.Status != status.Warn || !strings.HasPrefix(c.Summary, tc.saying) {
			t.Errorf("%v: %+v", tc.skipped, c)
		}
	}
}

// TestEveryToolNamedForABlockIsATool holds ReadBy to the list of tools, so a
// sentence never sends a person to a tool that is not there.
func TestEveryToolNamedForABlockIsATool(t *testing.T) {
	for blockType, id := range ReadBy {
		if _, ok := spec.Find(id); !ok {
			t.Errorf("%s is sent to %q, which is not a tool", blockType, id)
		}
		if KindOf(blockType) == KindOf("ODD") {
			t.Errorf("%s has no words", blockType)
		}
	}
}
