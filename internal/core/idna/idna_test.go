package idna

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// THE VECTORS IN THIS FILE COME FROM AN INDEPENDENT IMPLEMENTATION, NOT FROM
// THIS CODE AND NOT FROM MEMORY - docs/21 section 2. They were produced on
// 2026-08-26 by Python's own punycode and idna codecs, which share no line of
// code with this package, and the first of them was confirmed a third time by
// the DNS itself: this binary asked about the xn-- form of the same site and got
// the same addresses the browser gets.
//
// NON-ASCII IS WRITTEN AS \u ESCAPES because every file in this module is
// scanned for bytes above 0x7F and the allowlist is two files long. The escapes
// are also the honest form here: a reader can check a code point, and cannot
// check whether a glyph in a diff is the composed one or the decomposed one -
// which is the exact distinction this package refuses on.

func TestAnASCIIHostComesBackByteForByte(t *testing.T) {
	// The path every name this program has ever diagnosed takes. It runs before
	// anything else in ToASCII, so a change here cannot regress an ASCII name.
	for _, host := range []string{
		"example.com",
		"EXAMPLE.COM",
		"example.com.",
		"internal.corp.example",
		"::1",
		"192.0.2.10",
		"xn--bcher-kva.de",
		"",
	} {
		got, err := ToASCII(host)
		if err != nil {
			t.Errorf("ToASCII(%q) refused an ASCII host: %v", host, err)
			continue
		}
		if got != host {
			t.Errorf("ToASCII(%q) = %q, want it untouched", host, got)
		}
	}
}

// vectors is the table both tests below read.
//
// THE LAST ELEVEN ARE HERE FOR THE ALPHABET RATHER THAN FOR THE LANGUAGE, and
// that is measured: with the first ten alone, breaking the digit mapping at the
// boundary between letters and digits changed NOTHING, because not one expected
// output used a "z". Several of these are real internationalised top level
// domains, which is a nice property and not the reason any of them is here.
var vectors = []struct{ in, want string }{
	{"b\u00fccher", "xn--bcher-kva"},
	{"m\u00fcnchen", "xn--mnchen-3ya"},
	{"fran\u00e7ais", "xn--franais-xxa"},
	{"\u017c\u00f3\u0142w", "xn--w-uga1v8h"},
	{"na\u00efve", "xn--nave-6pa"},
	{"\u65e5\u672c\u8a9e", "xn--wgv71a119e"},
	{"\u30c9\u30e1\u30a4\u30f3", "xn--eckwd4c7c"},
	{"\u043f\u0440\u0438\u043c\u0435\u0440", "xn--e1afmkfd"},
	{"\u00fc", "xn--tda"},
	{"\u00e4\u00e4", "xn--4caa"},
	{"\u00f6sterreich", "xn--sterreich-z7a"},
	{"\ud55c\uad6d", "xn--3e0b707e"},
	{"\u03b5\u03bb\u03bb\u03ac\u03b4\u03b1", "xn--hxakic4aa"},
	{"\u0440\u043e\u0441\u0441\u0438\u044f", "xn--h1alffa9f"},
	{"\u53f0\u7063", "xn--kpry57d"},
	{"\u00edsland", "xn--sland-ysa"},
	{"cr\u00e8me", "xn--crme-6oa"},
	{"\u4e2d\u56fd", "xn--fiqs8s"},
	{"\u9999\u6e2f", "xn--j6w193g"},
	{"\u049b\u0430\u0437\u0430\u049b\u0441\u0442\u0430\u043d", "xn--80aaa0a6awh12ed"},
	{"\u10d2\u10d4", "xn--node"},
}

// TestTheVectorsUseTheWholeDigitAlphabet is an assertion about THIS TABLE and
// not about the code, and it exists because the table failed it.
//
// A Punycode digit is a letter for 0..25 and a digit for 26..35, so the mapping
// has a boundary that a table can miss entirely: ten perfectly good vectors went
// on passing with the boundary moved by one, because none of their encodings
// contained the letter it moved. A table that cannot see a broken alphabet will
// pass a broken encoder.
//
// ONLY THE PART AFTER THE LAST HYPHEN COUNTS. What comes before it is copied
// through unchanged, so a "z" there proves nothing about the digit mapping -
// which is exactly the trap, since xn--zrich-kva looks like it covers "z".
func TestTheVectorsUseTheWholeDigitAlphabet(t *testing.T) {
	seen := map[byte]bool{}
	for _, c := range vectors {
		encoded := strings.TrimPrefix(c.want, acePrefix)
		if i := strings.LastIndexByte(encoded, '-'); i >= 0 {
			encoded = encoded[i+1:]
		}
		for i := 0; i < len(encoded); i++ {
			seen[encoded[i]] = true
		}
	}
	var missing []string
	for d := 0; d < base; d++ {
		if !seen[digit(d)] {
			missing = append(missing, string(rune(digit(d))))
		}
	}
	if len(missing) > 0 {
		t.Errorf("no vector exercises the digit(s) %s, so a mapping broken there would go unnoticed",
			strings.Join(missing, ", "))
	}
}

func TestConvertedLabelsMatchAnIndependentImplementation(t *testing.T) {
	for _, c := range vectors {
		got, err := ToASCII(c.in)
		if err != nil {
			t.Errorf("ToASCII(%q) refused a name a browser resolves: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ToASCII(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestOnlyTheLabelsThatNeedConvertingAreConverted is the whole-host half, and it
// is the one the entry point actually calls.
func TestOnlyTheLabelsThatNeedConvertingAreConverted(t *testing.T) {
	got, err := ToASCII("b\u00fccher.de")
	if err != nil {
		t.Fatalf("ToASCII refused an ordinary German host: %v", err)
	}
	if got != "xn--bcher-kva.de" {
		t.Errorf("ToASCII = %q, want %q - the ASCII label must survive untouched", got, "xn--bcher-kva.de")
	}
}

// TestAnUppercaseNameIsLoweredBeforeConversion pins a difference that is
// invisible unless it is measured.
//
// Punycode copies the basic code points through unchanged, so the SAME name
// typed with a capital produces a DIFFERENT label: measured 2026-08-26 with the
// independent implementation, "B" plus u-umlaut plus "cher" encodes to
// "Bcher-kva" where the lower case form gives "bcher-kva". DNS would not find
// the first one. The entry point lowers the host already, so this is the second
// of two - and the one that keeps this package correct on its own.
func TestAnUppercaseNameIsLoweredBeforeConversion(t *testing.T) {
	got, err := ToASCII("B\u00fccher.de")
	if err != nil {
		t.Fatalf("ToASCII refused a capitalised name: %v", err)
	}
	if got != "xn--bcher-kva.de" {
		t.Errorf("ToASCII = %q, want %q", got, "xn--bcher-kva.de")
	}
}

// TestACombiningMarkIsRefusedRatherThanConvertedIntoADifferentName is the
// refusal this package exists to make loudly.
//
// MEASURED 2026-08-26, AND THE MEASUREMENT IS WHY THIS IS A REFUSAL AND NOT A
// CONVERSION. The decomposed spelling of the same word - "u" followed by a
// combining diaeresis - encodes to "ucher-egd", which is a perfectly well formed
// A-label FOR A DIFFERENT NAME. Composing it first is what NFC normalisation
// does and this package deliberately carries none of those tables, so converting
// it would put us back where we started: a confident report about a name nobody
// hosts.
func TestACombiningMarkIsRefusedRatherThanConvertedIntoADifferentName(t *testing.T) {
	got, err := ToASCII("u\u0308cher.de")
	if err == nil {
		t.Fatalf("a decomposed name was converted to %q instead of being refused", got)
	}
	if !strings.Contains(err.Error(), "xn--") {
		t.Errorf("the refusal does not tell the person what to type instead: %v", err)
	}
	// AND THE COMPOSED FORM OF THE SAME WORD MUST STILL WORK. Without this the
	// refusal could be satisfied by a function that refuses everything, which is
	// the shape OBS56 names: an assertion met by a breakage it is not about.
	if _, err := ToASCII("\u00fccher.de"); err != nil {
		t.Errorf("the composed form of the same name was refused too: %v", err)
	}
}

// TestALabelIsMeasuredAfterConversionAndNotBefore is why the order of these two
// steps is written down rather than left to whoever edits next.
//
// The label below is 44 characters. As UTF-8 it is well inside the 63 octets a
// DNS label may carry, and converted it is 65 - measured 2026-08-26. Checking
// the length first would pass it and then put a name on the wire that no
// resolver will accept.
func TestALabelIsMeasuredAfterConversionAndNotBefore(t *testing.T) {
	const long = "\u017c\u00f3\u0142wi\u0105\u0119\u0107\u0144\u015b\u017a" +
		"\u017c\u00f3\u0142wi\u0105\u0119\u0107\u0144\u015b\u017a" +
		"\u017c\u00f3\u0142wi\u0105\u0119\u0107\u0144\u015b\u017a" +
		"\u017c\u00f3\u0142wi\u0105\u0119\u0107\u0144\u015b\u017a"

	if n := utf8.RuneCountInString(long); n != 44 {
		t.Fatalf("the fixture is %d characters, not the 44 this test is about", n)
	}
	got, err := ToASCII(long + ".pl")
	if err == nil {
		t.Fatalf("a label of 65 octets was accepted as %q", got)
	}
	if !strings.Contains(err.Error(), "63") {
		t.Errorf("the refusal does not say what the limit is: %v", err)
	}
}

// FuzzToASCIIAnswersOrRefusesAndNeverPanics is docs/22 section 7b applied to the
// one new place where somebody else's bytes reach an algorithm of ours.
func FuzzToASCIIAnswersOrRefusesAndNeverPanics(f *testing.F) {
	for _, seed := range []string{
		"example.com", "b\u00fccher.de", "u\u0308cher.de", "", ".", "..",
		"xn--bcher-kva.de", "\u00fc", "\uffff", "a.b.c.d.e",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		got, err := ToASCII(host)
		if err != nil {
			// A refusal is an answer. The only thing it may never do is come
			// back with a name as well.
			if got != "" {
				t.Errorf("ToASCII refused %q and still answered %q", host, got)
			}
			return
		}
		if !isASCII(got) {
			t.Errorf("ToASCII(%q) = %q, which is not ASCII - the whole point is what goes on the wire", host, got)
		}
		// IDEMPOTENCE: converting an already converted name must not convert it
		// again. Without it a second pass anywhere in the entry point would turn
		// xn--bcher-kva into a label about the letters x, n and hyphen.
		again, err := ToASCII(got)
		if err != nil || again != got {
			t.Errorf("ToASCII(%q) = %q, then ToASCII of that = %q, %v", host, got, again, err)
		}
	})
}
