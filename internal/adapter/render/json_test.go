package render

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// TestBothSurfacesSayTheSameThingAboutAByteThatIsNotText is finding 13 of the
// external review, and it is a defect in the DIFFERENCE rather than in either
// renderer.
//
// The terminal writes such a byte as \xNN, with a paragraph arguing that a
// report must say what is really there rather than what a decoder made of it.
// encoding/json substitutes U+FFFD and returns no error, so the same run
// produced two documents disagreeing about one value - and the machine readable
// one, the one a pipeline believes, was the one that invented. Store paths,
// curl's instance string, gitconfig values and certificate subjects all arrive
// from places that can hold such a byte.
func TestBothSurfacesSayTheSameThingAboutAByteThatIsNotText(t *testing.T) {
	raw := "store" + string([]byte{0xff}) + "bad.crt"
	r := report.Report{
		Tool:   report.Tool{Name: "certdoctor", Version: "0"},
		Layers: []report.LayerResult{{ID: "L0", Detail: raw}},
	}

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("a report carrying one stray byte could not be encoded at all: %v", err)
	}
	// THE RUNE ITSELF AND NOT THE TEXT OF AN ESCAPE. encoding/json does not
	// escape U+FFFD, so it lands in the document as its own three bytes - an
	// assertion looking for the six characters of an escape sequence would have
	// passed on a document full of them, which is OBS56 written into the very
	// test meant to catch this.
	if strings.ContainsRune(string(document), utf8.RuneError) {
		t.Error("the document carries a substitution character, so it describes a decoder rather than the machine")
	}
	if !strings.Contains(string(document), `\\xff`) {
		t.Fatalf("the document does not spell the byte out: %s", document)
	}

	// AND THE TWO SURFACES AGREE, which is the property this is really about.
	// Either renderer alone could be defended; the pair could not.
	var terminal strings.Builder
	if err := (Terminal{}).Render(&terminal, r); err != nil {
		t.Fatalf("the terminal renderer refused the same report: %v", err)
	}
	if !strings.Contains(terminal.String(), `\xff`) {
		t.Fatalf("the terminal does not spell the byte out either: %s", terminal.String())
	}

	// THE DOCUMENT IS STILL DECODABLE, and a consumer now gets the value rather
	// than what a decoder made of it.
	if err := ValidateDocument(document); err != nil {
		t.Errorf("the escaped document no longer matches its own schema: %v", err)
	}
}

// TestOrdinaryTextIsNotRewrittenOnTheWayIntoTheDocument is the other half, and
// without it the rule above could be satisfied by a renderer that mangled
// everything.
//
// A JSON consumer decodes its own escapes, so a control character or a
// bidirectional override belongs in the document as itself - the terminal
// defangs those because a TERMINAL acts on them, and a document is not a
// terminal. Only a byte that is not text at all cannot survive the trip.
func TestOrdinaryTextIsNotRewrittenOnTheWayIntoTheDocument(t *testing.T) {
	// U+202E, the right-to-left override, built from its code point rather than
	// written out: every file of this module has to be ASCII, and building it
	// this way also keeps the test from depending on how any tool along the way
	// quotes a backslash.
	detail := "CN=" + string(rune(0x202e)) + "example.test"
	r := report.Report{
		Tool:   report.Tool{Name: "certdoctor", Version: "0"},
		Layers: []report.LayerResult{{ID: "L0", Detail: detail}},
	}
	document, err := Encode(r)
	if err != nil {
		t.Fatalf("an ordinary report was refused: %v", err)
	}

	// THE ROUND TRIP IS THE ASSERTION, and it is stronger than looking for a
	// spelling: whatever escaping the encoder chose, a consumer decoding this
	// document has to end up with the value that was on the machine. A renderer
	// that had rewritten the character would fail here however tidily it did it.
	var decoded struct {
		Layers []struct {
			Detail string `json:"detail"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("the document this renderer produced is not decodable: %v", err)
	}
	if len(decoded.Layers) != 1 || decoded.Layers[0].Detail != detail {
		t.Errorf("a consumer decodes %q and the machine held %q", decoded.Layers[0].Detail, detail)
	}
}

// TestTheDocumentKeepsNullApartFromAnEmptyListOfAskedNames is ADR20 on the field
// that carries the evidence of a channel nothing else in this program reports.
//
// The two states are different claims about the same run. Null says the script
// never ran, so nobody looked; an empty array says it ran and asked about
// nothing, which is a measurement. A renderer that flattened one into the other
// would take the difference away on the only surface a program reads.
func TestTheDocumentKeepsNullApartFromAnEmptyListOfAskedNames(t *testing.T) {
	for _, one := range []struct {
		name  string
		asked []string
		want  string
	}{
		{"never ran", nil, `"asked":null`},
		{"ran and asked nothing", []string{}, `"asked":[]`},
	} {
		t.Run(one.name, func(t *testing.T) {
			r := report.Report{
				Tool: report.Tool{Name: "certdoctor", Version: "0"},
				Layers: []report.LayerResult{{ID: "L2", Findings: []report.Finding{{
					Kind:      report.FindingPACScript,
					Summary:   "a script",
					Source:    report.SourceDetected,
					PACScript: &report.PACScript{URL: "http://wpad.corp/p.pac", Fetched: true, Asked: one.asked},
				}}}},
			}

			document, err := Encode(r)
			if err != nil {
				t.Fatalf("the report could not be encoded: %v", err)
			}
			compact := strings.ReplaceAll(strings.ReplaceAll(string(document), " ", ""), "\n", "")
			if !strings.Contains(compact, one.want) {
				t.Errorf("a script that %s produced a document without %s", one.name, one.want)
			}
		})
	}
}
