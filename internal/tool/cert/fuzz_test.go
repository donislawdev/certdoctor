package cert

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// FuzzDecode holds what the decoder promises for any bytes at all (ADR141
// point 9): it does not fall over, it answers with an outcome or a refusal
// and nothing else, an outcome speaks only the closed vocabularies, its data
// marshals, and every word in it is UTF-8.
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		fixtureLeaf + fixtureIntermediate + fixtureRoot,
		fixtureIntermediate + fixtureLeaf + fixtureKey,
		fixtureNegativeSerial + fixtureMD5,
		"-----BEGIN CERTIFICATE-----\nMII\n", `["MIIB"]`, "MIIBAA==", "\x30\x82\x01\x00", "",
	} {
		f.Add([]byte(seed))
	}
	f.Add(der(f, fixtureLeaf))
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := Decode(raw, now)
		if err != nil {
			var refusal *spec.Refusal
			if !errors.As(err, &refusal) || !utf8.ValidString(refusal.Reason) {
				t.Fatalf("Decode gave %v, which is not a refusal in UTF-8", err)
			}
			return
		}
		if _, err := json.Marshal(out.Data); err != nil {
			t.Fatalf("the data does not marshal: %v", err)
		}
		words := append([]string{}, out.Notes...)
		for _, c := range out.Checks {
			if !c.Status.Valid() {
				t.Fatalf("check %q has the status %q", c.ID, c.Status)
			}
			words = append(words, c.ID, c.Summary)
		}
		for _, b := range out.View {
			if !slices.Contains(spec.BlockKinds, b.Kind) {
				t.Fatalf("block %q is of the kind %q", b.Title, b.Kind)
			}
			words = append(words, b.Title, b.Body)
			for _, f := range b.Fields {
				if f.Status != "" && !f.Status.Valid() {
					t.Fatalf("row %q has the status %q", f.Label, f.Status)
				}
				words = append(words, f.Label, f.Value, f.Note)
			}
		}
		for _, w := range words {
			if !utf8.ValidString(w) {
				t.Fatalf("the outcome carries text that is not UTF-8: %q", w)
			}
		}
	})
}
