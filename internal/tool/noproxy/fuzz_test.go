package noproxy

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// FuzzAsk holds what the tester promises for any two inputs at all (ADR141
// point 9): it does not fall over, it answers with an outcome or a refusal and
// never with anything else - so a list it took is one every reading answers
// for - and an outcome carries one answer per reading, the one check, words in
// the closed vocabularies and data that marshals.
func FuzzAsk(f *testing.F) {
	for _, seed := range [][2]string{
		{".corp.example,localhost", "https://api.corp.example:8443/x"},
		{"*", "[::1]"},
		{" * ", "http://10.0.0.1"},
		{"10.0.0.0/8,[2001:db8::]/32,*.x", "https://[2001:db8::1]"},
		{"NO_PROXY=a b,c\t", "a"},
		{"", "localhost."},
		{"\xff", "\x00"},
		{"a,,,.", "0x7f.1"},
	} {
		f.Add([]byte(seed[0]), []byte(seed[1]))
	}
	f.Fuzz(func(t *testing.T, list, address []byte) {
		out, err := Ask(list, address)
		if err != nil {
			var refusal *spec.Refusal
			if !errors.As(err, &refusal) || !utf8.ValidString(refusal.Reason) {
				t.Fatalf("Ask gave %v, which is not a refusal in UTF-8", err)
			}
			return
		}
		d, ok := out.Data.(Data)
		if !ok || len(d.Readings) != len(proxy.NoProxyRules) {
			t.Fatalf("the data is %T with the wrong number of answers", out.Data)
		}
		if _, err := json.Marshal(d); err != nil {
			t.Fatalf("the data does not marshal: %v", err)
		}
		if len(out.Checks) != 1 || !out.Checks[0].Status.Valid() {
			t.Fatalf("checks %+v", out.Checks)
		}
		words := append([]string{out.Checks[0].Summary}, out.Notes...)
		for _, b := range out.View {
			if !slices.Contains(spec.BlockKinds, b.Kind) {
				t.Fatalf("block %q is of the kind %q", b.Title, b.Kind)
			}
			words = append(words, b.Title, b.Body)
			for _, f := range b.Fields {
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
