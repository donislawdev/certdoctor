package derinput

import (
	"errors"
	"testing"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// FuzzRead holds what the reader promises for any bytes at all (ADR141 point
// 9): it does not fall over, it answers with what it found or a refusal and
// nothing else, it never hands back nothing as found, and every word it says
// is UTF-8.
func FuzzRead(f *testing.F) {
	for _, seed := range []string{
		block("THING", "\x30one") + block("PRIVATE KEY", "k") + "after",
		"-----BEGIN THING-----\nMII\n", `"MGFiYw=="`, "MGFi\nYw", "\x30\x82\x01\x00", `-----BEGIN THING-----\nMA==\n`, "",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		in, err := things.Read(raw)
		if err != nil {
			var refusal *spec.Refusal
			if !errors.As(err, &refusal) || !utf8.ValidString(refusal.Reason) {
				t.Fatalf("Read gave %v, which is not a refusal in UTF-8", err)
			}
			return
		}
		if len(in.Objects) == 0 {
			t.Fatal("found nothing, and did not refuse")
		}
		for _, n := range in.Notes {
			if !utf8.ValidString(n) {
				t.Fatalf("a note is not UTF-8: %q", n)
			}
		}
	})
}
