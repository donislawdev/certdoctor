package redact

import (
	"fmt"
	"testing"
)

// BenchmarkTextGrowsWithTheSensitiveList is the measurement behind the decision
// NOT to replace the loop over patterns with one combined automaton.
//
// The external review of 2026-09-02 called masking quadratic - every sensitive
// name is matched against every masked string - and proposed a single
// alternation instead. The arithmetic is right and the conclusion did not
// survive being measured against a bounded list: since 2026-09-04 the resolver
// list this program builds a Redaction from is capped at what the platform's own
// resolver reads, so N is a handful rather than a file's worth. What this
// records is the shape of the curve and where it stops mattering, so a later
// change that unbounds the list again has a number to compare against.
//
// The input is written down here rather than described - docs/22 section 7aa:
// a measurement that might one day become a guard keeps its input beside its
// result.
func BenchmarkTextGrowsWithTheSensitiveList(b *testing.B) {
	line := "the resolver 10.0.0.1 answered for internal.corp.example, and 10.0.0.2 did not"
	for _, n := range []int{1, 4, 16, 64, 256, 1024} {
		names := make([]Sensitive, 0, n+1)
		names = append(names, Host("internal.corp.example"))
		for i := 0; i < n; i++ {
			names = append(names, Resolver(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)))
		}
		r := New(Everything, names...)
		b.Run(fmt.Sprintf("names=%d", n+1), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = r.Text(line)
			}
		})
	}
}
