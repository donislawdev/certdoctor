package prose

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var at = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func TestTimesAreWrittenInTheLargestUnitWithTwoOfItself(t *testing.T) {
	for _, tc := range []struct {
		later time.Duration
		want  string
	}{
		{0, "0 seconds"},
		{time.Second, "1 second"},
		{119 * time.Second, "119 seconds"},
		{2 * time.Minute, "2 minutes"},
		{119 * time.Minute, "119 minutes"},
		{2 * time.Hour, "2 hours"},
		{47 * time.Hour, "47 hours"},
		{48 * time.Hour, "2 days"},
		{729 * 24 * time.Hour, "729 days"},
		{730 * 24 * time.Hour, "1 year"},
	} {
		if got := Span(at, at.Add(tc.later)); got != tc.want {
			t.Errorf("Span over %v = %q, want %q", tc.later, got, tc.want)
		}
		if got := Span(at.Add(tc.later), at); got != tc.want {
			t.Errorf("Span back over %v = %q, want %q", tc.later, got, tc.want)
		}
	}
	// Past the 292 years a Duration can hold.
	if got := Span(at, time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)); got != "7972 years" {
		t.Errorf("Span to the year 9999 = %q", got)
	}
}

func TestADistanceSaysWhichWay(t *testing.T) {
	for _, tc := range []struct {
		when time.Time
		want string
	}{
		{at.Add(72 * time.Hour), "in 3 days"},
		{at.Add(-72 * time.Hour), "3 days ago"},
		{at, "now"},
	} {
		if got := Distance(at, tc.when); got != tc.want {
			t.Errorf("Distance = %q, want %q", got, tc.want)
		}
	}
	if got, want := Clock(at.In(time.FixedZone("x", 3600))), "2026-11-13 12:00:00 UTC"; got != want {
		t.Errorf("Clock = %q, want %q - a time in another zone is written in UTC", got, want)
	}
}

func TestNamesAreListedWithAnAndBeforeTheLast(t *testing.T) {
	for _, tc := range []struct {
		names []string
		want  string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a and b"},
		{[]string{"a", "b", "c"}, "a, b and c"},
	} {
		if got := List(tc.names); got != tc.want {
			t.Errorf("List(%q) = %q, want %q", tc.names, got, tc.want)
		}
	}
	if Plural(1, "byte") != "1 byte" || Plural(0, "byte") != "0 bytes" || Plural(2, "byte") != "2 bytes" {
		t.Error("Plural takes an s unless the count is one")
	}
}

// FuzzWords holds that any two times and any names give words in UTF-8 that
// name a unit, and never fall over - a certificate can say any second from
// the year 1 to 9999.
func FuzzWords(f *testing.F) {
	f.Add(int64(0), int64(253402300799), "a", "b")
	f.Add(int64(-62135596800), int64(0), "", "\xff")
	f.Fuzz(func(t *testing.T, a, b int64, x, y string) {
		const first, last = -62135596800, 253402300799
		if a < first || a > last || b < first || b > last {
			return
		}
		span := Span(time.Unix(a, 0), time.Unix(b, 0))
		if !strings.ContainsAny(span, "0123456789") || !utf8.ValidString(Distance(time.Unix(a, 0), time.Unix(b, 0))) {
			t.Fatalf("Span gave %q", span)
		}
		if List([]string{x, y}) != x+" and "+y {
			t.Fatal("two names are not joined with and")
		}
	})
}
