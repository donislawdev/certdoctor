// Package prose is how the tools write what they found in words: a time, how
// far it is from now, a count of something, a list of names. It is shared so
// two tools saying "expired 3 days ago" say it the same way (ADR146) - a
// helper package of the tools, on the tools' closed list, knowing no tool.
package prose

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Clock writes a time for a person, in UTC, to the second.
func Clock(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

// Span says how far apart two times are, in the largest unit that has at
// least two of itself, rounded down. It counts seconds, not a time.Duration,
// because a Duration stops at 292 years and a token or a certificate can say
// the year 9999.
func Span(a, b time.Time) string {
	s := b.Unix() - a.Unix()
	if s < 0 {
		s = -s
	}
	switch {
	case s < 2*60:
		return Plural(s, "second")
	case s < 2*3600:
		return Plural(s/60, "minute")
	case s < 2*86400:
		return Plural(s/3600, "hour")
	case s < 2*365*86400:
		return Plural(s/86400, "day")
	default:
		return Plural(s/31557600, "year")
	}
}

// Distance says when a time is, seen from now: "in 3 days", "3 days ago" or
// "now".
func Distance(now, at time.Time) string {
	switch {
	case at.After(now):
		return "in " + Span(now, at)
	case at.Before(now):
		return Span(now, at) + " ago"
	default:
		return "now"
	}
}

// Plural writes a count with its unit, the unit in its plural unless the count
// is one. The plural follows the regular English rules - "authority" gives
// "authorities", "address" gives "addresses", "byte" gives "bytes" - so a unit
// whose plural breaks them is counted with Word instead.
func Plural(n int64, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %s", n, plural(unit))
}

// plural is the regular English plural of a word: "ies" for a y after a
// consonant, "es" after s, x, z, ch and sh, and an s after anything else.
func plural(word string) string {
	if n := len(word); n > 1 && word[n-1] == 'y' && !strings.ContainsRune("aeiou", rune(word[n-2])) {
		return word[:n-1] + "ies"
	}
	for _, end := range []string{"s", "x", "z", "ch", "sh"} {
		if strings.HasSuffix(word, end) {
			return word + "es"
		}
	}
	return word + "s"
}

// Word picks the word for a count: one for exactly one, more for any other -
// a verb that agrees with the count, or a unit Plural cannot spell.
func Word(n int, one, more string) string {
	if n == 1 {
		return one
	}
	return more
}

// List writes names as "a", "a and b" or "a, b and c".
func List(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		out := names[0]
		for _, n := range names[1 : len(names)-1] {
			out += ", " + n
		}
		return out + " and " + names[len(names)-1]
	}
}

// Capped lists clauses like List, naming at most named of them and counting
// the rest: "a, b and 4 more".
func Capped(clauses []string, named int) string {
	if len(clauses) <= named {
		return List(clauses)
	}
	return strings.Join(clauses[:named], ", ") + fmt.Sprintf(" and %d more", len(clauses)-named)
}

// Cut shortens text to at most limit characters, ending what was cut with
// three dots - a library's words, a long name.
func Cut(text string, limit int) string {
	if utf8.RuneCountInString(text) > limit {
		return string([]rune(text)[:limit-1]) + "..."
	}
	return text
}

// Upper starts a sentence with a capital.
func Upper(s string) string {
	if s != "" && 'a' <= s[0] && s[0] <= 'z' {
		return string(s[0]-'a'+'A') + s[1:]
	}
	return s
}
