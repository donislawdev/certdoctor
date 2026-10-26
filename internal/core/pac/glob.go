package pac

// ShExpMatch reports whether text matches the shell expression pattern.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - "*" matches any number
// of characters and "?" matches exactly one, both always supported; character
// classes "[characters]" and "[^characters]" are "additionally supported by some
// implementations (including Firefox)". Its documented example is
// shExpMatch("http://home.netscape.com/people/ari/index.html", "*/ari/*"), true.
//
// THE CHARACTER CLASS IS A PLACE WHERE BROWSERS REALLY DISAGREE, AND THIS
// COMMENT IS THE HONEST HALF OF SUPPORTING IT. The original implementation
// converted the expression into a regular expression, so classes worked there by
// accident of the translation and work in Firefox today; implementations that
// hand-roll a glob do not all have them. Supporting them means agreeing with the
// browser most likely to be reading a PAC file with one in it. It also means
// this program cannot claim to speak for every client, and the layer that
// reports a match must not pretend otherwise.
//
// IT MATCHES RUNES, NOT BYTES - OBS88. A pattern or a URL can carry
// somebody else's UTF-8: an internationalised host reaches here in its unicode
// spelling, and a "?" is documented to match one CHARACTER. Comparing bytes
// would make "?" match one third of a letter and would make a class containing
// an accented character behave as though it held three unrelated ones.
//
// IT IS ITERATIVE AND ITS WORST CASE IS THE PRODUCT OF THE TWO LENGTHS, WHICH
// IS A SANDBOX REQUIREMENT AND NOT A PREFERENCE. This runs as native Go called
// from a PAC file, and measured on 2026-09-02 the sandbox's interrupt does NOT
// stop native code - a loop here would spend the user's whole run with nothing
// able to end it. The obvious recursive glob backtracks exponentially on
// patterns like "*a*a*a*b", which somebody else's file is free to contain.
func ShExpMatch(text, pattern string) bool {
	matched, _ := ShExpMatchUntil(text, pattern, nil)
	return matched
}

// stopEvery is how many steps ShExpMatchUntil takes between two questions to
// stop - a clock read costs tens of nanoseconds, and a step a few.
const stopEvery = 1 << 10

// ShExpMatchUntil is ShExpMatch that gives up when stop says so, and says
// whether it finished. A nil stop never stops it.
//
// BOUNDED IS NOT THE SAME AS SHORT, AND ADR114 IS WHERE THAT WAS FOUND. The
// worst case above is the product of the two lengths, and nothing bounds the
// lengths but the memory ceiling: a file can build a string of a hundred
// thousand letters in one line, and shExpMatch over it and a pattern half as
// long is billions of steps the stopwatch cannot interrupt. So the sandbox hands
// in the deadline its stopwatch works to, and this loop asks it. An unfinished
// match answers false, and the caller has to say why rather than let a branch be
// taken on it.
func ShExpMatchUntil(text, pattern string, stop func() bool) (matched, finished bool) {
	s, p := []rune(text), []rune(pattern)

	// starPattern remembers where the last "*" sat and how much of the text it
	// had swallowed, so a dead end costs one step back rather than a new call.
	starPattern, starText := -1, 0
	si, pi := 0, 0

	for steps := 1; si < len(s); steps++ {
		if stop != nil && steps%stopEvery == 0 && stop() {
			return false, false
		}
		switch {
		case pi < len(p) && p[pi] == '*':
			starPattern, starText = pi, si
			pi++
		case pi < len(p) && matchesOne(s[si], p[pi:]):
			si++
			pi += atomWidth(p[pi:])
		case starPattern >= 0:
			// The last "*" takes one more character and the pattern resumes
			// just after it.
			starText++
			si, pi = starText, starPattern+1
		default:
			return false, true
		}
	}

	// Text is spent. Only trailing stars may remain, because everything else
	// still demands a character that is not coming.
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p), true
}

// atomWidth returns how many runes of the pattern the leading atom occupies: one
// for a literal or "?", and the whole bracket for a class.
func atomWidth(p []rune) int {
	if len(p) == 0 || p[0] != '[' {
		return 1
	}
	if end := classEnd(p); end > 0 {
		return end + 1
	}
	// An unclosed bracket is a literal bracket, which is what a regular
	// expression translation would also end up doing rather than failing.
	return 1
}

// matchesOne reports whether c satisfies the leading atom of p.
func matchesOne(c rune, p []rune) bool {
	if len(p) == 0 {
		return false
	}
	switch {
	case p[0] == '?':
		return true
	case p[0] == '[':
		end := classEnd(p)
		if end <= 0 {
			return c == '['
		}
		return matchesClass(c, p[1:end])
	default:
		return c == p[0]
	}
}

// classEnd returns the index of the "]" closing a class opened at p[0], or -1
// when there is none.
//
// A "]" IMMEDIATELY AFTER THE OPENING BRACKET IS A LITERAL "]", which is the
// convention every shell and regular expression dialect shares, and without it
// "[]]" would be an unclosed class rather than a class holding one bracket.
func classEnd(p []rune) int {
	i := 1
	if i < len(p) && p[i] == '^' {
		i++
	}
	// The literal-bracket convention applies after the negation too, so "[^]]"
	// is a class holding one "]" rather than an unclosed one.
	if i < len(p) && p[i] == ']' {
		i++
	}
	for ; i < len(p); i++ {
		if p[i] == ']' {
			return i
		}
	}
	return -1
}

// matchesClass reports whether c is in the class body, honouring a leading "^"
// as negation and "a-z" as a range.
func matchesClass(c rune, body []rune) bool {
	negated := len(body) > 0 && body[0] == '^'
	if negated {
		body = body[1:]
	}

	found := false
	for i := 0; i < len(body); i++ {
		// A "-" between two characters is a range; one at either end is a
		// literal hyphen, so "[a-]" holds "a" and "-".
		if i+2 < len(body) && body[i+1] == '-' {
			if c >= body[i] && c <= body[i+2] {
				found = true
			}
			i += 2
			continue
		}
		if c == body[i] {
			found = true
		}
	}
	return found != negated
}
