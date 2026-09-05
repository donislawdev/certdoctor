package proxy

import "strings"

// SCUtil is what "scutil --proxy" said, taken apart but not interpreted.
//
// IT IS A MAP AND NOT A STRUCT WITH NAMED FIELDS, AND THAT IS THE HONEST SHAPE
// FOR WHAT WE KNOW. The STRUCTURE of the output is measured - see ParseSCUtil -
// but the KEY NAMES are not. On a Mac with no proxy configured, and that is the
// only Mac this project has ever read, the output holds ExceptionsList and
// FTPPassive and nothing else. Every other key this program might look for -
// HTTPEnable, HTTPSProxy, ProxyAutoConfigURLString - comes from Apple's
// documentation rather than from a machine, so a struct with those fields would
// dress an assessment up as a reading. A map lets the caller ask for a key and
// be told plainly that it was not there.
type SCUtil struct {
	// Scalars holds every "key : value" pair at the top level.
	Scalars map[string]string
	// Arrays holds every "key : <array> { ... }" block, in the order the
	// platform printed its numbered entries.
	Arrays map[string][]string
}

// Scalar returns the value for a key and whether the key was present at all.
//
// THE SECOND RETURN IS THE PRODUCT AND NOT A CONVENIENCE. "The key is absent"
// means macOS is not configured for that thing, and "the key is present and
// empty" would mean something else entirely. Collapsing them is the same defect
// the S14 probe carried until 2026-09-05, where a missing registry value and an
// empty one read identically and the restore would have written the wrong state
// back.
func (s SCUtil) Scalar(key string) (string, bool) {
	v, ok := s.Scalars[key]
	return v, ok
}

// Array returns the entries of an array key and whether the key was present.
func (s SCUtil) Array(key string) ([]string, bool) {
	v, ok := s.Arrays[key]
	return v, ok
}

// ExceptionsListKey is the key holding the macOS proxy exception list.
//
// MEASURED 2026-09-05: it is the key that exists on a Mac with no proxy
// configured at all, holding "*.local" and "169.254/16". Unlike every other key
// name this program might use here, this one came off a machine.
const ExceptionsListKey = "ExceptionsList"

// ExceptionsList returns the macOS exception list ready for Bypasses, joined the
// way RuleExceptionsList expects, plus whether the key was there.
//
// THE JOIN IS OURS BECAUSE THE PLATFORM HAS NO SEPARATOR - it hands over an
// array. A newline is used because it is the one character an entry cannot
// contain, and doing the join here rather than at each call site keeps that
// decision in one place.
func (s SCUtil) ExceptionsList() (string, bool) {
	entries, ok := s.Arrays[ExceptionsListKey]
	if !ok {
		return "", false
	}
	return strings.Join(entries, "\n"), true
}

// ParseSCUtil takes apart the output of "scutil --proxy".
//
// THE SHAPE IS MEASURED, 2026-09-05, on a Mac with no proxy configured, and the
// raw output is recorded beside probe S14 in internal_tools/README.md:
//
//	<dictionary> {
//	  ExceptionsList : <array> {
//	    0 : *.local
//	    1 : 169.254/16
//	  }
//	  FTPPassive : 1
//	}
//
// SO IT IS A NESTED DICTIONARY AND NOT A FLAT LIST OF PAIRS, which is the thing
// worth knowing before writing this: a parser that cut every line at its first
// colon would happily record an entry called "0" holding "*.local", and an entry
// called "ExceptionsList" holding "<array> {". It would work, by accident, and
// stop working the first time a real machine nests one level deeper.
//
// IT READS BY STRUCTURE AND NEVER BY PROSE - inviolable rule 19. The only words
// it recognises are "<array>" and the braces, which are punctuation of the
// format rather than English that could ever be localised.
//
// ANYTHING IT CANNOT PLACE IS DROPPED RATHER THAN GUESSED. A key nested deeper
// than one level does not become a top level key under a mangled name, because a
// report naming a setting that is not there is worse than a report missing one.
func ParseSCUtil(text string) SCUtil {
	out := SCUtil{Scalars: map[string]string{}, Arrays: map[string][]string{}}

	depth := 0
	openArray := ""
	for _, raw := range strings.Split(text, "\n") {
		// TrimSpace alone handles a carriage return, so there is no separate
		// TrimSuffix for it. The first draft had one and it could not change an
		// answer, which is the fifth line in this package measured to decide
		// nothing and the fourth removed for it.
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line == "}" {
			if openArray != "" {
				openArray = ""
			}
			depth--
			continue
		}
		if strings.HasSuffix(line, "{") {
			depth++
			// The outermost "<dictionary> {" carries no key of its own.
			if depth == 1 {
				continue
			}
			// A brace line with no colon needs no guard of its own: with no
			// colon there is no value, so the "<array>" test below refuses it
			// anyway. A guard here would look like it enforced the format and
			// would be the sixth line in this package unable to change an answer.
			key, value, _ := strings.Cut(line, ":")
			key = strings.TrimSpace(key)
			// Only an array one level in is collected. A nested dictionary
			// opens and closes without contributing anything, which keeps the
			// brace counting honest without inventing names for its contents.
			if depth == 2 && strings.HasPrefix(strings.TrimSpace(value), "<array>") {
				openArray = key
				out.Arrays[key] = []string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case openArray != "":
			// Inside an array the key is the index the platform printed. It is
			// deliberately not checked: the order on the wire is the order, and
			// asserting that it counts from zero would be a claim about a
			// format nobody documented.
			out.Arrays[openArray] = append(out.Arrays[openArray], value)
		case depth == 1:
			out.Scalars[key] = value
		}
	}
	return out
}
