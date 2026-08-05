// Package resolve is the L1 layer: what a name resolves to, seen through the two
// lenses D3 says a diagnostic tool needs.
//
// TODAY IT HOLDS THE PARSERS AND NOT THE LAYER, which is the same order P0 and
// the finding contract were built in: the shape and the things that guard it come
// first, and the code that produces values arrives afterwards to find the rules
// already standing rather than already broken.
//
// IT READS BYTES AND NOTHING ELSE. Opening the files is the file port's business,
// under a size limit and after the check for whether the path leads off this
// machine - ADR25. Everything here is a pure function of what it was handed, so
// the awkward configurations can be tested without a machine that has them.
package resolve

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// ResolverConfig is what this machine has WRITTEN DOWN about resolving names -
// the contents of resolv.conf, read.
//
// It is not a view of DNS and must never be reported as one. Nobody measured it,
// we read somebody's file, so it reaches a report as `configured` and never as
// `detected`.
type ResolverConfig struct {
	// Nameservers are the addresses of the resolvers, in the order the file
	// lists them. Order matters to the resolver and therefore to the report.
	Nameservers []string
	// Search is the list of domains appended to a name that has no dots.
	Search []string
	// Skipped names every line this parser did not use, with a reason. It is the
	// ban on silence applied to a parser: a file that was read and half
	// understood must not read like a file that was read and understood.
	Skipped []Skipped
}

// NameSources is the `hosts:` line of nsswitch.conf: where this system looks up
// a name, and in what order.
//
// WHY L1 READS THIS AT ALL, WHEN IT IS NOT ABOUT DNS. Because it decides whether
// the system consults the hosts FILE, and the direct view never does. Without it
// there is no honest way to say why the two views disagree about a name like
// localhost - and D3 measured exactly that disagreement, then recorded it as a
// fact about our instrument rather than about the user's machine.
type NameSources struct {
	// Order is the sources named on the line, in order, with the bracketed
	// actions between them dropped - those say what to do about a result, not
	// where to look for one.
	Order []string
	// Declared says whether the file named a hosts line at all. A file that does
	// not is a different fact from a file that names an empty one, and treating
	// them alike would report "this system does not consult /etc/hosts" about a
	// machine whose configuration simply lives elsewhere.
	Declared bool
	Skipped  []Skipped
}

// ConsultsHostsFile reports whether the system looks in the hosts file before or
// alongside DNS.
func (n NameSources) ConsultsHostsFile() bool {
	for _, source := range n.Order {
		if source == "files" {
			return true
		}
	}
	return false
}

// Skipped is one line a parser did not use, and why.
//
// The line number is what makes this actionable - "go and look at line 3" - and
// it is also the only part of an unreadable line that is SAFE TO REPORT. The
// text of such a line is by definition not text, so quoting it would put the very
// bytes this rule exists to stop straight into the report it was protecting.
//
// Why is our own English from the short list of literals in this file. It is not
// a public contract and has no registry, because it does not leave the layer's
// own sentence - if that ever changes, it needs one, like every other closed
// vocabulary in this program.
type Skipped struct {
	Line int
	Why  string
}

// Reasons a line is skipped.
const (
	whyNotText    = "its value is not text"
	whyNotAddress = "its value is not an address"
	whyUnknown    = "this parser does not use that directive"
)

// UnsupportedEncoding is returned for a file this parser will not read.
//
// IT IS AN ANSWER AND NOT A CRASH. What it prevents is measured rather than
// imagined: a resolv.conf in UTF-16LE read as UTF-8 yields zero nameservers, zero
// search domains and three unrecognised lines - so the parser would report "this
// machine has no resolver configured", confidently, about a machine that has
// three. A refusal that names the encoding sends somebody to look at the file. A
// clean parse of nothing sends them looking at their network.
type UnsupportedEncoding struct {
	Encoding string
}

func (e *UnsupportedEncoding) Error() string {
	return fmt.Sprintf("this file is %s and this parser reads UTF-8, so it was refused rather than read as "+
		"a file with nothing in it", e.Encoding)
}

// Byte order marks. Only the two-byte UTF-16 pair and the three-byte UTF-8 one
// are recognised: UTF-32 begins with the UTF-16LE pair followed by two zero
// bytes, and is refused by that rule rather than by one of its own.
var (
	bomUTF8    = []byte{0xef, 0xbb, 0xbf}
	bomUTF16LE = []byte{0xff, 0xfe}
	bomUTF16BE = []byte{0xfe, 0xff}
)

// Decode applies the encoding contract before a byte reaches a directive parser -
// ADR27.
//
// THREE OF THE FOUR SHAPES IT HANDLES WERE MEASURED, NOT IMAGINED. A UTF-8 byte
// order mark glues itself to the first directive, so the first `nameserver` is
// not recognised and the file looks like one with a resolver missing. A UTF-16
// mark loses the whole file the same way. A byte that is not valid UTF-8 inside a
// value travels all the way into --json, which is a document a consumer cannot
// decode - our contract, broken by somebody else's file.
//
// WHAT IT CANNOT DO, said here so nobody reads it as wider than it is: a legacy
// eight-bit encoding WITHOUT a byte order mark is indistinguishable from broken
// UTF-8. windows-1250 is what a Polish Windows produces, and there is no mark to
// find. Such a file gets as far as the value check, where its directives are
// named as unreadable rather than passed on. That is the scope of this rule, not
// a gap in it - telling the two apart would mean guessing a code page from byte
// statistics, and a guess there decides what a report says about somebody's
// machine.
func Decode(data []byte) ([]byte, error) {
	switch {
	case hasPrefix(data, bomUTF16LE):
		// Checked before UTF-8, because the two-byte mark is not a prefix of the
		// three-byte one and the order of these cases is otherwise free.
		return nil, &UnsupportedEncoding{Encoding: "UTF-16LE, by its byte order mark"}
	case hasPrefix(data, bomUTF16BE):
		return nil, &UnsupportedEncoding{Encoding: "UTF-16BE, by its byte order mark"}
	case hasPrefix(data, bomUTF8):
		return data[len(bomUTF8):], nil
	}
	return data, nil
}

func hasPrefix(data, prefix []byte) bool {
	return len(data) >= len(prefix) && string(data[:len(prefix)]) == string(prefix)
}

// readable reports whether a value can be put in a report.
//
// TWO RULES, AND THE SECOND IS THE INVISIBLE ONE. Invalid UTF-8 would reach
// --json and make the document undecodable. A NUL, or any other control
// character, renders IDENTICALLY to a clean value on every surface this program
// has - so a value carrying one would be compared by eye against the value
// somebody expected, found equal, and the real difference would stay hidden.
func readable(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ParseResolverConfig reads resolv.conf.
//
// It takes the bytes rather than a path, because opening a file is the file
// port's business - it has to judge whether the path leads off this machine
// before anything touches it, and cap the size before anything is parsed.
func ParseResolverConfig(data []byte) (ResolverConfig, error) {
	decoded, err := Decode(data)
	if err != nil {
		return ResolverConfig{}, err
	}

	var config ResolverConfig
	for index, line := range lines(decoded) {
		number := index + 1
		keyword, value, ok := directive(line)
		if !ok {
			continue
		}
		switch keyword {
		case "nameserver":
			config.Nameservers, config.Skipped = appendNameserver(config.Nameservers, config.Skipped, number, value)
		case "search":
			config.Search, config.Skipped = appendSearch(config.Search, config.Skipped, number, value)
		case "domain":
			// The older spelling of search, carrying exactly one name. The file
			// format says the last of the two wins, so this replaces rather than
			// appends - a parser that merged them would report a search list this
			// machine does not have.
			config.Search, config.Skipped = replaceSearch(config.Skipped, number, value)
		default:
			// options, sortlist and anything else. Named rather than dropped: a
			// reader has to be able to tell "this file has nothing else in it"
			// from "this parser ignored half of it".
			config.Skipped = append(config.Skipped, Skipped{Line: number, Why: whyUnknown})
		}
	}
	return config, nil
}

func appendNameserver(servers []string, skipped []Skipped, number int, value string) ([]string, []Skipped) {
	switch {
	case !readable(value):
		return servers, append(skipped, Skipped{Line: number, Why: whyNotText})
	// A nameserver has to be an address, and this is the one place a value is
	// checked for meaning rather than for shape. The reason is inviolable rule
	// 16: this address goes into the set of places this program may connect to,
	// and a set entry that is not an address is a hole in a promise, not an
	// untidy report.
	case !isAddress(value):
		return servers, append(skipped, Skipped{Line: number, Why: whyNotAddress})
	}
	return append(servers, value), skipped
}

func appendSearch(search []string, skipped []Skipped, number int, value string) ([]string, []Skipped) {
	names, ok := readableFields(value)
	if !ok {
		return search, append(skipped, Skipped{Line: number, Why: whyNotText})
	}
	return append(search, names...), skipped
}

// replaceSearch applies a domain directive over whatever came before it.
//
// AN UNREADABLE DOMAIN LINE CLEARS THE LIST RATHER THAN LEAVING THE OLD ONE, and
// that is the uncomfortable choice of the two. Keeping the earlier search list
// would show a list this machine no longer uses, presented as current - a
// confident wrong answer. Clearing it shows nothing and says, on the skipped
// line, that there was something here we could not read. The second is honest
// about the same ignorance.
func replaceSearch(skipped []Skipped, number int, value string) ([]string, []Skipped) {
	if !readable(value) {
		return nil, append(skipped, Skipped{Line: number, Why: whyNotText})
	}
	return strings.Fields(value), skipped
}

// isAddress reports whether a value is an address this program could send a
// query to.
//
// A zone identifier is accepted - fe80::1%eth0 is a legitimate entry in this file
// - and stripped nowhere here, because what the file says is what the report
// shows.
func isAddress(value string) bool {
	_, err := netip.ParseAddr(value)
	return err == nil
}

// ParseNameSources reads the `hosts:` line of nsswitch.conf and nothing else.
//
// ONLY WHAT FEEDS A STATED FACT IS READ. The file describes lookups for passwd,
// group, netgroup and half a dozen other databases, none of which this program
// says anything about - and reading them anyway would mean carrying data with no
// sentence behind it, which is how a diagnostic tool turns into a dump.
func ParseNameSources(data []byte) (NameSources, error) {
	decoded, err := Decode(data)
	if err != nil {
		return NameSources{}, err
	}

	var sources NameSources
	for index, line := range lines(decoded) {
		number := index + 1
		keyword, value, ok := directive(line)
		if !ok || keyword != "hosts:" {
			continue
		}
		// A second hosts line is not merged with the first. The C library reads
		// the file top to bottom and the last one wins, so merging would report an
		// order this system does not use.
		if !readable(value) {
			sources.Order, sources.Declared = nil, true
			sources.Skipped = append(sources.Skipped, Skipped{Line: number, Why: whyNotText})
			continue
		}
		sources.Order, sources.Declared = sourcesOf(value), true
	}
	return sources, nil
}

// sourcesOf keeps the source names and drops the bracketed actions between them.
//
// `hosts: files [NOTFOUND=return] dns` names two places to look and one rule
// about what to do in between. Counting the action as a source would put
// [NOTFOUND=return] in a report as somewhere this machine looks up names.
//
// A FIELD CARRYING A BRACKET IS NEVER A SOURCE, whichever bracket and wherever it
// sits. The first version only looked at the first and last character, so a
// stray closing bracket - a field like `0]` - fell through as an ordinary source
// name and would have been reported as a place this system looks names up. The
// fuzzer found it within a second; no hand written case here had that shape,
// because nobody writes an nsswitch.conf that way on purpose.
//
// A malformed bracket is therefore read as a broken action rather than invented
// into a source. That direction is deliberate: a source this parser did not list
// costs one word of a sentence, and a source it made up is a claim about where
// somebody's machine looks for names.
func sourcesOf(value string) []string {
	var order []string
	depth := 0
	for _, field := range strings.Fields(value) {
		opens := strings.Count(field, "[")
		closes := strings.Count(field, "]")
		if opens > 0 || closes > 0 || depth > 0 {
			depth += opens - closes
			// Clamped, so that a file with more closing brackets than opening
			// ones cannot drive the count negative and make the rest of the line
			// read as sources again.
			if depth < 0 {
				depth = 0
			}
			continue
		}
		order = append(order, field)
	}
	return order
}

// lines splits a file into its lines, in order.
//
// A SLICE AND NOT A MAP KEYED BY LINE NUMBER, which is what this was first
// written as. Ranging over a map in Go is randomised, so the nameservers would
// have come out in a different order on every run - and their order is what the
// resolver uses, so the report would have been wrong in a way that changed each
// time somebody looked. The line number is the index plus one.
//
// IT NO LONGER STRIPS THE CARRIAGE RETURN, AND THE REGISTER IS WHY. A file
// written on Windows and copied into a container keeps its \r, so this used to
// trim one off each line - and the mutation deleting that survived a full run.
// The reason is one function away: directive puts every line through TrimSpace
// before doing anything with it, and \r is whitespace, so it was already gone by
// the time anything could be confused by it. CRLF files are still handled and
// still tested - by the trim that was there first.
func lines(data []byte) []string {
	return strings.Split(string(data), "\n")
}

// directive splits one line into its keyword and the rest, or reports that there
// is nothing on it.
//
// A comment starts with # or ; and both spellings are in use. They are matched at
// the start of the line only: this file format has no trailing comments, and
// treating a # in the middle of a value as one would silently cut the value
// short - which is the shape of failure this whole package is built against.
func directive(line string) (keyword, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		return "", "", false
	}
	// Space or tab, because both are used as the separator and nsswitch.conf in
	// particular is normally written with tabs. Splitting on a space alone made
	// the whole tab-separated line read as one keyword, so every directive in it
	// came back unrecognised - a file fully understood and reported as a file
	// with nothing in it.
	at := strings.IndexAny(trimmed, " \t")
	if at < 0 {
		// A keyword with no value. It is handed on with an empty value so the
		// caller names it as skipped rather than dropping it in silence.
		return trimmed, "", true
	}
	return trimmed[:at], strings.TrimSpace(trimmed[at+1:]), true
}

// readableFields splits a value into words, refusing the whole line if any part
// of it is not text.
//
// The whole line rather than the offending word: a search list with one word
// silently missing is a search list that resolves names differently from the one
// on disk, and nothing in the report would say a word had gone.
func readableFields(value string) ([]string, bool) {
	if !readable(value) {
		return nil, false
	}
	return strings.Fields(value), true
}
