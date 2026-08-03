// Package redact takes out of text the things that must never reach a report.
//
// WHY THIS PACKAGE EXISTS BEFORE THE LAYER THAT NEEDS IT. Layer L0 dumps
// environment variables, and the ordinary corporate value of one of them is
// http://user:password@proxy:8080. Writing that layer first would mean that for
// some length of time this program contained code that prints a password into a
// report the user then pastes into a ticket. The plan puts masking first for
// exactly that reason, and this file is that decision carried out.
//
// TWO LEVELS, AND ONLY ONE OF THEM IS OPTIONAL.
//
//   - Credentials is the floor. It cannot be switched off, because a masking
//     that depends on a flag is one forgotten flag away from a leak. It is a
//     property of the layer that produces the text, not a favour asked by the
//     caller.
//   - Everything is what --redact adds: host names and personal names become
//     stable pseudonyms.
//
// WHAT THIS IS NOT. It is a sieve, not a guarantee, and the report says so in
// its own footer. A credential in a format nobody anticipated goes straight
// through, and so does a secret printed by somebody else's tool with no
// structure around it. Nothing in this program may rest a claim about safety on
// this package having run.
package redact

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Placeholder is what replaces something that must not be shown.
//
// It is deliberately not empty and deliberately not a run of asterisks. An
// empty string cannot be told from a variable that was set to nothing, and
// asterisks look like part of the value. This reads as a decision.
const Placeholder = "[redacted]"

// Mode says how much is taken out.
//
// The zero value is the floor rather than "no masking at all", so a forgotten
// assignment still removes credentials. Every default in this program leans the
// same way.
type Mode uint8

const (
	// Credentials removes user info from URLs and the values of settings whose
	// name says they hold a secret. Always on.
	Credentials Mode = iota
	// Everything additionally replaces host names and personal names with
	// stable pseudonyms.
	Everything
)

// credentialWords name a setting whose VALUE is a secret, wherever the setting
// appears - a query parameter, a Java system property, a line of somebody
// else's output.
//
// A word here is matched against the SEGMENTS of a name, never against the name
// as a substring. See namesASecret for why, and for what the first version of
// this rule destroyed.
//
// The list is narrower than it could be, and each absence is deliberate. "key"
// is NOT here: it is a segment of keyStore, and masking the path to a key store
// would delete the single most useful thing in a trust diagnosis while
// protecting nothing. It is added back for query parameters below, where a bare
// key= is almost always a credential and almost never a path.
//
// "authorization" is spelled out rather than left to "auth", because segment
// matching is exact and the two are different words. Leaving it out would let
// AUTHORIZATION=... through, which the header rule only catches when a colon
// follows instead of an equals sign.
var credentialWords = []string{
	"token", "secret", "password", "passwd", "pwd",
	"signature", "auth", "authorization", "credential", "apikey", "api_key",
}

// queryOnlyCredentialWords are additionally treated as secret inside a query
// string. Both appear in the contract document's list, and both are too broad
// to apply to arbitrary name=value text.
var queryOnlyCredentialWords = []string{"key", "sig"}

var (
	settingSecretWords = wordSet(credentialWords)
	querySecretWords   = wordSet(append(append([]string{}, credentialWords...), queryOnlyCredentialWords...))
)

// wordSet turns a word list into the set namesASecret consults, with the plural
// of each word alongside it.
//
// The plural is not tidiness. GOOGLE_APPLICATION_CREDENTIALS and AWS_CREDENTIALS
// are ordinary names, and exact segment matching would let both through while
// masking the singular - a rule that depends on how somebody pluralised a word
// is a rule with a hole in it.
func wordSet(words []string) map[string]bool {
	set := make(map[string]bool, len(words)*2)
	for _, word := range words {
		set[word] = true
		set[word+"s"] = true
	}
	return set
}

var (
	// userInfo matches the user info of a URL: everything between the scheme
	// separator and an @ that comes before any slash.
	//
	// A URL is matched here with a pattern rather than parsed, on purpose. The
	// text arriving at this function is rarely a bare URL - it is an
	// environment variable holding Java options, or the stderr of curl, with a
	// URL somewhere inside it. A parser would refuse the whole string and let
	// the credential through.
	userInfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)([^/\s@]+)@`)

	// settingAssignment matches ANY name=value pair, and says nothing about
	// whether the value is a secret. That question is answered in Go by
	// namesASecret.
	//
	// THE SPLIT IS THE POINT. A pattern carrying the word list inside it can
	// only ask whether the name CONTAINS a credential word, and that question
	// has a wrong answer built into it: NODE_TLS_REJECT_UNAUTHORIZED contains
	// "auth". Deciding in code lets the name be taken apart properly.
	settingAssignment = regexp.MustCompile(`([a-zA-Z0-9_.\-\[\]]+)(\s*=\s*)([^\s&;"']+)`)

	// queryAssignment matches one query parameter and its value.
	//
	// The name may not contain a slash, a hash, a colon or a question mark. A
	// real parameter name never does, and without that the pattern would run
	// from an ampersand anywhere in the text across a whole URL to find a
	// credential word somewhere behind it - masking a value that has nothing to
	// do with the ampersand it started from.
	queryAssignment = regexp.MustCompile(`([?&])([^=&\s/#?:]*)(=)([^&\s]*)`)

	// environmentAssignment recognises the start of an environment variable
	// sitting behind a header value on the same line. See splitHeaderValue.
	//
	// An underscore is REQUIRED, and that requirement is what makes this safe to
	// act on. Without it the pattern would also match an all upper case base64
	// value ending in its padding sign - and cutting there would leave part of a
	// credential standing in the report. Every variable this tool reports on
	// carries an underscore, so demanding one costs nothing and closes that.
	environmentAssignment = regexp.MustCompile(`^[A-Z][A-Z0-9]*_[A-Z0-9_]*=`)

	// headerValue matches an authorization header or a cookie, whose value the
	// name=value rule would only half remove.
	//
	// This shape was not imagined - the first run of these tests failed on it.
	// The rule about masking authorization headers was written down and the
	// pattern implementing it only knew about equals signs, which is precisely
	// how a rule turns into prose. Header lines arrive prefixed inside somebody
	// else's verbose output, so nothing is anchored to the start of a line.
	//
	// BOTH SEPARATORS, AND THE SECOND ONE WAS MEASURED RATHER THAN FORESEEN.
	// AUTHORIZATION=Bearer abc123 is an ordinary environment variable, and the
	// name=value rule stops its value at the first space - so it removed the
	// word "Bearer" and left the token standing. These names carry values with
	// spaces in them whichever punctuation introduces them, so the rule that
	// reads to the end of the line has to own both.
	headerValue = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization|(?:set-)?cookie)(\s*[:=]\s*)([^\r\n]*)`)

	// hostInURL matches the host of a URL, stepping over any user info.
	//
	// TWO THINGS HERE WERE FOUND BY FUZZING AND NEITHER WAS OBVIOUS.
	//
	// First, the user info has to be stepped over rather than assumed absent.
	// The original stopped only at a slash, so it swallowed an already masked
	// user info together with the host and https://[redacted]@proxy:8080 came
	// out as https://host-1 - losing both which machine it was and that
	// credentials had been there.
	//
	// Second, and this is the subtle one: the user info group below uses
	// EXACTLY the character class the credential rule uses, which is wider than
	// the one for the host. It has to. If this rule recognised a narrower user
	// info than the credential rule does, then masking a credential would
	// create an authority this rule had not seen, and a second pass would find
	// a host where the first pass found none. Masking would stop being
	// idempotent - measured on the input "A://#@0". Two rules that rewrite the
	// same text have to agree on where things are.
	hostInURL = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://(?:[^/\s@]+@)?)([^/\s?#@]+)`)
)

// Redaction masks text and remembers the pseudonyms it has handed out.
//
// It is stateful for one reason, and it is the reason the owner chose
// pseudonyms over a flat marker: the same host has to read as the same host
// everywhere in one report. A reader looking at a masked report still has to be
// able to see that the proxy in L2 and the name in L1 are one machine, or that
// they are two. A report where every name became the same marker answers none
// of the questions it was pasted in to answer.
//
// It is not safe for use from several goroutines. That is deliberate and
// matches where it is used: one report, assembled in order.
type Redaction struct {
	mode Mode
	// pseudonyms maps a real name to the name it is shown as.
	pseudonyms map[string]string
	// issued is the reverse: every pseudonym handed out, so that masking an
	// already masked text does not pseudonymise the pseudonym.
	issued map[string]bool
	counts map[string]int
	// sensitive are names the caller knows are personal or internal and that no
	// pattern would find on its own - the user's account name above all.
	sensitive []sensitiveName
}

// sensitiveName is one caller-supplied name together with the matcher that
// finds it.
//
// WHY A MATCHER AND NOT A PLAIN SUBSTRING REPLACEMENT. The first version used
// strings.ReplaceAll, which has no idea what a word is. A service account called
// sys turned "system trust store" into "[name-1]tem trust store", and adm turned
// "administrator" into "[name-1]inistrator". Short account names are ordinary -
// sys, adm, svc, ci, ops - and so is a target host whose first label is api. The
// result was not a leak, it was a report that looked corrupted, and a report
// whose text looks broken stops being believed at the line above as well.
type sensitiveName struct {
	text    string
	pattern *regexp.Regexp
}

// New starts a redaction.
//
// sensitive is the list of names the caller already knows have to go under
// Everything: the account name the process runs as, the target host. They are
// passed in rather than discovered here, because this package reads no
// environment and no file - assessment has to be reproducible from its input.
func New(mode Mode, sensitive ...string) *Redaction {
	kept := make([]string, 0, len(sensitive))
	for _, name := range sensitive {
		if name != "" {
			kept = append(kept, name)
		}
	}
	// Longest first, so that masking a name never leaves a shorter name that is
	// a prefix of it sitting in the text.
	sortByLengthDescending(kept)

	matchers := make([]sensitiveName, 0, len(kept))
	for _, name := range kept {
		matchers = append(matchers, sensitiveName{text: name, pattern: wholeWord(name)})
	}

	return &Redaction{
		mode:       mode,
		pseudonyms: map[string]string{},
		// The placeholder is seeded as already issued, so that a text which has
		// been through here once cannot have its markers renamed into
		// pseudonyms on a second pass.
		issued:    map[string]bool{Placeholder: true},
		counts:    map[string]int{},
		sensitive: matchers,
	}
}

// wholeWord builds the matcher for one sensitive name.
//
// The word boundary is only asked for at an end that is an ASCII letter or
// digit, and both halves of that matter. A name may legitimately begin or end
// with a separator - ".corp" is a suffix somebody might hand us - and \b in
// front of a dot demands a word character before it, which refuses to match at
// the start of a string. Go's \b is ASCII only, so a name ending in a letter
// outside ASCII would get a boundary that can never be satisfied.
func wholeWord(name string) *regexp.Regexp {
	runes := []rune(name)
	pattern := regexp.QuoteMeta(name)
	if isASCIIWord(runes[0]) {
		pattern = `\b` + pattern
	}
	if isASCIIWord(runes[len(runes)-1]) {
		pattern += `\b`
	}
	return regexp.MustCompile(pattern)
}

// isASCIIWord reports whether r is what Go's \b counts as a word character.
func isASCIIWord(r rune) bool {
	return r == '_' ||
		(r >= '0' && r <= '9') ||
		(r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z')
}

// isNamePart reports whether r belongs to a segment of a setting name, as
// opposed to being one of the separators between segments.
func isNamePart(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// Text masks one piece of text.
//
// THE ORDER IS NOT THE OBVIOUS ONE. Names go first, credentials second, and
// that was found by fuzzing after the obvious order failed.
//
// A pipeline of rewriting rules is not idempotent just because each rule is.
// Masking a host removes characters, and removing characters changes which
// text the LATER rules see. The failing input was
// "&0Ap0://A0000=A0#keY=00000000000000": on the first pass the credential rule
// found no secret, then the host rule deleted an equals sign, and on the second
// pass the credential rule matched text that had not existed before. Two passes
// disagreed, which for a report that gets quoted and re-quoted means two copies
// that disagree and no way to tell which is right.
//
// With names first, nothing downstream of them rewrites in a way that can feed
// them again: a pseudonym is recognised and returned unchanged, and the
// placeholder contains no scheme separator, no at sign and no equals sign, so
// it cannot create a new match for anything.
//
// NOTHING HOLDS THIS ORDER IN PLACE TODAY, AND THAT IS MEASURED RATHER THAN
// ASSUMED. Reversing it - names last - was tried on 2026-08-03 and changed no
// output at all: eight realistic inputs in both modes were byte identical, the
// whole seed corpus passed, and 518351 fuzz executions over 45 seconds found
// nothing. The likely reason is that stepping over user info in hostInURL,
// added later than this paragraph, made the credential rule normalise the same
// text either way.
//
// So the order stays because it is the one that was proven safe, not because a
// test would object. Anyone reversing it gets a green run and has to re-run the
// fuzzer to learn anything.
func (r *Redaction) Text(s string) string {
	if s == "" {
		return s
	}
	if r.mode == Everything {
		s = r.maskNames(s)
	}
	return maskCredentials(s)
}

// maskCredentials applies the floor - the four rules that run whatever the mode
// is and whatever the caller asked for.
//
// It takes no receiver on purpose. Nothing here is stateful, and keeping it that
// way is what lets CarriedCredentials be defined as "this changed the text"
// instead of as a second list of rules that has to be kept in step with this
// one by hand.
func maskCredentials(s string) string {
	s = maskUserInfo(s)
	s = maskHeaders(s)
	s = maskSettings(s)
	s = maskQuery(s)
	return s
}

// Target masks the URL the user asked about and reports whether anything was
// removed.
//
// WHY THE TARGET HAS A RULE OF ITS OWN, STRICTER THAN Text. Everything else
// this package masks arrives from the machine - a variable, somebody's stderr -
// where a value that looks ordinary usually is. The target is typed by a person
// under time pressure and is capable of being a secret in three different
// places at once: user info, a token in the query, a session identifier in the
// path. Text masks by NAME, which cannot help here, because "s=abc" has no way
// to prove it is not a session. So the target is masked BY POSITION.
//
// The parts, and what each one costs:
//
//   - user info: replaced, as everywhere else,
//   - query VALUES: all of them, regardless of the parameter name. Parameter
//     names survive, because "your URL carries a token" is half the diagnosis
//     and can be said without saying the token,
//   - path: one marker for the whole of it. Deciding which segments look like
//     identifiers would take a threshold on length or entropy, and a threshold
//     chosen by guesswork is a promise nobody measured. A leaked session
//     identifier cannot be withdrawn. A lost path costs one sentence,
//   - fragment: dropped, without a marker. It NEVER REACHES THE SERVER, so it
//     is the one part of a URL with risk on one side and nothing on the other.
//
// A URL that could not be parsed is returned unchanged with removed reported as
// true, because a string this function did not understand is the last one that
// should be printed as if it had been cleared.
func (r *Redaction) Target(raw string) (masked string, removed bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return Placeholder, true
	}

	// ASSEMBLED BY HAND RATHER THAN THROUGH url.URL.String(). That method
	// percent-encodes a path, which turns the marker into %5Bredacted%5D - a
	// report that reads like a bug and cannot be searched for. Building the
	// string here also keeps the query in the order somebody typed it.
	var out strings.Builder
	out.WriteString(parsed.Scheme)
	out.WriteString("://")

	if parsed.User != nil {
		out.WriteString(Placeholder)
		out.WriteString("@")
		removed = true
	}
	out.WriteString(parsed.Host)

	switch {
	case parsed.EscapedPath() == "" || parsed.EscapedPath() == "/":
		out.WriteString(parsed.EscapedPath())
	default:
		out.WriteString("/")
		out.WriteString(Placeholder)
		removed = true
	}

	if parsed.RawQuery != "" {
		out.WriteString("?")
		out.WriteString(maskQueryValues(parsed.RawQuery))
		removed = true
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		removed = true
	}

	// Through Text last, so that the stronger mode pseudonymises the host by
	// the same rule as everywhere else. Nothing above can create a match Text
	// has not already seen: the placeholder carries no scheme separator, no at
	// sign and no equals sign.
	return r.Text(out.String()), removed
}

// maskQueryValues keeps every parameter name and replaces every value.
//
// It rebuilds the string by hand rather than through the query parser, because
// that parser drops a parameter with no equals sign and reorders nothing it was
// asked to keep. A target is quoted back to the person who typed it, so its
// parameters stay in the order they wrote them.
func maskQueryValues(query string) string {
	parts := strings.Split(query, "&")
	for i, part := range parts {
		if at := strings.Index(part, "="); at >= 0 {
			parts[i] = part[:at+1] + Placeholder
			continue
		}
		if part == "" {
			continue
		}
		// A segment with no equals sign is a value with no name, and this
		// function masks by POSITION. The first version left it alone, reasoning
		// that a bare name carries nothing to hide - which reads the segment as
		// a name rather than as a value and is the one assumption the rest of
		// this rule refuses to make. A signed URL whose whole query is one
		// opaque token has exactly this shape, and a token that reaches a ticket
		// cannot be taken back.
		parts[i] = Placeholder
	}
	return strings.Join(parts, "&")
}

// CarriedCredentials reports whether masking would remove anything from s.
//
// The fact that a proxy URL carries credentials is itself diagnostic - it is
// half the answer to "why does this get a 407" - and it is the part that can be
// said without saying the secret. So the report carries the fact and never the
// content.
//
// IT IS DERIVED FROM THE RULES RATHER THAN LISTING THEM, and that is a fix for
// a defect this shape had. The first version named three of the four patterns
// and left out the header rule, so an authorization header came back "carries
// nothing" while masking removed it - a false negative in a field the report
// prints as a fact. A second list of rules is a list that drifts. Asking the
// rules themselves cannot.
func (r *Redaction) CarriedCredentials(s string) bool {
	return maskCredentials(s) != s
}

// Mode says how much this redaction takes out.
func (r *Redaction) Mode() Mode { return r.mode }

func maskUserInfo(s string) string {
	return userInfo.ReplaceAllString(s, "${1}"+Placeholder+"@")
}

// maskHeaders replaces the value of an authorization header or a cookie.
//
// The value runs to the end of the line, EXCEPT where an environment variable
// starts on that same line - see splitHeaderValue. A dump that put a header and
// a proxy setting on one line would otherwise lose the setting, and losing a
// setting is losing the diagnosis.
func maskHeaders(s string) string {
	return headerValue.ReplaceAllStringFunc(s, func(match string) string {
		parts := headerValue.FindStringSubmatch(match)
		secret, tail := splitHeaderValue(parts[3])
		if secret == "" {
			return match
		}
		return parts[1] + parts[2] + Placeholder + tail
	})
}

// splitHeaderValue separates a header value from anything that follows it on the
// same line.
//
// MEASURED, NOT IMAGINED. The line
//
//	cookie: a=b HTTPS_PROXY=http://proxy.corp:8080 NO_PROXY=.corp
//
// used to come back as "cookie: [redacted]" and nothing else, because the value
// pattern ran to the end of the line. Both proxy settings disappeared, silently,
// from the only place they were going to be reported.
//
// The cut is deliberately narrow. It happens only at an environment variable, so
// a cookie carrying "; Path=/" keeps its whole value masked rather than being
// cut at a word that is not a variable at all. Refusing to cut is the safe
// direction here, so the rule for cutting is the one that has to be sure.
func splitHeaderValue(rest string) (secret, tail string) {
	for at := 1; at < len(rest); at++ {
		if rest[at] != ' ' && rest[at] != '\t' {
			continue
		}
		following := strings.TrimLeft(rest[at:], " \t")
		if environmentAssignment.MatchString(following) {
			return rest[:at], rest[at:]
		}
	}
	return rest, ""
}

// maskSettings replaces the value of every name=value pair whose name says the
// value is a secret.
func maskSettings(s string) string {
	return settingAssignment.ReplaceAllStringFunc(s, func(match string) string {
		parts := settingAssignment.FindStringSubmatch(match)
		if !namesASecret(settingName(parts[1]), settingSecretWords) {
			return match
		}
		return parts[1] + parts[2] + Placeholder
	})
}

// maskQuery does the same inside a query string, where two more words count as
// naming a secret.
func maskQuery(s string) string {
	return queryAssignment.ReplaceAllStringFunc(s, func(match string) string {
		parts := queryAssignment.FindStringSubmatch(match)
		if !namesASecret(parts[2], querySecretWords) {
			return match
		}
		return parts[1] + parts[2] + parts[3] + Placeholder
	})
}

// settingName strips the command line switch a name arrives wearing.
//
// A Java system property reaches us as -Dname=value, and the -D belongs to
// java rather than to the name. Without this the segmenter reads -Dpassword as
// the single word "dpassword" and a trust store password written the short way
// goes straight into the report - caught by the existing tests the moment
// segmenting replaced substring matching.
//
// The single capital is only dropped when a lower case letter follows it, which
// is the shape of a switch letter glued to a word. Dropping one letter can at
// worst make a name look like a credential that was not one, and over-masking
// is the direction this package errs in on purpose.
func settingName(raw string) string {
	trimmed := strings.TrimLeft(raw, "-")
	if trimmed == raw || trimmed == "" {
		return raw
	}
	runes := []rune(trimmed)
	if len(runes) > 1 && unicode.IsUpper(runes[0]) && unicode.IsLower(runes[1]) {
		return string(runes[1:])
	}
	return trimmed
}

// namesASecret reports whether a setting name says that its value is a secret.
//
// WHY THE NAME IS TAKEN APART INSTEAD OF SEARCHED. The first version asked
// whether the name CONTAINED one of the words, and the answer that question got
// wrong was NODE_TLS_REJECT_UNAUTHORIZED=0, because "unauthorized" contains
// "auth". The value it deleted - 0 - is the entire finding: it is certificate
// verification switched off in Node. A rule that removes the diagnosis to
// protect a secret that was never there is worse than having no rule.
//
// A segment is what separators and case changes divide a name into, so
// proxyPassword, PROXY_PASSWORD and proxy.password all produce "password" while
// UNAUTHORIZED produces "unauthorized", which is nobody's credential word. The
// name with its separators removed is checked as well, because API_KEY and
// apikey are one word written two ways.
func namesASecret(name string, words map[string]bool) bool {
	segments := segmentsOf(name)
	for _, segment := range segments {
		if words[segment] {
			return true
		}
	}
	return words[strings.Join(segments, "")]
}

// segmentsOf splits a setting name into its lower case parts.
//
// Three boundaries, and the third is the one that is easy to leave out. A run of
// separators ends a segment. A capital after a lower case letter or a digit ends
// one, which is ordinary camel case. And a lower case letter after two capitals
// ends one BEFORE the last of them, so that SSLKeyPassword becomes ssl, key and
// password rather than one word - without that rule the password segment never
// appears and the value goes into the report.
func segmentsOf(name string) []string {
	runes := []rune(name)
	var out []string
	start := -1

	emit := func(end int) {
		if start >= 0 && end > start {
			out = append(out, strings.ToLower(string(runes[start:end])))
		}
		start = -1
	}

	for i, r := range runes {
		switch {
		case !isNamePart(r):
			emit(i)
		case start < 0:
			start = i
		case unicode.IsUpper(r) && !unicode.IsUpper(runes[i-1]):
			emit(i)
			start = i
		case unicode.IsLower(r) && i-1 > start && unicode.IsUpper(runes[i-1]) && unicode.IsUpper(runes[i-2]):
			emit(i - 1)
			start = i - 1
		}
	}
	emit(len(runes))
	return out
}

// maskNames replaces host names and the caller's sensitive names with stable
// pseudonyms.
//
// WHAT IT DOES NOT FIND, and this belongs next to the code rather than in a
// document nobody opens: a host name sitting in free text with no URL around it
// and no entry in the sensitive list. Finding those would mean guessing which
// dotted words are host names, and a guess here either misses the interesting
// ones or renames half the report. What is covered is what can be established:
// the host part of a URL, and the names the caller handed over knowing what
// they are.
func (r *Redaction) maskNames(s string) string {
	for _, name := range r.sensitive {
		if !name.pattern.MatchString(s) {
			continue
		}
		// Literal replacement, so that a pseudonym is never read as an
		// expansion reference by the regexp package.
		s = name.pattern.ReplaceAllLiteralString(s, r.pseudonymFor("name", name.text))
	}
	return hostInURL.ReplaceAllStringFunc(s, func(match string) string {
		parts := hostInURL.FindStringSubmatch(match)
		host, port := splitPort(parts[2])
		return parts[1] + r.pseudonymFor("host", host) + port
	})
}

// splitPort separates a trailing port from a host, returning the port with its
// colon still attached or an empty string.
//
// WHY THIS IS HERE. The first version keyed the pseudonym on the whole
// authority, so the same machine mentioned once with a port and once without
// got two different pseudonyms - and the report then said two hosts where there
// was one, which is the exact failure pseudonyms exist to prevent. Caught by
// the stability test on its first run.
//
// A port number is not a name and stays visible under --redact. It is
// diagnostic and it identifies nobody.
// A second defect on the same path, and again from the fuzzer rather than from
// reasoning: the first version treated everything after a closing bracket as
// the port, with no colon required. The authority "[]00" then split into the
// host "[]" and the port "00", and re-joining produced "host-100" - a pseudonym
// with digits glued to it, which the next pass read as a host it had never seen
// and renamed again. Masking stopped being idempotent on an input nobody would
// have thought to write down.
//
// Now a port is only a port when a colon says so and digits follow. Anything
// else stays part of the host, where being wrong costs a pseudonym and not a
// broken report.
func splitPort(authority string) (host, port string) {
	// An IPv6 literal carries colons of its own, so the port can only be what
	// follows the closing bracket.
	if strings.HasPrefix(authority, "[") {
		end := strings.Index(authority, "]")
		if end < 0 {
			return authority, ""
		}
		if rest := authority[end+1:]; isPort(rest) {
			return authority[:end+1], rest
		}
		return authority, ""
	}
	at := strings.LastIndex(authority, ":")
	if at < 0 || !isPort(authority[at:]) {
		return authority, ""
	}
	return authority[:at], authority[at:]
}

// isPort reports whether s is a colon followed by at least one digit and
// nothing else.
func isPort(s string) bool {
	if len(s) < 2 || s[0] != ':' {
		return false
	}
	for _, digit := range s[1:] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// pseudonymFor hands out a stable replacement.
//
// Two properties matter and both are tested. The same real name always gets the
// same pseudonym, so the report stays readable. And a pseudonym handed to this
// function comes back unchanged, so masking an already masked text is a no-op -
// without that, a second pass would rename the first host to the second and the
// report would disagree with itself.
//
// WHY THE BRACKETS, WHICH ARE NOT DECORATION. The pseudonym used to read
// host-1, and host-1 is an ordinary name for an ordinary machine. Handed a real
// machine called host-1, this function found it in the issued set and returned
// it untouched: the real name went into a report stamped redacted, AND it became
// indistinguishable from the pseudonym of a different machine. Two machines read
// as one, which is precisely the failure pseudonyms exist to prevent, next to a
// leak in the mode whose whole purpose is not to leak.
//
// A name in DNS cannot contain a bracket, so the collision is now impossible by
// construction rather than avoided by counting. The shape also matches the
// placeholder, which makes both readable as decisions rather than as values.
func (r *Redaction) pseudonymFor(kind, real string) string {
	if r.issued[real] {
		return real
	}
	if existing, seen := r.pseudonyms[real]; seen {
		return existing
	}
	r.counts[kind]++
	pseudonym := "[" + kind + "-" + strconv.Itoa(r.counts[kind]) + "]"
	r.pseudonyms[real] = pseudonym
	r.issued[pseudonym] = true
	return pseudonym
}

func sortByLengthDescending(names []string) {
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && len(names[j]) > len(names[j-1]); j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
}
