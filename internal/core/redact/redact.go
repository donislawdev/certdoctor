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
	"regexp"
	"strconv"
	"strings"
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
// The list is narrower than it could be, and each absence is deliberate. "key"
// is NOT here: it matches keyStore, and masking the path to a key store would
// delete the single most useful thing in a trust diagnosis while protecting
// nothing. It is added back for query parameters below, where a bare key= is
// almost always a credential and almost never a path.
var credentialWords = []string{
	"token", "secret", "password", "passwd", "pwd",
	"signature", "auth", "credential", "apikey", "api_key",
}

// queryOnlyCredentialWords are additionally treated as secret inside a query
// string. Both appear in the contract document's list, and both are too broad
// to apply to arbitrary name=value text.
var queryOnlyCredentialWords = []string{"key", "sig"}

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

	// settingValue matches name=value where the name says the value is secret.
	settingValue = regexp.MustCompile(
		`(?i)([a-z0-9_.\-\[\]]*(?:` + strings.Join(credentialWords, "|") + `)[a-z0-9_.\-]*)(\s*=\s*)([^\s&;"']+)`)

	// queryValue matches the same inside a query string, with the two extra
	// words that are only safe to treat as secret there.
	//
	// The name may not contain a slash, a hash, a colon or a question mark. A
	// real parameter name never does, and without that the pattern would run
	// from an ampersand anywhere in the text across a whole URL to find a
	// credential word somewhere behind it - masking a value that has nothing to
	// do with the ampersand it started from.
	queryValue = regexp.MustCompile(
		`(?i)([?&][^=&\s/#?:]*(?:` + strings.Join(append(append([]string{}, credentialWords...), queryOnlyCredentialWords...), "|") + `)[^=&\s/#?:]*)(=)([^&\s]*)`)

	// headerValue matches an authorization header or a cookie, which use a
	// colon and would be missed by the name=value rule.
	//
	// This shape was not imagined - the first run of these tests failed on it.
	// The rule about masking authorization headers was written down and the
	// pattern implementing it only knew about equals signs, which is precisely
	// how a rule turns into prose. Header lines arrive prefixed inside somebody
	// else's verbose output, so nothing is anchored to the start of a line.
	headerValue = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization|(?:set-)?cookie)(\s*:\s*)([^\r\n]*)`)

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
	sensitive []string
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

	return &Redaction{
		mode:       mode,
		pseudonyms: map[string]string{},
		issued:     map[string]bool{},
		counts:     map[string]int{},
		sensitive:  kept,
	}
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
	s = r.maskUserInfo(s)
	s = r.maskHeaders(s)
	s = r.maskSettings(s)
	s = r.maskQuery(s)
	return s
}

// CarriedCredentials reports whether masking would remove anything from s.
//
// The fact that a proxy URL carries credentials is itself diagnostic - it is
// half the answer to "why does this get a 407" - and it is the part that can be
// said without saying the secret. So the report carries the fact and never the
// content.
func (r *Redaction) CarriedCredentials(s string) bool {
	return userInfo.MatchString(s) || settingValue.MatchString(s) || queryValue.MatchString(s)
}

// Mode says how much this redaction takes out.
func (r *Redaction) Mode() Mode { return r.mode }

func (r *Redaction) maskUserInfo(s string) string {
	return userInfo.ReplaceAllString(s, "${1}"+Placeholder+"@")
}

func (r *Redaction) maskHeaders(s string) string {
	return headerValue.ReplaceAllString(s, "${1}${2}"+Placeholder)
}

func (r *Redaction) maskSettings(s string) string {
	return settingValue.ReplaceAllString(s, "${1}${2}"+Placeholder)
}

func (r *Redaction) maskQuery(s string) string {
	return queryValue.ReplaceAllString(s, "${1}${2}"+Placeholder)
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
		if strings.Contains(s, name) {
			s = strings.ReplaceAll(s, name, r.pseudonymFor("name", name))
		}
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
// without that, a second pass would rename host-1 to host-2 and the report
// would disagree with itself.
func (r *Redaction) pseudonymFor(kind, real string) string {
	if r.issued[real] {
		return real
	}
	if existing, seen := r.pseudonyms[real]; seen {
		return existing
	}
	r.counts[kind]++
	pseudonym := kind + "-" + strconv.Itoa(r.counts[kind])
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
