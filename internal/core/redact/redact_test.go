package redact

import (
	"regexp"
	"strings"
	"testing"
)

// TestTheDocumentedLeaksAreClosed walks the concrete values this package was
// written against. Each row is a real shape somebody's machine produces, not an
// invented one.
func TestTheDocumentedLeaksAreClosed(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		gone    string
		survive string
	}{
		{
			name:    "the corporate proxy value from the plan",
			input:   "http://user:hunter2@proxy.corp.example:8080",
			gone:    "hunter2",
			survive: "proxy.corp.example:8080",
		},
		{
			name:    "user info with no password at all is still user info",
			input:   "https://sometoken@registry.example/",
			gone:    "sometoken",
			survive: "registry.example",
		},
		{
			name:    "a trust store password in Java options",
			input:   "-Djavax.net.ssl.trustStorePassword=changeit -Dfoo=bar",
			gone:    "changeit",
			survive: "-Dfoo=bar",
		},
		{
			name:    "a token in a query string",
			input:   "https://api.example/v1?token=abc123&page=2",
			gone:    "abc123",
			survive: "page=2",
		},
		{
			name:    "a bare key parameter, which in a query is a credential",
			input:   "https://api.example/v1?key=abc123",
			gone:    "abc123",
			survive: "api.example",
		},
		{
			name:    "an authorization header echoed by somebody else's tool",
			input:   `> Proxy-Authorization: Basic ZGVtbzpzZWNyZXQ=`,
			gone:    "ZGVtbzpzZWNyZXQ",
			survive: "Proxy-Authorization",
		},
		{
			name:    "user info inside a longer error message",
			input:   `curl: (56) Received HTTP code 407 from proxy after CONNECT to http://bob:s3cr3t@proxy:3128`,
			gone:    "s3cr3t",
			survive: "407",
		},
		{
			name:    "several URLs in one value",
			input:   "http://a:one@x:1,https://b:two@y:2",
			gone:    "two",
			survive: "x:1",
		},
	}

	for _, c := range cases {
		got := New(Credentials).Text(c.input)
		if strings.Contains(got, c.gone) {
			t.Errorf("%s: %q survived in %q", c.name, c.gone, got)
		}
		if c.survive != "" && !strings.Contains(got, c.survive) {
			t.Errorf("%s: %q was removed and should not have been - %q", c.name, c.survive, got)
		}
	}
}

// TestAPathToATrustStoreIsNotTreatedAsASecret is the deliberate narrowness of
// the word list, checked rather than trusted.
//
// The word "key" is not a general credential marker because it matches
// keyStore, and the path to a key store is the single most useful thing in a
// trust diagnosis. Masking it would protect nothing and delete the answer.
func TestAPathToATrustStoreIsNotTreatedAsASecret(t *testing.T) {
	survives := []string{
		`-Djavax.net.ssl.keyStore=C:\Program Files\OpenJDK\jdk-21\lib\security\cacerts`,
		`-Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts`,
		"http.sslcainfo=/usr/share/ca-certificates/corp.crt",
		"cafile=/home/build/certs/bundle.pem",
	}
	for _, setting := range survives {
		if got := New(Credentials).Text(setting); got != setting {
			t.Errorf("a path was masked as a secret:\n  in:  %s\n  out: %s", setting, got)
		}
	}
}

// TestAHostIsMaskedEvenWhenACredentialStandsInFrontOfIt closes a hole the
// mutation register found, and it is worth saying how it stayed open.
//
// The rule that hands out pseudonyms has to step OVER user info to reach the
// host. A version that stopped at the at sign left the host untouched, so
// --redact returned an internal proxy name into a report somebody was about to
// paste into a ticket - which is the one thing --redact exists to prevent.
//
// Every property this package had still passed, and that is the instructive
// part: masking is idempotent whether or not the host was touched, because the
// credential rule normalises the same text on the second pass either way. A
// property that holds over every input can still hold over an output that is
// wrong.
func TestAHostIsMaskedEvenWhenACredentialStandsInFrontOfIt(t *testing.T) {
	leaks := []string{"proxy.corp.example", "registry.internal"}
	cases := []string{
		"http://user:hunter2@proxy.corp.example:8080",
		"https://sometoken@registry.internal/v1",
		// The already masked shape, because a report gets masked again by
		// whoever quotes it.
		"https://" + Placeholder + "@proxy.corp.example:8080",
	}
	for _, value := range cases {
		got := New(Everything).Text(value)
		for _, name := range leaks {
			if strings.Contains(got, name) {
				t.Errorf("--redact left a host name standing behind user info:\n  in:  %s\n  out: %s", value, got)
			}
		}
		if !strings.Contains(got, "host-") {
			t.Errorf("no pseudonym was handed out at all:\n  in:  %s\n  out: %s", value, got)
		}
	}
}

// TestATargetKeepsItsShapeAndLosesItsSecrets covers the rule that replaces
// reducing the target to its origin.
//
// WHAT CHANGED AND WHY IT IS NOT SIMPLY "SHOW MORE". Until now the report threw
// away everything after the host, because there was no masking and a URL can
// itself be a secret. Now the URL is shown, but the parts that cannot defend
// themselves are handled by position rather than by name:
//
//   - user info always goes, as everywhere else,
//   - EVERY query value goes, not only the ones whose parameter is named like a
//     credential. In a target somebody typed, "s=abc" has no way to prove it is
//     not a session,
//   - the whole path becomes one marker. Deciding which segments look like
//     identifiers would need a threshold on length or entropy, and a threshold
//     chosen by guesswork is a promise nobody measured. A leaked session
//     identifier cannot be taken back, a lost path costs one sentence,
//   - the fragment is dropped without a marker, because it NEVER REACHES THE
//     SERVER. It is pure risk with no diagnostic value, and it is the only part
//     of a URL where there is nothing to weigh.
//
// Parameter NAMES survive on purpose. "your URL carries a token" is half the
// diagnosis and it can be said without saying the token.
func TestATargetKeepsItsShapeAndLosesItsSecrets(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		removed bool
	}{
		{"https://example.com", "https://example.com", false},
		{"https://example.com/", "https://example.com/", false},
		{"http://user:hunter2@proxy.corp.example:8080", "http://[redacted]@proxy.corp.example:8080", true},
		{"https://api.example.com/session/abc123", "https://api.example.com/[redacted]", true},
		{"https://api.example/v1?token=X&format=json", "https://api.example/[redacted]?token=[redacted]&format=[redacted]", true},
		{"https://example.com/#top", "https://example.com/", true},
		{"https://example.com?a=1", "https://example.com?a=[redacted]", true},
	}

	for _, c := range cases {
		got, removed := New(Credentials).Target(c.in)
		if got != c.want {
			t.Errorf("target %q\n  got:  %s\n  want: %s", c.in, got, c.want)
		}
		if removed != c.removed {
			t.Errorf("target %q reported removed=%v, want %v", c.in, removed, c.removed)
		}
	}
}

// TestAMaskedTargetStillHidesTheHostUnderTheStrongerMode keeps the two rules
// composed. The target is the one value that goes through a path of its own, so
// it is also the one that could quietly stop obeying --redact.
func TestAMaskedTargetStillHidesTheHostUnderTheStrongerMode(t *testing.T) {
	got, _ := New(Everything).Target("https://internal.corp.example/a/b?token=X")
	if strings.Contains(got, "internal.corp.example") {
		t.Errorf("--redact left the target host in place: %q", got)
	}
	if strings.Contains(got, "X") && !strings.Contains(got, "host-") {
		t.Errorf("the token survived: %q", got)
	}
}

// TestMaskingIsIdempotent is property 2 from the standard of code. Without it a
// second pass turns a masked report into rubbish, and reports pass through more
// than one hand.
func TestMaskingIsIdempotent(t *testing.T) {
	inputs := []string{
		"http://user:hunter2@proxy:8080",
		"https://api.example/v1?token=abc&key=def",
		"-Dpassword=secret -Duser=bob",
		"https://internal.corp.example/a/b?sig=zzz",
		"",
		"nothing to mask here at all",
	}
	for _, mode := range []Mode{Credentials, Everything} {
		for _, input := range inputs {
			r := New(mode, Name("bob"))
			once := r.Text(input)
			twice := r.Text(once)
			if once != twice {
				t.Errorf("mode %d: masking %q twice changed it:\n  once:  %q\n  twice: %q", mode, input, once, twice)
			}
		}
	}
}

// TestAPseudonymIsStableWithinOneReport is the whole reason --redact hands out
// pseudonyms rather than one marker. A reader has to be able to see that two
// mentions are the same machine, or that they are not.
func TestAPseudonymIsStableWithinOneReport(t *testing.T) {
	r := New(Everything)

	first := r.Text("https://internal.corp.example/a")
	again := r.Text("http://internal.corp.example:8080/b")
	other := r.Text("https://other.corp.example/c")

	if strings.Contains(first, "internal.corp.example") {
		t.Fatalf("the host survived --redact: %q", first)
	}
	firstName := pseudonymIn(t, first)
	againName := pseudonymIn(t, again)
	otherName := pseudonymIn(t, other)

	if firstName != againName {
		t.Errorf("one host got two pseudonyms: %q and %q", firstName, againName)
	}
	if otherName == firstName {
		t.Errorf("two different hosts got the same pseudonym %q - the report cannot be read", otherName)
	}
}

// pseudonymPattern is the shape a pseudonym has. The brackets are the whole
// defence against a real machine being called host-1, so a test that found
// pseudonyms by scanning for "host-" would keep passing if they were removed.
var pseudonymPattern = regexp.MustCompile(`\[(?:host|name)-\d+\]`)

func pseudonymIn(t *testing.T, masked string) string {
	t.Helper()
	found := pseudonymPattern.FindString(masked)
	if found == "" {
		t.Fatalf("no pseudonym in %q", masked)
	}
	return found
}

// TestTwoRunsOfTheSameInputProduceTheSameText keeps pseudonyms from breaking the
// determinism property. Numbers handed out in encounter order are only stable
// while the encounter order is.
func TestTwoRunsOfTheSameInputProduceTheSameText(t *testing.T) {
	values := []string{
		"https://a.example/x",
		"http://user:p@b.example:1/y",
		"https://a.example/z",
	}
	var first []string
	for attempt := 0; attempt < 10; attempt++ {
		r := New(Everything, Name("user"))
		var got []string
		for _, v := range values {
			got = append(got, r.Text(v))
		}
		if first == nil {
			first = got
			continue
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("run %d produced %q where the first produced %q", attempt, got[i], first[i])
			}
		}
	}
}

// TestCredentialMaskingCannotBeSwitchedOff pins the floor. The zero value of
// Mode is the safe one, so a forgotten assignment still removes credentials.
func TestCredentialMaskingCannotBeSwitchedOff(t *testing.T) {
	var unset Mode
	if unset != Credentials {
		t.Fatalf("the zero mode is %d, want the credential floor", unset)
	}
	for _, mode := range []Mode{Credentials, Everything} {
		if got := New(mode).Text("http://u:leaked@h:1"); strings.Contains(got, "leaked") {
			t.Errorf("mode %d let a password through: %q", mode, got)
		}
	}
}

// TestOnlyTheStrongerModeTouchesNames is the other side of the same rule. A
// host name is not a secret, and removing it by default would take the report's
// usefulness away from everybody to protect the few who asked for it.
func TestOnlyTheStrongerModeTouchesNames(t *testing.T) {
	const value = "https://internal.corp.example/path"
	if got := New(Credentials).Text(value); got != value {
		t.Errorf("the default mode changed a host name:\n  in:  %s\n  out: %s", value, got)
	}
	if got := New(Everything).Text(value); got == value {
		t.Error("--redact left the host name in place")
	}
}

// TestTheCallersSensitiveNamesGoUnderTheStrongerMode covers the one thing no
// pattern finds: the account name the process runs as, which shows up in every
// path on the machine.
//
// THE NAME IN THIS FIXTURE IS INVENTED AND HAS TO STAY INVENTED. This repository
// is published, so a fixture is read by strangers - and the property under test
// holds for ANY name, so a real one would prove nothing extra while putting
// somebody's account name in front of everybody who clones this. The names a
// fixture may use are listed in internal/guard/personal_test.go, and a guard
// refuses the rest.
func TestTheCallersSensitiveNamesGoUnderTheStrongerMode(t *testing.T) {
	const path = `C:\Users\jdoe\AppData\Roaming\npm\.npmrc`

	if got := New(Everything, Name("jdoe")).Text(path); strings.Contains(got, "jdoe") {
		t.Errorf("the account name survived --redact: %q", got)
	}
	if got := New(Everything, Name("jdoe")).Text(path); !strings.Contains(got, "npm") {
		t.Errorf("--redact removed more of the path than the name: %q", got)
	}
	if got := New(Credentials, Name("jdoe")).Text(path); got != path {
		t.Errorf("the default mode touched a path: %q", got)
	}
}

// TestALongerNameIsMaskedBeforeAShorterOneItContains guards an ordering bug
// that would leave half a name behind: masking "bob" first turns "bobby" into
// "name-1by".
func TestALongerNameIsMaskedBeforeAShorterOneItContains(t *testing.T) {
	got := New(Everything, Name("bob"), Name("bobby")).Text("/home/bobby/x and /home/bob/y")
	if strings.Contains(got, "bobby") || strings.Contains(got, "by/") {
		t.Errorf("a name was masked in pieces: %q", got)
	}

	// THE CASE THAT STILL NEEDS THE ORDERING, and it is neither the one above nor
	// the first one written for it.
	//
	// Since names are matched on word boundaries, "bob" no longer matches inside
	// "bobby", so that first row would pass whatever the order was - a mutation
	// survived and said so. The replacement written next was a host inside a URL,
	// and that survived too, for a subtler reason worth keeping: masking the
	// inner name leaves "corp.[name-1]", which the host rule then pseudonymises
	// WHOLE, so both orders end up clean and the test could not tell them apart.
	//
	// A path has no host rule behind it to tidy up the mess. A dot is not a word
	// character, so the short name is still found inside the long one, and what
	// is left over stays left over.
	path := New(Everything, Name("example"), Name("corp.example")).Text("/etc/ssl/corp.example/ca.pem")
	if strings.Contains(path, "corp.") {
		t.Errorf("a name was masked in pieces, leaving half of it behind: %q", path)
	}
}

// TestAPortIsOnlyAPortWhenAColonSaysSo pins the rule directly rather than
// through the fuzzer.
//
// It used to be covered only by the idempotence target, and that cover was lost
// when pseudonyms gained their brackets: a bracketed pseudonym is recognised as
// already issued whatever follows it, so masking stayed idempotent even with
// this rule broken. The property still holds and the rule stopped being the
// reason - which is exactly the shape of a test that quietly checks nothing.
func TestAPortIsOnlyAPortWhenAColonSaysSo(t *testing.T) {
	cases := []struct{ authority, host, port string }{
		{"proxy.corp.example:8080", "proxy.corp.example", ":8080"},
		{"proxy.corp.example", "proxy.corp.example", ""},
		{"[::1]:8080", "[::1]", ":8080"},
		{"[::1]", "[::1]", ""},
		// The shape the fuzzer found: digits glued to a closing bracket with no
		// colon. Reading them as a port produced a pseudonym with numbers stuck
		// to it, which the next pass read as a host it had never seen.
		{"[]00", "[]00", ""},
		{"host:notaport", "host:notaport", ""},
		{"host:", "host:", ""},
	}
	for _, c := range cases {
		host, port := splitPort(c.authority)
		if host != c.host || port != c.port {
			t.Errorf("splitPort(%q) = %q, %q - want %q, %q", c.authority, host, port, c.host, c.port)
		}
	}
}

// TestASettingNameIsReadInSegmentsAndNotAsASubstring is the guard on the rule
// that decides whether a value is a secret.
//
// THE ROW THAT MATTERS MOST IS THE FIRST ONE. NODE_TLS_REJECT_UNAUTHORIZED=0 is
// certificate verification switched off in Node, and it is a finding L0 exists
// to report. A rule asking whether the name CONTAINS "auth" answered yes -
// "unauthorized" contains it - and replaced the 0 with a marker, deleting the
// diagnosis in order to protect a secret that was never there.
//
// The rows below it are the other side: a rule narrow enough to keep that value
// still has to catch a password however somebody spelled the name.
func TestASettingNameIsReadInSegmentsAndNotAsASubstring(t *testing.T) {
	survives := []string{
		"NODE_TLS_REJECT_UNAUTHORIZED=0",
		"HTTPS_PROXY=http://proxy.corp.example:8080",
		"NO_PROXY=.corp,localhost",
		"SSL_CERT_AUTHORITY=/etc/ssl/certs/corp.pem",
		"REQUESTS_CA_BUNDLE=/etc/ssl/authority.pem",
		"-Dfoo=bar",
		"tokenizer.mode=fast",
	}
	masked := []string{
		"-Dpassword=hunter2",
		"-Djavax.net.ssl.trustStorePassword=changeit",
		"SSLKeyPassword=changeit",
		// An acronym running straight into the word, with no lower case letter
		// between them. The ordinary camel case rule does not see this one - it
		// looks for a capital after a small letter and there is none - so
		// without the acronym boundary the whole name reads as one word and the
		// password goes into the report. Added after a mutation survived and
		// showed that the row above it was being caught by the other rule.
		"SSLPassword=changeit",
		"proxyPassword=hunter2",
		"API_KEY=abc123",
		"apikey=abc123",
		"PROXY_AUTH=basic",
		"AUTHORIZATION=Bearer abc",
		"GOOGLE_APPLICATION_CREDENTIALS=/home/build/sa.json",
	}

	for _, setting := range survives {
		if got := New(Credentials).Text(setting); got != setting {
			t.Errorf("a value that is the diagnosis was masked:\n  in:  %s\n  out: %s", setting, got)
		}
	}
	for _, setting := range masked {
		got := New(Credentials).Text(setting)
		if !strings.HasSuffix(got, Placeholder) {
			t.Errorf("a secret was left in place:\n  in:  %s\n  out: %s", setting, got)
		}
	}
}

// TestAPseudonymCannotCollideWithARealName covers the defect that made --redact
// leak the thing it exists to hide.
//
// A machine called host-1 is unremarkable. The pseudonyms used to have exactly
// that shape, so asking for one for a machine already called host-1 found it in
// the issued set and handed it back untouched: the real name went into a report
// marked redacted, and it became the same string as the pseudonym of a
// different machine. Two hosts read as one, which is what pseudonyms exist to
// prevent, and the name leaked in the mode whose only job is that it does not.
func TestAPseudonymCannotCollideWithARealName(t *testing.T) {
	r := New(Everything)

	first := r.Text("https://proxy.corp.example/a")
	collider := r.Text("https://host-1/b")
	again := r.Text("https://proxy.corp.example/c")

	if strings.Contains(collider, "//host-1/") {
		t.Errorf("a real machine called host-1 survived --redact: %q", collider)
	}
	if pseudonymIn(t, collider) == pseudonymIn(t, first) {
		t.Errorf("two different machines were given the same name: %q and %q", first, collider)
	}
	if pseudonymIn(t, again) != pseudonymIn(t, first) {
		t.Errorf("one machine was given two names: %q and %q", first, again)
	}
}

// TestAHeaderValueDoesNotSwallowTheSettingBehindIt covers a rule that used to
// run to the end of the line and take everything with it.
//
// A dump putting a header and a proxy setting on one line lost the setting
// entirely, silently, in the only place it was going to be reported. Over
// masking never leaks, which is why this stayed invisible - it destroys the
// diagnosis instead.
func TestAHeaderValueDoesNotSwallowTheSettingBehindIt(t *testing.T) {
	const line = "cookie: sid=abc123 HTTPS_PROXY=http://proxy.corp.example:8080 NO_PROXY=.corp"

	got := New(Credentials).Text(line)
	if strings.Contains(got, "abc123") {
		t.Errorf("the cookie survived: %q", got)
	}
	for _, kept := range []string{"HTTPS_PROXY=", "proxy.corp.example", "NO_PROXY=.corp"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q was swallowed by the header rule: %q", kept, got)
		}
	}
}

// TestACookieKeepsItsWholeValueMasked is the other half of the rule above. The
// cut is only made at an environment variable, so an ordinary cookie attribute
// must not end it - refusing to cut is the safe direction and this pins it.
func TestACookieKeepsItsWholeValueMasked(t *testing.T) {
	got := New(Credentials).Text("set-cookie: sid=abc123; Path=/; HttpOnly")
	if strings.Contains(got, "abc123") || strings.Contains(got, "HttpOnly") {
		t.Errorf("a cookie was cut short of its own end: %q", got)
	}
}

// TestATargetQuerySegmentWithNoNameIsStillMasked closes the one shape in a
// target that used to be passed through whole.
//
// Target masks by POSITION, because a value in a URL somebody typed cannot
// prove what it is. A segment with no equals sign was left alone on the
// reasoning that a bare NAME hides nothing - which reads it as a name rather
// than as a value, and that is the single assumption the rest of the rule
// refuses to make. A signed URL carrying one opaque token has this shape.
func TestATargetQuerySegmentWithNoNameIsStillMasked(t *testing.T) {
	const token = "eyJhbGciOiJIUzI1NiJ9.payload.signature"

	got, removed := New(Credentials).Target("https://api.example/v1?" + token)
	if strings.Contains(got, token) {
		t.Errorf("an opaque query value survived: %q", got)
	}
	if !removed {
		t.Error("the target was cut and did not report that it had been")
	}
}

// TestAShortSensitiveNameDoesNotRewriteOrdinaryWords covers the replacement that
// had no idea what a word was.
//
// Service accounts called sys, adm, svc or ci are ordinary, and so is a target
// host whose first label is api. Substring replacement turned "system trust
// store" into a pseudonym glued to "tem" - not a leak, but a report that looks
// corrupted, and a report whose text looks broken stops being believed a line
// higher up as well.
func TestAShortSensitiveNameDoesNotRewriteOrdinaryWords(t *testing.T) {
	const text = "system trust store, administrator, apikey policy, /home/sys/.npmrc"

	got := New(Everything, Name("sys")).Text(text)
	for _, kept := range []string{"system", "trust store", "administrator", "apikey"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q was rewritten by a three letter account name: %q", kept, got)
		}
	}
	if strings.Contains(got, "/home/sys/") {
		t.Errorf("the account name itself survived where it stood alone: %q", got)
	}
}

// TestAHandedOverHostReadsAsAHostEverywhere is ADR26 asserted directly, and it
// is the reason Sensitive is a type rather than a string.
//
// L1 reports a host name TWICE in shapes that look nothing alike: bare, in a
// field of its own, and inside a URL. Both have to come out as one pseudonym and
// both have to be labelled a host. The second half is the part that would rot
// quietly: the two rules key on the real name, so they agree on the NUMBER
// whatever the kind is, and only the word inside the brackets would go wrong.
func TestAHandedOverHostReadsAsAHostEverywhere(t *testing.T) {
	const text = "proxy.corp.example answered for https://proxy.corp.example:8080/x"

	got := New(Everything, Host("proxy.corp.example")).Text(text)
	if strings.Contains(got, "proxy.corp.example") {
		t.Fatalf("a host handed over as sensitive survived: %q", got)
	}
	if strings.Contains(got, "[name-") {
		t.Errorf("a host was pseudonymised as a name, so one machine reads as two ideas: %q", got)
	}
	if strings.Count(got, "[host-1]") != 2 {
		t.Errorf("the bare name and the name in the URL did not come out as one pseudonym: %q", got)
	}
	// The port is diagnostic and identifies nobody, so it stays.
	if !strings.Contains(got, ":8080") {
		t.Errorf("the port was masked along with the host: %q", got)
	}
}

// TestAResolverReadsAsInfrastructureAndNotAsTheAnswer is ADR32 pinned.
//
// The rule it defends is a DISTINCTION, not a blanket: a resolver address is a
// piece of somebody's network and goes under a pseudonym, while the address a
// name resolved to is the answer they came for and stays. A test that only
// checked the masking half would pass on an implementation that masked every
// address and destroyed the diagnosis, so both halves are here.
func TestAResolverReadsAsInfrastructureAndNotAsTheAnswer(t *testing.T) {
	const text = "10.1.2.53 answered NOERROR and gave 192.0.2.10"

	got := New(Everything, Resolver("10.1.2.53")).Text(text)
	if strings.Contains(got, "10.1.2.53") {
		t.Errorf("a resolver handed over as sensitive survived: %q", got)
	}
	if !strings.Contains(got, "[resolver-1]") {
		t.Errorf("the resolver did not read as a resolver: %q", got)
	}
	if strings.Contains(got, "[host-") || strings.Contains(got, "[name-") {
		t.Errorf("a resolver was labelled as something else, so one row carries two ideas: %q", got)
	}
	// THE HALF THAT WOULD GO MISSING. The address the name resolved to is the
	// answer, and a redaction that took it as well would answer "what does this
	// resolve to" with a pseudonym.
	if !strings.Contains(got, "192.0.2.10") {
		t.Errorf("the address the name resolved to was masked, which deletes the diagnosis: %q", got)
	}
}

// TestAResolverAddressIsNotMatchedInsideALongerOne covers the boundary the
// pseudonym machinery has to get right for addresses specifically.
//
// Names have letters and read wrongly when cut. Addresses read wrongly when
// EXTENDED: 10.1.2.5 sitting inside 10.1.2.53 would turn a neighbouring resolver
// into "[resolver-1]3", which looks like a corrupted report rather than a bug.
func TestAResolverAddressIsNotMatchedInsideALongerOne(t *testing.T) {
	got := New(Everything, Resolver("10.1.2.5")).Text("10.1.2.5 and 10.1.2.53 and 110.1.2.5")

	if strings.Count(got, "[resolver-1]") != 1 {
		t.Errorf("the address matched inside a longer one: %q", got)
	}
	if !strings.Contains(got, "10.1.2.53") || !strings.Contains(got, "110.1.2.5") {
		t.Errorf("a neighbouring address was damaged: %q", got)
	}
}

// TestAnAccountAndAHostAreToldApart is the other side of the kind. Without it the
// kind could be ignored entirely and the test above would still pass, because one
// name cannot show that two labels exist.
func TestAnAccountAndAHostAreToldApart(t *testing.T) {
	got := New(Everything, Host("build.corp.example"), Name("jdoe")).
		Text("build.corp.example is reached by jdoe")

	if !strings.Contains(got, "[host-1]") {
		t.Errorf("the host did not read as a host: %q", got)
	}
	if !strings.Contains(got, "[name-1]") {
		t.Errorf("the account did not read as a name: %q", got)
	}
}

// TestASensitiveNameWithNoTextIsDropped covers the one input that would turn this
// list into a disaster rather than a mistake.
//
// An empty name compiled into a matcher matches at every position, so it would
// replace the whole report with pseudonyms - and the zero value of an exported
// struct is something a caller can write by accident.
func TestASensitiveNameWithNoTextIsDropped(t *testing.T) {
	const text = "https://api.example/v1 reached by jdoe"

	for _, empty := range []Sensitive{Host(""), Name(""), {}} {
		got := New(Everything, empty).Text(text)
		if !strings.Contains(got, "jdoe") {
			t.Errorf("an empty sensitive name rewrote text it should not have touched: %q", got)
		}
	}
}

// TestCarriedCredentialsSaysWhetherThereWasAnythingToRemove keeps the one
// diagnostic fact that can be reported without reporting the secret.
func TestCarriedCredentialsSaysWhetherThereWasAnythingToRemove(t *testing.T) {
	r := New(Credentials)
	carrying := []string{
		"http://user:pass@proxy:8080",
		"https://x/?token=abc",
		"-Dpassword=hunter2",
		// The two shapes the first version of this function could not see. It
		// named three of the four rules and left the header rule out, so these
		// came back clean while masking removed them.
		"Authorization: Bearer abc123",
		"proxy-authorization: Basic ZGVtbzpzZWNyZXQ",
	}
	clean := []string{
		"http://proxy.corp.example:8080",
		"https://api.example/v1?page=2",
		"",
		"/etc/ssl/certs/ca-certificates.crt",
		"NODE_TLS_REJECT_UNAUTHORIZED=0",
	}
	for _, value := range carrying {
		if !r.CarriedCredentials(value) {
			t.Errorf("%q carries a credential and was reported as clean", value)
		}
	}
	for _, value := range clean {
		if r.CarriedCredentials(value) {
			t.Errorf("%q carries nothing and was reported as carrying a credential", value)
		}
	}
}

// TestCarriedCredentialsAgreesWithWhatMaskingActuallyRemoves is the property
// behind the row above, and it is the one that cannot drift.
//
// The report prints this fact as a claim about a value. A version of it kept as
// its own list of patterns will disagree with the masking the day a rule is
// added to one and not the other, and the disagreement is invisible: nothing
// compares them. Asking whether masking changed the text is the same question
// the field is supposed to answer.
func TestCarriedCredentialsAgreesWithWhatMaskingActuallyRemoves(t *testing.T) {
	corpus := []string{
		"http://user:pass@proxy:8080",
		"Authorization: Bearer abc123",
		"set-cookie: sid=abc; Path=/",
		"-Dpassword=hunter2",
		"-Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts",
		"https://api.example/v1?token=abc&page=2",
		"https://api.example/v1?page=2",
		"NODE_TLS_REJECT_UNAUTHORIZED=0",
		"HTTPS_PROXY=http://proxy.corp.example:8080",
		"",
		"nothing to mask here at all",
	}
	r := New(Credentials)
	for _, value := range corpus {
		removed := r.Text(value) != value
		if got := r.CarriedCredentials(value); got != removed {
			t.Errorf("%q: CarriedCredentials says %v, masking %s the text",
				value, got, map[bool]string{true: "changed", false: "left alone"}[removed])
		}
	}
}

// TestASettingNamedAsASecretLosesItsWholeValue is the rule ADR19 added, and the
// hole it closes is one a reader has to be shown to believe.
//
// Text masks BY NAME. Hand it a bare value and the name is gone, so the rule
// that would have fired has nothing to fire on: masking PROXY_PASSWORD's value
// on its own leaves it exactly as it was. The layer that reports environment
// variables hands over the value alone - it must, because gluing NAME=VALUE back
// together is what deleted a finding once already - so without this the first
// variable named as a secret walks into the report.
func TestASettingNamedAsASecretLosesItsWholeValue(t *testing.T) {
	r := New(Credentials)

	// The shape of the hole, stated first: the value alone survives Text.
	if got := r.Text("hunter2"); got != "hunter2" {
		t.Fatalf("this test no longer demonstrates anything: Text alone returned %q", got)
	}

	masked, carried := r.SettingValue("PROXY_PASSWORD", "hunter2")
	if strings.Contains(masked, "hunter2") {
		t.Errorf("the value of a setting named as a secret survived: %q", masked)
	}
	if !carried {
		t.Error("a credential was removed and the finding does not record that anything was")
	}
}

// TestAVariableWhoseNameOnlyContainsACredentialWordKeepsItsValue is D8 checked
// through the door ADR19 opened.
//
// The value 0 in NODE_TLS_REJECT_UNAUTHORIZED is certificate verification
// switched off in Node - the entire finding. An earlier rule deleted it because
// "unauthorized" contains "auth". Passing the name beside the value must not
// bring that back: the name is read in segments, and none of node, tls, reject
// or unauthorized is anybody's credential word.
func TestAVariableWhoseNameOnlyContainsACredentialWordKeepsItsValue(t *testing.T) {
	r := New(Credentials)

	masked, carried := r.SettingValue("NODE_TLS_REJECT_UNAUTHORIZED", "0")
	if masked != "0" {
		t.Errorf("the whole finding was masked away: %q", masked)
	}
	if carried {
		t.Error("a value that is not a secret was reported as having carried one")
	}
}

// TestAValueMaskedOnItsOwnStillLosesItsUserInfo keeps the new rule from
// replacing the old ones. A proxy URL carries its credential inside a structure
// that names it, so it has to be caught whatever the setting is called.
func TestAValueMaskedOnItsOwnStillLosesItsUserInfo(t *testing.T) {
	r := New(Credentials)

	masked, carried := r.SettingValue("HTTPS_PROXY", "http://user:hunter2@proxy.corp:8080")
	if strings.Contains(masked, "hunter2") {
		t.Errorf("a password inside a proxy URL survived: %q", masked)
	}
	if !strings.Contains(masked, "proxy.corp") {
		t.Errorf("the host was taken out under the floor mode, which is not what it is for: %q", masked)
	}
	if !carried {
		t.Error("user info was removed and the finding does not say a credential was there")
	}
}

// TestASettingSetToNothingCarriesNothing covers the degenerate but legal input.
// HTTPS_PROXY= with no value switches proxying off in some tools, so it is a
// real state - and nothing can have been removed from it, whatever its name.
func TestASettingSetToNothingCarriesNothing(t *testing.T) {
	for _, name := range []string{"HTTPS_PROXY", "PROXY_PASSWORD"} {
		masked, carried := New(Credentials).SettingValue(name, "")
		if masked != "" {
			t.Errorf("%s set to nothing came back as %q", name, masked)
		}
		if carried {
			t.Errorf("%s set to nothing was reported as having carried a credential", name)
		}
	}
}

// TestPseudonymisingAHostIsNotReportedAsRemovingACredential is the separation
// that makes the flag in the report mean something.
//
// Under the stronger mode a proxy host becomes a pseudonym, so the value changes
// - but nothing secret was taken out of it. A report saying this variable
// carried a credential would be a false accusation drawn from the fact that
// --redact was on.
func TestPseudonymisingAHostIsNotReportedAsRemovingACredential(t *testing.T) {
	masked, carried := New(Everything).SettingValue("HTTPS_PROXY", "http://proxy.corp:8080")

	if strings.Contains(masked, "proxy.corp") {
		t.Errorf("the stronger mode left the host in place: %q", masked)
	}
	if carried {
		t.Errorf("masking a host was reported as removing a credential: %q", masked)
	}
}
