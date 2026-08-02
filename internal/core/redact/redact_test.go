package redact

import (
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
			input:   "http://user:haslo@proxy.corp.example:8080",
			gone:    "haslo",
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

// TestMaskingIsIdempotent is property 2 from the standard of code. Without it a
// second pass turns a masked report into rubbish, and reports pass through more
// than one hand.
func TestMaskingIsIdempotent(t *testing.T) {
	inputs := []string{
		"http://user:haslo@proxy:8080",
		"https://api.example/v1?token=abc&key=def",
		"-Dpassword=secret -Duser=bob",
		"https://internal.corp.example/a/b?sig=zzz",
		"",
		"nothing to mask here at all",
	}
	for _, mode := range []Mode{Credentials, Everything} {
		for _, input := range inputs {
			r := New(mode, "bob")
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

func pseudonymIn(t *testing.T, masked string) string {
	t.Helper()
	at := strings.Index(masked, "host-")
	if at < 0 {
		t.Fatalf("no pseudonym in %q", masked)
	}
	end := at
	for end < len(masked) && masked[end] != '/' && masked[end] != ':' {
		end++
	}
	return masked[at:end]
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
		r := New(Everything, "user")
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
func TestTheCallersSensitiveNamesGoUnderTheStrongerMode(t *testing.T) {
	const path = `C:\Users\Testtt\AppData\Roaming\npm\.npmrc`

	if got := New(Everything, "Testtt").Text(path); strings.Contains(got, "Testtt") {
		t.Errorf("the account name survived --redact: %q", got)
	}
	if got := New(Everything, "Testtt").Text(path); !strings.Contains(got, "npm") {
		t.Errorf("--redact removed more of the path than the name: %q", got)
	}
	if got := New(Credentials, "Testtt").Text(path); got != path {
		t.Errorf("the default mode touched a path: %q", got)
	}
}

// TestALongerNameIsMaskedBeforeAShorterOneItContains guards an ordering bug
// that would leave half a name behind: masking "bob" first turns "bobby" into
// "name-1by".
func TestALongerNameIsMaskedBeforeAShorterOneItContains(t *testing.T) {
	got := New(Everything, "bob", "bobby").Text("/home/bobby/x and /home/bob/y")
	if strings.Contains(got, "bobby") || strings.Contains(got, "by/") {
		t.Errorf("a name was masked in pieces: %q", got)
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
	}
	clean := []string{
		"http://proxy.corp.example:8080",
		"https://api.example/v1?page=2",
		"",
		"/etc/ssl/certs/ca-certificates.crt",
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
