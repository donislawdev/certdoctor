package proxy

import (
	"fmt"
	"strings"
	"testing"
)

// declaredNames is what machine.ProxyVariables() hands this package, in the
// order L0 reports.
//
// IT IS WRITTEN OUT HERE AND DERIVED THERE, and that is not the duplication
// OBS50 warns about: the mutation register anchors each entry inside one NAMED
// file, so a literal in a test cannot make an entry aimed at variables.go match
// twice. What it would be if this list drifted is a test agreeing with itself,
// which is why the assertions below never assume more than the order.
var declaredNames = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"ALL_PROXY", "all_proxy",
	"NO_PROXY", "no_proxy",
}

// environment turns a map into the port. A key present with an empty value is a
// variable set to nothing, which is a different fact from an absent one.
func environment(values map[string]string) Lookup {
	return func(name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	}
}

func TestTheLowerCaseSpellingWins(t *testing.T) {
	lens := EnvironmentLens(environment(map[string]string{
		"HTTP_PROXY":  "upper.corp:8080",
		"http_proxy":  "lower.corp:8080",
		"HTTPS_PROXY": "only-upper.corp:8080",
	}), declaredNames)

	if !lens.Read {
		t.Fatalf("the environment was handed over and the lens says it could not be read: %+v", lens)
	}
	got, ok := ServerFor(lens.Servers, "http")
	if !ok || got.Address != "lower.corp:8080" {
		t.Errorf("http got %+v (found %v), and both vendors say the lower case spelling wins", got, ok)
	}
	got, ok = ServerFor(lens.Servers, "https")
	if !ok || got.Address != "only-upper.corp:8080" {
		t.Errorf("https got %+v (found %v), and the upper case spelling is the only one set", got, ok)
	}
}

// TestAnEmptyLowerCaseValueDoesNotHideTheUpperCaseOne is the half of the
// precedence only one vendor documents, and the reason is written at the
// function: reporting no proxy on a machine where Go and .NET use one is the
// expensive direction to be wrong in.
func TestAnEmptyLowerCaseValueDoesNotHideTheUpperCaseOne(t *testing.T) {
	lens := EnvironmentLens(environment(map[string]string{
		"http_proxy": "",
		"HTTP_PROXY": "upper.corp:8080",
	}), declaredNames)

	got, ok := ServerFor(lens.Servers, "http")
	if !ok || got.Address != "upper.corp:8080" {
		t.Errorf("http got %+v (found %v); an empty lower case value names no proxy, so the upper case one answers", got, ok)
	}
}

// TestAllProxyBecomesTheDefaultEntry pins that the environment's fallback and
// the Windows list's bare entry are one concept rather than two.
func TestAllProxyBecomesTheDefaultEntry(t *testing.T) {
	lens := EnvironmentLens(environment(map[string]string{
		"all_proxy":  "fallback.corp:1080",
		"http_proxy": "http.corp:8080",
	}), declaredNames)

	got, ok := ServerFor(lens.Servers, "http")
	if !ok || got.Address != "http.corp:8080" {
		t.Errorf("http got %+v (found %v), want its own entry", got, ok)
	}
	got, ok = ServerFor(lens.Servers, "ftp")
	if !ok || got.Address != "fallback.corp:1080" {
		t.Errorf("a protocol with no entry got %+v (found %v), want the all_proxy fallback", got, ok)
	}
	if !got.IsDefault() {
		t.Errorf("the all_proxy entry is %+v, and a fallback is an entry naming no protocol", got)
	}
}

func TestNoProxyFillsTheBypassAndKeepsAbsentApartFromEmpty(t *testing.T) {
	cases := []struct {
		name      string
		values    map[string]string
		wantSet   bool
		wantValue string
	}{
		{
			name:   "absent means this stack holds no exception list",
			values: map[string]string{"http_proxy": "p:8080"},
		},
		{
			name:      "set to nothing means a list excusing nobody",
			values:    map[string]string{"no_proxy": ""},
			wantSet:   true,
			wantValue: "",
		},
		{
			name:      "the lower case spelling wins here too",
			values:    map[string]string{"no_proxy": "a.corp", "NO_PROXY": "b.corp"},
			wantSet:   true,
			wantValue: "a.corp",
		},
		{
			name:      "an empty lower case one still counts as a list being there",
			values:    map[string]string{"no_proxy": "", "NO_PROXY": "b.corp"},
			wantSet:   true,
			wantValue: "b.corp",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lens := EnvironmentLens(environment(c.values), declaredNames)
			if lens.BypassSet != c.wantSet {
				t.Errorf("BypassSet is %v, want %v - absent and empty are different facts", lens.BypassSet, c.wantSet)
			}
			if lens.Bypass != c.wantValue {
				t.Errorf("Bypass is %q, want %q", lens.Bypass, c.wantValue)
			}
		})
	}
}

// TestAnEnvironmentNobodyAskedAboutIsNotAnEnvironmentWithoutProxies is the pair
// the whole Lens type exists to keep apart.
func TestAnEnvironmentNobodyAskedAboutIsNotAnEnvironmentWithoutProxies(t *testing.T) {
	unread := EnvironmentLens(nil, declaredNames)
	if unread.Read {
		t.Error("no way to read the environment was supplied and the lens says it was read")
	}
	if unread.Detail == "" {
		t.Error("the lens could not be read and says nothing about why, which Lens.Read calls a defect on our side")
	}
	if unread.Servers != nil {
		t.Errorf("Servers is %+v, and nil is what says this stack was never read", unread.Servers)
	}

	empty := EnvironmentLens(environment(nil), declaredNames)
	if !empty.Read {
		t.Error("an environment with no proxy variables in it was still read")
	}
	if empty.Servers == nil || len(empty.Servers) != 0 {
		t.Errorf("Servers is %+v, want an empty slice - the stack was read and names nobody", empty.Servers)
	}
	if empty.NamesAProxy() {
		t.Error("an environment with nothing set is being reported as naming a proxy")
	}
}

// TestTheEnvironmentLensCarriesNoRule holds the one thing that makes this stack
// different from the other three: one NO_PROXY is read at least three ways, so
// the rule belongs to whichever runtime is being asked about.
func TestTheEnvironmentLensCarriesNoRule(t *testing.T) {
	lens := EnvironmentLens(environment(map[string]string{"no_proxy": "a.corp"}), declaredNames)
	if lens.Rule != "" {
		t.Errorf("the environment lens claims rule %q, and no single reading of NO_PROXY is the right one", lens.Rule)
	}
}

// TestANameNoVendorReadsIsIgnored keeps a variable nothing on the machine
// consults out of the report. Every vendor checks exactly two spellings, so a
// mixed one is read by none of them.
//
// NODE_USE_ENV_PROXY IS DELIBERATELY NOT IN HERE, and finding out why is what
// this test was worth. It ends in _PROXY and would arrive as a proxy called
// "1" - but the rule that keeps it out is machine.ProxyVariables's, not this
// function's, and writing it here as well would be one RULE in two places.
// The bad caller is real and the answer to it is the caller, not a second copy.
func TestANameNoVendorReadsIsIgnored(t *testing.T) {
	lens := EnvironmentLens(environment(map[string]string{
		"Http_Proxy": "mixed.corp:8080",
		"PROXY":      "bare.corp:8080",
		"_proxy":     "empty-token.corp:8080",
	}), []string{"Http_Proxy", "PROXY", "_proxy"})

	if len(lens.Servers) != 0 {
		t.Errorf("Servers is %+v, and none of those names is one a vendor documents reading", lens.Servers)
	}
}

// TestTheUpperCaseHttpSpellingIsCalledOutBecauseCurlRefusesIt is the divergence
// INSIDE one stack. proxy.Divergence compares places, and both halves of this
// one are the same place, so it can only be said in a sentence.
func TestTheUpperCaseHttpSpellingIsCalledOutBecauseCurlRefusesIt(t *testing.T) {
	called := EnvironmentLens(environment(map[string]string{
		"HTTP_PROXY": "upper.corp:8080",
	}), declaredNames)
	if !strings.Contains(called.Detail, "curl") || !strings.Contains(called.Detail, "HTTP_PROXY") {
		t.Errorf("detail is %q, and it has to name curl and the spelling curl refuses", called.Detail)
	}

	quiet := EnvironmentLens(environment(map[string]string{
		"http_proxy": "lower.corp:8080",
	}), declaredNames)
	if strings.Contains(quiet.Detail, "curl") {
		t.Errorf("detail is %q, and the lower case spelling is the one curl honours", quiet.Detail)
	}

	// The reason is specific to the HTTP_ prefix and the CGI convention, so the
	// same shape one protocol over is not the same fact.
	https := EnvironmentLens(environment(map[string]string{
		"HTTPS_PROXY": "upper.corp:8080",
	}), declaredNames)
	if strings.Contains(https.Detail, "curl") {
		t.Errorf("detail is %q, and curl accepts the upper case spelling of every variable but the http one", https.Detail)
	}
}

func TestBothSpellingsNamingDifferentProxiesIsSaidOutLoud(t *testing.T) {
	differ := EnvironmentLens(environment(map[string]string{
		"https_proxy": "a.corp:8080",
		"HTTPS_PROXY": "b.corp:8080",
	}), declaredNames)
	if !strings.Contains(differ.Detail, "https_proxy") || !strings.Contains(differ.Detail, "HTTPS_PROXY") {
		t.Errorf("detail is %q, and it has to name both spellings that disagree", differ.Detail)
	}

	agree := EnvironmentLens(environment(map[string]string{
		"https_proxy": "a.corp:8080",
		"HTTPS_PROXY": "a.corp:8080",
	}), declaredNames)
	if agree.Detail != "" {
		t.Errorf("detail is %q, and two spellings holding the same value are the ordinary Windows machine", agree.Detail)
	}
}

// TestAPasswordFromTheEnvironmentDoesNotReachTheLens checks the whole lens and
// not one field, for the reason given beside the same check on Server.
func TestAPasswordFromTheEnvironmentDoesNotReachTheLens(t *testing.T) {
	lens := EnvironmentLens(environment(map[string]string{
		"https_proxy": "http://bob:hunter2@p.corp:8080",
	}), declaredNames)

	got, ok := ServerFor(lens.Servers, "https")
	if !ok || got.Address != "p.corp:8080" {
		t.Fatalf("https got %+v (found %v), want the address with the credentials gone", got, ok)
	}
	if !got.CarriedCredentials {
		t.Error("the entry named a user and a password and the lens does not record that it did")
	}
	if strings.Contains(fmt.Sprintf("%+v", lens), "hunter2") {
		t.Errorf("the password survived somewhere in the lens: %+v", lens)
	}
}

// TestTheServerOrderIsTheOrderTheNamesArriveIn keeps the report order decided in
// one place - the declared list L0 already reports from.
func TestTheServerOrderIsTheOrderTheNamesArriveIn(t *testing.T) {
	lens := EnvironmentLens(environment(map[string]string{
		"all_proxy":   "c.corp",
		"https_proxy": "b.corp",
		"http_proxy":  "a.corp",
	}), declaredNames)

	want := []string{"a.corp", "b.corp", "c.corp"}
	if len(lens.Servers) != len(want) {
		t.Fatalf("got %d servers, want %d: %+v", len(lens.Servers), len(want), lens.Servers)
	}
	for i := range want {
		if lens.Servers[i].Address != want[i] {
			t.Errorf("position %d is %q, want %q - the order is the order of the names handed in",
				i, lens.Servers[i].Address, want[i])
		}
	}
}

// TestAValueNamingNoAddressIsNotAServer covers the one arm parseServer refuses
// on: a variable holding something that names nothing.
func TestAValueNamingNoAddressIsNotAServer(t *testing.T) {
	lens := EnvironmentLens(environment(map[string]string{
		"http_proxy":  "http://",
		"https_proxy": "b.corp",
	}), declaredNames)

	if _, ok := ServerFor(lens.Servers, "http"); ok {
		t.Errorf("http got an entry out of a value naming no address: %+v", lens.Servers)
	}
	if got, ok := ServerFor(lens.Servers, "https"); !ok || got.Address != "b.corp" {
		t.Errorf("https got %+v (found %v), and one unreadable variable must not take the others with it", got, ok)
	}
}
