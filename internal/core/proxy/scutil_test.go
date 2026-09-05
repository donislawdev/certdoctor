package proxy

import "testing"

// measuredOutput is the exact text "scutil --proxy" printed on the owner's Mac
// on 2026-09-05, on a machine with no proxy configured. It is a MEASUREMENT kept
// as its own fixture, which is what docs/22 section 7aa asks of any number or
// output that might one day become a guard.
const measuredOutput = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
}`

func TestTheMeasuredMacOutputComesApartAsItWasPrinted(t *testing.T) {
	got := ParseSCUtil(measuredOutput)

	entries, ok := got.Array(ExceptionsListKey)
	if !ok {
		t.Fatal("ExceptionsList was not found, and it is the one key measured on a real Mac")
	}
	want := []string{"*.local", "169.254/16"}
	if len(entries) != len(want) {
		t.Fatalf("ExceptionsList has %d entries, want %d: %q", len(entries), len(want), entries)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("ExceptionsList entry %d is %q, want %q - order is the platform's", i, entries[i], want[i])
		}
	}

	if v, ok := got.Scalar("FTPPassive"); !ok || v != "1" {
		t.Errorf("FTPPassive came out as %q (found %v), want \"1\"", v, ok)
	}

	// The numbered keys inside the array must NOT become top level settings.
	// A parser cutting every line at its first colon would report a setting
	// called "0" holding "*.local", and it would look plausible.
	for _, stray := range []string{"0", "1", ExceptionsListKey, "<dictionary>"} {
		if _, ok := got.Scalar(stray); ok {
			t.Errorf("%q became a top level scalar, so the nesting was not read", stray)
		}
	}
}

// TestTheExceptionListIsHandedOverJoinedTheWayTheRuleExpects closes the loop
// between the two halves: what the platform prints and what RuleExceptionsList
// reads. If these ever drift, the shipped macOS default silently stops being
// applied and nothing else notices.
func TestTheExceptionListIsHandedOverJoinedTheWayTheRuleExpects(t *testing.T) {
	list, ok := ParseSCUtil(measuredOutput).ExceptionsList()
	if !ok {
		t.Fatal("the measured output has no exception list")
	}
	if list != ExceptionsListDefault {
		t.Errorf("the parsed list is %q and the constant says %q - one of them is describing a different Mac", list, ExceptionsListDefault)
	}
	if !ask(t, RuleExceptionsList, list, host("printer.local")) {
		t.Error("the list taken off a real Mac did not excuse a .local name")
	}
	if !ask(t, RuleExceptionsList, list, host("169.254.1.1")) {
		t.Error("the list taken off a real Mac did not excuse a link-local address")
	}
	if ask(t, RuleExceptionsList, list, host("example.com")) {
		t.Error("the list taken off a real Mac excused an ordinary name")
	}
}

// TestAnAbsentKeyIsAnAnswerAndNotABlank is the distinction the whole type exists
// for. On the measured Mac there is no HTTPEnable at all, and "macOS is not
// configured for this" has to be tellable from "it is configured to empty".
func TestAnAbsentKeyIsAnAnswerAndNotABlank(t *testing.T) {
	got := ParseSCUtil(measuredOutput)
	for _, key := range []string{"HTTPEnable", "HTTPSProxy", "ProxyAutoConfigURLString", "ProxyAutoDiscoveryEnable"} {
		if v, ok := got.Scalar(key); ok {
			t.Errorf("%q was reported as present with %q, and the measured output has no such key", key, v)
		}
	}
	if _, ok := got.Array("NoSuchList"); ok {
		t.Error("an array key that is not there was reported as present")
	}
	if _, ok := got.ExceptionsList(); !ok {
		t.Error("the exception list that IS there was reported as absent")
	}
}

func TestAConfiguredMacComesApartToo(t *testing.T) {
	// The key names here are Apple's documentation rather than a measurement,
	// and the test says so. What it pins is the PARSING - scalars beside an
	// array, an array that is not first, and values holding colons of their own.
	configured := `<dictionary> {
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.corp.example
  ProxyAutoConfigURLString : http://wpad.corp.example/proxy.pac
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
    2 : *.corp.example
  }
  FTPPassive : 1
}`
	got := ParseSCUtil(configured)

	for key, want := range map[string]string{
		"HTTPEnable":               "1",
		"HTTPPort":                 "8080",
		"HTTPProxy":                "proxy.corp.example",
		"ProxyAutoConfigURLString": "http://wpad.corp.example/proxy.pac",
		"FTPPassive":               "1",
	} {
		if v, ok := got.Scalar(key); !ok || v != want {
			t.Errorf("%s came out as %q (found %v), want %q", key, v, ok, want)
		}
	}
	entries, _ := got.Array(ExceptionsListKey)
	if len(entries) != 3 || entries[2] != "*.corp.example" {
		t.Errorf("the exception list came out as %q, want three entries ending in *.corp.example", entries)
	}
}

// TestANestedDictionaryContributesNothing keeps the brace counting honest. A key
// one level deeper is dropped rather than promoted under a mangled name, because
// a report naming a setting that is not there is worse than one missing it.
func TestANestedDictionaryContributesNothing(t *testing.T) {
	nested := `<dictionary> {
  Top : 1
  Inner : <dictionary> {
    Buried : 2
  }
  After : 3
}`
	got := ParseSCUtil(nested)
	if v, ok := got.Scalar("Top"); !ok || v != "1" {
		t.Errorf("Top came out as %q (found %v)", v, ok)
	}
	if v, ok := got.Scalar("After"); !ok || v != "3" {
		t.Errorf("After came out as %q (found %v), so the nested block broke the depth count", v, ok)
	}
	if _, ok := got.Scalar("Buried"); ok {
		t.Error("a key nested one level deeper was promoted to a top level setting")
	}
	if _, ok := got.Scalar("Inner"); ok {
		t.Error("the nested dictionary itself became a scalar")
	}
	// AND IT MUST NOT HAVE BECOME AN ARRAY EITHER, which this test did not ask
	// until 2026-09-05. The name says a nested dictionary contributes NOTHING,
	// and the four checks above cover only the scalar map - so the whole Arrays
	// half of that sentence went unasserted. Measured by the mutation register:
	// widening the "<array>" prefix check to accept any value turns every nested
	// block into an empty array, and every assertion above still passed.
	if _, ok := got.Array("Inner"); ok {
		t.Error("the nested dictionary opened an array, so a block that carries no list became one")
	}
}

func TestNothingAtAllComesApartWithoutComplaint(t *testing.T) {
	for _, text := range []string{"", "\n\n", "no colon here", "}"} {
		got := ParseSCUtil(text)
		if len(got.Scalars) != 0 || len(got.Arrays) != 0 {
			t.Errorf("input %q produced %+v, and there is nothing in it to produce", text, got)
		}
	}
}

// TestCarriageReturnsDoNotBecomePartOfAValue covers the one way this text can
// arrive differently from how it was measured: through a pipe on a machine that
// ends its lines the other way.
func TestCarriageReturnsDoNotBecomePartOfAValue(t *testing.T) {
	got := ParseSCUtil("<dictionary> {\r\n  HTTPProxy : proxy.corp\r\n}\r\n")
	if v, ok := got.Scalar("HTTPProxy"); !ok || v != "proxy.corp" {
		t.Errorf("HTTPProxy came out as %q (found %v), want %q", v, ok, "proxy.corp")
	}
}

// TestAnAbsentExceptionListIsSaidToBeAbsent covers the other half of
// ExceptionsList. A Mac that printed no such key must not be described as one
// with an empty exception list, because an empty list excuses nobody and an
// absent one means the question was never answered.
func TestAnAbsentExceptionListIsSaidToBeAbsent(t *testing.T) {
	got := ParseSCUtil("<dictionary> {\n  FTPPassive : 1\n}")
	if list, ok := got.ExceptionsList(); ok {
		t.Errorf("an absent exception list was reported as present, holding %q", list)
	}
}

// TestABraceLineWithoutAKeyIsIgnored covers the shape this parser cannot name.
// Nothing in the measured output looks like this, and that is exactly why the
// branch needs an input: an unnamed block must not become a key.
func TestABraceLineWithoutAKeyIsIgnored(t *testing.T) {
	got := ParseSCUtil("<dictionary> {\n  Top : 1\n  {\n    Buried : 2\n  }\n  After : 3\n}")
	if v, ok := got.Scalar("Top"); !ok || v != "1" {
		t.Errorf("Top came out as %q (found %v)", v, ok)
	}
	if v, ok := got.Scalar("After"); !ok || v != "3" {
		t.Errorf("After came out as %q (found %v), so an unnamed block broke the depth count", v, ok)
	}
	if _, ok := got.Scalar("Buried"); ok {
		t.Error("a key inside an unnamed block became a top level setting")
	}
}

// TestTheStockMacLensIsAMachineWithNoProxyAndABypassListAnyway is the measured
// output turned into a lens, and it holds the fact that surprised this plan:
// every Mac excuses .local names and link-local addresses before anybody touches
// a setting, so an empty exception list in a report would be wrong.
func TestTheStockMacLensIsAMachineWithNoProxyAndABypassListAnyway(t *testing.T) {
	lens := LensFromSCUtil(ParseSCUtil(measuredOutput))

	if !lens.Read {
		t.Fatal("the command answered and the lens says the stack could not be read")
	}
	if lens.Stack != StackMacSystem || lens.Source != SourceSCUtil {
		t.Errorf("the lens lost track of where it came from: %+v", lens)
	}
	if lens.NamesAProxy() {
		t.Errorf("Servers is %+v on a Mac with no proxy configured", lens.Servers)
	}
	if lens.Servers == nil {
		t.Error("Servers is nil, and nil is reserved for a stack that was not read")
	}
	if !lens.BypassSet || lens.Bypass != ExceptionsListDefault {
		t.Errorf("bypass is %q (set %v), want the default list this machine printed", lens.Bypass, lens.BypassSet)
	}
	if lens.Rule != RuleExceptionsList {
		t.Errorf("rule is %q, and this list means what macOS says it means", lens.Rule)
	}
	if lens.PACURL != "" {
		t.Errorf("PACURL is %q on output that named no script", lens.PACURL)
	}
	if lens.AutoDetect != Unasked {
		t.Errorf("AutoDetect is %v, and the key was not in the output at all", lens.AutoDetect)
	}
}

func TestTheMacLensReadsAProxyPerProtocolWithItsPort(t *testing.T) {
	lens := LensFromSCUtil(SCUtil{Scalars: map[string]string{
		"HTTPEnable":               "1",
		"HTTPProxy":                "p.corp",
		"HTTPPort":                 "8080",
		"HTTPSEnable":              "1",
		"HTTPSProxy":               "s.corp",
		"ProxyAutoConfigURLString": "http://wpad.corp/proxy.pac",
		"ProxyAutoDiscoveryEnable": "1",
	}})

	got, ok := ServerFor(lens.Servers, "http")
	if !ok || got.Address != "p.corp:8080" {
		t.Errorf("http got %+v (found %v), want host and port joined", got, ok)
	}
	// macOS names the protocol an entry is FOR and never how the proxy itself is
	// reached, so claiming a scheme would be inventing one.
	if got.Scheme != "" {
		t.Errorf("http entry claims scheme %q, and this output does not say", got.Scheme)
	}
	got, ok = ServerFor(lens.Servers, "https")
	if !ok || got.Address != "s.corp" {
		t.Errorf("https got %+v (found %v), want the host alone where no port was given", got, ok)
	}
	if lens.PACURL != "http://wpad.corp/proxy.pac" {
		t.Errorf("PACURL is %q, want the script this machine names", lens.PACURL)
	}
	if lens.AutoDetect != On {
		t.Errorf("AutoDetect is %v, and the discovery key says 1", lens.AutoDetect)
	}
}

// TestAProxyTurnedOffIsNotReportedAndAKeyWeNeverSawDoesNotSilenceOne is the
// asymmetry written at LensFromSCUtil, and it is the half worth a test: the
// enable key names are an assessment, so an absent one must not be allowed to
// decide that a machine has no proxy.
func TestAProxyTurnedOffIsNotReportedAndAKeyWeNeverSawDoesNotSilenceOne(t *testing.T) {
	off := LensFromSCUtil(SCUtil{Scalars: map[string]string{
		"HTTPEnable": "0",
		"HTTPProxy":  "p.corp",
	}})
	if off.NamesAProxy() {
		t.Errorf("Servers is %+v, and this machine says the proxy is off", off.Servers)
	}
	if off.Detail == "" {
		t.Error("a proxy is configured and switched off, and the lens says nothing about it")
	}

	noEnableKey := LensFromSCUtil(SCUtil{Scalars: map[string]string{"HTTPProxy": "p.corp"}})
	if !noEnableKey.NamesAProxy() {
		t.Error("a proxy went unreported because a key whose name this project has never measured was absent")
	}

	empty := LensFromSCUtil(SCUtil{Scalars: map[string]string{"HTTPProxy": ""}})
	if empty.NamesAProxy() {
		t.Errorf("Servers is %+v, and a key holding nothing names no proxy", empty.Servers)
	}
}

func TestMacAutoDiscoveryOffIsNotTheSameAsAbsent(t *testing.T) {
	off := LensFromSCUtil(SCUtil{Scalars: map[string]string{"ProxyAutoDiscoveryEnable": "0"}})
	if off.AutoDetect != Off {
		t.Errorf("AutoDetect is %v, and the machine printed the key with a 0 in it", off.AutoDetect)
	}

	absent := LensFromSCUtil(SCUtil{})
	if absent.AutoDetect != Unasked {
		t.Errorf("AutoDetect is %v, and nothing in the output answered that question", absent.AutoDetect)
	}
	if !absent.Read {
		t.Error("an empty dictionary is still a dictionary the command handed over")
	}
}
