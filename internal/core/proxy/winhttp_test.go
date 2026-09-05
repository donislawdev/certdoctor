package proxy

import "testing"

// The dwAccessType values as they arrive on the wire, written out here instead
// of taken from the package's own constants.
//
// THE MUTATION REGISTER FOUND THIS AND NOT A READER. The entry moving
// the package's accessTypeNamedProxy off 3 SURVIVED while these fixtures used it:
// the input moved with the value under test, so the switch went on matching and
// the test went on agreeing. That is OBS48 - a test whose oracle is the thing
// it checks agrees with it whatever it does - and the cure is the one that
// observation prescribes, a second reading written out by hand.
//
// Source for the numbers: winhttp.h, the same reading cited beside the constants
// they stand against, confirmed by probe S14 on 2026-09-04.
const (
	wireAccessTypeNoProxy    uint32 = 1
	wireAccessTypeNamedProxy uint32 = 3
)

// TestAUserWithNoInternetExplorerSettingsIsAnAnswerAndNotAFailure holds the
// distinction the Present field exists for. The call comes back FALSE and the
// machine has told us something.
func TestAUserWithNoInternetExplorerSettingsIsAnAnswerAndNotAFailure(t *testing.T) {
	lens := LensFromIEProxyConfig(IEProxyConfig{Present: false})

	if !lens.Read {
		t.Error("a user with no Internet Explorer settings is being reported as a stack we could not read")
	}
	if lens.Servers == nil || len(lens.Servers) != 0 {
		t.Errorf("Servers is %+v, want an empty slice - the stack answered and names nobody", lens.Servers)
	}
	if lens.Detail == "" {
		t.Error("nothing says why this stack names no proxy, and the reason is not that it holds none")
	}
	if lens.AutoDetect != Unasked {
		t.Errorf("AutoDetect is %v, and a call that reported no settings answered nothing about auto-detect", lens.AutoDetect)
	}
	if lens.BypassSet {
		t.Error("BypassSet is true on a reading that produced no exception list")
	}
}

func TestTheInternetSettingsLensCarriesWhatTheCallReturned(t *testing.T) {
	// The values are the ones probe S14 measured on 2026-09-05 with a proxy set
	// in the current user's Internet Settings, including the <local> macro that
	// came back verbatim - OBS110.
	lens := LensFromIEProxyConfig(IEProxyConfig{
		Present:        true,
		AutoDetect:     true,
		AutoConfigURL:  "http://127.0.0.1:65535/s14.pac",
		Proxy:          "127.0.0.1:65535",
		ProxyBypass:    "<local>;*.s14.invalid",
		ProxyBypassSet: true,
	})

	if lens.Stack != StackWinINET {
		t.Errorf("stack is %q, want %q", lens.Stack, StackWinINET)
	}
	if lens.Source != SourceIEProxyConfig {
		t.Errorf("source is %q, and a reader has to be able to repeat the reading", lens.Source)
	}
	if !lens.NamesAProxy() {
		t.Fatalf("Servers is %+v, and this reading names one", lens.Servers)
	}
	if got, ok := ServerFor(lens.Servers, "https"); !ok || got.Address != "127.0.0.1:65535" {
		t.Errorf("https got %+v (found %v), want the proxy this call returned", got, ok)
	}
	if lens.Bypass != "<local>;*.s14.invalid" || !lens.BypassSet {
		t.Errorf("bypass is %q (set %v), and the macro has to survive the reading untouched", lens.Bypass, lens.BypassSet)
	}
	if lens.Rule != RuleWinINET {
		t.Errorf("rule is %q, and this list is only meaningful read the way Internet Explorer settings hold it", lens.Rule)
	}
	if lens.PACURL != "http://127.0.0.1:65535/s14.pac" {
		t.Errorf("PACURL is %q, want the address the call returned", lens.PACURL)
	}
	if lens.AutoDetect != On {
		t.Errorf("AutoDetect is %v, and fAutoDetect was TRUE", lens.AutoDetect)
	}
}

// TestAnAutoConfigAddressIsReportedAsConfigurationAndNotAsUse is OBS111 held to
// its instruction: this call returns the address whether or not the switch that
// enables it is on, and the switch lives in a blob this program does not read.
func TestAnAutoConfigAddressIsReportedAsConfigurationAndNotAsUse(t *testing.T) {
	with := LensFromIEProxyConfig(IEProxyConfig{Present: true, AutoConfigURL: "http://wpad.corp/proxy.pac"})
	if with.Detail == "" {
		t.Error("a PAC address was reported with nothing saying that its presence is not proof it is in use")
	}
	if with.NamesAProxy() {
		t.Error("a stack holding only a script address is being counted as one that names a proxy")
	}

	without := LensFromIEProxyConfig(IEProxyConfig{Present: true, Proxy: "p.corp:8080"})
	if without.Detail != "" {
		t.Errorf("detail is %q on a reading with no script address at all", without.Detail)
	}
}

func TestAutoDetectOffIsNotTheSameAsNeverAsked(t *testing.T) {
	off := LensFromIEProxyConfig(IEProxyConfig{Present: true, AutoDetect: false})
	if off.AutoDetect != Off {
		t.Errorf("AutoDetect is %v, and this structure has the field and it was FALSE", off.AutoDetect)
	}

	// The other structure has no such field at all, which is the second of the
	// two negatives a boolean would have had to collapse.
	winhttp := LensFromWinHTTPProxyInfo(WinHTTPProxyInfo{AccessType: wireAccessTypeNoProxy})
	if winhttp.AutoDetect != Unasked {
		t.Errorf("AutoDetect is %v, and WINHTTP_PROXY_INFO has no auto-detect member to report", winhttp.AutoDetect)
	}
}

func TestTheDefaultWinHTTPConfigurationIsReadFromItsAccessType(t *testing.T) {
	named := LensFromWinHTTPProxyInfo(WinHTTPProxyInfo{
		AccessType:     wireAccessTypeNamedProxy,
		Proxy:          "http=a.corp:8080;https=b.corp:8080",
		ProxyBypass:    "<local>",
		ProxyBypassSet: true,
	})
	if !named.Read || len(named.Servers) != 2 {
		t.Fatalf("a named proxy reading gave %+v, want the two servers the list holds", named)
	}
	if named.Rule != RuleWinHTTP {
		t.Errorf("rule is %q, and WinHTTP reads its bypass list its own way", named.Rule)
	}
	if named.PACURL != "" {
		t.Errorf("PACURL is %q, and this call knows nothing about automatic configuration", named.PACURL)
	}

	direct := LensFromWinHTTPProxyInfo(WinHTTPProxyInfo{
		AccessType:     wireAccessTypeNoProxy,
		ProxyBypass:    "<local>",
		ProxyBypassSet: true,
	})
	if !direct.Read {
		t.Error("an access type saying no proxy is an answer, not a stack we could not read")
	}
	if direct.NamesAProxy() {
		t.Errorf("Servers is %+v on a reading whose access type says there is no proxy", direct.Servers)
	}
	if direct.Detail == "" {
		t.Error("nothing says what a service reading this configuration would do")
	}
	// The list is reported even with no proxy: it is what the machine holds, and
	// it starts mattering the moment somebody sets one.
	if !direct.BypassSet {
		t.Error("an exception list came back with the reading and the lens dropped it")
	}
}

// TestAnAccessTypeThisProgramCannotReadIsNotGuessedAt is inviolable rule 15 in
// the one arm the vendor says cannot happen. Two values are documented; picking
// one of them for a third would report a machine we did not understand as one
// we did.
func TestAnAccessTypeThisProgramCannotReadIsNotGuessedAt(t *testing.T) {
	lens := LensFromWinHTTPProxyInfo(WinHTTPProxyInfo{AccessType: 99, Proxy: "p.corp:8080"})

	if lens.Read {
		t.Error("an access type outside the two documented ones was read as though it had been understood")
	}
	if lens.Servers != nil {
		t.Errorf("Servers is %+v, and nil is what says nothing was established here", lens.Servers)
	}
	if lens.Detail == "" {
		t.Error("the reading was refused and says nothing about why")
	}
	if lens.Stack != StackWinHTTP || lens.Source != SourceWinHTTPProxyConfig {
		t.Errorf("a refused reading lost track of which call it came from: %+v", lens)
	}
}

// TestTheTwoWindowsStacksCanDisagreeAboutWhetherAProxyExists is the whole
// premise of L2, and the numbers are not invented: measured 2026-09-05 by probe
// S14 with a proxy set in HKCU, the IE call returned it in full and
// WinHttpGetDefaultProxyConfiguration still reported no proxy. Nothing on that
// machine is misconfigured.
func TestTheTwoWindowsStacksCanDisagreeAboutWhetherAProxyExists(t *testing.T) {
	ie := LensFromIEProxyConfig(IEProxyConfig{
		Present:        true,
		Proxy:          "127.0.0.1:65535",
		ProxyBypass:    "<local>;*.s14.invalid",
		ProxyBypassSet: true,
	})
	winhttp := LensFromWinHTTPProxyInfo(WinHTTPProxyInfo{AccessType: wireAccessTypeNoProxy})

	class, compared := Compare([]Lens{ie, winhttp})
	if !compared {
		t.Fatal("two readable stacks were not compared")
	}
	if class != DivergeOneSided {
		t.Errorf("the two stacks were classed %q, want %q - one names a proxy and the other names none",
			class, DivergeOneSided)
	}
}

// TestTwoStacksThatBothNameNothingAreNotAFinding keeps the ordinary machine out
// of the interesting class.
func TestTwoStacksThatBothNameNothingAreNotAFinding(t *testing.T) {
	ie := LensFromIEProxyConfig(IEProxyConfig{Present: false})
	winhttp := LensFromWinHTTPProxyInfo(WinHTTPProxyInfo{AccessType: wireAccessTypeNoProxy})

	class, compared := Compare([]Lens{ie, winhttp})
	if !compared || class != DivergeAgreeDirect {
		t.Errorf("the two stacks were classed %q (compared %v), want %q", class, compared, DivergeAgreeDirect)
	}
}
