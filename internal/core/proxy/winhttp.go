package proxy

// The two Windows readings live here, in the core, with no build tag on the
// file - the same decision ParseSCUtil one file over rests on, and for the same
// two measured reasons. The mutation register runs on Windows, so a rule behind
// //go:build !windows can never have an entry in it (OBS102); and a coverage
// floor is the lower bound of two platforms, so a rule only one of them compiles
// has half its branches unmeasured (OBS100). What is left for the adapter is
// calling somebody else's API and handing back strings.
//
// SO A WINDOWS-SHAPED TYPE IN A FILE EVERY PLATFORM COMPILES IS THE POINT AND
// NOT AN OVERSIGHT. It costs nothing on Linux and it buys a table test.

// SourceIEProxyConfig and SourceWinHTTPProxyConfig name the calls their lenses
// come from, so that a reader of a report can repeat the reading.
//
// THEY ARE HERE RATHER THAN IN THE ADAPTER because they are text, and because a
// string spelled in two layers is the shape OBS50 measures - it is the same
// argument that put the scutil command line next door.
const (
	SourceIEProxyConfig      = "winhttp.dll!WinHttpGetIEProxyConfigForCurrentUser"
	SourceWinHTTPProxyConfig = "winhttp.dll!WinHttpGetDefaultProxyConfiguration"
)

// Access types, from winhttp.h, the same kind of source as the ERROR_NO_MORE_ITEMS
// constant in internal/adapter/dns. The numbers were read there and confirmed by
// probe S14 on 2026-09-04; the documentation names them without giving values.
//
// SOURCE for which of them can arrive here: Microsoft,
// WinHttpGetDefaultProxyConfiguration, read 2026-09-06 - "If the registry
// contains a list of proxy servers, the dwAccessType member of pProxyInfo is set
// to WINHTTP_ACCESS_TYPE_NAMED_PROXY. Otherwise, it is set to
// WINHTTP_ACCESS_TYPE_NO_PROXY."
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetdefaultproxyconfiguration
//
// TWO VALUES ARE DOCUMENTED AND A THIRD IS HANDLED ANYWAY, which is not the same
// as a branch that decides nothing. A value outside these two is an answer this
// program cannot read, and saying so is inviolable rule 15 - the alternative is
// to pick one of the two and report a machine we did not understand as one we
// did. It is also OBS95 read forwards: a classification listing N cases is the
// place to ask what happens to the N plus first.
const (
	accessTypeNoProxy    uint32 = 1
	accessTypeNamedProxy uint32 = 3
)

// IEProxyConfig is what WinHttpGetIEProxyConfigForCurrentUser returned, taken
// apart but not interpreted.
//
// SOURCE for the shape: Microsoft, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, read
// 2026-09-06 - BOOL fAutoDetect, LPWSTR lpszAutoConfigUrl, LPWSTR lpszProxy,
// LPWSTR lpszProxyBypass. fAutoDetect being TRUE "indicates that the Internet
// Explorer proxy configuration for the current user specifies 'automatically
// detect settings'"; lpszAutoConfigUrl "contains the auto-configuration URL if
// the Internet Explorer proxy configuration for the current user specifies 'Use
// automatic proxy configuration'".
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_current_user_ie_proxy_config
type IEProxyConfig struct {
	// Present says whether the current user has Internet Explorer proxy settings
	// at all.
	//
	// FALSE HERE IS AN ANSWER AND NOT A FAILURE, which is the whole reason the
	// field exists. Microsoft, WinHttpGetIEProxyConfigForCurrentUser, read
	// 2026-09-06, lists ERROR_FILE_NOT_FOUND with the meaning "No Internet
	// Explorer proxy settings can be found" - so the call returning FALSE with
	// that code has told us what the machine holds, and reporting it as a stack
	// we could not read would hide a fact behind our own failure.
	// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetieproxyconfigforcurrentuser
	Present bool
	// AutoDetect is fAutoDetect.
	AutoDetect bool
	// AutoConfigURL is lpszAutoConfigUrl.
	AutoConfigURL string
	// Proxy is lpszProxy, the proxy server list.
	Proxy string
	// ProxyBypass is lpszProxyBypass, the exception list.
	ProxyBypass string
	// ProxyBypassSet says whether lpszProxyBypass was a string at all rather
	// than NULL.
	//
	// ONLY THE BYPASS CARRIES THIS FLAG, and the asymmetry is deliberate. Lens
	// keeps "no exception list" apart from "an exception list excusing nothing",
	// so the distinction has somewhere to go; for the proxy list and the PAC
	// address it does not, because nil Servers and an empty PACURL already say
	// it. A flag with nowhere to be read is a field that goes stale.
	ProxyBypassSet bool
}

// LensFromIEProxyConfig turns that reading into what the WinINET stack says.
func LensFromIEProxyConfig(cfg IEProxyConfig) Lens {
	lens := Lens{
		Stack:   StackWinINET,
		Source:  SourceIEProxyConfig,
		Read:    true,
		Servers: []Server{},
	}
	if !cfg.Present {
		lens.Detail = "this user has no Internet Explorer proxy settings, which is what this call reports rather than a reading that failed"
		return lens
	}

	lens.Servers = ParseServerList(cfg.Proxy)
	lens.Bypass, lens.BypassSet = cfg.ProxyBypass, cfg.ProxyBypassSet
	lens.Rule = RuleWinINET
	lens.PACURL = cfg.AutoConfigURL
	lens.AutoDetect = tristateOf(cfg.AutoDetect)
	if lens.PACURL != "" {
		// OBS111, measured 2026-09-05: writing AutoConfigURL into the registry
		// without touching any switch that enables it makes this call hand the
		// address straight back, and the switch lives in a blob this program
		// does not read. So the sentence says what was found and stops there.
		lens.Detail = "an automatic configuration script is configured here, and this call returns its address whether or not the setting that enables it is on"
	}
	return lens
}

// WinHTTPProxyInfo is what WinHttpGetDefaultProxyConfiguration filled in.
//
// SOURCE for the shape: Microsoft, WINHTTP_PROXY_INFO, read 2026-09-06 - DWORD
// dwAccessType, LPWSTR lpszProxy, LPWSTR lpszProxyBypass.
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_proxy_info
type WinHTTPProxyInfo struct {
	// AccessType is dwAccessType, as the number rather than as a reading of it.
	AccessType uint32
	// Proxy is lpszProxy, the proxy server list.
	Proxy string
	// ProxyBypass is lpszProxyBypass, the exception list.
	ProxyBypass string
	// ProxyBypassSet says whether lpszProxyBypass was a string rather than NULL.
	ProxyBypassSet bool
}

// LensFromWinHTTPProxyInfo turns that reading into what the WinHTTP stack says.
//
// THIS IS THE HALF OF THE MEASUREMENT L2 EXISTS FOR. Measured 2026-09-05 with a
// proxy set in the current user's Internet Settings: the lens above came back
// with the proxy, the exception list and the PAC address, and this one still
// said WINHTTP_ACCESS_TYPE_NO_PROXY. Edge and .NET go through the proxy, a
// service on WinHTTP goes direct, and neither reading is wrong.
func LensFromWinHTTPProxyInfo(info WinHTTPProxyInfo) Lens {
	lens := Lens{
		Stack:   StackWinHTTP,
		Source:  SourceWinHTTPProxyConfig,
		Read:    true,
		Servers: []Server{},
		Bypass:  info.ProxyBypass,
		// The exception list is reported even alongside no proxy, because it is
		// what the machine holds and a list nothing uses today is a list that
		// starts being used the moment somebody sets a proxy.
		BypassSet: info.ProxyBypassSet,
		Rule:      RuleWinHTTP,
		// This structure has no PAC address and no auto-detect field - WinHTTP
		// discovers those separately - so claiming either would be answering a
		// question nobody put to this call.
	}

	switch info.AccessType {
	case accessTypeNamedProxy:
		lens.Servers = ParseServerList(info.Proxy)
	case accessTypeNoProxy:
		lens.Detail = "this machine's default WinHTTP configuration names no proxy, so a service reading it connects direct"
	default:
		return UnreadableLens(StackWinHTTP, SourceWinHTTPProxyConfig,
			"this call reported an access type this program does not know how to read, so what a service on WinHTTP would do here is undetermined")
	}
	return lens
}

// tristateOf turns a flag a stack really has into the two answers that are not
// "this stack was never asked".
func tristateOf(on bool) Tristate {
	if on {
		return On
	}
	return Off
}
