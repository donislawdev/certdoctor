//go:build windows

package proxyconf

import (
	"fmt"
	"syscall"
	"unsafe"

	"context"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// Read asks both places Windows keeps proxy configuration, and they can say
// different things about the same machine.
//
// MEASURED 2026-09-05 BY PROBE S14, WHICH IS WHY THERE ARE TWO CALLS HERE AND
// NOT ONE. With a proxy set in the current user's Internet Settings, the first
// returned it in full - server, exception list and PAC address - and the second
// still reported WINHTTP_ACCESS_TYPE_NO_PROXY. Edge, Chrome and .NET follow the
// first; a service on WinHTTP follows the second; neither machine is
// misconfigured and neither reading is wrong.
//
// NEITHER PORT IS USED HERE AND BOTH ARE TAKEN ANYWAY, so that a caller has one
// call to write rather than a build-tagged pair of its own - the same reason
// dns.Enumerate takes a file source on this platform and ignores it.
func Read(context.Context, Command) []proxy.Lens {
	library, err := systemLibrary("winhttp.dll")
	if err != nil {
		// One failure, both stacks: neither can be read without the library, and
		// saying so twice is better than answering for a stack nobody asked.
		reason := fmt.Sprintf("winhttp.dll could not be loaded from the system directory, so neither of this machine's proxy stacks could be asked: %v", err)
		return []proxy.Lens{
			proxy.UnreadableLens(proxy.StackWinINET, proxy.SourceIEProxyConfig, reason),
			proxy.UnreadableLens(proxy.StackWinHTTP, proxy.SourceWinHTTPProxyConfig, reason),
		}
	}
	return []proxy.Lens{readInternetSettings(library), readDefaultConfiguration(library)}
}

// ieProxyConfig is WINHTTP_CURRENT_USER_IE_PROXY_CONFIG.
//
// TRANSCRIBED FROM THE VENDOR, read 2026-09-06: BOOL fAutoDetect, LPWSTR
// lpszAutoConfigUrl, LPWSTR lpszProxy, LPWSTR lpszProxyBypass.
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_current_user_ie_proxy_config
//
// THE PADDING IS LEFT TO THE COMPILER AND THAT IS DELIBERATE. BOOL is an int32
// and pointers are eight bytes on amd64, so Go inserts four bytes after the
// first field by itself; a hand written padding field would produce two
// paddings and a structure that reads the wrong offsets.
type ieProxyConfig struct {
	autoDetect    int32
	autoConfigURL *uint16
	proxy         *uint16
	proxyBypass   *uint16
}

// winHTTPProxyInfo is WINHTTP_PROXY_INFO: DWORD dwAccessType, LPWSTR lpszProxy,
// LPWSTR lpszProxyBypass. Read at the same source on the same day.
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_proxy_info
type winHTTPProxyInfo struct {
	accessType  uint32
	proxy       *uint16
	proxyBypass *uint16
}

// readInternetSettings asks WinHttpGetIEProxyConfigForCurrentUser.
func readInternetSettings(library *syscall.LazyDLL) proxy.Lens {
	var raw ieProxyConfig
	result, _, callErr := library.NewProc("WinHttpGetIEProxyConfigForCurrentUser").
		Call(uintptr(unsafe.Pointer(&raw)))

	// THE FREEING IS REGISTERED BEFORE ANY BRANCH READS A FIELD, because the
	// vendor requires it and because a panic between here and the end would
	// otherwise leak. Microsoft, same page, read 2026-09-06: "The caller must
	// free the lpszProxy, lpszProxyBypass and lpszAutoConfigUrl strings [...] if
	// they are non-NULL. Use GlobalFree to free the strings."
	defer func() {
		globalFree(raw.autoConfigURL)
		globalFree(raw.proxy)
		globalFree(raw.proxyBypass)
	}()

	if result == 0 {
		if ieSettingsAbsent(uintptr(errnoOf(callErr))) {
			// The machine answered: this user has no such settings.
			return proxy.LensFromIEProxyConfig(proxy.IEProxyConfig{Present: false})
		}
		return proxy.UnreadableLens(proxy.StackWinINET, proxy.SourceIEProxyConfig,
			fmt.Sprintf("the call returned FALSE with %v, so what Edge and .NET would do here is unknown", callErr))
	}

	autoConfigURL, urlWhole := wide(raw.autoConfigURL)
	server, serverWhole := wide(raw.proxy)
	bypass, bypassWhole := wide(raw.proxyBypass)
	if !urlWhole || !serverWhole || !bypassWhole {
		return proxy.UnreadableLens(proxy.StackWinINET, proxy.SourceIEProxyConfig, unterminated)
	}

	return proxy.LensFromIEProxyConfig(proxy.IEProxyConfig{
		Present:        true,
		AutoDetect:     raw.autoDetect != 0,
		AutoConfigURL:  autoConfigURL,
		Proxy:          server,
		ProxyBypass:    bypass,
		ProxyBypassSet: raw.proxyBypass != nil,
	})
}

// readDefaultConfiguration asks WinHttpGetDefaultProxyConfiguration.
//
// SOURCE, read 2026-09-06: it "retrieves the default WinHTTP proxy configuration
// from the registry" and "does not retrieve the configuration for the current
// session", and it "allocates memory for the string members of pProxyInfo. To
// free this memory, call GlobalFree."
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetdefaultproxyconfiguration
func readDefaultConfiguration(library *syscall.LazyDLL) proxy.Lens {
	var raw winHTTPProxyInfo
	result, _, callErr := library.NewProc("WinHttpGetDefaultProxyConfiguration").
		Call(uintptr(unsafe.Pointer(&raw)))

	defer func() {
		globalFree(raw.proxy)
		globalFree(raw.proxyBypass)
	}()

	if result == 0 {
		return proxy.UnreadableLens(proxy.StackWinHTTP, proxy.SourceWinHTTPProxyConfig,
			fmt.Sprintf("the call returned FALSE with %v, so what a service on WinHTTP would do here is unknown", callErr))
	}

	server, serverWhole := wide(raw.proxy)
	bypass, bypassWhole := wide(raw.proxyBypass)
	if !serverWhole || !bypassWhole {
		return proxy.UnreadableLens(proxy.StackWinHTTP, proxy.SourceWinHTTPProxyConfig, unterminated)
	}

	return proxy.LensFromWinHTTPProxyInfo(proxy.WinHTTPProxyInfo{
		AccessType:     raw.accessType,
		Proxy:          server,
		ProxyBypass:    bypass,
		ProxyBypassSet: raw.proxyBypass != nil,
	})
}

// unterminated is what a stack gets when a string somebody else allocated ran
// past the ceiling below without a NUL in it. Reporting the part we read would
// be a value that did less than it promised and looked whole.
const unterminated = "a string this call returned had no terminator within the length this program will read, so what it held was not established"

// stringCeiling bounds how far wide will walk.
//
// IT IS OBLIGATORY RATHER THAN CAREFUL. Without it, a pointer into memory
// holding no NUL turns the loop below into a walk to the first unmapped page.
// The number is absurdly high next to a proxy list and still finite, which is
// the only property that matters.
const stringCeiling = 1 << 16

// wide reads a NUL terminated UTF-16 string from a pointer somebody else's API
// returned, and says whether it found the terminator.
func wide(p *uint16) (string, bool) {
	if p == nil {
		return "", true
	}
	var out []uint16
	for i := 0; i < stringCeiling; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2))
		if c == 0 {
			return syscall.UTF16ToString(out), true
		}
		out = append(out, c)
	}
	return "", false
}

// globalFree hands one string back. A NULL is not passed on: the vendor asks for
// the non-NULL ones and nothing else.
func globalFree(p *uint16) {
	if p == nil {
		return
	}
	syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalFree").Call(uintptr(unsafe.Pointer(p)))
}

// errnoOf pulls the number out of what LazyProc.Call returns. It is the number
// and never the wording - inviolable rule 19, and the wording here is in the
// language of the machine being diagnosed.
func errnoOf(err error) syscall.Errno {
	if errno, ok := err.(syscall.Errno); ok {
		return errno
	}
	return 0
}

// systemLibrary loads one DLL from the system directory and from nowhere else.
//
// THIS IS THE SECOND COPY OF THIS FUNCTION IN THE TREE AND THE DUPLICATION IS A
// DECISION OF THE OWNER'S, TAKEN 2026-09-06 WITH THE ALTERNATIVE PRICED. The
// first is in internal/adapter/dns/nameservers_windows.go. Sharing it means a
// third adapter package imported by two others, which is a sideways edge and
// costs two entries in the layer guard's intraLayerEdges - a standing guard
// widened. This is the shape of OBS50, "one rule in two places", and it is being
// committed with its eyes open: measured the same day, NO mutation entry anchors
// on either copy, so the register damage that shape usually carries does not
// happen here. Recorded as OBS116, with the condition for undoing it named: the
// THIRD caller is where this gets pulled out, because two copies can be read
// side by side and three cannot. A change to the rule belongs in both files.
//
// WHY IT IS NEEDED AT ALL, MEASURED RATHER THAN ASSUMED. A bare name goes
// through the loader's search order, whose first directory is the one holding
// the executable - so a winhttp.dll planted beside certdoctor.exe would be
// loaded instead. The exception is a KnownDLL, which the loader takes from the
// section the system mapped at boot. Read from this machine's registry
// 2026-08-27, HKLM SYSTEM CurrentControlSet Control Session Manager KnownDLLs:
// 37 entries, kernel32.dll among them and winhttp.dll NOT. So the kernel32 call
// in globalFree above is safe as written and this one would not have been.
//
// THE SYSTEM DIRECTORY IS ASKED FOR RATHER THAN GUESSED, because %SystemRoot% is
// an environment variable and this program is built around not trusting the
// environment to tell the truth about the machine.
func systemLibrary(name string) (*syscall.LazyDLL, error) {
	get := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")
	if err := get.Find(); err != nil {
		return nil, fmt.Errorf("GetSystemDirectoryW is not available, so %s could not be loaded from a known place: %w", name, err)
	}
	buffer := make([]uint16, syscall.MAX_PATH)
	written, _, _ := get.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if written == 0 || written >= uintptr(len(buffer)) {
		return nil, fmt.Errorf("the system directory could not be established, so %s was not loaded", name)
	}
	return syscall.NewLazyDLL(syscall.UTF16ToString(buffer[:written]) + `\` + name), nil
}
