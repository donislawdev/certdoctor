//go:build windows

package dns

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
)

// Enumerate asks Windows twice, because there are two questions and they have
// different answers.
//
// MEASURED BY PROBE S7 ON 2026-08-05, on the owner's machine: the registry
// returned {1.1.1.1, 192.168.1.1, 8.8.8.8} and GetNetworkParams returned
// {1.1.1.1, 8.8.8.8}. Neither is a mistake. The registry holds what is WRITTEN
// DOWN - including adapters that are not up and the separate IPv6 branch - while
// the API reports what the stack WILL USE, where a manually set NameServer beats
// the DHCP one on the same adapter.
//
// If the registry cannot be read the API answer still stands on its own, because
// a machine whose resolvers we can ask about is more useful than a refusal. The
// reverse is not true: without the API list there is nothing to ask.
//
// The file port is unused on this platform and is taken anyway, so that the
// entry point has ONE call to write rather than a build-tagged pair of its own.
func Enumerate(_ file.Source) (Nameservers, error) {
	toAsk, err := networkParamsResolvers()
	if err != nil {
		return Nameservers{}, fmt.Errorf("asking Windows which resolvers the stack uses: %w", err)
	}

	known, registryErr := registryResolvers()
	from := "GetNetworkParams and the registry"
	if registryErr != nil {
		// Named, not swallowed. The allowed set is narrower than it should be
		// when this happens, and a later refusal would otherwise look like a bug
		// in the guard rather than like a registry we could not read.
		from = fmt.Sprintf("GetNetworkParams only, because the registry could not be read: %v", registryErr)
	}

	return Nameservers{ToAsk: toAsk, Known: merged(toAsk, known), From: from}, nil
}

// interfaceKeys are two, because Windows keeps IPv4 and IPv6 configuration in
// separate service branches. Asking only the first gives an answer that is
// correct and incomplete.
var interfaceKeys = []string{
	`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
	`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
}

// globalKeys hold the machine-wide setting. It is set rarely and wins over the
// per-adapter one, so skipping it would give a list that is right for the
// ordinary machine and wrong for the one where somebody set it.
var globalKeys = []string{
	`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
	`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`,
}

// registryResolvers walks everything Windows has written down.
func registryResolvers() ([]string, error) {
	var found []string
	for _, path := range globalKeys {
		found = append(found, valuesUnder(path)...)
	}
	for _, base := range interfaceKeys {
		root, err := openKey(base)
		if err != nil {
			// A branch that is not there is not an error: a machine with no IPv6
			// stack simply has no Tcpip6 interfaces key.
			continue
		}
		guids, err := subKeys(root)
		syscall.RegCloseKey(root)
		if err != nil {
			return found, fmt.Errorf("listing adapters under %s: %w", base, err)
		}
		for _, guid := range guids {
			found = append(found, valuesUnder(base+`\`+guid)...)
		}
	}
	return found, nil
}

// valuesUnder reads both spellings of the setting from one key.
//
// NameServer is what somebody typed and DhcpNameServer is what the network
// handed out. Both are read because the set of places this program may connect
// to has to cover everything written down, not everything currently winning.
func valuesUnder(path string) []string {
	key, err := openKey(path)
	if err != nil {
		return nil
	}
	defer syscall.RegCloseKey(key)

	var out []string
	for _, name := range []string{"NameServer", "DhcpNameServer"} {
		value, err := readString(key, name)
		if err != nil {
			continue
		}
		out = append(out, splitServers(value)...)
	}
	return out
}

// splitServers cuts on every separator Windows uses here. A NameServer set by
// hand is comma separated, DhcpNameServer is space separated, and a semicolon
// turns up as well.
func splitServers(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			out = append(out, field)
		}
	}
	return out
}

func openKey(path string) (syscall.Handle, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var handle syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, name, 0, syscall.KEY_READ, &handle)
	return handle, err
}

// stringKind reports whether a registry value of this type can be read back as
// a string - P3-4.
//
// IT IS ITS OWN FUNCTION SO THAT THE DECISION CAN BE ASSERTED. The read around
// it needs a real registry handle, and a test that had to plant a value of the
// wrong type would be a test that writes to the machine it runs on.
//
// Types from winreg.h, the same source as errNoMoreItems: REG_SZ is 1 and
// REG_EXPAND_SZ is 2. REG_MULTI_SZ is deliberately NOT here: UTF16ToString stops
// at the first NUL, so it would return the first string of several and look like
// a whole answer.
func stringKind(kind uint32) bool {
	return kind == syscall.REG_SZ || kind == syscall.REG_EXPAND_SZ
}

func readString(key syscall.Handle, name string) (string, error) {
	valueName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var kind, size uint32
	if err := syscall.RegQueryValueEx(key, valueName, nil, &kind, nil, &size); err != nil {
		return "", err
	}
	// THE KIND IS READ AND, SINCE P3-4, ALSO CHECKED. It was asked for and
	// thrown away, so a value stored as REG_BINARY or REG_DWORD came back
	// through UTF16ToString as whatever those bytes happen to spell - and this
	// function's answers become resolver addresses and go into the set of places
	// this program may connect to. REG_MULTI_SZ is refused for a subtler reason:
	// UTF16ToString stops at the first NUL, so it would return the first string
	// of several and look like a complete answer.
	//
	// Kinds from winreg.h, the same source as errNoMoreItems below: REG_SZ is 1
	// and REG_EXPAND_SZ is 2.
	if !stringKind(kind) {
		return "", fmt.Errorf("%s is stored as registry type %d rather than as a string, so reading it as one would invent an answer", name, kind)
	}
	buffer := make([]uint16, size/2+1)
	if err := syscall.RegQueryValueEx(key, valueName, nil, &kind, (*byte)(unsafe.Pointer(&buffer[0])), &size); err != nil {
		return "", err
	}
	return syscall.UTF16ToString(buffer), nil
}

// errNoMoreItems is ERROR_NO_MORE_ITEMS.
//
// FOUND WHEN PROBE S7 FIRST COMPILED: the standard library does not carry this
// constant - it lives in x/sys/windows, which is a dependency. It is a small
// thing and it belongs to the answer to "with no dependencies at all": yes, and
// the number has to be written down here with a note saying where it is from.
//
// Source: winerror.h, ERROR_NO_MORE_ITEMS.
const errNoMoreItems = syscall.Errno(259)

func subKeys(key syscall.Handle) ([]string, error) {
	var out []string
	buffer := make([]uint16, 256)
	for index := uint32(0); ; index++ {
		length := uint32(len(buffer))
		err := syscall.RegEnumKeyEx(key, index, &buffer[0], &length, nil, nil, nil, nil)
		if err == errNoMoreItems {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, syscall.UTF16ToString(buffer[:length]))
	}
}

// ipAddrString and fixedInfo are transcribed from iptypes.h.
//
// THIS IS EXACTLY THE COST privilege_windows.go AVOIDED: declaring these structs
// is a claim about the memory layout of somebody else's API, and nobody checks it
// for us. Probe S7 existed to find out whether it was worth paying, and the
// answer was yes - this is the only way to learn which resolvers the stack will
// actually use without adding a dependency.
//
// Lengths from the header: MAX_HOSTNAME_LEN 128, MAX_DOMAIN_NAME_LEN 128,
// MAX_SCOPE_ID_LEN 256, each plus four.
type ipAddrString struct {
	Next    *ipAddrString
	Address [16]byte
	Mask    [16]byte
	Context uint32
}

type fixedInfo struct {
	HostName      [132]byte
	DomainName    [132]byte
	CurrentDNS    *ipAddrString
	DNSServerList ipAddrString
	NodeType      uint32
	ScopeID       [260]byte
	EnableRouting uint32
	EnableProxy   uint32
	EnableDNS     uint32
}

// systemLibrary loads one DLL from the system directory and from nowhere else -
// P3-3.
//
// WHY THIS ONE NEEDS IT AND THE ONE IN THE RENDERER DOES NOT, MEASURED RATHER
// THAN ASSUMED. A bare name goes through the loader's search order, and the
// first directory on that path is the one holding the executable - so a copy
// planted beside certdoctor.exe would be loaded instead. The exception is a
// KnownDLL, which the loader takes from the section the system mapped at boot
// and never searches for. Read from this machine's registry 2026-08-27,
// HKLM SYSTEM CurrentControlSet Control Session Manager KnownDLLs: 37
// entries, kernel32.dll among them and iphlpapi.dll NOT. So the call in the
// renderer is safe as written and this one was not.
//
// THE SYSTEM DIRECTORY IS ASKED FOR RATHER THAN GUESSED. %SystemRoot% is an
// environment variable, and this program is built around not trusting the
// environment to tell the truth about the machine. GetSystemDirectoryW lives in
// kernel32, which the paragraph above establishes is safe to load by name.
//
// WHY NOT golang.org/x/sys/windows, WHICH HAS NewLazySystemDLL. It is a
// dependency, and inviolable rule 5 makes that a decision rather than a
// convenience - for a function this file can write in fifteen lines.
//
// THERE IS A SECOND COPY OF THIS FUNCTION SINCE 2026-09-06, in
// internal/adapter/proxyconf/proxyconf_windows.go, and a change to the rule here
// belongs in both. The duplication is the owner's decision with the alternative
// priced - sharing it costs two entries in the layer guard's intraLayerEdges -
// and it is recorded as OBS116 with the condition for undoing it named: the
// THIRD caller.
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

// networkParamsResolvers asks the stack which resolvers it will use.
//
// KNOWN LIMIT, READ FROM THE DOCUMENTATION AND NOT MEASURED HERE: this API
// reports IPv4 only. The owner's machine has no entry in the Tcpip6 branch, so
// probe S7 could not confirm it either way - and inviolable rule 18 says that
// difference has to be visible rather than smoothed over. The registry side does
// see the IPv6 branch, so the allowed set is not narrowed by this.
func networkParamsResolvers() ([]string, error) {
	library, err := systemLibrary("iphlpapi.dll")
	if err != nil {
		return nil, err
	}
	proc := library.NewProc("GetNetworkParams")

	var size uint32
	// The first call is SUPPOSED to fail and hand back the buffer size. Code 111
	// is ERROR_BUFFER_OVERFLOW and it is the normal path here, not a failure.
	proc.Call(0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil, fmt.Errorf("GetNetworkParams did not report a buffer size")
	}

	// THE SIZE COMES FROM THE OTHER SIDE AND THE CAST BELOW TRUSTS IT COMPLETELY.
	// Everything after this line reads fields at fixed offsets and then walks a
	// linked list through them; a buffer shorter than the structure makes every
	// one of those reads run past its end, and Go says nothing about it because
	// unsafe.Pointer is the point at which it stops looking. Refusing is the only
	// answer available - there is no partial FIXED_INFO to read - and an error
	// here costs the API list while the registry list still stands on its own,
	// which is the fallback this function was already built around.
	if uintptr(size) < unsafe.Sizeof(fixedInfo{}) {
		return nil, fmt.Errorf("GetNetworkParams asked for %d bytes and FIXED_INFO is %d, so the answer was refused rather than read past its end",
			size, unsafe.Sizeof(fixedInfo{}))
	}

	buffer := make([]byte, size)
	result, _, _ := proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if result != 0 {
		return nil, fmt.Errorf("GetNetworkParams returned %d", result)
	}

	// ALIGNMENT IS THE OTHER HALF AND IT IS NOT GUARANTEED BY THE LANGUAGE.
	// fixedInfo contains a pointer, so it wants pointer alignment, and a []byte
	// promises none - Go's allocator gives it in practice for a block this size
	// and that is an implementation detail rather than a contract. It is written
	// down rather than worked around: the fix would be to allocate a fixedInfo
	// and cast the other way, which trades this for having to know the exact
	// layout of a structure whose tail is variable.
	info := (*fixedInfo)(unsafe.Pointer(&buffer[0]))
	var out []string
	for node := &info.DNSServerList; node != nil; node = node.Next {
		if address := cstring(node.Address[:]); address != "" {
			out = append(out, address)
		}
	}
	return out, nil
}

// cstring reads a NUL terminated string out of a fixed array.
func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// NameSourcesPath is empty on this system, and that is the honest value.
//
// Windows has no nsswitch.conf and no equivalent single file naming the order of
// name sources - the order is decided inside the resolver itself. Inventing a
// path here so that both platforms "have one" would put a filename into the
// report that nobody could go and look at.
const NameSourcesPath = ""

// NameSources answers that this system does not record its name sources in a
// file we can read.
//
// IT RETURNS AN UNDECLARED VALUE RATHER THAN AN ERROR, because nothing failed.
// The zero value says Declared is false, which is exactly the fact: no file said
// anything about where names are looked up. An error here would put a failure in
// the report about a system that is working normally.
func NameSources(file.Source) (resolve.NameSources, error) {
	return resolve.NameSources{}, nil
}
