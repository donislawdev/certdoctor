//go:build windows

package dns

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
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

func readString(key syscall.Handle, name string) (string, error) {
	valueName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var kind, size uint32
	if err := syscall.RegQueryValueEx(key, valueName, nil, &kind, nil, &size); err != nil {
		return "", err
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

// networkParamsResolvers asks the stack which resolvers it will use.
//
// KNOWN LIMIT, READ FROM THE DOCUMENTATION AND NOT MEASURED HERE: this API
// reports IPv4 only. The owner's machine has no entry in the Tcpip6 branch, so
// probe S7 could not confirm it either way - and inviolable rule 18 says that
// difference has to be visible rather than smoothed over. The registry side does
// see the IPv6 branch, so the allowed set is not narrowed by this.
func networkParamsResolvers() ([]string, error) {
	proc := syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetNetworkParams")

	var size uint32
	// The first call is SUPPOSED to fail and hand back the buffer size. Code 111
	// is ERROR_BUFFER_OVERFLOW and it is the normal path here, not a failure.
	proc.Call(0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil, fmt.Errorf("GetNetworkParams did not report a buffer size")
	}

	buffer := make([]byte, size)
	result, _, _ := proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if result != 0 {
		return nil, fmt.Errorf("GetNetworkParams returned %d", result)
	}

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
