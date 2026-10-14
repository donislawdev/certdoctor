//go:build windows

package systemstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The values below are wincrypt.h's, and every one of them was exercised on the
// owner's machine before it was written here - probe S20 on 2026-09-23 and
// 2026-10-13, and a one-off probe on 2026-10-14.
//
// THE LIBRARY IS LOADED BY THE STANDARD LIBRARY, FROM THE SYSTEM DIRECTORY.
// syscall declares crypt32.dll and advapi32.dll through its list of system DLLs
// and loads them with LOAD_LIBRARY_SEARCH_SYSTEM32 - read in src/syscall of Go
// 1.27.2 on 2026-10-14 - so a crypt32.dll planted beside certdoctor.exe is not
// the one that answers. That is why this file carries no third copy of the
// systemLibrary function OBS116 is waiting to pull out.
const (
	// storeProviderSystem is CERT_STORE_PROV_SYSTEM_W, and the two locations are
	// CERT_SYSTEM_STORE_CURRENT_USER and CERT_SYSTEM_STORE_LOCAL_MACHINE -
	// documented under CertOpenStore.
	storeProviderSystem = 10
	storeCurrentUser    = 1 << 16
	storeLocalMachine   = 2 << 16
	storeOpenExisting   = 0x00004000
	storeReadOnly       = 0x00008000

	// The two predefined chain engines. CertGetCertificateChain documents both
	// names and says a NULL handle is HCCE_CURRENT_USER - read 2026-10-14 at
	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain
	// The value of HCCE_LOCAL_MACHINE is wincrypt.h's, and it was measured the
	// same day: the call accepted it and answered for the machine's stores.
	engineCurrentUser  syscall.Handle = 0
	engineLocalMachine syscall.Handle = 1

	// noNetwork is the whole of ADR101 in one number - the three flags without
	// which building a chain fetches from the network: CACHE_ONLY_URL_RETRIEVAL,
	// DISABLE_AUTH_ROOT_AUTO_UPDATE and DISABLE_AIA, documented on the same page.
	// Measured 2026-10-14: a certificate naming 127.0.0.1:9 as its issuer's
	// address built in no measurable time, so the address was not tried.
	noNetwork = 0x00000004 | 0x00000100 | 0x00002000

	// serverAuth is the usage the chain is built for, szOID_PKIX_KP_SERVER_AUTH,
	// NUL terminated because crypt32 reads a C string.
	serverAuth = "1.3.6.1.5.5.7.3.1\x00"
)

// engines are the two rows this probe writes - ADR103.
var engines = []struct {
	instance string
	location uint32
	engine   syscall.Handle
}{
	{report.InstanceCurrentUser, storeCurrentUser, engineCurrentUser},
	{report.InstanceLocalMachine, storeLocalMachine, engineLocalMachine},
}

func platformProbe(now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		// ONE CLOCK READING AND ONE LIST FOR BOTH ROWS. Two readings could put the
		// two rows on opposite sides of the freshness line, and the list is a
		// fact about the machine rather than about either engine.
		at := now()
		list := readProgramList()
		stores := make([]report.TrustStore, 0, len(engines))
		for _, e := range engines {
			stores = append(stores, storeFor(ctx, e.instance, e.location, e.engine, chain, list, at))
		}
		return stores, nil
	}
}

// storeFor turns one engine into one row of the matrix.
//
// THE CALLS BELOW CANNOT BE INTERRUPTED, AND THAT IS ACCEPTED RATHER THAN
// MISSED. crypt32 takes no context, and with the network switched off it has
// nothing slow to wait for - measured 2026-10-14, about 90 ms for the first
// chain while the engine starts and under a millisecond after. So the context
// is asked once, before anything is read.
func storeFor(ctx context.Context, instance string, location uint32, engine syscall.Handle,
	chain [][]byte, list programList, at time.Time) report.TrustStore {
	store := report.TrustStore{
		Runtime:   report.RuntimeSystemStore,
		Instance:  instance,
		StoreForm: report.StoreSystem,
		// NOTHING SELECTS A PLATFORM STORE - every program on the machine that
		// asks the platform gets it - so the honest list is the empty one.
		SelectedBy: []string{},
	}
	if err := ctx.Err(); err != nil {
		store.NotAssessed = fmt.Sprintf("this store was not asked: %v", err)
		return store
	}
	if len(chain) == 0 || len(chain[0]) == 0 {
		store.NotAssessed = "no chain was presented, so this store had nothing to judge"
		return store
	}
	anchors, err := countAnchors(location)
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the Root store could not be read: %v", err)
		return store
	}
	b, err := build(engine, chain, at)
	if err != nil {
		store.NotAssessed = fmt.Sprintf("Windows could not build a chain for it: %v", err)
		return store
	}
	judge(&store, b, list, at)
	if store.TrustsPresentedChain != nil {
		// A COUNT TRAVELS ONLY WITH A VERDICT - the contract refuses a row that
		// says it could not assess a store and still counts what is in it.
		store.TrustAnchorCount = anchors
	}
	return store
}

// countAnchors counts the certificates in one location's logical Root store.
//
// THE LOGICAL STORE, NOT THE SUM OF THE PHYSICAL ONES. Measured 2026-09-23: the
// logical Root store holds 91 here because it CONTAINS AuthRoot and Enterprise,
// so adding those up counts twice - and the logical store is the one a chain
// is built against. A certificate seen twice is still counted once.
func countAnchors(location uint32) (int, error) {
	name, err := syscall.UTF16PtrFromString("Root")
	if err != nil {
		return 0, err
	}
	store, err := syscall.CertOpenStore(storeProviderSystem, 0, 0,
		location|storeOpenExisting|storeReadOnly, uintptr(unsafe.Pointer(name)))
	if err != nil {
		return 0, err
	}
	defer func() { _ = syscall.CertCloseStore(store, 0) }()

	seen := map[[sha256.Size]byte]bool{}
	var certificate *syscall.CertContext
	for {
		// A nil return frees the context handed in, so the loop leaks nothing
		// when it ends - and it never leaves early.
		certificate, err = syscall.CertEnumCertificatesInStore(store, certificate)
		if certificate == nil {
			break
		}
		seen[sha256.Sum256(unsafe.Slice(certificate.EncodedCert, certificate.Length))] = true
	}
	if !endOfStore(err) {
		// A walk that stopped for any other reason counted part of the store,
		// and a part reported as the whole is the silence rule 1 forbids.
		return 0, err
	}
	return len(seen), nil
}

// endOfStore reports whether an enumeration stopped because the store ran out.
//
// SOURCE: CertEnumCertificatesInStore, read 2026-10-14 at
// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore
// - CRYPT_E_NOT_FOUND at the end of a store, ERROR_NO_MORE_FILES at the end of a
// collection store, and a logical system store is a collection.
func endOfStore(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	const cryptNotFound syscall.Errno = 0x80092004
	return errno == cryptNotFound || errno == syscall.ERROR_NO_MORE_FILES
}

// build asks one engine what it makes of the presented chain.
//
// THE PRESENTED CERTIFICATES GO IN AS AN ADDITIONAL STORE, the way a TLS client
// hands Windows what the server sent. The time is THIS probe's clock rather than
// the machine's, so the clock that decides "expired" here is the one every
// other row of the matrix was judged with - pTime, documented on the
// CertGetCertificateChain page.
func build(engine syscall.Handle, chain [][]byte, at time.Time) (built, error) {
	presented, err := syscall.CertOpenStore(syscall.CERT_STORE_PROV_MEMORY, 0, 0,
		syscall.CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, 0)
	if err != nil {
		return built{}, err
	}
	defer func() { _ = syscall.CertCloseStore(presented, 0) }()

	leaf, err := add(presented, chain)
	if err != nil {
		return built{}, err
	}
	defer func() { _ = syscall.CertFreeCertificateContext(leaf) }()

	usage := []byte(serverAuth)
	identifiers := []*byte{&usage[0]}
	var para syscall.CertChainPara
	para.Size = uint32(unsafe.Sizeof(para))
	para.RequestedUsage.Type = syscall.USAGE_MATCH_TYPE_OR
	para.RequestedUsage.Usage.Length = uint32(len(identifiers))
	para.RequestedUsage.Usage.UsageIdentifiers = &identifiers[0]

	when := syscall.NsecToFiletime(at.UnixNano())
	var chainContext *syscall.CertChainContext
	err = syscall.CertGetCertificateChain(engine, leaf, &when, presented, &para, noNetwork, 0, &chainContext)
	runtime.KeepAlive(usage)
	runtime.KeepAlive(identifiers)
	if err != nil {
		return built{}, err
	}
	defer syscall.CertFreeCertificateChain(chainContext)
	return copyOut(chainContext), nil
}

// add puts the presented certificates into the memory store and returns the
// leaf as the store holds it.
//
// ONE UNREADABLE INTERMEDIATE IS NOT A REASON TO THROW AWAY THE REST - the same
// rule the shared verifier follows. An unreadable LEAF is, because there is
// then nothing to build a chain for.
func add(store syscall.Handle, chain [][]byte) (*syscall.CertContext, error) {
	var leaf *syscall.CertContext
	for i, der := range chain {
		if len(der) == 0 {
			continue
		}
		created, err := syscall.CertCreateCertificateContext(
			syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &der[0], uint32(len(der)))
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("the presented leaf could not be read by Windows: %w", err)
			}
			continue
		}
		if i == 0 {
			err = syscall.CertAddCertificateContextToStore(store, created, syscall.CERT_STORE_ADD_ALWAYS, &leaf)
		} else {
			err = syscall.CertAddCertificateContextToStore(store, created, syscall.CERT_STORE_ADD_ALWAYS, nil)
		}
		_ = syscall.CertFreeCertificateContext(created)
		if err != nil && i == 0 {
			return nil, fmt.Errorf("the presented leaf could not be held by Windows: %w", err)
		}
	}
	if leaf == nil {
		return nil, errors.New("no leaf was presented")
	}
	return leaf, nil
}

// copyOut takes what judge needs out of the chain context, before the context
// is freed and every pointer in it goes with it.
func copyOut(chainContext *syscall.CertChainContext) built {
	out := built{status: chainContext.TrustStatus.ErrorStatus}
	if chainContext.ChainCount == 0 || chainContext.Chains == nil {
		return out
	}
	simple := unsafe.Slice(chainContext.Chains, chainContext.ChainCount)[0]
	if simple == nil || simple.NumElements == 0 || simple.Elements == nil {
		return out
	}
	for _, e := range unsafe.Slice(simple.Elements, simple.NumElements) {
		if e == nil || e.CertContext == nil {
			continue
		}
		out.elements = append(out.elements, element{
			der:    bytes.Clone(unsafe.Slice(e.CertContext.EncodedCert, e.CertContext.Length)),
			status: e.TrustStatus.ErrorStatus,
		})
	}
	return out
}

// The registry key and the two values read from it.
//
// SOURCE for the key and EncodedCtl: Certificates and trust in Windows, read
// 2026-10-13 at https://learn.microsoft.com/windows-server/identity/ad-cs/certificate-trust
// LastSyncTime is a JUDGEMENT, not a source: its meaning is read off its name and
// checked against this machine, where it held a FILETIME three days old on
// 2026-10-14. Its absence costs only a FAIL turned undetermined.
//
// READABLE WITHOUT ELEVATION, by the key's own access list rather than by a run:
// BUILTIN\Users has read access, read 2026-10-13.
const (
	autoUpdateKey  = `SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate`
	encodedList    = "EncodedCtl"
	lastSynced     = "LastSyncTime"
	registryBinary = 3 // REG_BINARY
)

// listCeiling bounds how much of the registry this program will read for the
// list. Measured 2026-10-13: 206 702 bytes. The ceiling is eighty times that and
// still finite, which is the only property that matters - a value of any size
// would otherwise be allocated on somebody else's say-so.
const listCeiling = 16 << 20

// readProgramList reads this machine's copy of the program list, or says why it
// could not. It never fails the probe: without the list the rows can still be
// written, and every question only the list could settle comes back
// undetermined.
func readProgramList() programList {
	path, err := syscall.UTF16PtrFromString(autoUpdateKey)
	if err != nil {
		return unavailableList(fmt.Sprintf("could not be located (%v)", err))
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_READ, &key); err != nil {
		return unavailableList(fmt.Sprintf("could not be opened in the registry (%v)", err))
	}
	defer func() { _ = syscall.RegCloseKey(key) }()

	der, err := registryValue(key, encodedList)
	if err != nil {
		return unavailableList(fmt.Sprintf("could not be read from the registry (%v)", err))
	}
	var synced time.Time
	if raw, err := registryValue(key, lastSynced); err == nil && len(raw) == 8 {
		filetime := syscall.Filetime{
			LowDateTime:  binary.LittleEndian.Uint32(raw[0:4]),
			HighDateTime: binary.LittleEndian.Uint32(raw[4:8]),
		}
		synced = time.Unix(0, filetime.Nanoseconds()).UTC()
	}
	list, err := parseProgramList(der, synced)
	if err != nil {
		return unavailableList(fmt.Sprintf("could not be parsed (%v)", err))
	}
	return list
}

// registryValue reads one binary value, refusing any other kind and any size
// past the ceiling.
func registryValue(key syscall.Handle, name string) ([]byte, error) {
	value, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var kind, size uint32
	if err := syscall.RegQueryValueEx(key, value, nil, &kind, nil, &size); err != nil {
		return nil, err
	}
	if kind != registryBinary {
		return nil, fmt.Errorf("the value %s is of registry type %d rather than binary", name, kind)
	}
	if size == 0 || size > listCeiling {
		return nil, fmt.Errorf("the value %s holds %d bytes", name, size)
	}
	buffer := make([]byte, size)
	if err := syscall.RegQueryValueEx(key, value, nil, &kind, &buffer[0], &size); err != nil {
		return nil, err
	}
	return buffer[:size], nil
}
