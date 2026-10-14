package guard

import (
	"fmt"
	"testing"
)

// unsafeAllowlist names the files allowed to import unsafe, each with the reason
// it needs to - OBS157.
//
// WHY THIS LIST EXISTS, AND WHY ONLY NOW. A file importing unsafe reads memory
// somebody else's API allocated, at offsets this program computes, and a wrong
// offset there does not fail - it reads the wrong bytes and reports them as a
// fact about the machine. For two months a sentence in the project's own notes
// said one package did this. Measured 2026-10-14: four do, and nothing anywhere
// counted them, so the fifth would have arrived the same way the second did -
// without anybody deciding it.
//
// A REASON PER ENTRY RATHER THAN A BARE TRUE, unlike execAllowlist, because the
// four entries are not one rule in four places. Each reads a different
// structure from a different API, and the reason is what a reviewer checks the
// offsets against.
//
// TEST FILES ARE NOT COUNTED, the same choice checkExec makes: a test reading
// what the probe it tests reads is not a second way into production memory.
var unsafeAllowlist = map[string]string{
	"internal/adapter/privilege/privilege_windows.go": "GetTokenInformation writes the elevation flag into a buffer this program sizes",
	"internal/adapter/dns/nameservers_windows.go": "registry values and GetNetworkParams are read into buffers sized by the " +
		"answer of a first call",
	"internal/adapter/proxyconf/proxyconf_windows.go": "WinHTTP returns its proxy configuration as structures and " +
		"strings it allocated and this program frees",
	"internal/adapter/probe/systemstore/probe_windows.go": "crypt32 returns certificates and chain contexts as " +
		"structures it owns, copied out before they are freed",
}

// unsafePackages are the imports able to read memory by address.
var unsafePackages = map[string]bool{
	"unsafe": true,
}

// TestNothingOutsideTheAllowlistReadsForeignMemory is the guard.
func TestNothingOutsideTheAllowlistReadsForeignMemory(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkUnsafe(tr), "unsafe outside the allowlist")
}

// TestTheUnsafeGuardCanFail is the canary. Without it the check above would
// look exactly the same if it had read no files at all.
func TestTheUnsafeGuardCanFail(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "reads_foreign_memory.go", "internal/adapter/probe/planted.go")},
	}
	requireViolation(t, checkUnsafe(planted), "may not import unsafe")
}

// TestAnAllowlistedFileMayImportUnsafe proves the list is consulted rather than
// decorative.
func TestAnAllowlistedFileMayImportUnsafe(t *testing.T) {
	unsafeAllowlist["internal/adapter/probe/planted.go"] = "a planted entry"
	defer delete(unsafeAllowlist, "internal/adapter/probe/planted.go")

	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "reads_foreign_memory.go", "internal/adapter/probe/planted.go")},
	}
	for _, v := range checkUnsafe(planted) {
		t.Errorf("an allowlisted file was reported anyway: %s", v.Detail)
	}
}

// TestATestFileMayImportUnsafe is the exemption pinned in both directions with
// the canary above - the same fixture, only the name differs.
func TestATestFileMayImportUnsafe(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "reads_foreign_memory.go", "internal/adapter/probe/planted_test.go")},
	}
	for _, v := range checkUnsafe(planted) {
		t.Errorf("a test file was reported: %s", v.Detail)
	}
}

// TestTheUnsafeAllowlistNamesFilesThatExistAndSaysWhy closes the ambush OBS63
// records: an entry naming a file that is not there exempts whatever later
// appears under that name, and an entry with no reason is a bare exemption.
func TestTheUnsafeAllowlistNamesFilesThatExistAndSaysWhy(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for rel, why := range unsafeAllowlist {
		if !present[rel] {
			t.Errorf("the unsafe allowlist names %s, which is not in the tree", rel)
		}
		if why == "" {
			t.Errorf("the unsafe allowlist names %s and does not say why", rel)
		}
	}
}

// checkUnsafe reports every non-test file outside the list that imports unsafe.
//
// WHAT IT DOES NOT SEE: whether the offsets in an allowed file are right. That
// is a question about values, answered by each file's own tests against the
// real API - this scanner reads imports.
func checkUnsafe(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || unsafeAllowlist[sf.rel] != "" {
			continue
		}
		for _, imp := range importsOf(sf) {
			if !unsafePackages[imp.path] {
				continue
			}
			violations = append(violations, Violation{sf.rel, imp.line, fmt.Sprintf(
				"%s may not import unsafe - it reads memory by address, where a wrong offset reports the wrong bytes "+
					"as a fact about the machine, so every file doing it is on the list in unsafe_test.go with its reason", sf.rel)})
		}
	}
	return sortViolations(violations)
}
