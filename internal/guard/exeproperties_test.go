package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

// Both Windows binaries say who made them, what they are and which version.
//
// Windows reads that out of a resource compiled into the exe, and without one
// the Details tab of the file's properties is blank and Task Manager lists the
// bare file name. A tool somebody finds on a build agent months later is the
// case this is for: they have to work out what it is and where it came from.
//
// THE VERSION IS THE HALF THAT DRIFTS. It lives in certdoctor.go and only the
// owner sets it, while the resource is a committed binary made from it by
// .github/scripts/winres.sh. Raising the version without running the script
// gives a program that reports one version and a file that shows another.
//
// So this reads the compiled resources, not winres.json: what ships is what is
// asked, which is also what catches a resource nobody regenerated after the
// JSON changed. CI makes them again and asks for the same bytes - this says
// which word is missing, on every platform the tests run on.
func TestBothWindowsBinariesCarryTheirVersionAndAuthor(t *testing.T) {
	root, _, err := findModuleRoot()
	if err != nil {
		t.Fatal(err)
	}
	version := declaredVersion(t, root)
	for _, binary := range []struct {
		name string
		syso string
	}{
		{"certdoctor.exe", "cmd/certdoctor/rsrc_windows_amd64.syso"},
		{"certdoctor.exe", "cmd/certdoctor/rsrc_windows_arm64.syso"},
		{"certdoctor-gui.exe", "cmd/certdoctor-gui/rsrc_windows_amd64.syso"},
	} {
		t.Run(binary.syso, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(binary.syso)))
			if err != nil {
				t.Fatalf("no compiled resource for %s: %v\n"+
					"Make it with: bash .github/scripts/winres.sh", binary.name, err)
			}
			for _, miss := range missingFromResource(raw, resourceWords(version, binary.name)) {
				t.Errorf("%s does not carry %s.\n"+
					"The resource was not made again after the version or winres.json changed -\n"+
					"run: bash .github/scripts/winres.sh", binary.syso, miss)
			}
		})
	}
}

// TestTheResourceCheckCanFail is the canary. A resource holds its strings as
// UTF-16, so a search for the plain bytes of a word finds nothing in a real
// resource and everything in a file that merely mentions the word - a check
// that cannot fail reads exactly like one that never does.
func TestTheResourceCheckCanFail(t *testing.T) {
	want := resourceWords("9.9.9", "certdoctor.exe")
	if missing := missingFromResource([]byte("9.9.9 DonislawDev certdoctor certdoctor.exe"), want); len(missing) != len(want) {
		t.Errorf("plain bytes satisfied %d of %d words, and a resource stores UTF-16",
			len(want)-len(missing), len(want))
	}
	whole := asUTF16("9.9.9") + asUTF16("DonislawDev") + asUTF16("certdoctor") + asUTF16("certdoctor.exe")
	if missing := missingFromResource([]byte(whole), want); len(missing) != 0 {
		t.Errorf("a resource carrying every word is said to miss %v", missing)
	}
	if missing := missingFromResource([]byte(whole), resourceWords("9.9.10", "certdoctor.exe")); len(missing) != 1 {
		t.Errorf("another version was not found missing: %v", missing)
	}
}

// resourceWords is what a binary's resource has to carry, each with what it is.
func resourceWords(version, fileName string) map[string]string {
	return map[string]string{
		"the version from certdoctor.go": version,
		"the author":                     "DonislawDev",
		"the product name":               "certdoctor",
		"its own file name":              fileName,
	}
}

// missingFromResource names what of want the resource does not carry, sorted
// so a failure reads the same on every run.
func missingFromResource(raw []byte, want map[string]string) []string {
	var missing []string
	for what, word := range want {
		if !strings.Contains(string(raw), asUTF16(word)) {
			missing = append(missing, what+" ("+word+")")
		}
	}
	sort.Strings(missing)
	return missing
}

// versionLine is how certdoctor.go declares the version, and the line
// .github/scripts/winres.sh reads it from.
var versionLine = regexp.MustCompile(`(?m)^const Version = "(.*)"$`)

// declaredVersion reads the version from certdoctor.go as text. The guard does
// not import the module root - only the entry points may - and the script that
// writes the resources reads the same line the same way.
func declaredVersion(t *testing.T, root string) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(root, "certdoctor.go"))
	if err != nil {
		t.Fatal(err)
	}
	found := versionLine.FindAllStringSubmatch(string(source), -1)
	if len(found) != 1 || found[0][1] == "" {
		t.Fatalf("certdoctor.go declares the version %d time(s), and the resources need exactly one", len(found))
	}
	return found[0][1]
}

// asUTF16 is how a Windows resource stores a string: little endian UTF-16,
// which is what every system this ships to uses.
func asUTF16(s string) string {
	var b strings.Builder
	for _, unit := range utf16.Encode([]rune(s)) {
		b.WriteByte(byte(unit))
		b.WriteByte(byte(unit >> 8))
	}
	return b.String()
}
