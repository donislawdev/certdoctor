package guard

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The OpenGL binding of the window is a copy of a published module with one
// change (ADR125 point 3), kept in this repository and named by a replace
// directive in go.mod. The published module links opengl32.dll on Windows, so
// the window imports it at load time and the system's copy is mapped before any
// code of ours runs - measured 2026-11-04 on the window built from it. A window
// that starts again with a software renderer needs that name free until it has
// loaded the renderer itself.
//
// A replaced module is one the toolchain no longer checks: go.sum stops
// carrying its sum, and the bytes are whatever this directory holds. So the two
// things the toolchain held are held here instead - that the version copied
// still has the sum written in the note beside the copy, and that the copy is
// that version plus exactly the change the note describes, file by file.
const (
	bindingModule = "github.com/go-gl/gl"
	bindingCopy   = "third_party/go-gl-gl"
	bindingNote   = "PATCH.md"
)

// bindingCarried says whether a file of the published module is one the copy
// keeps: the module's own two files and the two packages the toolkit imports -
// v2.1/gl on every release of the window, v3.1/gles2 on arm64, where go mod
// tidy looks for it too.
func bindingCarried(rel string) bool {
	return rel == "go.mod" || rel == "LICENSE" ||
		strings.HasPrefix(rel, "v2.1/gl/") || strings.HasPrefix(rel, "v3.1/gles2/")
}

// A bindingChange is one piece of the patch: text the published file carries
// exactly once, and what the copy carries in its place.
type bindingChange struct{ file, published, patched string }

// bindingPatch is the whole patch. Two files carry the link directive - the
// generated package.go repeats on a line of its own what procaddr.go says - and
// one function changes how it finds wglGetProcAddress.
var bindingPatch = []bindingChange{
	{"v2.1/gl/procaddr.go", "#cgo !gles2,windows       LDFLAGS: -lopengl32\n", ""},
	{"v2.1/gl/package.go", "// #cgo !gles2,windows       LDFLAGS: -lopengl32\n", ""},
	{"v2.1/gl/procaddr.go", bindingLookupPublished, bindingLookupPatched},
}

// The Windows branch of GlowGetProcAddress as published: wglGetProcAddress is
// called as a linked symbol, which is what names opengl32.dll in the import
// table even without the directive.
const bindingLookupPublished = `	static HMODULE ogl32dll = NULL;
	static void* GlowGetProcAddress(const char* name) {
		void* pf = wglGetProcAddress((LPCSTR) name);
		if (pf) {
			return pf;
		}
		if (ogl32dll == NULL) {
			ogl32dll = LoadLibraryA("opengl32.dll");
		}
		return GetProcAddress(ogl32dll, (LPCSTR) name);
	}
`

// The same branch in the copy: the library is loaded by name at the first call
// and wglGetProcAddress is found in it, so nothing is imported at load time and
// a library of that name loaded before the first call is the one used.
const bindingLookupPatched = `	// PATCHED - see PATCH.md at the root of this copy. wglGetProcAddress is
	// found by name in the library instead of being linked, so the program
	// does not import opengl32.dll when it starts, and the library of that
	// name already loaded at the first call here is the one used.
	typedef PROC (WINAPI *glowWglGetProcAddress)(LPCSTR);
	static HMODULE ogl32dll = NULL;
	static glowWglGetProcAddress wglGetProcAddressPtr = NULL;
	static void* GlowGetProcAddress(const char* name) {
		if (ogl32dll == NULL) {
			ogl32dll = LoadLibraryA("opengl32.dll");
			if (ogl32dll == NULL) {
				return NULL;
			}
			wglGetProcAddressPtr = (glowWglGetProcAddress) GetProcAddress(ogl32dll, "wglGetProcAddress");
		}
		if (wglGetProcAddressPtr != NULL) {
			void* pf = (void*) wglGetProcAddressPtr((LPCSTR) name);
			if (pf) {
				return pf;
			}
		}
		return (void*) GetProcAddress(ogl32dll, (LPCSTR) name);
	}
`

// The version and the sum the note names, each the first of its kind in it.
var (
	bindingNoteVersion = regexp.MustCompile("`(v0\\.0\\.0-[0-9]{14}-[0-9a-f]{12})`")
	bindingNoteSum     = regexp.MustCompile("`(h1:[A-Za-z0-9+/]{43}=)`")
)

// TestTheOpenGLBindingIsThePinnedModulePlusExactlyThePatch is the guard.
//
// The published version is read from the module's zip in the download cache -
// the file whose sum the toolchain checks on download, and the one this test
// sums again itself - rather than from the directory unpacked beside it, which
// is only a convenience: on this machine on 2026-11-04 the unpacked toolkit
// carried sixteen files its own tests had written into it, and go mod verify
// said so. Fetching it needs the toolchain and, on a fresh machine, the
// network, the same as every guard here that asks go list about the modules.
func TestTheOpenGLBindingIsThePinnedModulePlusExactlyThePatch(t *testing.T) {
	root, _, err := findModuleRoot()
	if err != nil {
		t.Fatalf("finding the module root: %v", err)
	}
	version, replacement := bindingRequirement(t, root)
	if replacement != "./"+bindingCopy {
		t.Fatalf("go.mod replaces %s with %q, want ./%s - the copy this guard checks is the one every build of the window takes",
			bindingModule, replacement, bindingCopy)
	}
	note := readText(t, filepath.Join(root, bindingCopy, bindingNote))
	noteVersion, noteSum := firstGroup(bindingNoteVersion, note), firstGroup(bindingNoteSum, note)
	if noteVersion != version {
		t.Fatalf("go.mod requires %s %s and %s/%s names %q - the note has to name the version the copy was taken from",
			bindingModule, version, bindingCopy, bindingNote, noteVersion)
	}
	sum, published := bindingPublished(t, root, version)
	if sum != noteSum {
		t.Fatalf("%s@%s sums to %s and %s/%s says %q.\n"+
			"go.sum stopped carrying this module when it was replaced, so the note is where the pin lives,\n"+
			"and a different sum is different bytes under the same version.", bindingModule, version, sum, bindingCopy, bindingNote, noteSum)
	}
	copied := filesUnder(t, filepath.Join(root, bindingCopy))
	requireNoViolations(t, checkBindingCopy(copied, published), "the copy of the OpenGL binding")
}

// TestTheBindingGuardCanFail plants one gap per question: a byte changed in a
// carried file, a carried file missing, a file the published module does not
// have, and a published file that no longer carries what the patch replaces.
// A copy checked against nothing looks exactly like a copy that matches.
func TestTheBindingGuardCanFail(t *testing.T) {
	published := map[string]string{
		"go.mod":              "module " + bindingModule + "\n",
		"LICENSE":             "MIT\n",
		"v2.1/gl/procaddr.go": "before\n" + bindingPatch[0].published + bindingLookupPublished + "after\n",
		"v2.1/gl/package.go":  "top\n" + bindingPatch[1].published + "rest\n",
		"v3.1/gles2/debug.go": "unchanged\n",
		"v4.6-core/gl/x.go":   "not carried\n",
	}
	faithful := map[string]string{
		"go.mod":              published["go.mod"],
		"LICENSE":             published["LICENSE"],
		"v2.1/gl/procaddr.go": "before\n" + bindingLookupPatched + "after\n",
		"v2.1/gl/package.go":  "top\nrest\n",
		"v3.1/gles2/debug.go": published["v3.1/gles2/debug.go"],
		bindingNote:           "the note is ours\n",
	}
	if v := checkBindingCopy(faithful, published); len(v) != 0 {
		t.Fatalf("a faithful copy was reported: %v", v)
	}

	changed := cloneFiles(faithful)
	changed["v3.1/gles2/debug.go"] = "unchanged, or nearly\n"
	requireViolation(t, checkBindingCopy(changed, published), "differs from the published file plus the patch")

	missing := cloneFiles(faithful)
	delete(missing, "v3.1/gles2/debug.go")
	requireViolation(t, checkBindingCopy(missing, published), "the copy does not")

	stray := cloneFiles(faithful)
	stray["v2.1/gl/extra.go"] = "ours\n"
	requireViolation(t, checkBindingCopy(stray, published), "is not a file of the published module")

	moved := cloneFiles(published)
	moved["v2.1/gl/package.go"] = "top\nrest\n"
	requireViolation(t, checkBindingCopy(faithful, moved), "carries the text the patch replaces 0 times")
}

// TestAModuleSumIsTheToolchainsOwn holds the sum computed here to one the
// toolchain wrote: the zip of goja, the module the command line links, summed
// the way the guard above sums the binding, against goja's line in go.sum. A
// sum computed wrongly would make that guard red on the right bytes - or, worse,
// teach that its red means nothing - so the arithmetic is checked on its own.
func TestAModuleSumIsTheToolchainsOwn(t *testing.T) {
	root, _, err := findModuleRoot()
	if err != nil {
		t.Fatalf("finding the module root: %v", err)
	}
	const module = "github.com/dop251/goja"
	cmd := exec.Command("go", "list", "-m", "-json", module)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -m %s: %v", module, err)
	}
	var m struct{ Version, Sum string }
	if err := json.Unmarshal(out, &m); err != nil || m.Sum == "" {
		t.Fatalf("go list -m %s answered no sum (%v)", module, err)
	}
	sum, _ := moduleZip(t, root, module, m.Version, func(string) bool { return false })
	if sum != m.Sum {
		t.Fatalf("%s@%s sums to %s here and %s in go.sum - the sum this guard computes is not the toolchain's",
			module, m.Version, sum, m.Sum)
	}
}

// checkBindingCopy compares the copy, file by file, with the carried files of
// the published module after the patch. Both are keyed by the path inside the
// module, slash separated.
func checkBindingCopy(copied, published map[string]string) []Violation {
	var violations []Violation
	want := map[string]string{}
	for rel, content := range published {
		if bindingCarried(rel) {
			want[rel] = content
		}
	}
	for _, change := range bindingPatch {
		if n := strings.Count(want[change.file], change.published); n != 1 {
			violations = append(violations, Violation{bindingCopy + "/" + change.file, 0, fmt.Sprintf(
				"the published %s carries the text the patch replaces %d times, want once - the patch no longer "+
					"describes this version, so the copy has to be taken again", change.file, n)})
			continue
		}
		want[change.file] = strings.Replace(want[change.file], change.published, change.patched, 1)
	}
	for rel, content := range want {
		ours, ok := copied[rel]
		if !ok {
			violations = append(violations, Violation{bindingCopy + "/" + rel, 0,
				"the published module carries this file and the copy does not - a package is carried whole or not at all"})
			continue
		}
		if ours != content {
			violations = append(violations, Violation{bindingCopy + "/" + rel, firstDifferingLine(content, ours),
				"differs from the published file plus the patch - the copy is allowed exactly the change " + bindingNote + " describes"})
		}
	}
	for rel := range copied {
		if _, ok := want[rel]; !ok && rel != bindingNote {
			violations = append(violations, Violation{bindingCopy + "/" + rel, 0,
				"is not a file of the published module that the copy carries, nor its note"})
		}
	}
	return sortViolations(violations)
}

// bindingRequirement answers the version go.mod requires and what it replaces
// the module with, as the toolchain reads them.
func bindingRequirement(t *testing.T, root string) (version, replacement string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-json", bindingModule)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -m %s: %v", bindingModule, err)
	}
	var m struct {
		Version string
		Replace *struct{ Path string }
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("reading go list -m %s: %v", bindingModule, err)
	}
	if m.Replace == nil {
		return m.Version, ""
	}
	return m.Version, m.Replace.Path
}

// bindingPublished fetches the published version of the binding and answers
// its sum and the files the copy carries.
func bindingPublished(t *testing.T, root, version string) (string, map[string]string) {
	t.Helper()
	return moduleZip(t, root, bindingModule, version, bindingCarried)
}

// moduleZip fetches module@version and answers the sum of its zip and the
// files keep picks, keyed by the path inside the module.
func moduleZip(t *testing.T, root, module, version string, keep func(rel string) bool) (string, map[string]string) {
	t.Helper()
	cmd := exec.Command("go", "mod", "download", "-json", module+"@"+version)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go mod download %s@%s: %v", module, version, err)
	}
	var d struct{ Zip, Error string }
	if err := json.Unmarshal(out, &d); err != nil || d.Error != "" || d.Zip == "" {
		t.Fatalf("go mod download %s@%s answered no zip (%v %s)", module, version, err, d.Error)
	}
	z, err := zip.OpenReader(d.Zip)
	if err != nil {
		t.Fatalf("opening %s: %v", d.Zip, err)
	}
	defer z.Close()
	prefix := module + "@" + version + "/"
	all := map[string][]byte{}
	files := map[string]string{}
	for _, f := range z.File {
		content, err := readZipped(f)
		if err != nil {
			t.Fatalf("reading %s in %s: %v", f.Name, d.Zip, err)
		}
		all[f.Name] = content
		if rel, ok := strings.CutPrefix(f.Name, prefix); ok && keep(rel) {
			files[rel] = string(content)
		}
	}
	return moduleSum(all), files
}

func readZipped(f *zip.File) ([]byte, error) {
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// moduleSum is the h1: sum the toolchain writes in go.sum - read in
// golang.org/x/mod/sumdb/dirhash, Hash1: the SHA-256 of a summary that lists,
// in sorted order of name, each file's SHA-256 in hexadecimal, two spaces and
// its name, one line per file, encoded in standard base64. Written out here
// because that module is not a dependency of this one, and checked against the
// toolchain's own answer by TestAModuleSumIsTheToolchainsOwn.
func moduleSum(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	summary := sha256.New()
	for _, name := range names {
		fmt.Fprintf(summary, "%x  %s\n", sha256.Sum256(files[name]), name)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(summary.Sum(nil))
}

// filesUnder reads every file below dir, keyed by its slash separated path.
func filesUnder(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(content)
		return nil
	})
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	return files
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func cloneFiles(files map[string]string) map[string]string {
	clone := make(map[string]string, len(files))
	for k, v := range files {
		clone[k] = v
	}
	return clone
}

// firstDifferingLine is the line, counted from one, at which two texts first
// differ.
func firstDifferingLine(a, b string) int {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			return i + 1
		}
	}
	return min(len(al), len(bl)) + 1
}
