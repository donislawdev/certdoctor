package python

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

func atNoon() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }

// mint makes one certificate under parent, or a self-signed one when parent is
// nil.
func mint(t *testing.T, name string, serial int64, parentDER []byte, parentKey *ecdsa.PrivateKey, isCA bool,
	tweak ...func(*x509.Certificate)) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: atNoon().Add(-time.Hour), NotAfter: atNoon().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	if !isCA {
		template.DNSNames = []string{name}
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	for _, apply := range tweak {
		apply(template)
	}
	parent, signer := template, key
	if parentDER != nil {
		issuer, err := x509.ParseCertificate(parentDER)
		if err != nil {
			t.Fatalf("no issuer: %v", err)
		}
		parent, signer = issuer, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("no certificate: %v", err)
	}
	return der, key
}

// bench is one root, the intermediate under it, a leaf under that, and a root
// that signed none of them - the shape of the S28 bench.
type bench struct{ root, inter, leaf, other []byte }

func newBench(t *testing.T) bench {
	rootDER, rootKey := mint(t, "certdoctor test root", 1, nil, nil, true)
	interDER, interKey := mint(t, "certdoctor test intermediate", 2, rootDER, rootKey, true)
	leafDER, _ := mint(t, "partner.test", 3, interDER, interKey, false)
	otherDER, _ := mint(t, "certdoctor unrelated root", 4, nil, nil, true)
	return bench{root: rootDER, inter: interDER, leaf: leafDER, other: otherDER}
}

func (b bench) chain() [][]byte { return [][]byte{b.leaf, b.inter} }

func pemOf(ders ...[]byte) string {
	var s strings.Builder
	for _, der := range ders {
		s.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	}
	return s.String()
}

// abs is a path that is absolute on the machine running the test, so a fixture
// passes filepath.IsAbs wherever CI runs it.
func abs(path string) string {
	path = filepath.FromSlash(path)
	if runtime.GOOS == "windows" {
		return `C:` + path
	}
	return path
}

// disk is the three file ports over maps.
type disk struct {
	files map[string]string
	links map[string]string
	dirs  map[string][]string
	errs  map[string]error
}

func newDisk() *disk {
	return &disk{files: map[string]string{}, links: map[string]string{}, dirs: map[string][]string{}, errs: map[string]error{}}
}

func (d *disk) source(path string) (io.ReadCloser, error) {
	content, ok := d.files[filepath.Clean(path)]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

func (d *disk) resolve(path string) (string, error) {
	if real, ok := d.links[filepath.Clean(path)]; ok {
		return real, nil
	}
	return path, nil
}

func (d *disk) list(dir string) ([]string, error) {
	if err := d.errs[filepath.Clean(dir)]; err != nil {
		return nil, err
	}
	names, ok := d.dirs[filepath.Clean(dir)]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return names, nil
}

// put writes a file, and a directory entry for it when dir is given.
func (d *disk) put(path, content string) { d.files[filepath.Clean(path)] = content }

func (d *disk) entry(dir, name, content string) {
	path := filepath.Join(dir, name)
	d.files[path] = content
	d.dirs[filepath.Clean(dir)] = append(d.dirs[filepath.Clean(dir)], path)
}

// replyOf is what the script prints for this answer.
func replyOf(t *testing.T, a answer) probe.Output {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	return probe.Output{Stdout: string(raw)}
}

func flags(v int64) *int64 { return &v }

func text(s string) *string { return &s }

// listing is an answer holding these certificates, verified with these flags, by
// a Python built with OpenSSL 3.5.4.
func listing(f int64, ders ...[]byte) answer {
	return answer{Version: "3.13.15", OpenSSL: []int{3, 5, 0, 4, 0}, Flags: flags(f), DER: ders}
}

// call is one run the probe asked for.
type call struct {
	binary string
	args   []string
}

// world is a machine for the probe: a disk, PATH, and what each interpreter
// answers.
type world struct {
	disk     *disk
	path     []string
	platform string
	replies  map[string]probe.Output
	errs     map[string]error
	calls    []call
	withheld []string
	// aliases are app execution aliases, path to package. The disk does not
	// hold them, as Windows does not let them be read.
	aliases map[string]string
	// addressed says the target is an IP address.
	addressed bool
}

func newWorld(platform string) *world {
	return &world{disk: newDisk(), platform: platform, replies: map[string]probe.Output{}, errs: map[string]error{},
		aliases: map[string]string{}}
}

// alias is the alias port over the world's aliases.
func (w *world) alias(path string) (string, error) {
	if pkg, ok := w.aliases[filepath.Clean(path)]; ok {
		return pkg, nil
	}
	return "", errors.New("not an app execution alias")
}

// rows runs the probe and checks every row against the contract.
func (w *world) rows(t *testing.T, chain [][]byte) []report.TrustStore {
	t.Helper()
	run := func(_ context.Context, binary string, args ...string) (probe.Output, error) {
		w.calls = append(w.calls, call{binary: binary, args: args})
		return w.replies[binary], w.errs[binary]
	}
	start := func(names ...string) probe.Runner {
		w.withheld = append(w.withheld, names...)
		return run
	}
	stores, err := Probe(w.disk.source, w.disk.resolve, w.alias, w.disk.list, start, w.path, w.platform, w.addressed,
		atNoon)(
		context.Background(), chain)
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	for i := range stores {
		if broken := (report.Finding{Kind: report.FindingTrustStore, Summary: "one row", Source: report.SourceDetected,
			TrustStore: &stores[i]}).Breach(); broken != "" {
			t.Fatalf("row %+v breaks the contract: %s", stores[i], broken)
		}
	}
	return stores
}

// one runs the probe over a single interpreter answering a, on platform.
func one(t *testing.T, platform string, a answer, chain [][]byte, set func(w *world)) report.TrustStore {
	t.Helper()
	w := newWorld(platform)
	interpreter := filepath.Join(abs("/usr/bin"), "python3")
	if platform == "windows" {
		interpreter = filepath.Join(abs("/Python313"), "python.exe")
	}
	w.path = []string{filepath.Dir(interpreter)}
	w.disk.put(interpreter, "ELF")
	w.replies[interpreter] = replyOf(t, a)
	if set != nil {
		set(w)
	}
	stores := w.rows(t, chain)
	if len(stores) != 1 {
		t.Fatalf("got %d rows for one interpreter", len(stores))
	}
	return stores[0]
}

func trustOf(store report.TrustStore) string {
	switch {
	case store.TrustsPresentedChain == nil:
		return "undetermined"
	case *store.TrustsPresentedChain:
		return "trusted"
	}
	return "refused " + string(store.TrustFailure)
}

// ONE INTERPRETER IS ONE ROW, WHATEVER LEADS TO IT - ADR112 part 1, decided by the
// owner. Two names linked to one file are one row, a virtual environment linked
// to that same file is a second, a pip leads to the Python its first line names
// even when no python on PATH is that one, and a command is credited only to what
// its first hit on PATH runs.
func TestEveryInterpreterIsOneRowWhateverLeadsToIt(t *testing.T) {
	b := newBench(t)
	w := newWorld("linux")
	venv, local, usr := abs("/venv/bin"), abs("/usr/local/bin"), abs("/usr/bin")
	w.path = []string{venv, local, usr}
	real := filepath.Join(usr, "python3.13")
	w.disk.put(real, "ELF")
	w.disk.put(filepath.Join(venv, "python"), "ELF")
	w.disk.links[filepath.Join(venv, "python")] = real
	w.disk.put(filepath.Join(abs("/venv"), "pyvenv.cfg"), "home = /usr/bin\n")
	w.disk.put(filepath.Join(local, "pip"), "#!"+filepath.Join(local, "python3.15")+"\nimport sys\n")
	w.disk.put(filepath.Join(local, "python3.15"), "ELF")
	for _, name := range []string{"python", "python3"} {
		w.disk.put(filepath.Join(usr, name), "ELF")
		w.disk.links[filepath.Join(usr, name)] = real
	}
	w.disk.put(filepath.Join(usr, "pip3"), "#! "+filepath.Join(usr, "python3")+" -P\n")
	for _, binary := range []string{filepath.Join(venv, "python"), filepath.Join(local, "python3.15"), filepath.Join(usr, "python")} {
		w.replies[binary] = replyOf(t, listing(0x8000, b.root))
	}

	stores := w.rows(t, b.chain())
	want := []struct {
		instance string
		by       []string
	}{
		{filepath.Join(venv, "python"), []string{"PATH", "python"}},
		{filepath.Join(local, "python3.15"), []string{"PATH", "pip"}},
		{filepath.Join(usr, "python"), []string{"PATH", "python3", "pip3"}},
	}
	if len(stores) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(stores), len(want), stores)
	}
	for i, wanted := range want {
		if stores[i].Instance != wanted.instance || !slices.Equal(stores[i].SelectedBy, wanted.by) {
			t.Errorf("row %d is %s %v, want %s %v", i, stores[i].Instance, stores[i].SelectedBy, wanted.instance, wanted.by)
		}
		if got := trustOf(stores[i]); got != "trusted" {
			t.Errorf("row %d is %s", i, got)
		}
	}
	if len(w.calls) != 3 {
		t.Errorf("asked %d times for three interpreters: %+v", len(w.calls), w.calls)
	}
}

// NO PYTHON IS NO ROW, NOT A FAILURE - docs/20 rule 1 - and nothing is started.
func TestNoPythonIsNoRow(t *testing.T) {
	w := newWorld("linux")
	w.path = []string{abs("/usr/bin")}
	if stores := w.rows(t, nil); stores != nil || len(w.calls) != 0 {
		t.Errorf("a machine without python gave %v and started %v", stores, w.calls)
	}
}

// A pip SCRIPT LEADS TO THE INTERPRETER ITS FIRST LINE NAMES, in the three shapes
// measured or read - and to nothing when that line names no file this program
// can start by its absolute path.
func TestAPipScriptLeadsToTheInterpreterItNames(t *testing.T) {
	b := newBench(t)
	tools, other := abs("/tools"), abs("/opt/bin")
	spaced := filepath.Join(abs("/opt/my python/bin"), "python3")
	cases := []struct {
		name, script, want string
	}{
		{"a path and its options", "#! " + filepath.Join(other, "python3.12") + " -P\n", filepath.Join(other, "python3.12")},
		{"a path and a tab", "#!" + filepath.Join(other, "python3.12") + "\t-s\n", filepath.Join(other, "python3.12")},
		{"env asking PATH", "#!/usr/bin/env python3\n", filepath.Join(other, "python3")},
		{"sh running a quoted path", "#!/bin/sh\n'''exec' \"" + spaced + "\" \"$0\" \"$@\"\n' '''\n", spaced},
		{"sh without the exec line", "#!/bin/sh\necho hello\n", ""},
		{"no first line naming anything", "import sys\n", ""},
		{"a relative interpreter", "#!python3\n", ""},
		{"an interpreter that is not there", "#!" + filepath.Join(other, "python9") + "\n", ""},
		{"env naming nothing on PATH", "#!/usr/bin/env python7\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld("linux")
			w.path = []string{tools}
			w.disk.put(filepath.Join(tools, "pip"), c.script)
			for _, interpreter := range []string{filepath.Join(other, "python3.12"), spaced} {
				w.disk.put(interpreter, "ELF")
			}
			// python3 is on PATH only as what env finds, after the pip - and a file
			// by that bare name exists, so a relative interpreter is refused for
			// being relative rather than for being missing.
			w.path = append(w.path, other)
			w.disk.put(filepath.Join(other, "python3"), "ELF")
			w.disk.put("python3", "ELF")
			for _, interpreter := range []string{filepath.Join(other, "python3.12"), filepath.Join(other, "python3"), spaced} {
				w.replies[interpreter] = replyOf(t, listing(0x8000, b.root))
			}
			stores := w.rows(t, b.chain())
			var reached []string
			for _, store := range stores {
				if slices.Contains(store.SelectedBy, "pip") {
					reached = append(reached, store.Instance)
				}
			}
			switch {
			case c.want == "" && len(reached) != 0:
				t.Errorf("pip was credited to %v", reached)
			case c.want != "" && !slices.Equal(reached, []string{c.want}):
				t.Errorf("pip was credited to %v, want %s", reached, c.want)
			}
		})
	}
}

// launcher is a pip.exe as pip's installer writes it: launcher code holding "#!"
// of its own, the line naming the interpreter, and the script as a zip archive.
func launcher(t *testing.T, line string) string {
	t.Helper()
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	// STORED, NOT DEFLATED, and opening with "#!" of its own, so a line looked
	// for anywhere but before the archive is found in the wrong place.
	w, err := z.CreateHeader(&zip.FileHeader{Name: "__main__.py", Method: zip.Store})
	if err == nil {
		_, err = w.Write([]byte("#!not-the-interpreter\nimport pip\n"))
	}
	if err != nil {
		t.Fatalf("no archive: %v", err)
	}
	if err := z.Close(); err != nil {
		t.Fatalf("no archive: %v", err)
	}
	return "MZ launcher code that parses #! lines\x00\x00" + line + archive.String()
}

// ON WINDOWS THE INSTALL MANAGER'S ALIAS NAMES ITS INTERPRETER BESIDE ITSELF, AND
// A pip.exe NAMES ITS OWN BEFORE ITS ARCHIVE - both measured with probe S28. Each
// command is credited to the first hit on PATH, so the pip.exe of Python 3.12 is
// shadowed by the alias and its interpreter keeps the row without a name.
func TestOnWindowsAliasesAndLaunchersLeadToTheirInterpreter(t *testing.T) {
	b := newBench(t)
	w := newWorld("windows")
	aliases, scripts := abs("/Users/jdoe/AppData/Local/Python/bin"), abs("/Program Files/Python312/Scripts")
	core := abs("/Users/jdoe/AppData/Local/Python/pythoncore-3.15-64/python.exe")
	old := abs("/Program Files/Python312/python.exe")
	w.path = []string{aliases, scripts}
	for _, name := range []string{"python.exe", "pip.exe"} {
		w.disk.put(filepath.Join(aliases, name), "MZ")
		w.disk.put(filepath.Join(aliases, name)+".__target__", core+"\r\n")
	}
	w.disk.put(filepath.Join(scripts, "pip.exe"), launcher(t, "#!\""+old+"\"\r\n"))
	// Older launchers end the line with "\n\r\n" - measured on Python 3.10's.
	w.disk.put(filepath.Join(scripts, "pip3.exe"), launcher(t, "#!\""+old+"\"\n\r\n"))
	w.disk.put(core, "MZ")
	w.disk.put(old, "MZ")
	w.replies[core] = replyOf(t, listing(0x8000, b.root))
	w.replies[old] = replyOf(t, listing(0x8000, b.root))

	stores := w.rows(t, b.chain())
	if len(stores) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(stores), stores)
	}
	if stores[0].Instance != core || !slices.Equal(stores[0].SelectedBy, []string{"PATH", "python", "pip"}) {
		t.Errorf("first row %s %v", stores[0].Instance, stores[0].SelectedBy)
	}
	if stores[1].Instance != old || !slices.Equal(stores[1].SelectedBy, []string{"PATH", "pip3"}) {
		t.Errorf("second row %s %v", stores[1].Instance, stores[1].SelectedBy)
	}
	if stores[0].StoreForm != report.StoreSystem || stores[0].StorePath != "" {
		t.Errorf("python on Windows reads the platform's stores, got %s %q", stores[0].StoreForm, stores[0].StorePath)
	}
}

// The Windows machine the alias tests share: WindowsApps, the install manager's
// own directory, and the runtime both lead to.
var (
	windowsApps   = abs("/Users/jdoe/AppData/Local/Microsoft/WindowsApps")
	managerBin    = abs("/Users/jdoe/AppData/Local/Python/bin")
	managerCore   = abs("/Users/jdoe/AppData/Local/Python/pythoncore-3.15-64/python.exe")
	pythonManager = "PythonSoftwareFoundation.PythonManager_qbz5n2kfra8p0"
)

// started is the answer of an interpreter that says where it was started from.
func started(executable string, a answer) answer {
	a.Executable = executable
	return a
}

// AN APP EXECUTION ALIAS IS ASKED WHICH INTERPRETER IT STARTS, AND THE ANSWER IS
// KEPT - ADR112, decided by the owner. Measured on the owner's machine: the
// install manager's python.exe in WindowsApps started pythoncore-3.15-64, the
// interpreter its own python.exe names in .__target__. So the aliases and the
// manager's files are one row, the interpreter is not asked a third time, and a
// pip alias - never started - still takes its name from the pip behind it.
func TestAnAppAliasIsAskedWhichInterpreterItIs(t *testing.T) {
	b := newBench(t)
	w := newWorld("windows")
	w.path = []string{windowsApps, managerBin}
	for _, name := range []string{"python.exe", "python3.exe", "pip.exe"} {
		w.aliases[filepath.Join(windowsApps, name)] = pythonManager
		w.replies[filepath.Join(windowsApps, name)] = replyOf(t, started(managerCore, listing(0x8000, b.root)))
	}
	for _, name := range []string{"python.exe", "pip.exe"} {
		w.disk.put(filepath.Join(managerBin, name), "MZ")
		w.disk.put(filepath.Join(managerBin, name)+".__target__", managerCore+"\r\n")
	}
	w.disk.put(managerCore, "MZ")

	stores := w.rows(t, b.chain())
	if len(stores) != 1 || stores[0].Instance != managerCore ||
		!slices.Equal(stores[0].SelectedBy, []string{"PATH", "python", "python3"}) {
		t.Fatalf("got %+v", stores)
	}
	if got := trustOf(stores[0]); got != "trusted" {
		t.Errorf("the row is %s (%q)", got, stores[0].NotAssessed)
	}
	var ran []string
	for _, c := range w.calls {
		ran = append(ran, filepath.Base(c.binary))
		if !slices.Equal(c.args, arguments) {
			t.Errorf("%s was started with %v", c.binary, c.args)
		}
	}
	if !slices.Equal(ran, []string{"python.exe", "python3.exe"}) || filepath.Dir(w.calls[0].binary) != windowsApps {
		t.Errorf("started %+v", w.calls)
	}
}

// AN INTERPRETER FOUND BEFORE ITS ALIAS IS NOT ASKED TWICE - the order of PATH
// on the owner's machine, where the install manager's directory comes first.
// A SHADOWED ALIAS OF A PACKAGE ALREADY STARTED IS NOT STARTED - OBS191, the
// cheaper variant the owner chose. Here the manager's launchers come first on
// PATH, so both aliases are shadowed: the first is still started, because
// nothing of its package has been, and the second is not. A WindowsApps PATH
// lists twice is the same case, and its second alias is not started either.
func TestAShadowedAliasOfAPackageAlreadyStartedIsNotStarted(t *testing.T) {
	b := newBench(t)
	w := newWorld("windows")
	w.path = []string{managerBin, windowsApps, windowsApps}
	for _, name := range []string{"python.exe", "python3.exe"} {
		w.disk.put(filepath.Join(managerBin, name), "MZ")
		w.disk.put(filepath.Join(managerBin, name)+".__target__", managerCore)
		w.aliases[filepath.Join(windowsApps, name)] = pythonManager
		w.replies[filepath.Join(windowsApps, name)] = replyOf(t, started(managerCore, listing(0x8000, b.root)))
	}
	w.disk.put(managerCore, "MZ")

	stores := w.rows(t, b.chain())
	if len(stores) != 1 || !slices.Equal(stores[0].SelectedBy, []string{"PATH", "python", "python3"}) {
		t.Fatalf("got %+v", stores)
	}
	if len(w.calls) != 1 || w.calls[0].binary != filepath.Join(windowsApps, "python.exe") {
		t.Errorf("started %+v, want the first alias of the package alone", w.calls)
	}

	// A shadowed alias of a package nothing has started yet is still asked: it
	// may be the only way to a runtime of its own.
	w = newWorld("windows")
	w.path = []string{managerBin, windowsApps}
	w.disk.put(filepath.Join(managerBin, "python3.exe"), "MZ")
	w.disk.put(filepath.Join(managerBin, "python3.exe")+".__target__", managerCore)
	w.disk.put(managerCore, "MZ")
	alias := filepath.Join(windowsApps, "python3.exe")
	w.aliases[alias] = pythonManager
	w.replies[alias] = replyOf(t, started(managerCore, listing(0x8000, b.root)))
	w.rows(t, b.chain())
	if len(w.calls) != 1 || w.calls[0].binary != alias {
		t.Errorf("a shadowed alias of a package not yet started was not asked: %+v", w.calls)
	}
}

func TestAnInterpreterFoundBeforeItsAliasIsAskedOnce(t *testing.T) {
	b := newBench(t)
	w := newWorld("windows")
	w.path = []string{managerBin, windowsApps}
	w.disk.put(filepath.Join(managerBin, "python.exe"), "MZ")
	w.disk.put(filepath.Join(managerBin, "python.exe")+".__target__", managerCore)
	w.disk.put(managerCore, "MZ")
	alias := filepath.Join(windowsApps, "python3.exe")
	w.aliases[alias] = pythonManager
	w.replies[alias] = replyOf(t, started(managerCore, listing(0x8000, b.root)))

	stores := w.rows(t, b.chain())
	if len(stores) != 1 || !slices.Equal(stores[0].SelectedBy, []string{"PATH", "python", "python3"}) {
		t.Fatalf("got %+v", stores)
	}
	if got := trustOf(stores[0]); got != "trusted" {
		t.Errorf("the row is %s (%q)", got, stores[0].NotAssessed)
	}
	if len(w.calls) != 1 || w.calls[0].binary != alias {
		t.Errorf("started %+v", w.calls)
	}
}

// THE STORE'S STAND-IN IS NEVER STARTED, AND IT KEEPS ITS NAME - typing python
// on that machine reaches the stand-in, not the Python later on PATH. The package
// is compared as Windows compares it, without case.
func TestTheStoresStandInIsNeverStarted(t *testing.T) {
	b := newBench(t)
	w := newWorld("windows")
	real := filepath.Join(abs("/Python313"), "python.exe")
	w.path = []string{windowsApps, filepath.Dir(real)}
	w.aliases[filepath.Join(windowsApps, "python.exe")] = strings.ToLower(storeStandIn)
	w.aliases[filepath.Join(windowsApps, "python3.exe")] = storeStandIn
	w.disk.put(real, "MZ")
	w.replies[real] = replyOf(t, listing(0x8000, b.root))

	stores := w.rows(t, b.chain())
	if len(stores) != 1 || stores[0].Instance != real || !slices.Equal(stores[0].SelectedBy, []string{"PATH"}) {
		t.Fatalf("got %+v", stores)
	}
	if len(w.calls) != 1 || w.calls[0].binary != real {
		t.Errorf("started %+v", w.calls)
	}
}

// AN ALIAS THAT DOES NOT SAY WHICH INTERPRETER IT IS GETS ONE ROW PER PACKAGE -
// a failed start says so on the row, and an answer without sys.executable is
// judged as it came. Two packages are two rows.
func TestAnAliasThatDoesNotSayWhichItIsIsOneRowPerPackage(t *testing.T) {
	b := newBench(t)
	w := newWorld("windows")
	w.path = []string{windowsApps, abs("/Other/WindowsApps")}
	failing, silent := filepath.Join(windowsApps, "python.exe"), filepath.Join(abs("/Other/WindowsApps"), "python.exe")
	w.aliases[failing] = pythonManager
	w.aliases[filepath.Join(windowsApps, "python3.exe")] = strings.ToUpper(pythonManager)
	w.replies[failing] = probe.Output{ExitCode: 1}
	w.replies[filepath.Join(windowsApps, "python3.exe")] = probe.Output{ExitCode: 1}
	w.aliases[silent] = "Someone.Python_1234567890abc"
	w.replies[silent] = replyOf(t, started("python.exe", listing(0x8000, b.root)))

	stores := w.rows(t, b.chain())
	if len(stores) != 2 {
		t.Fatalf("got %d rows: %+v", len(stores), stores)
	}
	if stores[0].Instance != failing || !slices.Equal(stores[0].SelectedBy, []string{"PATH", "python", "python3"}) ||
		stores[0].NotAssessed != "python exited with 1 when asked for its certificate list" {
		t.Errorf("the failing alias gave %+v", stores[0])
	}
	if stores[1].Instance != silent || trustOf(stores[1]) != "trusted" {
		t.Errorf("the alias with no executable gave %+v", stores[1])
	}
}

// A LAUNCHER THIS CANNOT READ LEADS NOWHERE rather than to a guess: no archive, an
// archive whose end record points before the file, no line before the archive.
func TestALauncherThatCannotBeReadLeadsNowhere(t *testing.T) {
	good := launcher(t, "#!"+abs("/Python313/python.exe")+"\n")
	end := strings.LastIndex(good, "PK\x05\x06")
	bogus := []byte(good)
	copy(bogus[end+16:], []byte{0xff, 0xff, 0xff, 0x7f})
	for name, content := range map[string]string{
		"no archive":          "MZ #!" + abs("/Python313/python.exe") + "\n",
		"a bogus end record":  string(bogus),
		"a cut end record":    good[:end+10],
		"no line before it":   strings.Replace(good, "#!", "--", -1),
		"an unreadable start": "",
	} {
		t.Run(name, func(t *testing.T) {
			d := newDisk()
			d.put(abs("/Python313/python.exe"), "MZ")
			d.put(abs("/s/pip.exe"), content)
			if got := launcherTarget(d.source, abs("/s/pip.exe")); got != "" && name != "an unreadable start" {
				t.Errorf("got %q", got)
			}
		})
	}
	d := newDisk()
	d.put(abs("/s/pip.exe"), good)
	if got := launcherTarget(d.source, abs("/s/pip.exe")); got != abs("/Python313/python.exe") {
		t.Errorf("the twin read %q", got)
	}
}

// THE ANCHOR RULE IS THE ONE THE INTERPRETER'S FLAGS NAME - ADR112 part 2,
// measured by S28: with PARTIAL_CHAIN an intermediate on the list ends the
// chain, without it only a self-signed certificate does.
func TestTheAnchorRuleFollowsTheFlags(t *testing.T) {
	b := newBench(t)
	cases := []struct {
		name    string
		flags   int64
		list    [][]byte
		want    string
		anchors int
	}{
		{"3.13 and on, an intermediate alone", 0x88000, [][]byte{b.inter, b.other}, "trusted", 2},
		{"3.12 and before, an intermediate alone", 0x8000, [][]byte{b.inter, b.other}, "refused unknown_authority", 1},
		{"3.12 and before, the root", 0x8000, [][]byte{b.root}, "trusted", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := one(t, "linux", listing(c.flags, c.list...), b.chain(), nil)
			if got := trustOf(store); got != c.want || store.TrustAnchorCount != c.anchors {
				t.Errorf("got %s with %d anchors, want %s with %d", got, store.TrustAnchorCount, c.want, c.anchors)
			}
		})
	}
}

// withoutKeyID is a root and the chain a server sends under it, whose
// intermediate carries an authority key identifier with no key identifier in it -
// port 8445 of the S28 bench.
func withoutKeyID(t *testing.T) (root []byte, chain [][]byte) {
	t.Helper()
	rootDER, rootKey := mint(t, "certdoctor test root", 1, nil, nil, true)
	interDER, interKey := mint(t, "certdoctor test intermediate", 2, rootDER, rootKey, true, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: []byte{0x30, 0x00}}}
	})
	leafDER, _ := mint(t, "partner.test", 3, interDER, interKey, false)
	return rootDER, [][]byte{leafDER, interDER}
}

// STRICT ONLY TAKES AWAY - ADR112 part 3. With OpenSSL 3 its rules are applied
// here, so a chain keeping to them is trusted and one breaking them is refused
// with the rule and the certificate - measured by S28, an intermediate without an
// authority key identifier refused by every Python from 3.13 on.
func TestStrictRulesAreAppliedWithOpenSSL3(t *testing.T) {
	b := newBench(t)
	if got := trustOf(one(t, "linux", listing(0x88020, b.root), b.chain(), nil)); got != "trusted" {
		t.Errorf("a chain keeping to the strict rules came out %s", got)
	}
	if got := trustOf(one(t, "linux", listing(0x88020, b.other), b.chain(), nil)); got != "refused unknown_authority" {
		t.Errorf("a refusal under STRICT came out %s", got)
	}

	root, chain := withoutKeyID(t)
	store := one(t, "windows", listing(0x88020, root), chain, nil)
	if trustOf(store) != "refused nonconforming_certificate" || store.Fix != nil ||
		!strings.Contains(store.RefusalDetail, "the intermediate CN=certdoctor test intermediate does not name the key") {
		t.Errorf("an intermediate breaking a strict rule came out %s, %q, fix %v", trustOf(store), store.RefusalDetail, store.Fix)
	}
}

// OPENSSL 1.1.1 HOLDS A CHAIN TO FAR FEWER STRICT RULES than OpenSSL 3, whose
// rules are the ones applied here - so under any other OpenSSL a trust is not
// proven, and a refusal stands.
func TestStrictUnderAnotherOpenSSLLeavesATrustUnproven(t *testing.T) {
	b := newBench(t)
	cases := map[string]struct {
		version []int
		says    string
	}{
		"OpenSSL 1.1.1":       {[]int{1, 1, 1, 20, 15}, "an OpenSSL reporting version 1.1.1.20.15"},
		"no version reported": {nil, "an OpenSSL whose version it did not report"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := listing(0x88020, b.root)
			a.OpenSSL = c.version
			store := one(t, "linux", a, b.chain(), nil)
			if trustOf(store) != "undetermined" || !strings.Contains(store.NotAssessed, c.says) {
				t.Errorf("a trust came out %s: %q", trustOf(store), store.NotAssessed)
			}
			a.DER = [][]byte{b.other}
			if got := trustOf(one(t, "linux", a, b.chain(), nil)); got != "refused unknown_authority" {
				t.Errorf("a refusal came out %s", got)
			}
			// A rule of OpenSSL 3 that another OpenSSL may not have refuses nothing.
			root, chain := withoutKeyID(t)
			a.DER = [][]byte{root}
			if got := trustOf(one(t, "linux", a, chain, nil)); got != "undetermined" {
				t.Errorf("a chain breaking a rule of OpenSSL 3 came out %s", got)
			}
		})
	}
}

// A STRICT REFUSAL BESIDE A DIRECTORY THIS PROGRAM CANNOT READ IS NO REFUSAL,
// and the rule it named goes with it - ADR114. The rule used to stay, the
// contract refused the row, and the orchestrator dropped the whole matrix with it.
func TestAStrictRefusalLeftUnprovenNamesNoRule(t *testing.T) {
	root, chain := withoutKeyID(t)
	a := listing(0x88020, root)
	a.DirEnv = text("certs")
	store := one(t, runtime.GOOS, a, chain, nil)
	if trustOf(store) != "undetermined" || store.RefusalDetail != "" {
		t.Errorf("got %s naming the rule %q", trustOf(store), store.RefusalDetail)
	}
}

// THE HASHED DIRECTORY IS PART OF THE STORE - ADR112 part 2, measured by S28:
// Fedora listed nothing and Python trusted the directory. Only a hashed name
// counts, and a certificate on the list and in the directory counts once.
func TestTheHashedDirectoryIsPartOfTheStore(t *testing.T) {
	b := newBench(t)
	certs := abs("/etc/pki/tls/certs")
	a := listing(0x8000)
	a.DirDefault = certs
	store := one(t, "linux", a, b.chain(), func(w *world) {
		w.disk.entry(certs, "0a1b2c3d.0", pemOf(b.root))
		w.disk.entry(certs, "ca-bundle.crt", pemOf(b.other))
	})
	if trustOf(store) != "trusted" || store.TrustAnchorCount != 1 {
		t.Errorf("got %s with %d anchors, want the hashed root alone", trustOf(store), store.TrustAnchorCount)
	}
	if store.StoreForm != report.StoreSystem || store.StorePath != "" {
		t.Errorf("a python reading no file is on the platform's store, got %s %q", store.StoreForm, store.StorePath)
	}

	refused := one(t, "linux", a, b.chain(), func(w *world) {
		w.disk.entry(certs, "0a1b2c3d.0", pemOf(b.other))
		w.disk.entry(certs, "root.pem", pemOf(b.root))
	})
	if trustOf(refused) != "refused unknown_authority" {
		t.Errorf("a root under a name OpenSSL never opens was counted: %s", trustOf(refused))
	}

	a.DER = [][]byte{b.root}
	twice := one(t, "linux", a, b.chain(), func(w *world) { w.disk.entry(certs, "0a1b2c3d.0", pemOf(b.root)) })
	if twice.TrustAnchorCount != 1 {
		t.Errorf("one root on the list and in the directory counted %d times", twice.TrustAnchorCount)
	}
}

// SSL_CERT_DIR REPLACES THE DEFAULT DIRECTORY, EVEN SET TO NOTHING, and names
// several - by_dir.c, quoted in answer.go. A relative one is no one directory, so
// a refusal beside it is undetermined, and a trust is not.
func TestSSLCertDirReplacesTheDefault(t *testing.T) {
	b := newBench(t)
	host := runtime.GOOS
	first, second, fallback := abs("/a"), abs("/b"), abs("/etc/ssl/certs")
	withRoot := func(dir string) func(w *world) {
		return func(w *world) { w.disk.entry(dir, "0a1b2c3d.0", pemOf(b.root)) }
	}
	cases := []struct {
		name string
		env  *string
		list [][]byte
		set  func(w *world)
		want string
	}{
		{"two directories, the root in the second", text(first + string(os.PathListSeparator) + second), nil,
			withRoot(second), "trusted"},
		{"set to nothing, the root in the default", text(""), [][]byte{b.other}, withRoot(fallback), "refused unknown_authority"},
		{"unset, the root in the default", nil, [][]byte{b.other}, withRoot(fallback), "trusted"},
		{"a relative one beside a refusal", text("certs"), [][]byte{b.other}, nil, "undetermined"},
		{"a relative one beside a trust", text("certs"), [][]byte{b.root}, nil, "trusted"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := listing(0x8000, c.list...)
			a.DirEnv, a.DirDefault = c.env, fallback
			store := one(t, host, a, b.chain(), c.set)
			if got := trustOf(store); got != c.want {
				t.Errorf("got %s, want %s (%q)", got, c.want, store.NotAssessed)
			}
			if c.want == "undetermined" && !strings.Contains(store.NotAssessed, "relative directory") {
				t.Errorf("the row does not say why: %q", store.NotAssessed)
			}
		})
	}
}

// A DIRECTORY THAT CANNOT BE READ LEAVES A REFUSAL UNPROVEN, and a trust the list
// alone reached stands - a directory adds signers and never takes one away.
func TestADirectoryThatCannotBeReadLeavesOnlyARefusalUnproven(t *testing.T) {
	b := newBench(t)
	certs := abs("/etc/ssl/certs")
	denied := func(w *world) { w.disk.errs[filepath.Clean(certs)] = errors.New("permission denied") }
	a := listing(0x8000, b.other)
	a.DirDefault = certs
	store := one(t, "linux", a, b.chain(), denied)
	if trustOf(store) != "undetermined" || !strings.Contains(store.NotAssessed, certs) {
		t.Errorf("got %s: %q", trustOf(store), store.NotAssessed)
	}
	a.DER = [][]byte{b.root}
	if got := trustOf(one(t, "linux", a, b.chain(), denied)); got != "trusted" {
		t.Errorf("a trust from the list alone came out %s", got)
	}
}

// THE FILE IS SPELLED AS THE PLATFORM STORE'S ROW SPELLS IT WHEN IT IS THAT FILE,
// so the two count as one store and hand a person one command - and as Python
// named it otherwise. On Windows the stores are the platform's, and a file
// beside them is named too, so the row counts as a store of its own.
func TestTheFileIsSpelledAsThePlatformStoreSpellsIt(t *testing.T) {
	b := newBench(t)
	const bundle, named = "/etc/ssl/certs/ca-certificates.crt", "/usr/lib/ssl/cert.pem"
	cases := []struct {
		name, platform, cafile string
		link, put              bool
		form                   report.StoreForm
		path                   string
	}{
		{"linux, the platform's bundle under another name", "linux", named, true, true, report.StoreFile, bundle},
		{"linux, a file of its own", "linux", "/home/jdoe/ca.pem", false, true, report.StoreFile, "/home/jdoe/ca.pem"},
		{"linux, no platform bundle to compare with", "linux", named, true, false, report.StoreFile, named},
		{"another platform", "darwin", named, false, true, report.StoreFile, named},
		{"windows, a file beside the stores", "windows", named, false, true, report.StoreSystem, named},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := listing(0x8000, b.root)
			a.CAFile = text(c.cafile)
			store := one(t, c.platform, a, b.chain(), func(w *world) {
				if c.put {
					w.disk.put(bundle, pemOf(b.root))
				}
				if c.link {
					w.disk.links[filepath.Clean(named)] = bundle
				}
			})
			if store.StoreForm != c.form || store.StorePath != c.path {
				t.Errorf("got %s %q, want %s %q", store.StoreForm, store.StorePath, c.form, c.path)
			}
		})
	}
}

// AN ANSWER THAT IS NOT ONE SAYS SO ON ITS OWN, and every row still keeps the
// contract - the answer is input from somebody else's program, rule 35.
func TestAnAnswerThatIsNotOneSaysWhy(t *testing.T) {
	cases := []struct {
		name string
		out  probe.Output
		err  error
		says string
	}{
		{"the run failed", probe.Output{}, errors.New("no such file"), "could not be asked"},
		{"the answer was cut", probe.Output{Stdout: "{", Truncated: true}, nil, "more than this program keeps"},
		{"a Python 2 refusing -I", probe.Output{ExitCode: 2}, nil, "exited with 2"},
		{"not JSON", probe.Output{Stdout: "Python 3.13"}, nil, "not the JSON"},
		{"no flags", probe.Output{Stdout: `{"version":"3.13.15"}`}, nil, "flags are missing"},
		{"no version", probe.Output{Stdout: `{"flags":557088}`}, nil, "flags are missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld("linux")
			interpreter := filepath.Join(abs("/usr/bin"), "python3")
			w.path = []string{filepath.Dir(interpreter)}
			w.disk.put(interpreter, "ELF")
			w.replies[interpreter], w.errs[interpreter] = c.out, c.err
			stores := w.rows(t, nil)
			if len(stores) != 1 || !strings.Contains(stores[0].NotAssessed, c.says) {
				t.Errorf("got %+v, want a row saying %q", stores, c.says)
			}
		})
	}
}

// THE INTERPRETER IS STARTED WITHOUT EXACTLY THE TWO VARIABLES ADR112 part 6
// NAMES, AND RUNS ONLY THE CONSTANT SCRIPT, with -I, -S and -B before it.
func TestPythonStartsWithoutTheNamedVariablesAndRunsOnlyTheScript(t *testing.T) {
	b := newBench(t)
	w := newWorld("linux")
	interpreter := filepath.Join(abs("/usr/bin"), "python3")
	w.path = []string{filepath.Dir(interpreter)}
	w.disk.put(interpreter, "ELF")
	w.replies[interpreter] = replyOf(t, listing(0x8000, b.root))
	w.rows(t, b.chain())
	if !slices.Equal(w.withheld, []string{"SSLKEYLOGFILE", "OPENSSL_CONF"}) {
		t.Errorf("withheld %v", w.withheld)
	}
	if len(w.calls) != 1 || !slices.Equal(w.calls[0].args, []string{"-I", "-S", "-B", "-c", script}) {
		t.Errorf("started %+v", w.calls)
	}
}

// TestTheScriptRunsOnThePythonThisMachineHas asks a real interpreter the
// constant script, through the narrowed runner, and reads the answer the probe
// reads. A script whose output drifted from the struct would pass every test
// above. It is skipped where no Python is on PATH.
func TestTheScriptRunsOnThePythonThisMachineHas(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	open := func(path string) (io.ReadCloser, error) { return os.Open(path) }
	m := machine{source: open, alias: file.LiveAppAlias(), run: probe.Without(withheld...), platform: runtime.GOOS}
	found := m.interpreters(ctx, filepath.SplitList(os.Getenv("PATH")))
	if len(found) == 0 {
		t.Skip("no python on PATH, so there is nothing to ask")
	}
	a, why := found[0].reply, found[0].why
	if !found[0].asked {
		a, why = ask(ctx, m.run, found[0].path)
	}
	if why != "" {
		t.Fatalf("%s did not answer: %s", found[0].path, why)
	}
	if strings.Count(a.Version, ".") != 2 || !filepath.IsAbs(a.Executable) || len(a.OpenSSL) != 5 {
		t.Errorf("the version is %q, the executable %q and OpenSSL %v", a.Version, a.Executable, a.OpenSSL)
	}
	t.Logf("%s %s at %s with OpenSSL %v: flags %#x, %d certificates, file %v, directory %q", found[0].path, a.Version,
		a.Executable, a.OpenSSL, *a.Flags, len(a.DER), a.CAFile != nil, a.DirDefault)
}

// A FILE THAT IS GONE BY THE TIME IT IS READ LEADS NOWHERE - the walk opened it,
// and somebody may remove it before the second look.
func TestAFileGoneBeforeItIsReadLeadsNowhere(t *testing.T) {
	d := newDisk()
	missing := abs("/tools/pip")
	if got := scriptTarget(d.source, nil, missing); got != "" {
		t.Errorf("a script that is gone led to %q", got)
	}
	if got := launcherTarget(d.source, missing+".exe"); got != "" {
		t.Errorf("a launcher that is gone led to %q", got)
	}
	d.put(missing, "")
	if got := scriptTarget(d.source, nil, missing); got != "" {
		t.Errorf("an empty script led to %q", got)
	}
}

// ON WINDOWS SSL_CERT_DIR IS SPLIT ON A SEMICOLON - OpenSSL's LIST_SEPARATOR_CHAR
// there - whatever machine runs this test.
func TestSSLCertDirIsSplitAsWindowsSplitsIt(t *testing.T) {
	b := newBench(t)
	first, second := abs("/a"), abs("/b")
	a := listing(0x8000)
	a.DirEnv = text(first + ";" + second)
	store := one(t, "windows", a, b.chain(), func(w *world) { w.disk.entry(second, "0a1b2c3d.0", pemOf(b.root)) })
	if got := trustOf(store); got != "trusted" {
		t.Errorf("got %s (%q)", got, store.NotAssessed)
	}
}
