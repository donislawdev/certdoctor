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

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

func atNoon() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }

// mint makes one certificate under parent, or a self-signed one when parent is
// nil.
func mint(t *testing.T, name string, serial int64, parentDER []byte, parentKey *ecdsa.PrivateKey, isCA bool) ([]byte, *ecdsa.PrivateKey) {
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

// listing is an answer holding these certificates, verified with these flags.
func listing(f int64, ders ...[]byte) answer {
	return answer{Version: "3.13.15", Flags: flags(f), DER: ders}
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
}

func newWorld(platform string) *world {
	return &world{disk: newDisk(), platform: platform, replies: map[string]probe.Output{}, errs: map[string]error{}}
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
	stores, err := Probe(w.disk.source, w.disk.resolve, w.disk.list, start, w.path, w.platform, atNoon)(
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

// NO PYTHON IS NO ROW, NOT A FAILURE - docs/20 rule 1.
func TestNoPythonIsNoRow(t *testing.T) {
	w := newWorld("linux")
	w.path = []string{abs("/usr/bin")}
	if stores := w.rows(t, nil); stores != nil || len(w.withheld) != 0 {
		t.Errorf("a machine without python gave %v and started %v", stores, w.withheld)
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

// STRICT ONLY TAKES AWAY, so until its rules are applied here a trust is not
// proven and a refusal stands - ADR112 part 3.
func TestStrictLeavesATrustUnprovenAndARefusalStanding(t *testing.T) {
	b := newBench(t)
	store := one(t, "linux", listing(0x88020, b.root), b.chain(), nil)
	if trustOf(store) != "undetermined" || !strings.Contains(store.NotAssessed, "VERIFY_X509_STRICT") {
		t.Errorf("a trust under STRICT came out %s: %q", trustOf(store), store.NotAssessed)
	}
	if got := trustOf(one(t, "linux", listing(0x88020, b.other), b.chain(), nil)); got != "refused unknown_authority" {
		t.Errorf("a refusal under STRICT came out %s", got)
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
	open := func(path string) (io.ReadCloser, error) { return os.Open(path) }
	found := interpreters(open, nil, filepath.SplitList(os.Getenv("PATH")), runtime.GOOS)
	if len(found) == 0 {
		t.Skip("no python on PATH, so there is nothing to ask")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, why := ask(ctx, probe.Without(withheld...), found[0].path)
	if why != "" {
		t.Fatalf("%s did not answer: %s", found[0].path, why)
	}
	if strings.Count(a.Version, ".") != 2 {
		t.Errorf("the version is %q", a.Version)
	}
	t.Logf("%s %s: flags %#x, %d certificates, file %v, directory %q", found[0].path, a.Version, *a.Flags, len(a.DER),
		a.CAFile != nil, a.DirDefault)
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
