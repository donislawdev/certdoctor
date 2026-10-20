package probe

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The deferral of ADR110 on a Linux machine made of maps: a disk, the links on
// it, and an rpm that knows a set of files. Every distribution in the table and
// every condition that can fail is asked here, where the rule lives - curl and
// git each pin the words they put around it.

// machine is a Linux machine as the deferral sees it.
type machine struct {
	*disk
	links  map[string]string
	owned  map[string]bool
	rpmErr error
	ran    [][]string
}

func newMachine(id string) *machine {
	m := &machine{disk: newDisk(), links: map[string]string{}, owned: map[string]bool{}}
	if id != "" {
		m.files["/etc/os-release"] = []byte("NAME=Test\nID=" + id + "\n")
	}
	return m
}

func (m *machine) resolve(path string) (string, error) {
	if real, ok := m.links[path]; ok {
		return real, nil
	}
	return path, nil
}

func (m *machine) run(_ context.Context, executable string, args ...string) (Output, error) {
	m.ran = append(m.ran, append([]string{executable}, args...))
	if m.rpmErr != nil {
		return Output{}, m.rpmErr
	}
	if m.owned[args[len(args)-1]] {
		return Output{}, nil
	}
	return Output{ExitCode: 1}, nil
}

func (m *machine) ports() Ports { return Ports{Source: m.source, Resolve: m.resolve, Run: m.run} }

// withBundle puts the platform store's file where the distribution keeps it.
func (m *machine) withBundle(path string) *machine {
	m.files[path] = []byte("a bundle")
	return m
}

const compiledIn = "the bundle it reads is its build-time default"

// deferOn writes a curl row the way the curl probe would, and checks it against
// the contract, so no test below passes on a row the report would refuse.
func deferOn(t *testing.T, m *machine, binary, pkg string) report.TrustStore {
	t.Helper()
	return deferWith(t, m, LibcurlBuilds, "curl", binary, pkg)
}

// deferWith is deferOn for any table and runtime.
func deferWith(t *testing.T, m *machine, builds Builds, runtime, binary, pkg string) report.TrustStore {
	t.Helper()
	// An install found without a binary is named by its directory, the way the
	// git probe names one found only by /etc/gitconfig.
	instance := binary
	if instance == "" {
		instance = "/"
	}
	start := report.TrustStore{Runtime: runtime, Instance: instance, SelectedBy: []string{"PATH"}, StoreForm: report.StoreSystem}
	store := DeferToThePlatform(t.Context(), start, m.ports(), builds, binary, pkg, compiledIn)
	finding := report.Finding{Kind: report.FindingTrustStore, Summary: "a row", Source: report.SourceDetected, TrustStore: &store}
	if broken := finding.Breach(); broken != "" {
		t.Errorf("the contract refuses this row: %s", broken)
	}
	if store.TrustsPresentedChain != nil || store.StorePath != "" || store.StoreForm != report.StoreSystem {
		t.Errorf("got %+v - a row that defers or does not know judges nothing and names no file", store)
	}
	return store
}

func defersTo(store report.TrustStore, instance string) bool {
	return store.DefersTo != nil && store.DefersTo.Runtime == report.RuntimeSystemStore &&
		store.DefersTo.Instance == instance && strings.Contains(store.NotAssessed, "system-store "+instance)
}

// undeterminedBecause says the row kept its own sentence and said why it could
// not defer after it.
func undeterminedBecause(store report.TrustStore, why string) bool {
	return store.DefersTo == nil && store.NotAssessed == compiledIn+" - "+why
}

// EVERY DISTRIBUTION IN THE TABLE DEFERS through its own package database, to
// the instance the platform store's row carries for it.
func TestADistributionsOwnBuildDefersToThePlatformStore(t *testing.T) {
	debian := newMachine("debian").withBundle("/etc/ssl/certs/ca-certificates.crt")
	debian.files["/var/lib/dpkg/info/curl.list"] = []byte("/.\n/usr\n/usr/bin\n/usr/bin/curl\n")
	if store := deferOn(t, debian, "/usr/bin/curl", "curl"); !defersTo(store, "debian") {
		t.Errorf("debian: got %+v", store)
	}

	ubuntu := newMachine("ubuntu").withBundle("/etc/ssl/certs/ca-certificates.crt")
	ubuntu.files["/var/lib/dpkg/info/git.list"] = []byte("/usr/bin/git\n")
	if store := deferOn(t, ubuntu, "/usr/bin/git", "git"); !defersTo(store, "ubuntu") {
		t.Errorf("ubuntu: got %+v", store)
	}

	alpine := newMachine("alpine").withBundle("/etc/ssl/certs/ca-certificates.crt")
	alpine.files["/lib/apk/db/installed"] = []byte("C:Q1abc\nP:curl\nV:8.22.0-r0\nF:usr\nF:usr/bin\nR:curl\nR:wcurl\n\n" +
		"C:Q1def\nP:git\nF:usr/bin\nR:git\na:0:0:755\n")
	if store := deferOn(t, alpine, "/usr/bin/git", "git"); !defersTo(store, "alpine") {
		t.Errorf("alpine: got %+v", store)
	}

	// THE RED HAT FAMILY: the name Go finds first is a link to the other one,
	// measured in RHEL 9.7, so both names are the store's file.
	rhel := newMachine("rhel").withBundle("/etc/pki/tls/certs/ca-bundle.crt").
		withBundle("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
	rhel.links["/etc/pki/tls/certs/ca-bundle.crt"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	rhel.owned["/usr/bin/curl"] = true
	if store := deferOn(t, rhel, "/usr/bin/curl", "curl"); !defersTo(store, "rhel") {
		t.Errorf("rhel: got %+v", store)
	}
	if want := [][]string{{"/usr/bin/rpm", "-qf", "--", "/usr/bin/curl"}}; !slices.EqualFunc(rhel.ran, want, slices.Equal) {
		t.Errorf("rpm was asked %v, want %v - the exit code of one query about the binary", rhel.ran, want)
	}
}

// THE TABLE IS THE DECISION, pinned: eight distributions, each with the files
// its recipe names and the database that records its packages.
func TestTheTableIsTheOneWithSources(t *testing.T) {
	want := map[string]string{
		"debian": "dpkg", "ubuntu": "dpkg", "alpine": "apk",
		"rhel": "rpm", "centos": "rpm", "rocky": "rpm", "almalinux": "rpm", "fedora": "rpm",
	}
	if len(LibcurlBuilds) != len(want) {
		t.Errorf("%d distributions, want %d", len(LibcurlBuilds), len(want))
	}
	for id, db := range want {
		build := LibcurlBuilds[id]
		if build.packages.name != db {
			t.Errorf("%s: packages read by %q, want %q", id, build.packages.name, db)
		}
		bundles := []string{"/etc/ssl/certs/ca-certificates.crt"}
		if db == "rpm" {
			bundles = []string{"/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"}
		}
		if !slices.Equal(build.bundles, bundles) {
			t.Errorf("%s: bundles %v, want %v", id, build.bundles, bundles)
		}
	}
	if got := knownDistributions(LibcurlBuilds); got != "almalinux, alpine, centos, debian, fedora, rhel, rocky and ubuntu" {
		t.Errorf("the sentence names %q", got)
	}
}

// A DISTRIBUTION OUTSIDE THE TABLE IS NAMED, and so is the default a machine
// without os-release gets - ID_LIKE is never read.
func TestADistributionOutsideTheTableDoesNotDefer(t *testing.T) {
	arch := newMachine("arch").withBundle("/etc/ssl/certs/ca-certificates.crt")
	arch.files["/etc/os-release"] = []byte("ID=arch\nID_LIKE=debian\n")
	store := deferOn(t, arch, "/usr/bin/curl", "curl")
	want := `which file that is, this program knows only for the packages of almalinux, alpine, centos, debian, ` +
		`fedora, rhel, rocky and ubuntu, and this distribution is "arch"`
	if !undeterminedBecause(store, want) {
		t.Errorf("got %q", store.NotAssessed)
	}
	if store := deferOn(t, newMachine(""), "/usr/bin/curl", "curl"); !strings.HasSuffix(store.NotAssessed, `is "linux"`) {
		t.Errorf("no os-release: got %q", store.NotAssessed)
	}
}

// A BINARY THE DISTRIBUTION'S DATABASE DOES NOT KNOW IS NOT ITS BUILD, in each
// of the three databases - measured by S26: /usr/bin is not "from a package".
func TestABinaryNoPackageInstalledDoesNotDefer(t *testing.T) {
	debian := newMachine("debian").withBundle("/etc/ssl/certs/ca-certificates.crt")
	debian.files["/var/lib/dpkg/info/curl.list"] = []byte("/usr/bin/curl\n")
	store := deferOn(t, debian, "/usr/local/bin/curl", "curl")
	if !undeterminedBecause(store, "dpkg does not list /usr/local/bin/curl among the files of the curl package, "+
		"so it is not known to be debian's own build") {
		t.Errorf("dpkg: got %q", store.NotAssessed)
	}
	// A package that is not installed has no list, and that is a no, not an error.
	if store := deferOn(t, newMachine("debian"), "/usr/bin/git", "git"); !strings.Contains(store.NotAssessed, "dpkg does not list") {
		t.Errorf("no list: got %q", store.NotAssessed)
	}

	rhel := newMachine("rhel").withBundle("/etc/pki/tls/certs/ca-bundle.crt")
	store = deferOn(t, rhel, "/opt/curl/bin/curl", "curl")
	if !undeterminedBecause(store, "rpm -qf does not know /opt/curl/bin/curl as a file of any package, so it is not "+
		"known to be rhel's own build") {
		t.Errorf("rpm: got %q", store.NotAssessed)
	}
}

// APK'S RECORDS ARE READ AS RECORDS: the file has to be under the right
// directory, in the right package, and a blank line ends a package.
func TestApksRecordsAreReadAsRecords(t *testing.T) {
	cases := []struct {
		name, db string
		owned    bool
	}{
		{name: "the package's own file", db: "P:curl\nF:usr/bin\nR:curl\n", owned: true},
		{name: "a later directory of the same package", db: "P:curl\nF:usr\nR:curl\nF:usr/bin\nR:curl\n", owned: true},
		{name: "the same name in another directory", db: "P:curl\nF:usr/local/bin\nR:curl\n"},
		{name: "the same file in another package", db: "P:curl-static\nF:usr/bin\nR:curl\n"},
		{name: "another package's directory does not carry into this one", db: "P:other\nF:usr/bin\nR:x\nP:curl\nR:curl\n"},
		{name: "nothing carries past a blank line", db: "P:curl\nF:usr/bin\n\nR:curl\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMachine("alpine")
			m.files["/lib/apk/db/installed"] = []byte(c.db)
			owned, err := apkOwns(t.Context(), m.ports(), "/usr/bin/curl", "curl")
			if owned != c.owned || err != nil {
				t.Errorf("got %v %v, want %v", owned, err, c.owned)
			}
		})
	}
}

// THE BINARY IS ASKED ABOUT AS FOUND AND AS ITS LINKS LEAD - measured in Debian
// 13, where /bin links to usr/bin and dpkg knows only /usr/bin/curl.
func TestABinaryReachedThroughALinkIsAskedAboutWhereItLeads(t *testing.T) {
	debian := newMachine("debian").withBundle("/etc/ssl/certs/ca-certificates.crt")
	debian.files["/var/lib/dpkg/info/curl.list"] = []byte("/usr/bin/curl\n")
	debian.links["/bin/curl"] = "/usr/bin/curl"
	if store := deferOn(t, debian, "/bin/curl", "curl"); !defersTo(store, "debian") {
		t.Errorf("got %+v", store)
	}

	rhel := newMachine("rhel").withBundle("/etc/pki/tls/certs/ca-bundle.crt")
	rhel.links["/etc/pki/tls/certs/ca-bundle.crt"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	rhel.links["/usr/local/bin/curl"] = "/usr/bin/curl"
	rhel.owned["/usr/bin/curl"] = true
	if store := deferOn(t, rhel, "/usr/local/bin/curl", "curl"); !defersTo(store, "rhel") || len(rhel.ran) != 2 {
		t.Errorf("got %+v after asking rpm %v", store, rhel.ran)
	}
}

// A DATABASE THAT COULD NOT BE ASKED LEAVES THE QUESTION OPEN, with the reason -
// never read as a binary nobody installed.
func TestADatabaseThatCouldNotBeAskedSaysSo(t *testing.T) {
	debian := newMachine("debian").withBundle("/etc/ssl/certs/ca-certificates.crt")
	debian.errs["/var/lib/dpkg/info/curl.list"] = errors.New("denied")
	if store := deferOn(t, debian, "/usr/bin/curl", "curl"); !undeterminedBecause(store,
		"whether /usr/bin/curl is debian's own build was not established: denied") {
		t.Errorf("dpkg: got %q", store.NotAssessed)
	}

	// A line past what the scanner holds cuts the list short, and a list cut
	// short cannot say a file is missing from it.
	alpine := newMachine("alpine").withBundle("/etc/ssl/certs/ca-certificates.crt")
	alpine.files["/lib/apk/db/installed"] = []byte("P:curl\nD:" + strings.Repeat("x", 70000) + "\nF:usr/bin\nR:curl\n")
	if store := deferOn(t, alpine, "/usr/bin/curl", "curl"); !strings.Contains(store.NotAssessed, "was not established: ") {
		t.Errorf("apk: got %q", store.NotAssessed)
	}

	rhel := newMachine("rhel").withBundle("/etc/pki/tls/certs/ca-bundle.crt")
	rhel.links["/usr/local/bin/curl"] = "/usr/bin/curl"
	rhel.rpmErr = errors.New("no such file")
	store := deferOn(t, rhel, "/usr/local/bin/curl", "curl")
	if !undeterminedBecause(store, "whether /usr/local/bin/curl is rhel's own build was not established: no such file") ||
		len(rhel.ran) != 1 {
		t.Errorf("rpm: got %q after asking %v - an error ends the asking", store.NotAssessed, rhel.ran)
	}
}

// AN INSTALL FOUND WITHOUT A BINARY HAS NO PACKAGE TO ASK ABOUT.
func TestAnInstallWithoutABinaryDoesNotDefer(t *testing.T) {
	m := newMachine("debian").withBundle("/etc/ssl/certs/ca-certificates.crt")
	if store := deferOn(t, m, "", "git"); !undeterminedBecause(store,
		"no git binary was found for this install, so whether it is debian's own build was not established") {
		t.Errorf("got %q", store.NotAssessed)
	}
}

// THE FILE HAS TO BE THE PLATFORM STORE'S FILE - ADR110, condition 3. Another
// file first on Go's list, no file at all, or one of the family's two names
// leading somewhere else each keep the row from deferring, named.
func TestTheBuildsFileHasToBeThePlatformStoresFile(t *testing.T) {
	debian := newMachine("debian").withBundle("/etc/ssl/cert.pem")
	debian.files["/var/lib/dpkg/info/curl.list"] = []byte("/usr/bin/curl\n")
	store := deferOn(t, debian, "/usr/bin/curl", "curl")
	if !undeterminedBecause(store, "debian's packages are built to read /etc/ssl/certs/ca-certificates.crt, and the "+
		"platform's own store here is /etc/ssl/cert.pem, which is not the same file as /etc/ssl/certs/ca-certificates.crt") {
		t.Errorf("another file: got %q", store.NotAssessed)
	}

	delete(debian.files, "/etc/ssl/cert.pem")
	store = deferOn(t, debian, "/usr/bin/curl", "curl")
	if !undeterminedBecause(store, "debian's packages are built to read /etc/ssl/certs/ca-certificates.crt, and no CA "+
		"bundle is at any of the places the platform's own store is looked for") {
		t.Errorf("no file: got %q", store.NotAssessed)
	}

	// A BROKEN LINK: both names exist and are two files, so which one this
	// release reads is not known.
	rhel := newMachine("rhel").withBundle("/etc/pki/tls/certs/ca-bundle.crt").
		withBundle("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
	rhel.owned["/usr/bin/curl"] = true
	store = deferOn(t, rhel, "/usr/bin/curl", "curl")
	if !strings.HasSuffix(store.NotAssessed, "the platform's own store here is /etc/pki/tls/certs/ca-bundle.crt, "+
		"which is not the same file as /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem") || store.DefersTo != nil {
		t.Errorf("broken link: got %q", store.NotAssessed)
	}
	if !strings.Contains(store.NotAssessed, "rhel's packages are built to read /etc/pki/tls/certs/ca-bundle.crt or "+
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem") {
		t.Errorf("the sentence does not name both files the family builds to: %q", store.NotAssessed)
	}

	// THE EXTRACTED FILE ALONE, with the older name missing, is not enough
	// either - a release built to the older name would read nothing.
	fedora := newMachine("fedora").withBundle("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
	fedora.owned["/usr/bin/curl"] = true
	if store := deferOn(t, fedora, "/usr/bin/curl", "curl"); store.DefersTo != nil ||
		!strings.HasSuffix(store.NotAssessed, "which is not the same file as /etc/pki/tls/certs/ca-bundle.crt") {
		t.Errorf("one name missing: got %q", store.NotAssessed)
	}
}

// OPENSSL'S DEFAULT FILE IS A TABLE OF ITS OWN - ADR111 part 6: the file each
// distribution builds OpenSSL to read, through the same package database as
// the libcurl table, and no Fedora, whose OpenSSL does not read it (OBS186).
func TestTheOpenSSLTableIsTheOneWithSources(t *testing.T) {
	want := map[string]string{
		"debian": "/usr/lib/ssl/cert.pem", "ubuntu": "/usr/lib/ssl/cert.pem", "alpine": "/etc/ssl/cert.pem",
		"rhel": "/etc/pki/tls/cert.pem", "centos": "/etc/pki/tls/cert.pem", "rocky": "/etc/pki/tls/cert.pem",
		"almalinux": "/etc/pki/tls/cert.pem",
	}
	if len(OpenSSLBuilds) != len(want) {
		t.Errorf("%d distributions, want %d", len(OpenSSLBuilds), len(want))
	}
	for id, file := range want {
		build := OpenSSLBuilds[id]
		if !slices.Equal(build.bundles, []string{file}) {
			t.Errorf("%s: files %v, want %s", id, build.bundles, file)
		}
		if build.packages.name != LibcurlBuilds[id].packages.name {
			t.Errorf("%s: packages read by %q, want %q", id, build.packages.name, LibcurlBuilds[id].packages.name)
		}
	}
	if got := knownDistributions(OpenSSLBuilds); got != "almalinux, alpine, centos, debian, rhel, rocky and ubuntu" {
		t.Errorf("the sentence names %q", got)
	}
}

// NODE FROM A DISTRIBUTION'S PACKAGE DEFERS THROUGH THE LINK OpenSSL's default
// file is - measured by S27 in Ubuntu 26.04: /usr/lib/ssl/cert.pem leads to
// the bundle the platform store's row reads, and dpkg lists the binary in
// nodejs.list. In RHEL 9.8 /etc/pki/tls/cert.pem leads to the file
// ca-bundle.crt leads to.
func TestOpenSSLsDefaultFileDefersThroughItsLink(t *testing.T) {
	ubuntu := newMachine("ubuntu").withBundle("/etc/ssl/certs/ca-certificates.crt")
	ubuntu.links["/usr/lib/ssl/cert.pem"] = "/etc/ssl/certs/ca-certificates.crt"
	ubuntu.files["/var/lib/dpkg/info/nodejs.list"] = []byte("/usr/bin/node\n/usr/bin/nodejs\n")
	if store := deferWith(t, ubuntu, OpenSSLBuilds, "node", "/usr/bin/node", "nodejs"); !defersTo(store, "ubuntu") {
		t.Errorf("ubuntu: got %+v", store)
	}

	rhel := newMachine("rhel").withBundle("/etc/pki/tls/certs/ca-bundle.crt")
	rhel.links["/etc/pki/tls/certs/ca-bundle.crt"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	rhel.links["/etc/pki/tls/cert.pem"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	rhel.owned["/usr/bin/node"] = true
	if store := deferWith(t, rhel, OpenSSLBuilds, "node", "/usr/bin/node", "nodejs"); !defersTo(store, "rhel") {
		t.Errorf("rhel: got %+v", store)
	}

	// WITHOUT THE LINK - an image with libssl and no openssl package, which is
	// the package that holds it in Debian and Ubuntu - the file is another one.
	delete(ubuntu.links, "/usr/lib/ssl/cert.pem")
	if store := deferWith(t, ubuntu, OpenSSLBuilds, "node", "/usr/bin/node", "nodejs"); store.DefersTo != nil ||
		!strings.HasSuffix(store.NotAssessed, "which is not the same file as /usr/lib/ssl/cert.pem") {
		t.Errorf("no link: got %q", store.NotAssessed)
	}

	fedora := newMachine("fedora").withBundle("/etc/pki/tls/certs/ca-bundle.crt")
	fedora.owned["/usr/bin/node"] = true
	if store := deferWith(t, fedora, OpenSSLBuilds, "node", "/usr/bin/node", "nodejs"); store.DefersTo != nil ||
		!strings.HasSuffix(store.NotAssessed, `and this distribution is "fedora"`) {
		t.Errorf("fedora: got %q", store.NotAssessed)
	}
}
