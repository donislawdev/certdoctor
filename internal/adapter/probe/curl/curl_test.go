package curl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// hostSpelling is the twin of the one in probe/binaries_test.go, where the
// comment explains why all four of these test packages need it.
func hostSpelling(path string) string {
	return strings.ReplaceAll(path, `\`, string(filepath.Separator))
}

// The Windows tree these fixtures describe, spelled for the host. The SHAPE is
// Windows because that is the machine being described; only the separator
// follows the platform, so that filepath.Join and filepath.Clean have something
// they can take apart.
var (
	winSystem32     = hostSpelling(`C:\Windows\system32`)
	winSystem32Loud = hostSpelling(`C:\WINDOWS\system32`)
	system32Curl    = hostSpelling(`C:\Windows\system32\curl.exe`)
	gitBin          = hostSpelling(`C:\Program Files\Git\mingw64\bin`)
	gitBinCurl      = hostSpelling(`C:\Program Files\Git\mingw64\bin\curl.exe`)
)

func sourceOf(paths ...string) func(string) (io.ReadCloser, error) {
	key := func(path string) string { return strings.ToLower(filepath.Clean(path)) }

	present := map[string]bool{}
	for _, path := range paths {
		present[key(path)] = true
	}
	return func(path string) (io.ReadCloser, error) {
		if !present[key(path)] {
			return nil, errors.New("no such file")
		}
		return io.NopCloser(strings.NewReader("bundle")), nil
	}
}

func versionSaying(line string) probe.Runner {
	return func(context.Context, string, ...string) (probe.Output, error) {
		return probe.Output{Stdout: line + "\nRelease-Date: 2026-01-01\n"}, nil
	}
}

// EVERY curl ON PATH, NOT THE FIRST ONE - ADR50. Measured: two on this machine,
// and taking the first would have hidden the one shipped inside Git.
func TestEveryCurlOnPathIsFound(t *testing.T) {
	source := sourceOf(system32Curl, gitBinCurl)
	found := find(source, noLinks, []string{winSystem32, gitBin})
	if len(found) != 2 {
		t.Fatalf("found %d curl binaries, want 2", len(found))
	}
}

// THE DEFECT THIS TEST EXISTS FOR WAS MEASURED, NOT IMAGINED. PATH on this
// machine carries system32 in two spellings, so the first version of find
// reported ONE binary as TWO stores and the verdict counted ten where there are
// nine. Caught by running the binary.
//
// Where the filesystem tells case apart the two spellings are two files, so
// there they are two rows - ADR114 R15, asserted in the probe package.
func TestOneBinaryReachedByTwoSpellingsIsOneRowWhereCaseFolds(t *testing.T) {
	source := sourceOf(system32Curl)
	found := find(source, noLinks, []string{winSystem32, winSystem32Loud})
	if want := rowsForSystem32Twice(); len(found) != want {
		t.Fatalf("found %d rows for one binary, want %d: %+v", len(found), want, found)
	}
}

// rowsForSystem32Twice is how many rows system32 in two spellings makes here.
// It asks probe.PathKey rather than restating which platforms fold case, so the
// rule has one copy - its test is in the probe package.
func rowsForSystem32Twice() int {
	if probe.PathKey(winSystem32) == probe.PathKey(winSystem32Loud) {
		return 1
	}
	return 2
}

// SCHANNEL ASKS THE PLATFORM, AND THE ANSWER IS THE PLATFORM ROW'S. This probe
// never opens that store, so it claims no trust of its own - it names the row
// that answers, and the trust layer hands it that row's answer. ADR108 part 4,
// and which row was measured with probe S25 on 2026-10-20: a root held in this
// account's Root store alone was trusted by both builds on this machine.
func TestASchannelBuildJudgesByThisAccountsStore(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(schannelLine), Source: sourceOf()},
		noFiles, Install{Path: `C:\curl.exe`}, [][]byte{leafNaming(t, []string{"http://crl.test/a.crl"}, nil)},
		Environment{}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Error("a platform-store build produced a verdict this probe cannot reach")
	}
	if store.Backend != "schannel" {
		t.Errorf("backend %q, want schannel", store.Backend)
	}
	if store.DefersTo == nil || *store.DefersTo != (report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: report.InstanceCurrentUser}) {
		t.Fatalf("the row does not name this account's store as its answer: %+v", store.DefersTo)
	}
	if !strings.Contains(store.NotAssessed, "system-store CurrentUser") {
		t.Errorf("the reason does not say who answers instead: %q", store.NotAssessed)
	}
}

// schannelLine is the first line of curl --version on the owner's machine,
// measured 2026-10-20 for the binary in system32.
const schannelLine = "curl 8.21.0 (Windows) libcurl/8.21.0 Schannel zlib/1.3.2 WinIDN WinLDAP"

// leafNaming is a certificate whose only interesting fields are where it says
// its revocation can be checked.
func leafNaming(t *testing.T, crl, ocsp []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "partner.test"},
		NotBefore:             atNoon().Add(-time.Hour),
		NotAfter:              atNoon().Add(time.Hour),
		CRLDistributionPoints: crl,
		OCSPServer:            ocsp,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// THE MEASURED REFUSAL - probe S25: a leaf naming nowhere to check failed on
// both builds with CRYPT_E_NO_REVOCATION_CHECK, with the root trusted. The row
// refuses for itself and still names the store, so the signer line counts that
// store once.
func TestASchannelBuildRefusesALeafThatNamesNowhereToCheck(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(schannelLine), Source: sourceOf()},
		noFiles, Install{Path: `C:\curl.exe`}, [][]byte{leafNaming(t, nil, nil)}, Environment{}, atNoon())

	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain {
		t.Fatalf("a leaf naming nowhere to check was not refused: %+v", store)
	}
	if store.TrustFailure != report.NoRevocationInfo {
		t.Errorf("the refusal says %q", store.TrustFailure)
	}
	if store.DefersTo == nil {
		t.Error("the refusing row stopped naming the store it judges by")
	}
}

// A JUDGEMENT, PINNED SO IT IS NOT CHANGED BY ACCIDENT: S25 served revocation
// lists only, and a responder is taken to be an address too.
func TestAnOCSPResponderCountsAsSomewhereToCheck(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(schannelLine), Source: sourceOf()},
		noFiles, Install{Path: `C:\curl.exe`}, [][]byte{leafNaming(t, nil, []string{"http://ocsp.test"})}, Environment{}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Errorf("a leaf naming a responder was judged here: %+v", store)
	}
}

// A certificate Go cannot read is not a certificate naming nowhere - nothing
// was learned, so the row neither refuses nor takes a store's answer.
func TestALeafThatCannotBeReadLeavesTheRowUnassessed(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(schannelLine), Source: sourceOf()},
		noFiles, Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, Environment{}, atNoon())

	if store.TrustsPresentedChain != nil || store.DefersTo != nil {
		t.Errorf("an unreadable leaf still produced an answer or a store to take one from: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "could not be read") {
		t.Errorf("the reason does not say the certificate could not be read: %q", store.NotAssessed)
	}
}

// BRACKETS MARK THE BACKENDS A BUILD DID NOT SELECT - lib/vtls/vtls.c,
// multissl_version, in curl 8.21.0. Schannel is asked first, so before this a
// file-reading build that merely carries Schannel read as Schannel.
func TestTheSelectedBackendIsTheOneOutsideTheBrackets(t *testing.T) {
	cases := map[string]string{
		"curl 8.21.0 (x86_64-w64-mingw32) libcurl/8.21.0 OpenSSL/3.5.7 (Schannel) zlib/1.3.2": "openssl",
		"curl 8.21.0 (x86_64-w64-mingw32) libcurl/8.21.0 Schannel (OpenSSL/3.5.7) zlib/1.3.2": "schannel",
		schannelLine: "schannel",
	}
	for line, want := range cases {
		got, err := backendOf(context.Background(), versionSaying(line), Install{Path: `C:\curl.exe`})
		if err != nil || got != want {
			t.Errorf("%q read as %q (%v), want %q", line, got, err, want)
		}
	}
}

// A CONFIGURATION FILE CAN NAME A CA FILE OR TURN REVOCATION OFF, and this
// program does not read it - so a row that finds one takes no store's answer.
func TestAConfigurationFileStopsTheRowTakingTheStoresAnswer(t *testing.T) {
	profile := hostSpelling(`C:\Users\jdoe`)
	curlrc := filepath.Join(profile, ".curlrc")
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(schannelLine), Source: sourceOf(curlrc)},
		noFiles, Install{Path: system32Curl}, [][]byte{leafNaming(t, nil, nil)},
		Environment{Homes: map[string]string{"USERPROFILE": profile}}, atNoon())

	if store.TrustsPresentedChain != nil || store.DefersTo != nil {
		t.Fatalf("a row with a configuration file in reach still answered: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, curlrc) {
		t.Errorf("the reason does not name the file: %q", store.NotAssessed)
	}
}

// curl's own order, read in src/tool_findfile.c of 8.21.0 - including the turn
// a reader would not guess: once a place holding "curlrc" is reached, every later
// place is asked for ".curlrc" alone and later places without a dot are skipped.
func TestTheConfigurationFileIsLookedForInCurlsOwnOrder(t *testing.T) {
	j := filepath.Join
	home, profile, data, xdg := hostSpelling(`C:\h`), hostSpelling(`C:\p`), hostSpelling(`C:\a`), hostSpelling(`C:\x`)
	binary := gitBinCurl

	withoutXDG := configCandidates(windowsConfigOrder, map[string]string{"HOME": home, "USERPROFILE": profile, "APPDATA": data}, "", binary)
	wantWithout := []string{
		j(home, ".curlrc"), j(home, "_curlrc"),
		j(profile, ".curlrc"), j(profile, "_curlrc"),
		j(data, ".curlrc"), j(data, "_curlrc"),
		j(profile, "Application Data", ".curlrc"), j(profile, "Application Data", "_curlrc"),
		j(home, ".config", "curlrc"),
		j(gitBin, ".curlrc"), j(gitBin, "_curlrc"),
	}
	if strings.Join(withoutXDG, "|") != strings.Join(wantWithout, "|") {
		t.Errorf("without XDG_CONFIG_HOME:\n got %v\nwant %v", withoutXDG, wantWithout)
	}

	withXDG := configCandidates(windowsConfigOrder, map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home, "USERPROFILE": profile, "APPDATA": ""}, "", binary)
	wantWith := []string{
		j(xdg, "curlrc"),
		j(home, ".curlrc"),
		j(profile, ".curlrc"),
		j(profile, "Application Data", ".curlrc"),
		j(gitBin, ".curlrc"), j(gitBin, "_curlrc"),
	}
	if strings.Join(withXDG, "|") != strings.Join(wantWith, "|") {
		t.Errorf("with XDG_CONFIG_HOME:\n got %v\nwant %v", withXDG, wantWith)
	}
}

// A place on another machine is not opened - inviolable rule 16 - and whether a
// file waits there is then unknown, which the row says.
func TestAConfigurationFileOnAnotherMachineIsNotLookedPast(t *testing.T) {
	share := hostSpelling(`\\files\home\jdoe`)
	source := func(path string) (io.ReadCloser, error) {
		return nil, &file.RemotePath{Path: path}
	}
	found, unreadable := configFile(source, configCandidates(windowsConfigOrder, map[string]string{"HOME": share}, "", system32Curl))
	if found != "" || !strings.Contains(unreadable, "not on this machine") {
		t.Errorf("a place on another machine was looked past: found %q, said %q", found, unreadable)
	}
}

// A directory named like the file opens and does not read, and curl passes it
// over - so does this.
func TestADirectoryNamedLikeTheFileIsPassedOver(t *testing.T) {
	profile := hostSpelling(`C:\Users\jdoe`)
	directory := filepath.Join(profile, ".curlrc")
	beside := filepath.Join(winSystem32, ".curlrc")
	source := func(path string) (io.ReadCloser, error) {
		switch path {
		case directory:
			return io.NopCloser(failingReader{}), nil
		case beside:
			return io.NopCloser(strings.NewReader("")), nil
		}
		return nil, errors.New("no such file")
	}
	found, _ := configFile(source, configCandidates(windowsConfigOrder, map[string]string{"USERPROFILE": profile}, "", system32Curl))
	if found != beside {
		t.Errorf("found %q, want the empty file beside the binary - a directory is not a configuration file", found)
	}
}

// The entry point hands this package a getter, and the package asks it for
// exactly the variables curl's own tool reads - no more, so nothing else in the
// environment can steer a row, and no fewer, so no place curl looks is skipped.
func TestTheEnvironmentIsReadThroughTheGetterItIsHanded(t *testing.T) {
	asked := map[string]bool{}
	env := EnvironmentFrom(func(name string) string {
		asked[name] = true
		return "value of " + name
	}, "linux", "/home/jdoe")
	if env.CABundle != "value of CURL_CA_BUNDLE" || env.CertFile != "value of SSL_CERT_FILE" || env.CertDir != "value of SSL_CERT_DIR" {
		t.Errorf("the CA variables read %q, %q and %q", env.CABundle, env.CertFile, env.CertDir)
	}
	for _, name := range homeVariables {
		if env.Homes[name] != "value of "+name {
			t.Errorf("%s reads %q", name, env.Homes[name])
		}
	}
	if len(asked) != len(homeVariables)+3 {
		t.Errorf("the getter was asked for %d variables, want %d: %v", len(asked), len(homeVariables)+3, asked)
	}
	if env.Platform != "linux" || env.Account != "/home/jdoe" {
		t.Errorf("platform %q and account %q were not carried through", env.Platform, env.Account)
	}
}

// curl's own order for the CA variables - src/tool_operate.c, cacertpaths, in
// 8.21.0 and 7.76.1. CURL_CA_BUNDLE silences the other two, and a directory
// comes before a file because both versions then have a directory in play.
func TestTheCAVariablesAreReadInCurlsOwnOrder(t *testing.T) {
	cases := []struct {
		env                Environment
		variable, wantPath string
	}{
		{Environment{CABundle: "/a.pem", CertDir: "/d", CertFile: "/f.pem"}, "CURL_CA_BUNDLE", "/a.pem"},
		{Environment{CertDir: "/d", CertFile: "/f.pem"}, "SSL_CERT_DIR", "/d"},
		{Environment{CertFile: "/f.pem"}, "SSL_CERT_FILE", "/f.pem"},
		{Environment{}, "", ""},
	}
	for _, c := range cases {
		if variable, path := caNamed(c.env); variable != c.variable || path != c.wantPath {
			t.Errorf("%+v named %q by %q, want %q by %q", c.env, path, variable, c.wantPath, c.variable)
		}
	}
}

// SSL_CERT_FILE names the bundle exactly as CURL_CA_BUNDLE does - measured by
// S26 in five images, curl 7.76.1 to 8.21.0 - and a bundle that cannot be read
// says which variable named it.
func TestSSLCertFileNamesTheBundleTheRowReads(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(opensslLine), Source: sourceOf()},
		noFiles, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{CertFile: "/absent/file.pem"}, atNoon())

	if store.StoreForm != report.StoreFile || store.StorePath != "/absent/file.pem" {
		t.Errorf("the row does not name the file SSL_CERT_FILE points at: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "SSL_CERT_FILE") {
		t.Errorf("the reason does not name the variable: %q", store.NotAssessed)
	}
}

// A DIRECTORY IN SSL_CERT_DIR IS NOT JUDGED, because S26 measured that a
// certificate there counts only under its hashed name - and the row says so
// rather than reading the directory as a bundle.
func TestSSLCertDirLeavesTheRowUndetermined(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(opensslLine), Source: sourceOf("/certs/ours.pem")},
		noFiles, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}},
		Environment{CertDir: "/certs", CertFile: "/certs/ours.pem"}, atNoon())

	if store.TrustsPresentedChain != nil || store.StorePath != "" || store.StoreForm != report.StoreSystem {
		t.Errorf("a directory in play still produced a file row: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "SSL_CERT_DIR") || !strings.Contains(store.NotAssessed, "hashed") {
		t.Errorf("the reason does not say what would have to be known: %q", store.NotAssessed)
	}
}

// A file-reading build reads the configuration file too, and outside Windows
// the tool looks in its own places - so a .curlrc in HOME stops the row reading
// the bundle a variable names.
func TestAConfigurationFileStopsAFileReadingBuildToo(t *testing.T) {
	curlrc := filepath.Join("/home/jdoe", ".curlrc")
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(opensslLine), Source: sourceOf(curlrc, "/bundle.crt")},
		noFiles, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}},
		Environment{Platform: "linux", CABundle: "/bundle.crt", Homes: map[string]string{"HOME": "/home/jdoe"}}, atNoon())

	if store.TrustsPresentedChain != nil || store.StorePath != "" {
		t.Fatalf("a row with a configuration file in reach still read a bundle: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, curlrc) {
		t.Errorf("the reason does not name the file: %q", store.NotAssessed)
	}
}

// curl's order outside Windows - src/tool_findfile.c of 8.21.0, where
// CURLRC_DOTSCORE is 1: no "_curlrc", none of the three Windows places, no
// binary directory, and the account's home from the user database last.
func TestTheConfigurationFileIsLookedForInCurlsOwnOrderOutsideWindows(t *testing.T) {
	j := filepath.Join
	curlHome, home, xdg, account := "/c", "/h", "/x", "/acct"
	every := map[string]string{"CURL_HOME": curlHome, "HOME": home, "USERPROFILE": "/p", "APPDATA": "/a"}

	got := configCandidates(otherConfigOrder, every, account, "/usr/bin/curl")
	want := []string{j(curlHome, ".curlrc"), j(home, ".curlrc"), j(curlHome, ".config", "curlrc"), j(account, ".curlrc")}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("without XDG_CONFIG_HOME:\n got %v\nwant %v", got, want)
	}

	got = configCandidates(otherConfigOrder, map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home}, account, "/usr/bin/curl")
	want = []string{j(xdg, "curlrc"), j(home, ".curlrc"), j(account, ".curlrc")}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("with XDG_CONFIG_HOME:\n got %v\nwant %v", got, want)
	}

	got = configCandidates(otherConfigOrder, map[string]string{"HOME": home}, "", "/usr/bin/curl")
	want = []string{j(home, ".curlrc"), j(home, ".config", "curlrc")}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("with HOME alone and no account:\n got %v\nwant %v", got, want)
	}
}

// The platform picks the order, and only Windows gets the Windows one.
func TestEachPlatformGetsItsOwnConfigurationOrder(t *testing.T) {
	if order := configOrderOn("windows"); order.dotscore != 2 || !order.besideBinary || order.account {
		t.Errorf("windows got %+v, want curl's Windows order", order)
	}
	for _, platform := range []string{"linux", "darwin", ""} {
		if order := configOrderOn(platform); order.dotscore != 1 || order.besideBinary || !order.account {
			t.Errorf("%q got %+v, want the order outside Windows", platform, order)
		}
	}
}

// A REFUSAL BY THE NAMED FILE IS WEIGHED AGAINST THE BUILD'S DIRECTORIES -
// decided by the owner 2026-10-20 on S26: the Debian, Ubuntu and Alpine packages
// trusted a root kept only in /etc/ssl/certs while CURL_CA_BUNDLE named a file
// without it. On Windows nothing was measured, so the refusal stands there.
func TestARefusalByTheNamedFileIsWeighedAgainstTheBuildsDirectories(t *testing.T) {
	ours, other := leafNaming(t, nil, nil), leafNaming(t, nil, nil)
	source, files := diskOf(map[string][]byte{
		"/bundle.crt":             pemOf(other),
		"/etc/ssl/certs/ours.pem": pemOf(ours),
	}, map[string][]string{"/etc/ssl/certs": {"/etc/ssl/certs/ours.pem"}})

	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(opensslLine), Source: source}, files, Install{Path: "/usr/bin/curl"},
		[][]byte{ours}, Environment{Platform: "linux", CABundle: "/bundle.crt"}, atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "/etc/ssl/certs") ||
		!strings.Contains(store.NotAssessed, "CURL_CA_BUNDLE") {
		t.Errorf("on Linux: got %+v, want undetermined naming the directory and the variable", store)
	}
	if store.StorePath != "/bundle.crt" {
		t.Errorf("the row stopped naming the file it read: %+v", store)
	}

	store = storeFor(context.Background(), probe.Ports{Run: versionSaying(opensslLine), Source: source}, files, Install{Path: "/usr/bin/curl"},
		[][]byte{ours}, Environment{Platform: "windows", CABundle: "/bundle.crt"}, atNoon())
	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain || store.TrustFailure != report.UnknownAuthority {
		t.Errorf("on Windows: got %+v, want the file's refusal to stand", store)
	}
}

// The row says how the bundle it read ends, from the bytes it read - ADR114 B13.
// The command appends to that file, and a file ending mid-line gets none.
func TestTheRowSaysHowTheBundleItReadEnds(t *testing.T) {
	other := pemOf(leafNaming(t, nil, nil))
	cases := []struct {
		name   string
		bundle []byte
		want   report.FileEnd
	}{
		{"ending with a line feed", other, report.FileEndLineBreak},
		{"ending mid-line", bytes.TrimSuffix(other, []byte("\n")), report.FileEndMidLine},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			source, files := diskOf(map[string][]byte{"/bundle.crt": c.bundle}, nil)
			store := storeFor(context.Background(), probe.Ports{Run: versionSaying(opensslLine), Source: source}, files,
				Install{Path: "/usr/bin/curl"}, [][]byte{leafNaming(t, nil, nil)},
				Environment{Platform: "windows", CABundle: "/bundle.crt"}, atNoon())
			if store.TrustsPresentedChain == nil {
				t.Fatalf("the bundle was not read, so its end says nothing: %+v", store)
			}
			if store.FileEnd != c.want {
				t.Errorf("FileEnd %d, want %d", store.FileEnd, c.want)
			}
		})
	}
}

// opensslLine is a version line of a file-reading build.
const opensslLine = "curl 8.21.0 (x86_64-pc-linux-gnu) libcurl/8.21.0 OpenSSL/3.5.7 zlib/1.3.2"

// pemOf wraps one certificate for a bundle.
func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// diskOf is a disk holding exactly these files and directories.
func diskOf(files map[string][]byte, dirs map[string][]string) (file.Source, file.List) {
	source := func(path string) (io.ReadCloser, error) {
		data, ok := files[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	list := func(path string) ([]string, error) {
		names, ok := dirs[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return names, nil
	}
	return source, list
}

// noFiles is a machine with no directory a build could read beside its file.
func noFiles(string) ([]string, error) { return nil, fs.ErrNotExist }

// Through the whole row, not only through configFile: a place on another
// machine leaves the row unassessed and naming no store - inviolable rule 16.
func TestASchannelRowWithAConfigurationPlaceOffThisMachineIsUnassessed(t *testing.T) {
	source := func(path string) (io.ReadCloser, error) { return nil, &file.RemotePath{Path: path} }
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(schannelLine), Source: source}, noFiles, Install{Path: system32Curl},
		[][]byte{leafNaming(t, nil, nil)}, Environment{Homes: map[string]string{"HOME": hostSpelling(`\\files\home\jdoe`)}}, atNoon())

	if store.TrustsPresentedChain != nil || store.DefersTo != nil {
		t.Fatalf("a row that could not look for its configuration file still answered: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "not on this machine") {
		t.Errorf("the reason does not say where the file could not be looked for: %q", store.NotAssessed)
	}
}

// No certificate means nothing to ask about revocation, and nothing for a store
// to judge - the row says so rather than pointing at a store.
func TestASchannelRowWithNoChainIsUnassessed(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying(schannelLine), Source: sourceOf()}, noFiles, Install{Path: `C:\curl.exe`},
		nil, Environment{}, atNoon())

	if store.TrustsPresentedChain != nil || store.DefersTo != nil {
		t.Fatalf("a row with no chain answered: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "no chain was presented") {
		t.Errorf("the reason does not say there was no chain: %q", store.NotAssessed)
	}
}

// A binary that could not be started at all is a row without a backend, and
// the reason carries what went wrong.
func TestACurlThatCannotBeStartedIsUnassessed(t *testing.T) {
	run := func(context.Context, string, ...string) (probe.Output, error) {
		return probe.Output{}, errors.New("the file is not an executable")
	}
	store := storeFor(context.Background(), probe.Ports{Run: run, Source: sourceOf()}, noFiles, Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, Environment{}, atNoon())

	if store.Backend != "" || store.TrustsPresentedChain != nil {
		t.Fatalf("a curl that never ran produced a backend or a verdict: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "not an executable") {
		t.Errorf("the reason does not carry the failure: %q", store.NotAssessed)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("is a directory") }

// A BACKEND NOBODY HERE MEASURED IS NOT JUDGED BY A BUNDLE, whatever the
// environment names - a row read from it would be a verdict about a file the
// build may never open. Nothing here measured which store such a build reads,
// so it names none and says so - OBS180 corrected what it says.
func TestAnotherPlatformBackendIsNotJudgedByABundle(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying("curl 8.21.0 (x86_64-apple-darwin) libcurl/8.21.0 SecureTransport"), Source: sourceOf("/bundle.crt")},
		noFiles, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{CABundle: "/bundle.crt"}, atNoon())

	if store.StoreForm != report.StoreSystem || store.StorePath != "" {
		t.Errorf("a platform build was pointed at the bundle in the environment: %+v", store)
	}
	if store.TrustsPresentedChain != nil || store.DefersTo != nil {
		t.Errorf("a platform build nothing measured produced an answer: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "which store it reads was not established") {
		t.Errorf("the reason does not say the store was not established: %q", store.NotAssessed)
	}
}

// AN UNRECOGNISED BACKEND IS UNKNOWN AND NEVER A GUESS. Picking the commonest
// one and generating a fix for it is how somebody runs a command that does
// nothing while waiting for it to work.
func TestAnUnknownBackendIsUnassessedRatherThanAssumed(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying("curl 9.0.0 libcurl/9.0.0 SomeNewTLS"), Source: sourceOf()},
		noFiles, Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, Environment{}, atNoon())

	if store.Backend != "" {
		t.Errorf("an unrecognised backend was recorded as %q", store.Backend)
	}
	if store.TrustsPresentedChain != nil {
		t.Error("an unrecognised backend still produced a verdict")
	}
	// THE REASON HAS TO SAY WHICH OF THE TWO THIS IS. Both "backend unknown"
	// and "reads the platform store" end without a verdict, so asserting only
	// the absence of one is a correct answer to a different question - OBS56,
	// and the mutation register caught exactly that here.
	if !strings.Contains(store.NotAssessed, "does not recognise") {
		t.Errorf("the reason does not say the backend was unrecognised: %q", store.NotAssessed)
	}
	if strings.Contains(store.NotAssessed, "platform store") {
		t.Errorf("an unrecognised backend was reported as a platform-store build: %q", store.NotAssessed)
	}
}

// An OpenSSL build with no bundle named falls back to a build-time default this
// program cannot read off disk, and saying so is better than guessing at it.
func TestAnOpenSSLBuildWithNoBundleSaysSo(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying("curl 8.21.0 libcurl/8.21.0 OpenSSL/3.0"), Source: sourceOf()},
		noFiles, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{}, atNoon())

	if store.Backend != "openssl" {
		t.Errorf("backend %q, want openssl", store.Backend)
	}
	if store.StoreForm != report.StoreSystem || store.NotAssessed == "" {
		t.Errorf("a build-time default was not reported as undetermined: %+v", store)
	}
}

// ON LINUX THE DISTRIBUTION'S OWN curl, NAMING NO FILE, DEFERS TO THE PLATFORM
// STORE - ADR110, measured by S26. A curl that is not that build keeps its own
// sentence with the reason after it, and elsewhere nothing was measured, so the
// row stays as it was. The conditions themselves are asked in package probe.
func TestADistributionsCurlNamingNoFileDefersToThePlatformStore(t *testing.T) {
	source, list := diskOf(map[string][]byte{
		"/etc/os-release":                    []byte("ID=debian\n"),
		"/var/lib/dpkg/info/curl.list":       []byte("/usr/bin/curl\n"),
		"/etc/ssl/certs/ca-certificates.crt": []byte("bundle"),
	}, nil)
	ports := probe.Ports{Run: versionSaying(opensslLine), Source: source, Resolve: noLinks}
	linux := Environment{Platform: "linux"}

	store := storeFor(context.Background(), ports, list, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, linux, atNoon())
	want := report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: "debian"}
	if store.DefersTo == nil || *store.DefersTo != want || store.StorePath != "" || store.TrustsPresentedChain != nil {
		t.Errorf("got %+v, want a row deferring to system-store debian", store)
	}

	store = storeFor(context.Background(), ports, list, Install{Path: "/usr/local/bin/curl"}, [][]byte{{0x30}}, linux, atNoon())
	if store.DefersTo != nil || !strings.HasPrefix(store.NotAssessed, "this build reads a CA file and none of") ||
		!strings.Contains(store.NotAssessed, " - dpkg does not list /usr/local/bin/curl") {
		t.Errorf("a curl from no package: got %q", store.NotAssessed)
	}

	store = storeFor(context.Background(), ports, list, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}},
		Environment{Platform: "darwin"}, atNoon())
	if store.DefersTo != nil || strings.Contains(store.NotAssessed, " - ") {
		t.Errorf("another platform: got %q", store.NotAssessed)
	}

	// A FILE NAMED BY A VARIABLE IS JUDGED, NEVER DEFERRED - condition 4.
	store = storeFor(context.Background(), ports, list, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}},
		Environment{Platform: "linux", CABundle: "/etc/ssl/certs/ca-certificates.crt"}, atNoon())
	if store.DefersTo != nil || store.StorePath != "/etc/ssl/certs/ca-certificates.crt" {
		t.Errorf("a named file: got %+v", store)
	}
}

// With a bundle named, the row becomes a file store and goes through the SHARED
// verifier - the same one git uses. A bundle that cannot be read is UNKNOWN with
// a reason, never a failure to trust.
func TestAnOpenSSLBuildWithAnUnreadableBundleIsUnassessed(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying("curl 8.21.0 libcurl/8.21.0 OpenSSL/3.0"), Source: sourceOf()},
		noFiles, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{CABundle: "/absent/bundle.crt"}, atNoon())

	if store.StoreForm != report.StoreFile || store.StorePath != "/absent/bundle.crt" {
		t.Errorf("the row does not name the bundle it was pointed at: %+v", store)
	}
	if store.TrustsPresentedChain != nil || store.NotAssessed == "" {
		t.Errorf("an unreadable bundle did not come back as unassessed: %+v", store)
	}
}

// A binary that will not report its version is recognised by its EXIT CODE.
func TestACurlThatRefusesToReportIsUnassessed(t *testing.T) {
	run := func(context.Context, string, ...string) (probe.Output, error) {
		return probe.Output{ExitCode: 2, Stderr: "nie mozna uruchomic"}, nil
	}
	store := storeFor(context.Background(), probe.Ports{Run: run, Source: sourceOf()}, noFiles, Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, Environment{}, atNoon())

	if store.NotAssessed == "" {
		t.Error("a curl that would not answer gave no reason")
	}
	if strings.Contains(store.NotAssessed, "nie mozna") {
		t.Errorf("the reason quotes the tool's own localised message: %q", store.NotAssessed)
	}
}

// starting hands back run whatever is withheld, and records what was.
func starting(run probe.Runner, asked *[]string) func(...string) probe.Runner {
	return func(names ...string) probe.Runner {
		*asked = append(*asked, names...)
		return run
	}
}

// THE WHOLE PROBE, END TO END. Measured shape on this machine: two binaries,
// both Schannel, so two rows and no verdicts. Every process it starts goes
// without the two variables OBS189 names - SSLKEYLOGFILE, which made curl
// --version create a file, and OPENSSL_CONF, which can load a module.
func TestTheProbeReturnsOneRowPerBinary(t *testing.T) {
	source := sourceOf(system32Curl, hostSpelling(`C:\git\bin\curl.exe`))
	var asked []string
	stores, err := Probe(source, noLinks, noFiles, starting(versionSaying("curl 8.21.0 libcurl/8.21.0 Schannel"), &asked),
		[]string{winSystem32, winSystem32Loud, hostSpelling(`C:\git\bin`), hostSpelling(`C:\empty`)}, Environment{}, atNoon)(context.Background(), [][]byte{{0x30}})

	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if want := 1 + rowsForSystem32Twice(); len(stores) != want {
		t.Fatalf("%d rows, want %d - system32 appears twice on PATH", len(stores), want)
	}
	for _, store := range stores {
		if store.Runtime != "curl" || store.Backend != "schannel" {
			t.Errorf("row does not describe a schannel curl: %+v", store)
		}
	}
	if want := []string{"SSLKEYLOGFILE", "OPENSSL_CONF"}; !slices.Equal(asked, want) {
		t.Errorf("withheld %q, want %q", asked, want)
	}
}

// NO curl IS NOT AN ERROR - docs/20 rule 1.
func TestAMachineWithNoCurlIsNotAnError(t *testing.T) {
	var asked []string
	stores, err := Probe(sourceOf(), noLinks, noFiles, starting(nil, &asked), []string{`C:\empty`}, Environment{}, atNoon)(context.Background(), nil)
	if err != nil {
		t.Errorf("a machine without curl produced an error: %v", err)
	}
	if len(stores) != 0 {
		t.Errorf("%d rows for a machine with no curl", len(stores))
	}
}

// A bundle that reads fine goes through the SHARED verifier, and a chain the
// bundle does not close is DISTRUST - a verdict, not a failure.
func TestAReadableBundleProducesAVerdict(t *testing.T) {
	store := storeFor(context.Background(), probe.Ports{Run: versionSaying("curl 8.21.0 libcurl/8.21.0 OpenSSL/3.0"), Source: sourceOf("/bundle.crt")},
		noFiles, Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{CABundle: "/bundle.crt"}, atNoon())

	// The fixture bundle holds no PEM, so the verifier reports that rather than
	// inventing a verdict - which is the honest answer for an empty store.
	if store.TrustsPresentedChain != nil {
		t.Errorf("a store with no readable anchor produced a verdict: %+v", store)
	}
	if store.NotAssessed == "" {
		t.Error("a store with no readable anchor gave no reason")
	}
}

// atNoon is the clock these tests hand to the verifier.
//
// A FIXED INSTANT RATHER THAN time.Now, because the question this clock decides
// is whether a certificate is out of date - and a test whose answer depends on
// the day it runs is a test that will one day fail for a reason nobody planted.
func atNoon() time.Time { return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) }

// noLinks is a resolver for a filesystem with no symbolic links on it.
func noLinks(path string) (string, error) { return path, nil }

// A BACKEND NOBODY HERE MEASURED SAYS WHAT IT READS - OBS180. GnuTLS, wolfSSL,
// mbedTLS and rustls read the CA file curl hands them, never the platform's
// store on their own, and NSS and Secure Transport are backends curl removed.
// Each row stays unassessed and never claims a platform store answers for it.
func TestABackendNobodyMeasuredSaysWhatItReads(t *testing.T) {
	cases := []struct {
		line string
		says string
	}{
		{"curl 8.21.0 (x86_64-pc-linux-gnu) libcurl/8.21.0 GnuTLS/3.8.9 zlib/1.3",
			"this build uses gnutls, which reads the CA file curl hands it - the one CURL_CA_BUNDLE, SSL_CERT_FILE or " +
				"SSL_CERT_DIR names, or its build-time default - and how gnutls judges a chain against that file was not measured"},
		{"curl 8.21.0 libcurl/8.21.0 wolfSSL/5.8.2", "this build uses wolfssl, which reads the CA file curl hands it"},
		{"curl 8.21.0 libcurl/8.21.0 mbedTLS/3.6.4", "this build uses mbedtls, which reads the CA file curl hands it"},
		{"curl 8.21.0 libcurl/8.21.0 rustls-ffi/0.15.0/rustls/0.23.31", "this build uses rustls, which reads the CA file"},
		{"curl 7.76.1 (x86_64-redhat-linux-gnu) libcurl/7.76.1 NSS/3.67",
			"this build uses nss, which curl removed in 8.3.0, and which store it reads was not established"},
		{"curl 8.7.1 (x86_64-apple-darwin24.0) libcurl/8.7.1 SecureTransport",
			"this build uses securetransport, which curl removed in 8.15.0, and which store it reads was not established"},
	}
	for _, c := range cases {
		store := storeFor(context.Background(), probe.Ports{Run: versionSaying(c.line), Source: sourceOf()}, noFiles,
			Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{Platform: "linux"}, atNoon())
		if store.TrustsPresentedChain != nil || store.DefersTo != nil || !strings.HasPrefix(store.NotAssessed, c.says) {
			t.Errorf("%s: got %+v, want no verdict and a reason starting %q", c.line, store, c.says)
		}
		if strings.Contains(store.NotAssessed, "platform store") {
			t.Errorf("%s: the row still says a platform store answers for it: %q", c.line, store.NotAssessed)
		}
	}
}

// ON WINDOWS A BUILD THAT NAMES NO FILE LOOKS FOR curl-ca-bundle.crt FIRST, and
// the row names that search rather than a build-time default it may never
// reach - OBS180. Elsewhere off Linux nothing searches, and the row says what
// it always said.
func TestOnWindowsAFileBuildNamingNoFileSearchesForABundle(t *testing.T) {
	ports := probe.Ports{Run: versionSaying("curl 8.21.0 (x86_64-w64-mingw32) libcurl/8.21.0 OpenSSL/3.5.7"), Source: sourceOf()}
	store := storeFor(context.Background(), ports, noFiles, Install{Path: `C:\tools\curl.exe`}, [][]byte{{0x30}},
		Environment{Platform: "windows"}, atNoon())
	if store.NotAssessed != windowsSearch || store.TrustsPresentedChain != nil {
		t.Errorf("windows: got %+v", store)
	}
	if !strings.Contains(windowsSearch, "curl-ca-bundle.crt") || !strings.Contains(windowsSearch, "along PATH") {
		t.Errorf("the sentence does not name the file and where it is looked for: %q", windowsSearch)
	}

	store = storeFor(context.Background(), ports, noFiles, Install{Path: "/usr/local/bin/curl"}, [][]byte{{0x30}},
		Environment{Platform: "darwin"}, atNoon())
	if strings.Contains(store.NotAssessed, "curl-ca-bundle.crt") || !strings.HasSuffix(store.NotAssessed, "build-time default") {
		t.Errorf("darwin: got %q", store.NotAssessed)
	}
}
