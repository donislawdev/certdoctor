package git

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

const schannelBundle = "C:/ca/bundle.pem"

// onWindows is the row of Git for Windows for these settings, judging the one
// leaf anchorAndLeaf minted, with the given files on disk.
func onWindows(t *testing.T, settings Settings, env Environment, files map[string]string, leafDER []byte) report.TrustStore {
	t.Helper()
	if env.Platform == "" {
		env.Platform = "windows"
	}
	return storeFor(t.Context(), probe.Ports{Source: sourceOf(files)}, noFiles,
		Install{Instance: `C:\Program Files\Git\cmd\git.exe`, Root: `C:\Program Files\Git`}, settings, env,
		[][]byte{leafDER}, atNoon())
}

// schannelWith is git naming schannel at the system level, as an installer
// that chose it writes it, with the key set at the global level when on is
// not empty and http.sslCAInfo naming file when that is not empty.
func schannelWith(on, file string) Settings {
	s := Settings{Backend: "schannel", BackendLevel: "system"}
	if on != "" {
		s.UseCAInfo, s.UseCAInfoLevel = on, "global"
	}
	if file != "" {
		s.CAInfo, s.CAInfoLevel = file, "global"
	}
	return s
}

// GIT ON SCHANNEL READS THE FILE ONLY WHEN TOLD TO, AND THEN ONLY THE FILE -
// OBS183, measured by S35: the key unset or false leaves the Windows store
// deciding, true with a file named makes that file the only anchors, the
// variable wins over the key, and a directory changes nothing either way.
func TestOnSchannelTheFileDecidesOnlyWhenGitIsToldToReadIt(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	files := map[string]string{schannelBundle: string(anchorPEM), "C:/ca/empty.pem": ""}
	withDirectory := schannelWith("true", "")
	withDirectory.CAPath, withDirectory.CAPathLevel = "C:/ca/certs", "global"
	fileAndDirectory := schannelWith("true", schannelBundle)
	fileAndDirectory.CAPath, fileAndDirectory.CAPathLevel = "C:/ca/certs", "global"
	byVariable := Environment{CAInfo: Variable{Set: true, Value: schannelBundle}}

	cases := []struct {
		name     string
		settings Settings
		env      Environment
		byFile   bool
	}{
		{"the key unset (S35 A)", schannelWith("", schannelBundle), Environment{}, false},
		{"the key false", schannelWith("false", schannelBundle), Environment{}, false},
		{"the key true and nothing named (S35 H)", schannelWith("true", ""), Environment{}, false},
		{"the key true and a directory alone (S35 M)", withDirectory, Environment{}, false},
		{"the key true and a file (S35 B)", schannelWith("true", schannelBundle), Environment{}, true},
		{"the key standing alone and a file", schannelWith("yes", schannelBundle), Environment{}, true},
		{"the variable and the key true (S35 F)", schannelWith("true", ""), byVariable, true},
		{"the variable over an empty file (S35 G)", schannelWith("true", "C:/ca/empty.pem"), byVariable, true},
		{"a directory beside the file (S35 N)", fileAndDirectory, Environment{}, true},
	}
	for _, c := range cases {
		store := onWindows(t, c.settings, c.env, files, leafDER)
		trusted := store.TrustsPresentedChain != nil && *store.TrustsPresentedChain
		switch {
		case c.byFile && (!trusted || store.StoreForm != report.StoreFile || store.StorePath != filepath.Clean(schannelBundle)):
			t.Errorf("%s: want the file to decide, got %+v", c.name, store)
		case !c.byFile && (store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "system-store")):
			t.Errorf("%s: want the Windows store to decide, got %+v", c.name, store)
		}
	}
}

// A FILE GIT ON SCHANNEL CANNOT USE IS NOT JUDGED AS IF IT COULD - S35 L1, L2,
// L4: a block Windows cannot read, a begin line with no end and a file over
// 1 MiB stop every connection. And curl's scan, not a PEM parser, decides what
// is loaded: a begin line with no line break ends the reading, so an anchor
// after it does not count. The file of exactly 1 MiB is the case beside the
// limit, and a trusted row there says the limit is not reached early.
func TestAFileGitOnSchannelCannotUseIsNotJudged(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	pad := func(size int) string {
		return strings.Repeat("#", size-len(anchorPEM)-1) + "\n" + string(anchorPEM)
	}
	cases := []struct {
		name, bundle, want string
		trusted            bool
	}{
		{"exactly 1 MiB (S35 L3)", pad(1 << 20), "", true},
		{"one byte over 1 MiB (S35 L4)", pad(1<<20 + 1), "larger than 1048576 bytes", false},
		{"a begin line with no end (S35 L2)", string(anchorPEM) + "-----BEGIN CERTIFICATE-----\nMIIB\n",
			"no END CERTIFICATE line", false},
		{"a block nobody reads (S35 L1)", string(anchorPEM) + "-----BEGIN CERTIFICATE-----\nAAAA\n" +
			"-----END CERTIFICATE-----\n", "could not read", false},
		{"a begin line with no line break first", "-----BEGIN CERTIFICATE----- x\n" + string(anchorPEM),
			"no certificate git on Schannel reads", false},
		{"line breaks as CRLF (S35 L5)", string(bytes.ReplaceAll(anchorPEM, []byte("\n"), []byte("\r\n"))), "", true},
	}
	for _, c := range cases {
		files := map[string]string{schannelBundle: c.bundle}
		store := onWindows(t, schannelWith("true", schannelBundle), Environment{}, files, leafDER)
		trusted := store.TrustsPresentedChain != nil && *store.TrustsPresentedChain
		if trusted != c.trusted || !strings.Contains(store.NotAssessed, c.want) {
			t.Errorf("%s: want trusted %v and %q, got %+v", c.name, c.trusted, c.want, store)
		}
	}
}

// UNDER schannelCheckRevoke=true A TRUST CANNOT STAND, AND A REFUSAL DOES - S35
// C to E: Git for Windows tolerates an unknown revocation status unless told
// otherwise, and told true it insists on an answer this program never asks for.
func TestUnderStrictRevocationOnlyARefusalStands(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	otherPEM, _ := anchorAndLeaf(t)
	cases := []struct {
		name, value, bundle string
		verdict             string
	}{
		{"unset (S35 B)", "", string(anchorPEM), "trusted"},
		{"best-effort (S35 E)", "best-effort", string(anchorPEM), "trusted"},
		{"false (S35 D)", "false", string(anchorPEM), "trusted"},
		{"true over a trust (S35 C)", "true", string(anchorPEM), "unknown"},
		{"true over a refusal", "true", string(otherPEM), "refused"},
	}
	for _, c := range cases {
		settings := schannelWith("true", schannelBundle)
		if c.value != "" {
			settings.CheckRevoke, settings.CheckRevokeLevel = c.value, "global"
		}
		store := onWindows(t, settings, Environment{}, map[string]string{schannelBundle: c.bundle}, leafDER)
		if got := verdictOf(store); got != c.verdict {
			t.Errorf("%s: want %s, got %s in %+v", c.name, c.verdict, got, store)
		}
	}
}

func verdictOf(store report.TrustStore) string {
	switch {
	case store.TrustsPresentedChain == nil && strings.Contains(store.NotAssessed, "schannelCheckRevoke"):
		return "unknown"
	case store.TrustsPresentedChain == nil:
		return "unassessed: " + store.NotAssessed
	case *store.TrustsPresentedChain:
		return "trusted"
	}
	return "refused"
}

// A SCHANNEL KEY GIT CANNOT READ STOPS GIT WHATEVER THE BACKEND, a key under a
// condition matters only on schannel, and schannel named off Windows is a
// backend libcurl does not have.
func TestTheSchannelKeysOutsideTheirOrdinaryShape(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	files := map[string]string{schannelBundle: string(anchorPEM)}
	onOpenSSL := Settings{Backend: "openssl", BackendLevel: "system", CAInfo: schannelBundle, CAInfoLevel: "system"}
	unreadKey := onOpenSSL
	unreadKey.UseCAInfo, unreadKey.UseCAInfoLevel = "maybe", "global"
	bestEffort := onOpenSSL
	bestEffort.CheckRevoke, bestEffort.CheckRevokeLevel = "best-effort", "global"
	conditionalOff := onOpenSSL
	conditionalOff.Conditional = map[string]string{keyUseCAInfo: "a section for one address"}
	conditionalOn := schannelWith("true", schannelBundle)
	conditionalOn.Conditional = map[string]string{keyCheckRevoke: "a section for one address"}

	cases := []struct {
		name     string
		settings Settings
		platform string
		want     string
	}{
		{"an unread key on openssl", unreadKey, "windows", "git stops on a value"},
		{"best-effort on Windows", bestEffort, "windows", ""},
		{"best-effort elsewhere", bestEffort, "linux", "git stops on a value"},
		{"a conditional key on openssl", conditionalOff, "windows", ""},
		{"a conditional key on schannel", conditionalOn, "windows", "a section for one address"},
		{"schannel off Windows", schannelWith("true", schannelBundle), "darwin", "only on Windows"},
	}
	for _, c := range cases {
		store := onWindows(t, c.settings, Environment{Platform: c.platform}, files, leafDER)
		trusted := store.TrustsPresentedChain != nil && *store.TrustsPresentedChain
		if (c.want == "") != trusted || !strings.Contains(store.NotAssessed, c.want) {
			t.Errorf("%s: want %q, got %+v", c.name, c.want, store)
		}
	}
}

// THE TWO KEYS ARE READ AS http.c READS THEM - standing alone each is true, and
// best-effort is kept as written for the row to decide on.
func TestTheSchannelKeysAreReadFromTheConfiguration(t *testing.T) {
	settings := userConfig(t, "[http]\n\tschannelUseSSLCAInfo\n\tschannelCheckRevoke = best-effort\n", nil)
	if settings.UseCAInfo != "true" || settings.UseCAInfoLevel != "global" {
		t.Errorf("schannelUseSSLCAInfo alone: got %q at %q, want true at global", settings.UseCAInfo, settings.UseCAInfoLevel)
	}
	if settings.CheckRevoke != "best-effort" || settings.CheckRevokeLevel != "global" {
		t.Errorf("schannelCheckRevoke: got %q at %q", settings.CheckRevoke, settings.CheckRevokeLevel)
	}
	if settings := userConfig(t, "[http]\n\tschannelCheckRevoke\n", nil); settings.CheckRevoke != "true" {
		t.Errorf("schannelCheckRevoke alone: got %q, want true", settings.CheckRevoke)
	}
}
