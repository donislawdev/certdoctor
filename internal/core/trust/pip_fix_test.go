package trust

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// aPipOnTruststore is the row the python probe writes for a pip from 24.2 on,
// on Linux with nothing named for verification - the platform's file, spelled as
// the platform store's row spells it.
func aPipOnTruststore() report.TrustStore {
	s := aRefusedStore(report.RuntimePip, "/usr/bin/python3", "/etc/ssl/certs/ca-certificates.crt")
	s.Variant = report.PipTruststore
	s.SelectedBy = []string{"PATH", "pip3"}
	return s
}

// aPipOnCertifi is a pip before 24.2 reading the certifi it carries, with
// nothing named for verification.
func aPipOnCertifi() report.TrustStore {
	s := aRefusedStore(report.RuntimePip, "/usr/bin/python3",
		"/usr/lib/python3/dist-packages/pip/_vendor/certifi/cacert.pem")
	s.Variant = report.PipCertifi
	s.SelectedBy = []string{"PATH", "pip3"}
	return s
}

// A pip ON TRUSTSTORE GETS THE APPEND TO THE FILE IT READS - ADR112 part 5, the
// line the python row over the same file gets, caveat and all.
func TestAPipOnTruststoreGetsTheAppend(t *testing.T) {
	fix, why := fixFor(aPipOnTruststore(), true, false, posix())
	if fix == nil || why != "" {
		t.Fatalf("no command (%q)", why)
	}
	if want := `cat '<certificate.pem>' >> '/etc/ssl/certs/ca-certificates.crt'`; fix.Command != want {
		t.Errorf("got %q, wanted %q", fix.Command, want)
	}
	python, _ := fixFor(aPythonReadingAFile(), true, false, posix())
	if fix.Caveat != python.Caveat {
		t.Errorf("pip's caveat %q differs from python's over the same file %q", fix.Caveat, python.Caveat)
	}
	if !fix.RequiresElevation {
		t.Errorf("a file outside this account's own files did not ask for root: %+v", fix)
	}
}

// A pip ON certifi ALONE WITH NOTHING NAMED GETS NO COMMAND AND SAYS WHY - ADR112
// part 5: a file named there takes certifi's place, so the only command left
// would be one somebody has to fill with every root pip needs.
func TestAPipOnCertifiAloneSaysWhyItHasNoCommand(t *testing.T) {
	fix, why := fixFor(aPipOnCertifi(), true, false, posix())
	if fix != nil {
		t.Fatalf("a pip on certifi alone got %+v", fix)
	}
	for _, word := range []string{"certifi", "replace", "24.2", "legacy-certs"} {
		if !strings.Contains(why, word) {
			t.Errorf("the sentence does not say %q: %q", word, why)
		}
	}
}

// A FILE NAMED FOR VERIFICATION IS ADDED TO ON EITHER VARIANT, whichever of the
// four names set it - it is what pip reads beside or in place of certifi, and
// adding keeps what it already gives.
func TestAFileNamedForVerificationIsAddedTo(t *testing.T) {
	for _, name := range []string{report.PipRequestsCABundle, report.PipCurlCABundle, report.PipCertVariable,
		report.PipCertSetting} {
		t.Run(name, func(t *testing.T) {
			s := aPipOnCertifi()
			s.StorePath = "/etc/pki/company.pem"
			s.SelectedBy = append(s.SelectedBy, name)
			fix, why := fixFor(s, true, false, posix())
			if fix == nil || why != "" {
				t.Fatalf("no command (%q)", why)
			}
			if want := `cat '<certificate.pem>' >> '/etc/pki/company.pem'`; fix.Command != want {
				t.Errorf("got %q, wanted %q", fix.Command, want)
			}
		})
	}
}

// A pip ROW WITH NO FILE GETS NOTHING - on Windows it defers to this account's
// store and takes that row's command, decided by the owner 2026-10-27.
func TestAPipRowWithNoFileGetsNoCommand(t *testing.T) {
	s := aPipOnTruststore()
	s.StoreForm, s.StorePath = report.StoreSystem, ""
	if fix, why := fixFor(s, true, false, posix()); fix != nil || why != "" {
		t.Errorf("a pip row with no file got %+v (%q)", fix, why)
	}
}

// THE APPEND GATES HOLD FOR pip TOO - a file ending mid-line gets the sentence
// every other append gets.
func TestAPipFileEndingMidLineGetsNoAppend(t *testing.T) {
	s := aPipOnTruststore()
	s.FileEnd = report.FileEndMidLine
	if fix, why := fixFor(s, true, false, posix()); fix != nil || why != endsMidLine {
		t.Errorf("got %+v (%q)", fix, why)
	}
}
