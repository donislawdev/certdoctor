package main

import (
	"strings"
	"testing"
)

// realListing is what go version -m printed on 2026-10-28 for a linux/arm64
// release build of commit 89c6fca, with two changes: lines end in CRLF, as a
// pipe on Windows may leave them, and the file is a Windows path with a second
// ": " in it, which is what holds the rule that the toolchain follows the LAST
// one.
const realListing = "C:\\dist: two\\certdoctor: go1.27.3\r\n" +
	"\tpath\tgithub.com/donislawdev/certdoctor/cmd/certdoctor\r\n" +
	"\tmod\tgithub.com/donislawdev/certdoctor\tv0.0.0-20261028080106-89c6fcaaf91f\t\r\n" +
	"\tdep\tgithub.com/dlclark/regexp2/v2\tv2.10.1\th1:OfLIsGwI1ROq2rHdukCvJzojKjWiEIawRTr5Hqdzd5w=\r\n" +
	"\tdep\tgithub.com/dop251/goja\tv0.0.0-20261021125811-a6ef56644a78\th1:NylFfowas1yoqjtzXi2Y56ej99gfFmwIHYuOcaSD5II=\r\n" +
	"\tdep\tgithub.com/go-sourcemap/sourcemap\tv2.1.4+incompatible\th1:a+iTbH5auLKxaNwQFg0B+TCYl6lbukKPc7b5x0n1s6Q=\r\n" +
	"\tdep\tgithub.com/google/pprof\tv0.0.0-20261016150608-1facf8f91b50\th1:PlNWJRxu5APSV0pWqfIsZ0qt9OOGHSWfZQ4zvx+WgWs=\r\n" +
	"\tdep\tgolang.org/x/text\tv0.43.0\th1:1QivrlhwAsnMOcqgOdl9my7s9OyZl8O5/UGUTJVXoWc=\r\n" +
	"\tbuild\t-buildmode=exe\r\n" +
	"\tbuild\t-compiler=gc\r\n" +
	"\tbuild\t-trimpath=true\r\n" +
	"\tbuild\tCGO_ENABLED=0\r\n" +
	"\tbuild\tGOARCH=arm64\r\n" +
	"\tbuild\tGOOS=linux\r\n" +
	"\tbuild\tGOARM64=v8.0\r\n" +
	"\tbuild\tvcs=git\r\n" +
	"\tbuild\tvcs.revision=89c6fcaaf91fce867320c5a3dcd14db37ef50ddc\r\n" +
	"\tbuild\tvcs.time=2026-10-28T08:01:06Z\r\n" +
	"\tbuild\tvcs.modified=false\r\n"

func TestWhatGoVersionPrintsIsReadAsABuild(t *testing.T) {
	builds, err := parseBuilds(realListing)
	if err != nil {
		t.Fatal(err)
	}
	if len(builds) != 1 {
		t.Fatalf("%d builds read from one listing", len(builds))
	}
	b := builds[0]
	for _, check := range []struct{ field, got, want string }{
		{"file", b.file, `C:\dist: two\certdoctor`},
		{"target", b.target, "linux/arm64"},
		{"toolchain", b.goVersion, "go1.27.3"},
		{"revision", b.revision, "89c6fcaaf91fce867320c5a3dcd14db37ef50ddc"},
		{"time", b.time, "2026-10-28T08:01:06Z"},
		{"sourcemap", b.deps["github.com/go-sourcemap/sourcemap"], "v2.1.4+incompatible"},
	} {
		if check.got != check.want {
			t.Errorf("%s is %q, want %q", check.field, check.got, check.want)
		}
	}
	if len(b.deps) != 5 {
		t.Errorf("%d modules read, the listing names five", len(b.deps))
	}
}

func TestSeveralBuildsOfOneCommitAreReadInTheirOrder(t *testing.T) {
	builds, err := parseBuilds(fixtureListing())
	if err != nil {
		t.Fatal(err)
	}
	if len(builds) != 2 || builds[0].target != "linux/amd64" || builds[1].target != "windows/arm64" {
		t.Fatalf("read %+v", builds)
	}
}

// A commit time in another zone is still the same instant, and SPDX takes it
// in UTC with a Z.
func TestTheCommitTimeIsWrittenInUTC(t *testing.T) {
	text := strings.Replace(fixtureListing(), "vcs.time=2026-10-28T08:01:06Z", "vcs.time=2026-10-28T09:01:06+01:00", 1)
	builds, err := parseBuilds(text)
	if err != nil {
		t.Fatal(err)
	}
	if builds[0].time != "2026-10-28T08:01:06Z" {
		t.Errorf("the time is %q", builds[0].time)
	}
}

func TestAListingThatIsNotOfReleaseBuildsIsRefused(t *testing.T) {
	one := listingFor("dist/a", "linux/amd64", "go1.27.3", fixtureDeps)
	other := listingFor("dist/b", "linux/arm64", "go1.27.3", fixtureDeps)
	for _, c := range []struct{ name, text, want string }{
		{"nothing", "\n\n", "names no binary"},
		{"indented first", "\tpath\tx\n" + one, "line 1 is indented"},
		{"no toolchain", "dist/a\n", "names no binary and no toolchain"},
		{"not a toolchain", "dist/a: not a Go executable\n", "names no binary and no toolchain"},
		{"broken build line", one + "\tbuild\tnoequals\n", "build line missing '='"},
		{"another program", strings.Replace(one, "\tpath\t"+programPath, "\tpath\t"+modulePath+"/cmd/sbom", 1),
			"is a build of"},
		{"no commit", strings.Replace(one, "\tbuild\tvcs.revision="+fixtureRevision+"\n", "", 1), "records no vcs.revision"},
		{"edited tree", strings.Replace(one, "vcs.modified=false", "vcs.modified=true", 1), "not committed"},
		{"unknown edits", strings.Replace(one, "\tbuild\tvcs.modified=false\n", "", 1), "not committed"},
		{"time that is not one", strings.Replace(one, "2026-10-28T08:01:06Z", "yesterday", 1), "not a time"},
		{"replaced module", strings.Replace(one, "h1:AAAA=\n", "h1:AAAA=\n\t=>\texample.com/fork\tv9.9.9\th1:BBBB=\n", 1),
			"links example.com/fork in place of"},
		{"target twice", one + one, "are both builds for linux/amd64"},
		{"two commits", one + strings.Replace(other, fixtureRevision, "0000000000000000000000000000000000000000", 1),
			"one document describes one commit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseBuilds(c.text)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want one saying %q", err, c.want)
			}
		})
	}
}
