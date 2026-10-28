package main

import (
	"reflect"
	"testing"
)

func fixtureNoticesRead(t *testing.T) notices {
	t.Helper()
	n, err := parseNotices(fixtureNotices)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBuildsThatLinkWhatTheNoticesNameAreAccepted(t *testing.T) {
	builds, err := parseBuilds(fixtureListing())
	if err != nil {
		t.Fatal(err)
	}
	if problems := reconcile(builds, fixtureNoticesRead(t)); len(problems) != 0 {
		t.Errorf("problems with builds that match: %v", problems)
	}
}

// Every disagreement is reported, each naming the build it is about, so one run
// lists everything a dependency update has to touch.
func TestEveryDisagreementIsReported(t *testing.T) {
	deps := map[string]string{
		"example.com/alpha": "v1.2.4",
		"example.com/gamma": "v0.1.0",
	}
	builds, err := parseBuilds(listingFor("dist/a", "darwin/arm64", "go1.27.4", deps))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"darwin/arm64 was built with go1.27.4, and the notices name go1.27.3",
		"darwin/arm64 links example.com/alpha v1.2.4, and the notices name v1.2.3",
		"darwin/arm64 links example.com/gamma v0.1.0, which the notices do not name",
		"the notices name example.com/beta/v2, which none of the 1 build(s) given links",
	}
	if got := reconcile(builds, fixtureNoticesRead(t)); !reflect.DeepEqual(got, want) {
		t.Errorf("reported\n%q\nwant\n%q", got, want)
	}
}

// A module one build links is accounted for by that build, so a module linked
// on one system only is not reported as named and missing.
func TestAModuleIsLinkedWhenAnyBuildLinksIt(t *testing.T) {
	alphaOnly := map[string]string{"example.com/alpha": "v1.2.3"}
	text := listingFor("dist/a", "linux/amd64", "go1.27.3", alphaOnly) +
		listingFor("dist/b", "linux/arm64", "go1.27.3", fixtureDeps)
	builds, err := parseBuilds(text)
	if err != nil {
		t.Fatal(err)
	}
	if problems := reconcile(builds, fixtureNoticesRead(t)); len(problems) != 0 {
		t.Errorf("problems: %v", problems)
	}
}
