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

// fixtureNotes is the notices of both programs of the fixture tree.
func fixtureNotes(t *testing.T) map[string]notices {
	t.Helper()
	notes, err := parseTree(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	return notes
}

func readBuilds(t *testing.T, listing string) []build {
	t.Helper()
	builds, err := parseBuilds(listing)
	if err != nil {
		t.Fatal(err)
	}
	return builds
}

func TestBuildsThatLinkWhatTheNoticesNameAreAccepted(t *testing.T) {
	for name, listing := range map[string]string{
		"the command line":            fixtureListing(),
		"both programs":               fixtureListing() + fixtureWindowListing(),
		"the window alone, one build": windowListingFor("dist/w", "linux/amd64", windowDeps(fixturePortal)),
	} {
		if problems := reconcile(readBuilds(t, listing), fixtureNotes(t)); len(problems) != 0 {
			t.Errorf("%s: problems with builds that match: %v", name, problems)
		}
	}
}

// Every disagreement is reported, each naming the build it is about, so one run
// lists everything a dependency update has to touch.
func TestEveryDisagreementIsReported(t *testing.T) {
	deps := map[string]string{
		"example.com/alpha": "v1.2.4",
		"example.com/gamma": "v0.1.0",
	}
	builds := readBuilds(t, listingFor("dist/a", "darwin/arm64", "go1.27.4", deps))
	want := []string{
		"darwin/arm64 was built with go1.27.4, and the notices name go1.27.3",
		"darwin/arm64 links example.com/alpha v1.2.4, and the notices name v1.2.3",
		"darwin/arm64 links example.com/gamma v0.1.0, which the notices do not name",
		"the notices name example.com/beta/v2, which none of the 1 build(s) of certdoctor given links",
	}
	if got := reconcile(builds, fixtureNotes(t)); !reflect.DeepEqual(got, want) {
		t.Errorf("reported\n%q\nwant\n%q", got, want)
	}
}

// A build of the window is held to the window's notices and to no other: a
// module only the command line's notices name is one the window does not
// link, and one only the window's name is one the command line does not.
func TestEachProgramIsHeldToItsOwnNotices(t *testing.T) {
	window := windowDeps(map[string]string{"example.com/alpha": "v1.2.3"})
	delete(window, "example.com/glfw")
	listing := listingFor("dist/a", "linux/amd64", "go1.27.3", fixtureDeps) +
		windowListingFor("dist/w", "windows/amd64", window)
	want := []string{
		"certdoctor-gui windows/amd64 links example.com/alpha v1.2.3, which the window's notices do not name",
		"the window's notices name example.com/glfw, which none of the 1 build(s) of certdoctor-gui given links",
		"the window's notices name example.com/portal, which none of the 1 build(s) of certdoctor-gui given links",
	}
	if got := reconcile(readBuilds(t, listing), fixtureNotes(t)); !reflect.DeepEqual(got, want) {
		t.Errorf("reported\n%q\nwant\n%q", got, want)
	}
}

// A module one build links is accounted for by that build, so a module linked
// on one system only is not reported as named and missing.
func TestAModuleIsLinkedWhenAnyBuildLinksIt(t *testing.T) {
	alphaOnly := map[string]string{"example.com/alpha": "v1.2.3"}
	text := listingFor("dist/a", "linux/amd64", "go1.27.3", alphaOnly) +
		listingFor("dist/b", "linux/arm64", "go1.27.3", fixtureDeps)
	if problems := reconcile(readBuilds(t, text), fixtureNotes(t)); len(problems) != 0 {
		t.Errorf("problems: %v", problems)
	}
}
