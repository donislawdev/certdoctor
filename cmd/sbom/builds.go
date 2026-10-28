package main

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"time"
)

const (
	// modulePath is this project as the compiler records it.
	modulePath = "github.com/donislawdev/certdoctor"

	// programPath is the package a release binary is built from. A listing of
	// anything else - this command included - is not a release of certdoctor.
	programPath = modulePath + "/cmd/certdoctor"
)

// A build is one binary, as the compiler recorded it.
type build struct {
	file      string            // as go version -m named it, for messages
	target    string            // GOOS/GOARCH
	goVersion string            // the toolchain, which is also the standard library
	revision  string            // the commit
	time      string            // the commit time, in UTC
	deps      map[string]string // module path to version
}

// A listing is the text go version -m prints for one binary: a line naming the
// file and the toolchain, then the build information indented by one tab.
//
// The format is documented by "go help version", and its body is the format
// debug.ParseBuildInfo reads. That function leaves the toolchain unset by its
// own documentation, and the listing names it in its first line instead.
type listing struct {
	file      string
	goVersion string
	lines     []string
}

// parseBuilds reads the listing of one or more binaries.
//
// Every binary has to be a release build of the same commit. Two commits in
// one document would describe two different programs under one version, and a
// target given twice would describe one of them twice.
func parseBuilds(text string) ([]build, error) {
	listings, err := splitListings(text)
	if err != nil {
		return nil, err
	}
	var builds []build
	seen := map[string]string{}
	for _, l := range listings {
		b, err := readBuild(l)
		if err != nil {
			return nil, err
		}
		if earlier, ok := seen[b.target]; ok {
			return nil, fmt.Errorf("%s and %s are both builds for %s", earlier, b.file, b.target)
		}
		seen[b.target] = b.file
		if len(builds) > 0 && b.revision != builds[0].revision {
			return nil, fmt.Errorf("%s was built from commit %s and %s from %s, and one document describes one commit",
				builds[0].file, builds[0].revision, b.file, b.revision)
		}
		builds = append(builds, b)
	}
	return builds, nil
}

// splitListings cuts the text into one listing per binary.
func splitListings(text string) ([]listing, error) {
	var out []listing
	for n, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "\t"):
			if len(out) == 0 {
				return nil, fmt.Errorf("line %d is indented, and no binary was named before it", n+1)
			}
			out[len(out)-1].lines = append(out[len(out)-1].lines, line[1:])
		default:
			// The last ": " rather than the first, because a path on Windows
			// carries a colon after its drive letter and a file name may carry
			// one more.
			cut := strings.LastIndex(line, ": ")
			if cut < 0 || !strings.HasPrefix(line[cut+2:], "go") {
				return nil, fmt.Errorf("line %d names no binary and no toolchain: %q", n+1, line)
			}
			out = append(out, listing{file: line[:cut], goVersion: line[cut+2:]})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("standard input names no binary - pipe in what go version -m prints for the release builds")
	}
	return out, nil
}

// readBuild turns one listing into a build, and refuses one that is not a
// release build of a commit.
func readBuild(l listing) (build, error) {
	info, err := debug.ParseBuildInfo(strings.Join(l.lines, "\n") + "\n")
	if err != nil {
		return build{}, fmt.Errorf("%s: %w", l.file, err)
	}
	if info.Path != programPath {
		return build{}, fmt.Errorf("%s is a build of %q, and a release is a build of %s", l.file, info.Path, programPath)
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	// The commit and its time are what the document is named and dated by, so
	// a binary built without them - outside a checkout, or with -buildvcs=false
	// - cannot be described.
	for _, key := range []string{"GOOS", "GOARCH", "vcs.revision", "vcs.time"} {
		if settings[key] == "" {
			return build{}, fmt.Errorf("%s records no %s, which every release build does", l.file, key)
		}
	}
	if settings["vcs.modified"] != "false" {
		return build{}, fmt.Errorf("%s was built from a tree with changes that are not committed, so no commit describes it", l.file)
	}
	stamp, err := time.Parse(time.RFC3339, settings["vcs.time"])
	if err != nil {
		return build{}, fmt.Errorf("%s records a commit time that is not a time: %w", l.file, err)
	}
	b := build{
		file:      l.file,
		target:    settings["GOOS"] + "/" + settings["GOARCH"],
		goVersion: l.goVersion,
		revision:  settings["vcs.revision"],
		// SPDX asks for UTC with a Z and no fraction, which is one of the
		// spellings RFC 3339 allows and not the only one.
		time: stamp.UTC().Format("2006-01-02T15:04:05Z"),
		deps: map[string]string{},
	}
	for _, dep := range info.Deps {
		if dep.Replace != nil {
			return build{}, fmt.Errorf("%s links %s in place of %s, and the notices name modules rather than what replaced them",
				l.file, dep.Replace.Path, dep.Path)
		}
		b.deps[dep.Path] = dep.Version
	}
	return b, nil
}
