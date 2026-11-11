package main

import (
	"fmt"
	"maps"
	"slices"
)

// reconcile compares what the builds of each program link with what that
// program's notices name, and returns every disagreement rather than the
// first, so that one run says everything a dependency update has to touch.
//
// A module a build links and the notices do not name is the reason this
// command exists: its notice would be missing from the binary as well as from
// the document. A module the notices name and no build links is the opposite
// mistake, a notice for code that is not there - checked across the builds of
// that program rather than for each of them, because a module linked on one
// system only belongs in the notices all the same.
//
// The notices of a program no build is given for are not compared with
// anything, and that program is not in the document either.
func reconcile(builds []build, notes map[string]notices) []string {
	var problems []string
	for _, p := range programs {
		var mine []build
		for _, b := range builds {
			if b.program == p.path {
				mine = append(mine, b)
			}
		}
		if len(mine) > 0 {
			problems = append(problems, reconcileProgram(p, mine, notes[p.path])...)
		}
	}
	return problems
}

func reconcileProgram(p program, builds []build, n notices) []string {
	var problems []string
	linked := map[string]bool{}
	for _, b := range builds {
		if b.goVersion != n.std.version {
			problems = append(problems, fmt.Sprintf("%s was built with %s, and %s name %s",
				b.label(), b.goVersion, p.said, n.std.version))
		}
		for _, path := range sortedKeys(b.deps) {
			linked[path] = true
			c, named := n.modules[path]
			switch {
			case !named:
				problems = append(problems, fmt.Sprintf("%s links %s %s, which %s do not name",
					b.label(), path, b.deps[path], p.said))
			case c.version != b.deps[path]:
				problems = append(problems, fmt.Sprintf("%s links %s %s, and %s name %s",
					b.label(), path, b.deps[path], p.said, c.version))
			}
		}
	}
	for _, path := range sortedKeys(n.modules) {
		if !linked[path] {
			problems = append(problems, fmt.Sprintf("%s name %s, which none of the %d build(s) of %s given links",
				p.said, path, len(builds), p.name))
		}
	}
	return problems
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
