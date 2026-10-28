package main

import (
	"fmt"
	"maps"
	"slices"
)

// reconcile compares what the builds link with what the notices name, and
// returns every disagreement rather than the first, so that one run says
// everything a dependency update has to touch.
//
// A module a build links and the notices do not name is the reason this
// command exists: its notice would be missing from the binary as well as from
// the document. A module the notices name and no build links is the opposite
// mistake, a notice for code that is not there - checked across the builds
// given rather than for each of them, because a module linked on one system
// only belongs in the notices all the same.
func reconcile(builds []build, n notices) []string {
	var problems []string
	linked := map[string]bool{}
	for _, b := range builds {
		if b.goVersion != n.std.version {
			problems = append(problems, fmt.Sprintf("%s was built with %s, and the notices name %s",
				b.target, b.goVersion, n.std.version))
		}
		for _, path := range sortedKeys(b.deps) {
			linked[path] = true
			c, named := n.modules[path]
			switch {
			case !named:
				problems = append(problems, fmt.Sprintf("%s links %s %s, which the notices do not name",
					b.target, path, b.deps[path]))
			case c.version != b.deps[path]:
				problems = append(problems, fmt.Sprintf("%s links %s %s, and the notices name %s",
					b.target, path, b.deps[path], c.version))
			}
		}
	}
	for _, path := range sortedKeys(n.modules) {
		if !linked[path] {
			problems = append(problems, fmt.Sprintf("the notices name %s, which none of the %d build(s) given links",
				path, len(builds)))
		}
	}
	return problems
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
