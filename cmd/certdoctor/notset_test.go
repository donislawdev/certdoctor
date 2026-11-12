package main

import "strings"

// listedAsNotSet says whether the page names a variable in its "not set"
// paragraph - ADR137 - read the way a person reads it: every word after the
// label, up to the first one that does not end in a comma.
func listedAsNotSet(page, name string) bool {
	_, after, found := strings.Cut(page, "not set (default):")
	if !found {
		return false
	}
	for _, word := range strings.Fields(after) {
		entry, more := strings.CutSuffix(word, ",")
		if entry == name {
			return true
		}
		if !more {
			return false
		}
	}
	return false
}
