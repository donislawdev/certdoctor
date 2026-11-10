//go:build cgo

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOnlyAFileIsInTheWay - Save report asks before replacing a file, and only
// a file: a folder of that name cannot be replaced by the command line's
// rename, which refuses it in its own words, and a name with nothing at it is
// the ordinary case.
func TestOnlyAFileIsInTheWay(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "report.html")
	if err := os.WriteFile(file, []byte("<!DOCTYPE html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(dir, "report.md")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		file:                              true,
		folder:                            false,
		filepath.Join(dir, "report.json"): false,
		filepath.Join(dir, "gone", "x"):   false,
	} {
		if got := present(path); got != want {
			t.Errorf("%s: present %v, want %v", path, got, want)
		}
	}
}
