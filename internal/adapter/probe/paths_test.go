package probe

import (
	"path/filepath"
	"testing"
)

// filepathJoin keeps the relative-path test readable on every platform.
func filepathJoin(parts ...string) string { return filepath.Join(parts...) }

// absentPath is an absolute path that passes the absolute check and is still
// not there, so the test after it exercises the failure the OS reports rather
// than the one this package reports.
func absentPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "no-such-program")
}
