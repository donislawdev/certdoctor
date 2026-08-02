// Fixture, never compiled. The correct way for a test to write: it takes a
// temporary directory, which the runtime removes afterwards.
package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSomethingCleanly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixture.pem"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}
