// Fixture, never compiled. A test writing into the working tree instead of into
// a temporary directory of its own.
package store

import (
	"os"
	"testing"
)

func TestSomethingAndLeaveLitter(t *testing.T) {
	if err := os.WriteFile("fixture.pem", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}
