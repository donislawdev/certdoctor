package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// committed is the file the website reads, relative to this package.
var committed = filepath.Join("..", "..", "web", "data", "facts", "certdoctor.json")

// TestTheSiteSaysWhatTheProgramSays fails when the program changed something
// the website shows and the website's copy was not written again.
func TestTheSiteSaysWhatTheProgramSays(t *testing.T) {
	saved, err := os.ReadFile(committed)
	if err != nil {
		t.Fatalf("%v - write it with: go run ./cmd/sitefacts > web/data/facts/certdoctor.json", err)
	}
	if err := compare(saved, now(t)); err != nil {
		t.Error(err)
	}
}

// TestTheSiteFactsCheckCanFail is the canary: a file that differs from what
// the program says by one word is refused, so the check above cannot pass by
// comparing nothing.
func TestTheSiteFactsCheckCanFail(t *testing.T) {
	said := now(t)
	if err := compare(said, said); err != nil {
		t.Fatalf("the program's own words were refused: %v", err)
	}
	altered := bytes.Replace(said, []byte(`"DIAGNOSIS"`), []byte(`"DIAGNOSED"`), 1)
	if bytes.Equal(altered, said) {
		t.Fatal("the canary changed nothing - the exit codes are no longer in the document")
	}
	if compare(altered, said) == nil {
		t.Error("a file naming an exit code the program does not have was accepted")
	}
}

func now(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := write(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// compare reads the saved file with its line endings as a checkout on Windows
// may have them, because git normalises them on commit and the comparison is
// about words, not bytes on one machine.
func compare(saved, said []byte) error {
	if strings.ReplaceAll(string(saved), "\r\n", "\n") == string(said) {
		return nil
	}
	return fmt.Errorf("%s says something the program no longer says - write it again with "+
		"go run ./cmd/sitefacts > web/data/facts/certdoctor.json and read the website's diff", committed)
}
