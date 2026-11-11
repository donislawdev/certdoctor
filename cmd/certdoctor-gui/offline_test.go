//go:build cgo

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
)

// TestTheToolkitReadsNoWebAddress asks the toolkit to read a page from a
// server on this machine, first with its own handler - which has to reach the
// server, or this test proves nothing - and then with offline behind both
// schemes, which has to refuse every way of reading it without the server
// hearing a thing. A file on disk is still read afterwards.
func TestTheToolkitReadsNoWebAddress(t *testing.T) {
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = w.Write([]byte("page"))
	}))
	defer server.Close()
	page, err := storage.ParseURI(server.URL + "/page")
	if err != nil {
		t.Fatalf("parsing the address of the test server: %v", err)
	}

	test.NewTempApp(t) // registers the toolkit's own handler, as app.New does
	if r, err := storage.Reader(page); err == nil {
		_ = r.Close()
	}
	if asked.Load() == 0 {
		t.Fatal("the toolkit's own handler did not reach the server, so the refusal below would prove nothing")
	}

	refuseAddresses()
	before := asked.Load()
	if _, err := storage.Reader(page); !errors.Is(err, errNoAddress) {
		t.Errorf("reading a web address answered %v, and has to answer errNoAddress", err)
	}
	if _, err := storage.Exists(page); !errors.Is(err, errNoAddress) {
		t.Errorf("asking whether a web address exists answered %v, and has to answer errNoAddress", err)
	}
	if _, err := storage.CanRead(page); !errors.Is(err, errNoAddress) {
		t.Errorf("asking whether a web address can be read answered %v, and has to answer errNoAddress", err)
	}
	if secure, err := storage.ParseURI("https" + server.URL[len("http"):] + "/page"); err != nil {
		t.Errorf("parsing an https address: %v", err)
	} else if _, err := storage.Reader(secure); !errors.Is(err, errNoAddress) {
		t.Errorf("reading an https address answered %v, and has to answer errNoAddress", err)
	}
	if got := asked.Load(); got != before {
		t.Errorf("the server was asked %d more time(s) after the refusal", got-before)
	}

	readsAFile(t)
}

// readsAFile is the other side: the person's files are still read.
func readsAFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("writing a file to read: %v", err)
	}
	r, err := storage.Reader(storage.NewFileURI(path))
	if err != nil {
		t.Fatalf("reading a file after the refusal: %v", err)
	}
	defer func(c fyne.URIReadCloser) { _ = c.Close() }(r)
}
