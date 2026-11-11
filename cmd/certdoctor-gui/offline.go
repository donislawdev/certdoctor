//go:build cgo

package main

import (
	"errors"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage/repository"
)

// errNoAddress is what the toolkit is answered for every http and https
// address it is asked to read. It never reaches the screen: nothing in the
// window asks for one, and this is what keeps it so.
var errNoAddress = errors.New("certdoctor-gui reads no web address - it reads files on this machine only")

// offline stands behind the http and https schemes in place of the toolkit's
// own handler, which app.New registers there and which reads an address with
// http.Get on the default client (fyne v2.8.2, app/app.go and
// internal/repository/http.go). With it, an image, a Markdown link or a path
// written as an address cannot make the window fetch anything - inviolable
// rule 16: this program connects only to what the person asked about, and the
// window asks about nothing itself. Handing a page to the browser on a press
// does not go through it and is not touched.
type offline struct{}

func (offline) Exists(fyne.URI) (bool, error)               { return false, errNoAddress }
func (offline) Reader(fyne.URI) (fyne.URIReadCloser, error) { return nil, errNoAddress }
func (offline) CanRead(fyne.URI) (bool, error)              { return false, errNoAddress }
func (offline) Destroy(string)                              {}

// refuseAddresses puts offline behind both schemes. It has to run after the
// application is made, because that is when the toolkit registers its own -
// notelemetry_test.go holds run to calling it there.
func refuseAddresses() {
	repository.Register("http", offline{})
	repository.Register("https", offline{})
}
