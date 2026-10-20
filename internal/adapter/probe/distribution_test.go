package probe

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// How a Linux machine names its distribution and where it keeps its bundle,
// asked here where it lives - the platform store's row, curl and git each pin
// what they do with the answer.

// THE ID IS THE DISTRIBUTION'S OWN, checked against os-release(5) before it is
// printed - decided by the owner 2026-10-15.
func TestTheIDIsTheOneOsReleaseGives(t *testing.T) {
	const etc, usr = "/etc/os-release", "/usr/lib/os-release"
	cases := []struct {
		name string
		etc  string
		usr  string
		err  bool
		want string
	}{
		{name: "bare", etc: "NAME=Alpine\nID=alpine\nVERSION_ID=3.24.1\n", want: "alpine"},
		{name: "double quotes", etc: `ID="rhel"` + "\n" + `ID_LIKE="fedora"`, want: "rhel"},
		{name: "single quotes", etc: "ID='debian'", want: "debian"},
		{name: "the last assignment wins", etc: "ID=first\nID=second", want: "second"},
		{name: "a carriage return", etc: "ID=ubuntu\r\n", want: "ubuntu"},
		{name: "no ID at all", etc: "NAME=Something\n", want: "linux"},
		{name: "an empty ID", etc: "ID=\n", want: "linux"},
		{name: "upper case is not an ID", etc: "ID=Ubuntu", want: "linux"},
		{name: "a space is not an ID", etc: `ID="a b"`, want: "linux"},
		{name: "an escape is not an ID", etc: "ID=\x1b[31mred", want: "linux"},
		{name: "a page is not an ID", etc: "ID=" + strings.Repeat("a", 65), want: "linux"},
		{name: "sixty-four is", etc: "ID=" + strings.Repeat("a", 64), want: strings.Repeat("a", 64)},
		{name: "digits, dots, dashes and underscores are", etc: "ID=a.b_c-9", want: "a.b_c-9"},
		{name: "unmatched quotes", etc: `ID="rhel`, want: "linux"},
		{name: "only /usr/lib", usr: "ID=fedora", want: "fedora"},
		{name: "/etc is used exclusively", etc: "NAME=x", usr: "ID=fedora", want: "linux"},
		{name: "/etc unreadable", err: true, usr: "ID=fedora", want: "linux"},
		{name: "neither", want: "linux"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDisk()
			if c.etc != "" {
				d.files[etc] = []byte(c.etc)
			}
			if c.usr != "" {
				d.files[usr] = []byte(c.usr)
			}
			if c.err {
				d.errs[etc] = fmt.Errorf("denied")
			}
			if got := Distribution(d.source, LinuxReleases); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// THE FIRST BUNDLE THAT EXISTS IS THE ONE, a missing one is passed over, and
// one that exists and cannot be read ends the search with its name.
func TestTheFirstBundleThatExistsIsTheOne(t *testing.T) {
	d := newDisk()
	d.files[LinuxBundles[1]] = []byte("second")
	d.files[LinuxBundles[2]] = []byte("third")
	path, data, err := FirstBundle(d.source, LinuxBundles)
	if path != LinuxBundles[1] || string(data) != "second" || err != nil {
		t.Errorf("got %q %q %v, want the second bundle - the first is missing", path, data, err)
	}
	if slices.Contains(d.reads, LinuxBundles[2]) {
		t.Error("a bundle after the first one that exists was read")
	}

	d = newDisk()
	d.errs[LinuxBundles[0]] = &fs.PathError{Op: "open", Path: LinuxBundles[0], Err: fs.ErrPermission}
	d.files[LinuxBundles[1]] = []byte("second")
	path, _, err = FirstBundle(d.source, LinuxBundles)
	if path != LinuxBundles[0] || !strings.Contains(fmt.Sprint(err), "permission") {
		t.Errorf("got %q %v, want the first bundle named with why it could not be read", path, err)
	}

	path, data, err = FirstBundle(newDisk().source, LinuxBundles)
	if path != "" || data != nil || err != nil {
		t.Errorf("got %q %q %v, want nothing at all where no bundle exists", path, data, err)
	}
}

// THE LISTS ARE GO'S AND OS-RELEASE(5)'S, pinned, so a change to either is a
// decision rather than a drift. Sources are on the two variables.
func TestTheListsAreGosAndOsReleases(t *testing.T) {
	bundles := []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}
	if !slices.Equal(LinuxBundles, bundles) {
		t.Errorf("bundles %v, want Go's %v", LinuxBundles, bundles)
	}
	if !slices.Equal(LinuxReleases, []string{"/etc/os-release", "/usr/lib/os-release"}) {
		t.Errorf("releases %v, want os-release(5)'s precedence", LinuxReleases)
	}
	if FallbackDistribution != "linux" {
		t.Errorf("fallback %q, want os-release(5)'s default", FallbackDistribution)
	}
}
