package python

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The interpreter hands back certificates, not the file's bytes, so the probe
// reads the end of the file the command would append to - ADR114 B13. That is
// the row's path, the platform's own bundle when that is the file Python read.
func TestTheRowSaysHowTheFileItWouldAppendToEnds(t *testing.T) {
	b := newBench(t)
	const bundle, named, own = "/etc/ssl/certs/ca-certificates.crt", "/usr/lib/ssl/cert.pem", "/home/jdoe/ca.pem"
	whole := pemOf(b.root)
	cases := []struct {
		name, platform, cafile, put, content string
		want                                 report.FileEnd
	}{
		{"a file of its own ending with a line feed", "linux", own, own, whole, report.FileEndLineBreak},
		{"a file of its own ending mid-line", "linux", own, own, strings.TrimSuffix(whole, "\n"), report.FileEndMidLine},
		{"the platform's bundle under another name", "linux", named, bundle, strings.TrimSuffix(whole, "\n"),
			report.FileEndMidLine},
		{"a file gone before its end is read", "darwin", named, "", "", report.FileEndUnseen},
		{"windows reads the stores, not the file", "windows", named, named, whole, report.FileEndUnseen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := listing(0x8000, b.root)
			a.CAFile = text(c.cafile)
			store := one(t, c.platform, a, b.chain(), func(w *world) {
				if c.put != "" {
					w.disk.put(c.put, c.content)
				}
				if c.cafile == named && c.put == bundle {
					w.disk.links[filepath.Clean(named)] = bundle
				}
			})
			if store.FileEnd != c.want {
				t.Errorf("FileEnd %d, want %d (path %q)", store.FileEnd, c.want, store.StorePath)
			}
		})
	}
}
