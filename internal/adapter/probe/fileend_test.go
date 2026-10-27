package probe

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Only a line feed ends a line for encoding/pem and for OpenSSL, so only a line
// feed lets an appended block start its own - ADR114 B13.
func TestOnlyALineFeedEndsTheLastLine(t *testing.T) {
	cases := []struct {
		name string
		data string
		want report.FileEnd
	}{
		{"an empty file", "", report.FileEndLineBreak},
		{"a line feed", "-----END CERTIFICATE-----\n", report.FileEndLineBreak},
		{"a carriage return and a line feed", "-----END CERTIFICATE-----\r\n", report.FileEndLineBreak},
		{"no line break", "-----END CERTIFICATE-----", report.FileEndMidLine},
		{"a carriage return alone", "-----END CERTIFICATE-----\r", report.FileEndMidLine},
		{"a space after the last line feed", "-----END CERTIFICATE-----\n ", report.FileEndMidLine},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EndOf([]byte(c.data)); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

// ReadEndOf answers for a file this program did not read for the verdict, so
// every way the read can go wrong is an end it did not see.
func TestAFileWhoseEndCouldNotBeReadGetsNoAnswer(t *testing.T) {
	serving := func(r io.Reader, err error) func(string) (io.ReadCloser, error) {
		return func(string) (io.ReadCloser, error) {
			if err != nil {
				return nil, err
			}
			return io.NopCloser(r), nil
		}
	}
	broken := errors.New("the disk went away")
	cases := []struct {
		name   string
		source func(string) (io.ReadCloser, error)
		want   report.FileEnd
	}{
		// THE POSITIVE TWINS - OBS56. A reader answering "unseen" for everything
		// would pass every other case here.
		{"a file ending with a line feed", serving(bytes.NewReader([]byte("a\n")), nil), report.FileEndLineBreak},
		{"a file ending mid-line", serving(bytes.NewReader([]byte("a\nb")), nil), report.FileEndMidLine},
		{"the port refuses the path", serving(nil, broken), report.FileEndUnseen},
		{"the read breaks after a line feed", serving(io.MultiReader(bytes.NewReader([]byte("a\n")),
			failing{broken}), nil), report.FileEndUnseen},
		{"a file of exactly the ceiling", serving(io.LimitReader(lineFeeds{}, endCeiling), nil),
			report.FileEndLineBreak},
		{"a file past the ceiling", serving(io.LimitReader(lineFeeds{}, endCeiling+1), nil), report.FileEndUnseen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ReadEndOf(c.source, "/etc/ssl/extra.pem"); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

// failing is a reader that only fails.
type failing struct{ err error }

func (f failing) Read([]byte) (int, error) { return 0, f.err }

// lineFeeds is an endless file of line feeds.
type lineFeeds struct{}

func (lineFeeds) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '\n'
	}
	return len(p), nil
}
