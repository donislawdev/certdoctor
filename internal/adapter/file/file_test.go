package file

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// spy is an inner source that records what it was asked for and hands back
// bytes from memory. Nothing in this package's tests touches a disk.
type spy struct {
	asked   []string
	content string
}

func (s *spy) open(path string) (io.ReadCloser, error) {
	s.asked = append(s.asked, path)
	return io.NopCloser(strings.NewReader(s.content)), nil
}

// TestALocalPathReachesTheInnerSource is the ordinary path, and it belongs here
// so the refusals below mean something: a source that refused everything would
// satisfy every other test in this file.
func TestALocalPathReachesTheInnerSource(t *testing.T) {
	inner := &spy{content: "nameserver 192.0.2.53\n"}
	guarded := Guarded(inner.open, 0, nil)

	handle, err := guarded("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("a local path was refused: %v", err)
	}
	got, err := io.ReadAll(handle)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != inner.content {
		t.Errorf("the bytes came back as %q", got)
	}
	if len(inner.asked) != 1 {
		t.Errorf("the inner source was asked %d times", len(inner.asked))
	}
}

// TestARemotePathIsNeverOpened is docs/14 section 3a at the only place it can
// be enforced.
//
// The assertion that matters is that the inner source was NOT CALLED. Opening
// is the act that connects, so a check performed after the open would report
// the problem having already caused it - and on a UNC path to an unreachable
// host that costs twenty seconds and the user's identity.
func TestARemotePathIsNeverOpened(t *testing.T) {
	remote := []string{
		`\\fileserver\certs\ca.pem`,
		"//fileserver/certs/ca.pem",
		"http://internal.example.com/ca.pem",
		"  \\\\fileserver\\certs\\ca.pem  ",
	}

	for _, path := range remote {
		inner := &spy{content: "should never be read"}
		guarded := Guarded(inner.open, 0, nil)

		handle, err := guarded(path)

		if len(inner.asked) != 0 {
			t.Errorf("%q was opened: %v", path, inner.asked)
		}
		if handle != nil {
			t.Errorf("%q came back with something readable", path)
		}
		var remotePath *RemotePath
		if !errors.As(err, &remotePath) {
			t.Errorf("%q was refused with an indistinguishable error: %v", path, err)
		}
	}
}

// TestAMappedDriveIsNotRecognisedAndThatIsWritten pins the known blind spot.
//
// A drive letter pointing at a share is remote and looks exactly like a local
// disk from here; answering that needs the operating system, which this package
// may not ask. The gap is pinned by a test rather than left in a comment,
// because a guard believed to be wider than it is reads as permission to stop
// looking - and the day somebody teaches it drive letters, this test is what
// tells them the behaviour changed on purpose.
func TestAMappedDriveIsNotRecognisedAndThatIsWritten(t *testing.T) {
	if IsRemote(`Z:\certs\ca.pem`) {
		t.Error("a drive letter is now treated as remote - if that was intended, this test is the place to say so")
	}
	if IsRemote(`C:\Users\jdoe\ca.pem`) {
		t.Error("an ordinary local path was treated as remote")
	}
	if IsRemote("/etc/ssl/certs/ca-bundle.crt") {
		t.Error("an ordinary POSIX path was treated as remote")
	}
}

// TestTheLimitStopsBytesBeforeTheyReachAParser is docs/14 section 2.3.
//
// The cost of a hostile document is spent inside the parser, so the only lever
// is how many bytes it is ever given. This checks the lever holds.
func TestTheLimitStopsBytesBeforeTheyReachAParser(t *testing.T) {
	inner := &spy{content: strings.Repeat("x", 500)}
	guarded := Guarded(inner.open, 100, nil)

	handle, err := guarded("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	got, err := io.ReadAll(handle)

	var tooLarge *TooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("reading past the limit did not report it: err=%v, %d bytes", err, len(got))
	}
	if len(got) > 100 {
		t.Errorf("%d bytes got through a limit of 100", len(got))
	}
	if tooLarge.Limit != 100 {
		t.Errorf("the refusal reports a limit of %d", tooLarge.Limit)
	}
}

// TestAFileInsideTheLimitIsReadWhole is the other side. A cap that also
// truncated honest files would be worse than no cap: a parser handed a silently
// shortened configuration produces a confident wrong answer about it.
func TestAFileInsideTheLimitIsReadWhole(t *testing.T) {
	inner := &spy{content: strings.Repeat("y", 100)}
	guarded := Guarded(inner.open, 100, nil)

	handle, err := guarded("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	got, err := io.ReadAll(handle)
	if err != nil {
		t.Fatalf("a file exactly at the limit was refused: %v", err)
	}
	if string(got) != inner.content {
		t.Errorf("%d bytes came back for a %d byte file", len(got), len(inner.content))
	}
}

// TestALimitOfZeroMeansNoLimit covers the documented way of switching the cap
// off, which is what the first parser will use until its number is measured.
func TestALimitOfZeroMeansNoLimit(t *testing.T) {
	inner := &spy{content: strings.Repeat("z", 10_000)}
	guarded := Guarded(inner.open, 0, nil)

	handle, err := guarded("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	got, err := io.ReadAll(handle)
	if err != nil {
		t.Fatalf("an unlimited read failed: %v", err)
	}
	if len(got) != 10_000 {
		t.Errorf("%d bytes came back with no limit set", len(got))
	}
}

// TestTheRecorderSeesRefusedPathsToo is the half a success-only recorder would
// lose - and a refused path is the finding, not the footnote.
func TestTheRecorderSeesRefusedPathsToo(t *testing.T) {
	type attempt struct {
		path   string
		opened bool
	}
	var seen []attempt
	inner := &spy{content: "ok"}
	guarded := Guarded(inner.open, 0, func(path string, opened bool) { seen = append(seen, attempt{path, opened}) })

	_, _ = guarded("/etc/resolv.conf")
	_, _ = guarded(`\\fileserver\certs\ca.pem`)

	if len(seen) != 2 {
		t.Fatalf("the recorder saw %d attempts: %v", len(seen), seen)
	}
	if !seen[0].opened {
		t.Error("the local path was recorded as not opened")
	}
	if seen[1].opened {
		t.Error("the remote path was recorded as opened, and it must never be")
	}
}

// TestNoSourceAtAllIsAnErrorRatherThanAPanic keeps a defect on our side from
// ending the process instead of degrading with a reason.
func TestNoSourceAtAllIsAnErrorRatherThanAPanic(t *testing.T) {
	guarded := Guarded(nil, 0, nil)

	handle, err := guarded("/etc/resolv.conf")
	if err == nil {
		t.Fatal("a missing source reported success")
	}
	if handle != nil {
		t.Error("something readable came back from a source that does not exist")
	}
	var remotePath *RemotePath
	if errors.As(err, &remotePath) {
		t.Error("a defect on our side was reported as a remote path, which blames the user's configuration instead of us")
	}
}

// closeSpy records that the handle underneath was released.
type closeSpy struct {
	io.Reader
	closed bool
}

func (c *closeSpy) Close() error { c.closed = true; return nil }

// TestClosingReachesTheHandleUnderneath covers the release path.
//
// The cap wraps the real handle, so if it forgot to pass Close along, every
// capped read would leak a descriptor - and on the machine being diagnosed that
// is a leak this tool caused while looking for somebody else's problem.
func TestClosingReachesTheHandleUnderneath(t *testing.T) {
	underlying := &closeSpy{Reader: strings.NewReader("x")}
	guarded := Guarded(func(string) (io.ReadCloser, error) { return underlying, nil }, 10, nil)

	handle, err := guarded("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if !underlying.closed {
		t.Error("the handle underneath was never closed")
	}
}

// TestOnceTooLargeItStaysTooLarge covers the second read after the limit blew.
//
// A caller that ignores the first error and reads again must not start getting
// bytes back. Without the latch, the next call would find room again and hand
// over more of a file already judged too big.
func TestOnceTooLargeItStaysTooLarge(t *testing.T) {
	inner := &spy{content: strings.Repeat("x", 500)}
	guarded := Guarded(inner.open, 10, nil)

	handle, err := guarded("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if _, err := io.ReadAll(handle); err == nil {
		t.Fatal("the first read did not report the overrun")
	}

	buffer := make([]byte, 100)
	n, err := handle.Read(buffer)
	var tooLarge *TooLarge
	if !errors.As(err, &tooLarge) {
		t.Errorf("reading again after the overrun gave %d bytes and %v", n, err)
	}
	if n != 0 {
		t.Errorf("%d more bytes came back after the file was judged too large", n)
	}
}

// TestAFailingSourceIsReportedRatherThanWrapped covers the ordinary failure:
// the file is local, allowed, and simply not there. That is a fact about the
// user's machine and has to arrive as itself.
func TestAFailingSourceIsReportedRatherThanWrapped(t *testing.T) {
	missing := errors.New("no such file")
	var opened bool
	guarded := Guarded(
		func(string) (io.ReadCloser, error) { return nil, missing },
		100,
		func(_ string, ok bool) { opened = ok })

	handle, err := guarded("/etc/resolv.conf")
	if !errors.Is(err, missing) {
		t.Errorf("the underlying failure did not come back: %v", err)
	}
	if handle != nil {
		t.Error("something readable came back from a source that failed")
	}
	if opened {
		t.Error("a failed open was recorded as opened")
	}
}
