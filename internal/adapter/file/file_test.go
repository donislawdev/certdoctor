package file

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spy is an inner source that records what it was asked for and hands back
// bytes from memory. Nothing in this package's tests touches a disk.
type spy struct {
	asked   []string
	content string
}

// here is a resolver for a machine on which nothing is a link: it hands the
// path back untouched. Tests that are ABOUT links supply their own, so a reader
// can tell at the call site which kind of machine a test is describing.
func here(path string) (string, error) { return path, nil }

func (s *spy) open(path string) (io.ReadCloser, error) {
	s.asked = append(s.asked, path)
	return io.NopCloser(strings.NewReader(s.content)), nil
}

// TestALocalPathReachesTheInnerSource is the ordinary path, and it belongs here
// so the refusals below mean something: a source that refused everything would
// satisfy every other test in this file.
func TestALocalPathReachesTheInnerSource(t *testing.T) {
	inner := &spy{content: "nameserver 192.0.2.53\n"}
	guarded := Guarded(inner.open, here, 0, nil)

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
		guarded := Guarded(inner.open, here, 0, nil)

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
	guarded := Guarded(inner.open, here, 100, nil)

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
	guarded := Guarded(inner.open, here, 100, nil)

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
	guarded := Guarded(inner.open, here, 0, nil)

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
	guarded := Guarded(inner.open, here, 0, func(path string, opened bool) { seen = append(seen, attempt{path, opened}) })

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
	guarded := Guarded(nil, here, 0, nil)

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
	guarded := Guarded(func(string) (io.ReadCloser, error) { return underlying, nil }, here, 10, nil)

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
	guarded := Guarded(inner.open, here, 10, nil)

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
		here,
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

// TestASymbolicLinkOffThisMachineIsNeverOpened is the gap this port was widened
// to close.
//
// The path is local as written, so every check that reads text says yes. What it
// leads to is a share on another host, and opening it authenticates the person
// running this against a machine they never named.
//
// IT IS NOT A HYPOTHETICAL SHAPE. /etc/resolv.conf, the first real file this
// program reads, is a symbolic link in WSL and on any systemd machine - measured
// on 2026-08-05, not reasoned about.
func TestASymbolicLinkOffThisMachineIsNeverOpened(t *testing.T) {
	for _, target := range []string{`\\fileserver\wsl\resolv.conf`, "//fileserver/wsl/resolv.conf"} {
		inner := &spy{content: "should never be read"}
		guarded := Guarded(inner.open, func(string) (string, error) { return target, nil }, 0, nil)

		handle, err := guarded("/etc/resolv.conf")

		if len(inner.asked) != 0 {
			t.Errorf("a link to %s was opened: %v", target, inner.asked)
		}
		if handle != nil {
			t.Errorf("a link to %s came back with something readable", target)
		}
		var remotePath *RemotePath
		if !errors.As(err, &remotePath) {
			t.Fatalf("a link to %s was refused with an indistinguishable error: %v", target, err)
		}
		// Both ends are named, because the file to go and look at is the one the
		// configuration mentions, not the one it happens to point at today.
		if remotePath.Path != "/etc/resolv.conf" || remotePath.Via != target {
			t.Errorf("the refusal named %q via %q, which does not say which file to go and fix",
				remotePath.Path, remotePath.Via)
		}
	}
}

// TestThePathIsJudgedAsWrittenBeforeAnythingIsResolved pins the ORDER, which is
// the whole of what makes the step above safe.
//
// Resolving a path is itself a filesystem operation, so a version that resolved
// first would perform the slow, identity-leaking act on exactly the path it was
// about to refuse - the twenty-one seconds behind docs/14 section 3a were spent
// asking about a UNC path, not reading one. This is the test that fails if the
// two steps are ever swapped, and nothing else in this file would notice.
func TestThePathIsJudgedAsWrittenBeforeAnythingIsResolved(t *testing.T) {
	var resolverAsked bool
	inner := &spy{content: "should never be read"}
	guarded := Guarded(inner.open, func(p string) (string, error) {
		resolverAsked = true
		return p, nil
	}, 0, nil)

	if _, err := guarded(`\\fileserver\certs\ca.pem`); err == nil {
		t.Fatal("a UNC path was accepted")
	}
	if resolverAsked {
		t.Error("the resolver was asked about a path already known to be remote - resolving touches the filesystem, " +
			"so that is the connection this guard exists to prevent, made while preventing it")
	}
	if len(inner.asked) != 0 {
		t.Error("the source was asked as well")
	}
}

// TestAPathThatIsNotThereIsHandedOnRatherThanRefused keeps the guard from
// answering a question about the user's machine with a fact about us.
//
// "Your configuration names a file that does not exist" is a real diagnosis and
// one of the more common ones. Turning it into a refusal here would report our
// caution where their misconfiguration belongs.
func TestAPathThatIsNotThereIsHandedOnRatherThanRefused(t *testing.T) {
	inner := &spy{content: "reached"}
	guarded := Guarded(inner.open, func(string) (string, error) {
		return "", fs.ErrNotExist
	}, 0, nil)

	if _, err := guarded("/etc/resolv.conf"); err != nil {
		t.Fatalf("a missing file was refused rather than handed on: %v", err)
	}
	if len(inner.asked) != 1 {
		t.Error("the source never got the chance to report the absence")
	}
}

// TestAResolverThatCannotAnswerRefusesRatherThanGuessing covers the failure that
// is NOT an absence - a permission denied on a parent directory, say.
//
// Carrying on would mean opening a path without ever having established where it
// leads, which is the one thing this port exists to establish. Unknown is
// refused, and rule 15 is the same rule seen from the other side.
func TestAResolverThatCannotAnswerRefusesRatherThanGuessing(t *testing.T) {
	inner := &spy{content: "should never be read"}
	guarded := Guarded(inner.open, func(string) (string, error) {
		return "", errors.New("permission denied")
	}, 0, nil)

	handle, err := guarded("/etc/resolv.conf")
	if err == nil {
		t.Fatal("a path whose destination could not be established was opened anyway")
	}
	if handle != nil || len(inner.asked) != 0 {
		t.Error("the source was reached despite the destination being unknown")
	}
}

// TestNoResolverAtAllRefusesEverything pins the direction a forgotten port
// fails in.
//
// It is the same choice dial.Guarded makes for a nil allowed set: a missing port
// must not read as an absence of restrictions. Loud and wrong in the safe
// direction beats quiet and wrong in the other one.
func TestNoResolverAtAllRefusesEverything(t *testing.T) {
	inner := &spy{content: "should never be read"}
	guarded := Guarded(inner.open, nil, 0, nil)

	if _, err := guarded("/etc/resolv.conf"); err == nil {
		t.Fatal("a source with no way to resolve links opened a path anyway")
	}
	if len(inner.asked) != 0 {
		t.Error("the source was reached with the link check skipped")
	}
}

// TestALinkThatStaysOnThisMachineIsOpened is the other side. A guard refusing
// every link would pass all of the above and be useless, and nobody would find
// out until the first systemd machine.
func TestALinkThatStaysOnThisMachineIsOpened(t *testing.T) {
	inner := &spy{content: "nameserver 192.0.2.53\n"}
	guarded := Guarded(inner.open, func(string) (string, error) {
		return "/run/systemd/resolve/stub-resolv.conf", nil
	}, 0, nil)

	if _, err := guarded("/etc/resolv.conf"); err != nil {
		t.Fatalf("an ordinary link on this machine was refused: %v", err)
	}
	if len(inner.asked) != 1 {
		t.Fatalf("the source was asked %d times", len(inner.asked))
	}
	// The ORIGINAL path is what the source is asked for. Opening the resolved one
	// would work and would quietly stop matching what the recorder, the report
	// and the user's own configuration all call this file.
	if inner.asked[0] != "/etc/resolv.conf" {
		t.Errorf("the source was asked for %q rather than the path it was given", inner.asked[0])
	}
}

// TestARefusalSaysWhichFileToGoAndLookAt covers the two error texts, and they
// are covered because they ARE the product here.
//
// A refusal that a person cannot act on is the same as no answer. "Your
// resolv.conf leads to a file on a share" tells somebody what to change, and it
// has to name the path THEY wrote as well as the one it turned out to be - the
// second alone would send them looking for a file their configuration never
// mentions.
func TestARefusalSaysWhichFileToGoAndLookAt(t *testing.T) {
	direct := (&RemotePath{Path: "//fileserver/ca.pem"}).Error()
	if !strings.Contains(direct, "//fileserver/ca.pem") {
		t.Errorf("a refused remote path does not name itself: %q", direct)
	}

	viaLink := (&RemotePath{Path: "/etc/resolv.conf", Via: "//fileserver/resolv.conf"}).Error()
	for _, want := range []string{"/etc/resolv.conf", "//fileserver/resolv.conf"} {
		if !strings.Contains(viaLink, want) {
			t.Errorf("a refused link does not name %q: %q", want, viaLink)
		}
	}
	if viaLink == direct {
		t.Error("a path that was remote as written and a link that led somewhere remote read identically")
	}

	// The limit is a per-call parameter now, so the number in the message is the
	// only place a reader learns which limit they hit.
	tooLarge := (&TooLarge{Path: "/etc/resolv.conf", Limit: 1 << 20}).Error()
	for _, want := range []string{"/etc/resolv.conf", "1048576"} {
		if !strings.Contains(tooLarge, want) {
			t.Errorf("an oversized file does not name %q: %q", want, tooLarge)
		}
	}
}

// THE LISTING PORT REFUSES WHAT THE READING PORT REFUSES, and the reason is the
// same one docs/14 section 3a gives: a UNC path is a connection the network
// guard cannot see. A directory is no safer than a file in that respect, so the
// rule is checked in both directions rather than trusted to be symmetrical.
func TestGuardedListRefusesAPathThatWouldLeaveThisMachine(t *testing.T) {
	var asked []string
	list := GuardedList(
		func(string) ([]string, error) { return []string{"should not happen"}, nil },
		func(path string) (string, error) { return path, nil },
		func(path string, opened bool) { asked = append(asked, path) },
	)

	names, err := list("//fileserver/java")
	if names != nil {
		t.Errorf("a remote directory was listed anyway: %v", names)
	}
	var remote *RemotePath
	if !errors.As(err, &remote) {
		t.Fatalf("the refusal is not a RemotePath finding: %v", err)
	}
	if len(asked) != 1 {
		t.Errorf("the refusal was not recorded: %v", asked)
	}
}

// A LINK IS THE HALF A TEXT CHECK CANNOT SEE - the same measured case that made
// Resolve a port in the first place.
func TestGuardedListRefusesALinkLeadingOffThisMachine(t *testing.T) {
	list := GuardedList(
		func(string) ([]string, error) { return []string{"should not happen"}, nil },
		func(string) (string, error) { return "//fileserver/java", nil },
		nil,
	)

	if _, err := list("/usr/lib/jvm"); err == nil {
		t.Fatal("a link leading to a file server was followed")
	}
}

func TestGuardedListPassesALocalDirectoryThrough(t *testing.T) {
	var opened bool
	list := GuardedList(
		func(path string) ([]string, error) { return []string{path + "/jdk-25"}, nil },
		func(path string) (string, error) { return path, nil },
		func(_ string, ok bool) { opened = ok },
	)

	names, err := list("/usr/lib/jvm")
	if err != nil {
		t.Fatalf("a local directory was refused: %v", err)
	}
	if len(names) != 1 || names[0] != "/usr/lib/jvm/jdk-25" {
		t.Errorf("got %v", names)
	}
	if !opened {
		t.Error("a successful listing was not recorded as opened")
	}
}

// An unreadable directory is passed on rather than swallowed: "the place your
// runtimes live is not there" is a fact about the machine being diagnosed.
func TestGuardedListPassesOnAFailureToList(t *testing.T) {
	list := GuardedList(
		func(string) ([]string, error) { return nil, errors.New("no such directory") },
		func(path string) (string, error) { return path, nil },
		nil,
	)
	if _, err := list("/absent"); err == nil {
		t.Error("a directory that could not be listed came back as success")
	}
}

// The live plumbing is exercised against a real temporary directory, because it
// is the one piece of this package that touches a disk and a fake would prove
// nothing about it.
func TestTheLiveListingReturnsDirectoriesOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "jdk-25"), 0o755); err != nil {
		t.Fatalf("no directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "readme.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("no file: %v", err)
	}

	names, err := LiveList()(root)
	if err != nil {
		t.Fatalf("listing failed: %v", err)
	}
	if len(names) != 1 || filepath.Base(names[0]) != "jdk-25" {
		t.Errorf("got %v, want only the directory", names)
	}
	if _, err := LiveList()(filepath.Join(root, "absent")); err == nil {
		t.Error("listing a directory that is not there came back as success")
	}
}
