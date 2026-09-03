//go:build !windows

package dns

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
)

// WHY THIS FILE EXISTS AT ALL, and it is a measurement rather than tidiness.
//
// On 2026-09-03 the coverage gate went red on Linux and only on Linux: this
// package measured 91.4 percent on Windows and 75.8 in a container, against a
// floor of 90. The whole difference sat here - Enumerate at 12.5 percent,
// NameSources at 0.0 - which is to say the POSIX read of resolv.conf had never
// been executed by anything. It was invisible for a plain reason: the tests on
// ubuntu were failing EARLIER, so the coverage step never ran, and the floor
// file's own claim that Linux comes out at or above every Windows number was
// true when it was written and had quietly stopped being true. OBS100.
//
// So these are not tests written to move a number. The statements below decide
// which resolvers this program is ALLOWED TO CONNECT TO - inviolable rule 16 -
// and until now nothing had ever asked whether that path works.

// disk stands for a filesystem holding exactly the files it was given.
//
// IT REFUSES EVERYTHING ELSE WITH fs.ErrNotExist, and that strictness is the
// discipline of this fake rather than a detail of it. A fake more permissive
// than the disk it stands for invents subjects the code will never meet - which
// is not a worry but a defect this repository has already had, on 2026-09-02,
// when Windows-shaped keys resolved on Linux and conjured a third git
// installation onto a machine that has two.
//
// It also counts closes, because a handle this program forgets to close is a
// descriptor it leaks on the machine of somebody who ran it once to ask a
// question.
type disk struct {
	files   map[string]string
	asked   []string
	closed  int
	readErr error
}

func (d *disk) open(path string) (io.ReadCloser, error) {
	d.asked = append(d.asked, path)
	body, ok := d.files[path]
	if !ok {
		// Wrapped the way a real os.Open failure is, so that a caller testing
		// for fs.ErrNotExist is testing against the shape it will really meet.
		return nil, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
	}
	return &handle{owner: d, body: strings.NewReader(body)}, nil
}

type handle struct {
	owner   *disk
	body    *strings.Reader
	partial bool
}

// Read hands back the content, or - when the disk was given a readErr - a
// FRAGMENT and then the failure.
//
// THE FRAGMENT IS THE POINT AND NOT A DETAIL OF THE FAKE. A read that dies on
// its first call and a read that dies half way through are different subjects,
// and only the second is interesting here: it is what a disconnected network
// mount looks like from inside io.ReadAll, and it is the one that could leave a
// caller holding half a resolv.conf. Half a file reported as a whole one would
// be a confident wrong answer about somebody's network, which is the failure
// this whole program exists to avoid making.
func (h *handle) Read(p []byte) (int, error) {
	if h.owner.readErr == nil {
		return h.body.Read(p)
	}
	if !h.partial && len(p) > 0 {
		h.partial = true
		n, _ := h.body.Read(p[:1])
		return n, nil
	}
	return 0, h.owner.readErr
}

func (h *handle) Close() error {
	h.owner.closed++
	return nil
}

// utf16le is a file this program refuses to guess at: a byte order mark and
// then text nobody here can read as configuration.
var utf16le = []byte{0xFF, 0xFE, 'n', 0x00, 's', 0x00}

// TestTheResolverListIsReadFromTheFileEveryUnixSystemWritesItTo is the ordinary
// path, and it belongs first so the refusals below mean something - an Enumerate
// that failed on everything would satisfy every other test in this file.
//
// THE PATH IS SPELLED OUT HERE AND NOT TAKEN FROM ResolverConfPath. Asserting
// against the constant the code uses would make this function its own oracle:
// point the constant somewhere else and both sides would move together, with
// nothing going red. That is OBS48, and it has already been paid for in this
// repository once.
func TestTheResolverListIsReadFromTheFileEveryUnixSystemWritesItTo(t *testing.T) {
	machine := &disk{files: map[string]string{
		"/etc/resolv.conf": "nameserver 192.0.2.53\nnameserver 192.0.2.54\nsearch example.test\n",
	}}

	found, err := Enumerate(machine.open)
	if err != nil {
		t.Fatalf("a readable resolv.conf was not read: %v", err)
	}

	if len(machine.asked) != 1 || machine.asked[0] != "/etc/resolv.conf" {
		t.Errorf("the resolvers were looked for in %v and not in /etc/resolv.conf", machine.asked)
	}
	if machine.closed != 1 {
		t.Errorf("the file was closed %d times and should have been closed once", machine.closed)
	}

	// ORDER IS CONFIGURATION. A resolver library tries these in the order the
	// file lists them, so a fold that sorted or reversed them would report a
	// machine that behaves differently from the one in front of the reader.
	want := []string{"192.0.2.53", "192.0.2.54"}
	for name, list := range map[string][]string{"ToAsk": found.ToAsk, "Known": found.Known} {
		if len(list) != len(want) {
			t.Fatalf("%s came back as %v where %v was expected", name, list, want)
		}
		for i := range want {
			if list[i] != want[i] {
				t.Errorf("%s position %d is %q and should be %q", name, i, list[i], want[i])
			}
		}
	}
	if found.From != "/etc/resolv.conf" {
		t.Errorf("the report would say the list came from %q", found.From)
	}
}

// TestBothListsAreTheSameHereAndSayingOtherwiseWouldInventADifference holds the
// sentence the production comment makes.
//
// The two-list shape exists because Windows can be asked two questions with two
// honest answers. This system records its resolvers in one place and uses what
// it records, so a difference between the lists here would be one this code
// made up - and the wider list is what seeds the set of addresses this run is
// permitted to dial.
func TestBothListsAreTheSameHereAndSayingOtherwiseWouldInventADifference(t *testing.T) {
	machine := &disk{files: map[string]string{
		"/etc/resolv.conf": "nameserver 2001:db8::53\nnameserver 192.0.2.53\n",
	}}

	found, err := Enumerate(machine.open)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(found.ToAsk) != len(found.Known) {
		t.Fatalf("the list to ask has %d entries and the wider one has %d", len(found.ToAsk), len(found.Known))
	}
	for i := range found.ToAsk {
		if found.ToAsk[i] != found.Known[i] {
			t.Errorf("entry %d differs between the lists: %q against %q", i, found.ToAsk[i], found.Known[i])
		}
	}
}

// TestAnEmptyResolverFileIsAnAnswerAndNotAFailure is probe S11 written down.
//
// A machine with an empty resolv.conf still resolves names - the platform has
// its own fallback - so an error here would report a broken machine where there
// is a machine configured differently from the one we expected.
func TestAnEmptyResolverFileIsAnAnswerAndNotAFailure(t *testing.T) {
	machine := &disk{files: map[string]string{"/etc/resolv.conf": ""}}

	found, err := Enumerate(machine.open)
	if err != nil {
		t.Fatalf("an empty resolv.conf was reported as a failure: %v", err)
	}
	if len(found.ToAsk) != 0 {
		t.Errorf("an empty file produced %v", found.ToAsk)
	}
	if found.From == "" {
		t.Error("the enumeration did not say where it looked, and that goes into the report")
	}
}

// TestARefusalFromTheGuardedPortReachesTheCallerAsItsOwnReason is the one test
// here that is about somebody else's machine rather than about ours.
//
// resolv.conf IS A SYMBOLIC LINK on WSL and on any systemd machine, and a link
// into a mount from another host is a remote path wearing a local name. The
// guarded port refuses it and says so - docs/14 section 3a - and that refusal is
// an ANSWER a reader came here for: "your resolv.conf is a link to a file on a
// share". If this function flattened it into an ordinary failure, the report
// would say the resolvers could not be read and never say why.
func TestARefusalFromTheGuardedPortReachesTheCallerAsItsOwnReason(t *testing.T) {
	refusal := &file.RemotePath{Path: "/etc/resolv.conf", Via: "//host/share/resolv.conf"}

	found, err := Enumerate(func(string) (io.ReadCloser, error) { return nil, refusal })
	if err == nil {
		t.Fatal("a path leading off this machine was read instead of being reported")
	}

	var remote *file.RemotePath
	if !errors.As(err, &remote) {
		t.Errorf("the refusal did not survive as itself, so the report cannot name it: %v", err)
	}
	if len(found.ToAsk) != 0 || len(found.Known) != 0 {
		t.Errorf("a refused read still produced resolvers: %v", found)
	}
}

// TestAFileThisProgramCannotDecodeIsNamedRatherThanReadAsEmpty keeps a refusal
// from the parser from looking like a machine with no resolvers.
//
// ADR27 puts that judgement in the core, where an unreadable encoding is an
// ANSWER rather than a crash. What has to be true HERE is narrower: the answer
// reaches the caller as an error that names the file, because "no resolvers"
// and "your resolv.conf is in UTF-16" send a reader to two different places.
func TestAFileThisProgramCannotDecodeIsNamedRatherThanReadAsEmpty(t *testing.T) {
	machine := &disk{files: map[string]string{"/etc/resolv.conf": string(utf16le)}}

	found, err := Enumerate(machine.open)
	if err == nil {
		t.Fatal("a file in an encoding nobody here reads came back as an answer")
	}
	if !strings.Contains(err.Error(), "/etc/resolv.conf") {
		t.Errorf("the failure does not say which file it was about: %v", err)
	}
	if len(found.ToAsk) != 0 {
		t.Errorf("an undecodable file still produced resolvers: %v", found.ToAsk)
	}
	// THE HANDLE STILL HAS TO BE CLOSED. The close is deferred, so a rewrite that
	// moved it below the parse would leak on exactly the machines that have the
	// unusual file - the ones least likely to be tried by hand.
	if machine.closed != 1 {
		t.Errorf("the file was closed %d times on the parse failure path", machine.closed)
	}
}

// TestAReadThatFailsPartWayThroughIsNotReportedAsAnEmptyMachine covers the
// third way this can go wrong, which is neither the open nor the parse.
//
// A file that opens and then fails to read is what a disconnected network mount
// looks like from here, and reporting it as an empty configuration would blame
// the user's DNS setup for a storage problem.
func TestAReadThatFailsPartWayThroughIsNotReportedAsAnEmptyMachine(t *testing.T) {
	broken := errors.New("input/output error")
	machine := &disk{
		files:   map[string]string{"/etc/resolv.conf": "nameserver 192.0.2.53\n"},
		readErr: broken,
	}

	found, err := Enumerate(machine.open)
	if err == nil {
		t.Fatal("a file that could not be read came back as an answer")
	}
	if !errors.Is(err, broken) {
		t.Errorf("the reason the read failed did not survive: %v", err)
	}
	if len(found.ToAsk) != 0 {
		t.Errorf("a failed read still produced resolvers: %v", found.ToAsk)
	}
	if machine.closed != 1 {
		t.Errorf("the file was closed %d times on the read failure path", machine.closed)
	}
}

// TestWithNoWayToReadAFileTheResolversAreUnknownRatherThanAbsent is the nil
// port, and it is not a defensive nicety.
//
// Inviolable rule 15: unknown degrades WITH A REASON and never reports a clean
// machine. An empty list here would travel into the report as "this machine has
// no resolvers", which is a confident wrong answer about somebody's network.
func TestWithNoWayToReadAFileTheResolversAreUnknownRatherThanAbsent(t *testing.T) {
	found, err := Enumerate(nil)
	if err == nil {
		t.Fatal("with no way to read anything the enumeration still answered")
	}
	if !strings.Contains(err.Error(), "/etc/resolv.conf") {
		t.Errorf("the failure does not name the file it could not read: %v", err)
	}
	if len(found.ToAsk) != 0 || len(found.Known) != 0 {
		t.Errorf("nothing was read and resolvers came back anyway: %v", found)
	}

	sources, err := NameSources(nil)
	if err == nil {
		t.Fatal("with no way to read anything the name sources still answered")
	}
	if !strings.Contains(err.Error(), "/etc/nsswitch.conf") {
		t.Errorf("the failure does not name the file it could not read: %v", err)
	}
	if sources.Declared {
		t.Error("nothing was read and the order was reported as declared anyway")
	}
}

// TestTheLookupOrderIsReadFromTheFileThisSystemRecordsItIn is the second half of
// what a derived answer has to say about itself - ADR28.
//
// Probe S10 measured why this file matters: change that line to "hosts: dns" and
// an entry in the hosts file stops resolving. Our own view never looks there
// under any configuration, so this line is the only honest way to say why the
// two views disagree about a name like localhost.
//
// The path is spelled out here for the same reason it is in the test above.
func TestTheLookupOrderIsReadFromTheFileThisSystemRecordsItIn(t *testing.T) {
	machine := &disk{files: map[string]string{
		"/etc/nsswitch.conf": "passwd: files\nhosts: files [NOTFOUND=return] dns\n",
	}}

	sources, err := NameSources(machine.open)
	if err != nil {
		t.Fatalf("a readable nsswitch.conf was not read: %v", err)
	}

	if len(machine.asked) != 1 || machine.asked[0] != "/etc/nsswitch.conf" {
		t.Errorf("the lookup order was looked for in %v and not in /etc/nsswitch.conf", machine.asked)
	}
	if machine.closed != 1 {
		t.Errorf("the file was closed %d times and should have been closed once", machine.closed)
	}
	if !sources.Declared {
		t.Error("a file naming a hosts line was reported as naming none")
	}
	if !sources.ConsultsHostsFile() {
		t.Errorf("a line reading %q was read as not consulting the hosts file: %v", "hosts: files dns", sources.Order)
	}
}

// TestAMissingLookupOrderFileStaysRecognisableToTheCaller holds the contract the
// production comment states: a missing file is an ANSWER, not a failure of the
// run.
//
// THE ERROR IS RETURNED UNWRAPPED ON PURPOSE, and this is the test that says so.
// Enumerate wraps, this does not, and the difference is load-bearing: a caller
// that cannot tell "there is no such file" from "that file could not be read"
// has to describe both the same way. That is the shape ADR70 removed from L5 one
// floor up - an accusation about permissions on a machine where nobody denied
// anything - so it is worth a guard here rather than a hope.
func TestAMissingLookupOrderFileStaysRecognisableToTheCaller(t *testing.T) {
	machine := &disk{files: map[string]string{}}

	sources, err := NameSources(machine.open)
	if err == nil {
		t.Fatal("a file that is not there came back as a lookup order")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("an absent file is not recognisable as absent, so a caller must call it unreadable: %v", err)
	}
	if sources.Declared {
		t.Error("no file was read and the order was reported as declared anyway")
	}
	if machine.closed != 0 {
		t.Errorf("nothing was opened and %d closes happened", machine.closed)
	}
}

// TestALookupOrderThatCannotBeReadIsNamedRatherThanTreatedAsUndeclared keeps
// apart the two facts the production comment says are told apart.
//
// "There is no such file" and "the file is there and could not be read" are
// different facts about somebody's machine, and only the first one means the
// platform default applies.
func TestALookupOrderThatCannotBeReadIsNamedRatherThanTreatedAsUndeclared(t *testing.T) {
	broken := errors.New("input/output error")
	machine := &disk{
		files:   map[string]string{"/etc/nsswitch.conf": "hosts: files dns\n"},
		readErr: broken,
	}

	sources, err := NameSources(machine.open)
	if err == nil {
		t.Fatal("a file that could not be read came back as a lookup order")
	}
	if !strings.Contains(err.Error(), "/etc/nsswitch.conf") {
		t.Errorf("the failure does not name the file it was about: %v", err)
	}
	if !errors.Is(err, broken) {
		t.Errorf("the reason the read failed did not survive: %v", err)
	}
	if sources.Declared {
		t.Error("a failed read reported an order as declared")
	}
	if machine.closed != 1 {
		t.Errorf("the file was closed %d times on the read failure path", machine.closed)
	}
}

// TestALookupOrderInAnEncodingNobodyHereReadsIsAnErrorAndNotAnEmptyOrder is the
// parser refusal on this file, the counterpart of the resolv.conf case above.
func TestALookupOrderInAnEncodingNobodyHereReadsIsAnErrorAndNotAnEmptyOrder(t *testing.T) {
	machine := &disk{files: map[string]string{"/etc/nsswitch.conf": string(utf16le)}}

	sources, err := NameSources(machine.open)
	if err == nil {
		t.Fatal("a file in an encoding nobody here reads came back as an order")
	}
	if sources.Declared || len(sources.Order) != 0 {
		t.Errorf("an undecodable file still produced an order: %v", sources)
	}
	if machine.closed != 1 {
		t.Errorf("the file was closed %d times on the parse failure path", machine.closed)
	}
}
