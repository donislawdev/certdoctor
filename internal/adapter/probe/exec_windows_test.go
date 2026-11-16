//go:build windows

package probe

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestOnlyAProcessBornOfOursIsEnded holds endChildren to the rule that keeps it
// off somebody else's process: Windows keeps a dead parent's id in its child and
// hands ids out again, so a process naming one of ours as its parent counts only
// when it was created while that parent lived. A real process stands in for the
// child, under a made-up parent id, first outside that window and then inside.
func TestOnlyAProcessBornOfOursIsEnded(t *testing.T) {
	helper(t, "sleep")
	victim := exec.Command(self(t), "-test.run=TestHelperProcess")
	if err := victim.Start(); err != nil {
		t.Fatalf("the helper would not start: %v", err)
	}
	ended := make(chan struct{})
	go func() { _ = victim.Wait(); close(ended) }()
	t.Cleanup(func() { _ = victim.Process.Kill() })

	const madeUp = 4242
	entries := []syscall.ProcessEntry32{{ProcessID: uint32(victim.Process.Pid), ParentProcessID: madeUp}}
	now := time.Now().UnixNano()

	later := member{pid: madeUp, born: now + int64(time.Hour), ended: now + 2*int64(time.Hour)}
	if got := endChildren(entries, []member{later}, map[uint32]bool{}); len(got) != 0 {
		t.Fatalf("a process older than the parent it names was ended: %v", got)
	}
	select {
	case <-ended:
		t.Fatal("a process older than the parent it names stopped")
	case <-time.After(200 * time.Millisecond):
	}

	living := member{pid: madeUp, born: 0, ended: now + int64(time.Hour)}
	if got := endChildren(entries, []member{living}, map[uint32]bool{}); len(got) != 1 {
		t.Fatalf("a process born while its parent lived was not ended: %v", got)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the process endChildren said it ended is still running")
	}
}

// TestOneLookEndsEveryLevelItSees: endChildren follows what it ended down to
// what that started, within one snapshot - the later looks are for processes
// started while it was ending, not for depth. Two real processes stand in for a
// chain, the second named as the first's child.
func TestOneLookEndsEveryLevelItSees(t *testing.T) {
	helper(t, "sleep")
	var entries []syscall.ProcessEntry32
	var ended []chan struct{}
	parent := uint32(4242)
	for range 2 {
		p := exec.Command(self(t), "-test.run=TestHelperProcess")
		if err := p.Start(); err != nil {
			t.Fatalf("the helper would not start: %v", err)
		}
		done := make(chan struct{})
		go func() { _ = p.Wait(); close(done) }()
		t.Cleanup(func() { _ = p.Process.Kill() })
		entries = append(entries, syscall.ProcessEntry32{ProcessID: uint32(p.Process.Pid), ParentProcessID: parent})
		ended = append(ended, done)
		parent = uint32(p.Process.Pid)
	}

	root := member{pid: 4242, born: 0, ended: time.Now().UnixNano() + int64(time.Hour)}
	if got := endChildren(entries, []member{root}, map[uint32]bool{}); len(got) != 2 {
		t.Fatalf("one look ended %d of a chain of two", len(got))
	}
	for level, done := range ended {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("level %d is still running", level+1)
		}
	}
}

// TestWhatCannotBeAskedIsLeftAlone: a process that cannot be opened, a time
// that cannot be read and a snapshot the system refuses each end the walk there
// - nothing is ended on a guess, and the leader is still ended by exec's own
// kill before any of this.
func TestWhatCannotBeAskedIsLeftAlone(t *testing.T) {
	if _, ok := bornAt(0); ok {
		t.Error("a creation time came back for process 0, which cannot be opened")
	}
	if _, ok := creationOf(syscall.Handle(0)); ok {
		t.Error("a creation time came back for no handle")
	}
	if _, ok := endIfBornOf(0, member{born: 0, ended: time.Now().UnixNano()}); ok {
		t.Error("process 0 was reported as ended")
	}
	refused := func(uint32, uint32) (syscall.Handle, error) { return 0, errors.New("refused") }
	if got := listed(refused); got != nil {
		t.Errorf("a refused snapshot listed %d processes", len(got))
	}
	if len(snapshot()) == 0 {
		t.Error("the snapshot of this machine lists no process, not even this one")
	}
}

// TestAChildIsBornOfAParentOnlyWhileItLived is bornOf at its two edges.
func TestAChildIsBornOfAParentOnlyWhileItLived(t *testing.T) {
	parent := member{born: 100, ended: 200}
	for born, want := range map[int64]bool{99: false, 100: true, 150: true, 200: true, 201: false} {
		if bornOf(born, parent) != want {
			t.Errorf("born at %d: %v, want %v", born, !want, want)
		}
	}
}
