//go:build windows

package probe

import (
	"os"
	"reflect"
	"syscall"
	"time"
)

// ownGroup leaves the child as exec starts it. Windows has no process group a
// kill reaches through, so endGroup finds what the child started instead.
func ownGroup() *syscall.SysProcAttr { return nil }

// Access rights endGroup asks for, from learn.microsoft.com, Process Security
// and Access Rights, read 2026-11-16. syscall names the first and not the
// second.
const (
	processTerminate        = syscall.PROCESS_TERMINATE
	processQueryLimitedInfo = 0x1000
)

// endPasses is how many times endGroup looks again for processes started while
// it was ending the ones it had found.
const endPasses = 3

// endGroup ends the leader, then every process it started and every process
// those started - OBS197, closed by ADR150.
//
// A WRAPPER IS A PARENT, NOT THE PROGRAM, on Windows as on Linux and macOS.
// Measured 2026-10-27: Chocolatey's shim starts the real program as its child
// and does not end it when it is ended itself, so after a cancelled run that
// child went on running our script, and holding the pipe made the run wait its
// whole waitDelay. Scoop's shim ends its own child, and a program started
// directly has none. exec.CommandContext ends only the process it started.
//
// WHY NOT A JOB OBJECT. A job holds every descendant from the start, but a
// process has to be put into it before it starts one, which means starting it
// suspended and resuming it - with an undocumented call (NtResumeProcess), or
// by walking every thread on the machine at about 50 ms a start (probe S33,
// 2026-11-16) - and filling in the job's limits needs unsafe. This walks the
// processes once, on the one path where a run was cancelled, with nothing but
// the standard library's own calls.
//
// A PROCESS IS ENDED ONLY IF IT WAS BORN OF ONE OF OURS. Windows keeps the id of
// a parent in its child after the parent is gone, and hands ids out again, so
// an id alone could name somebody else's process. A child counts only when it
// was created after its parent and before endGroup ended that parent - a process
// that took a dead parent's id later, and anything it starts, fails the second
// half. The leader's own id cannot be reused meanwhile: exec still holds its
// handle, because Cancel runs before Wait.
func endGroup(leader *os.Process) error {
	born, ok := bornAt(uint32(leader.Pid)) //nolint:gosec // G115: a Windows process ID is a DWORD
	err := leader.Kill()
	if ok {
		endDescendants(member{pid: uint32(leader.Pid), born: born, ended: time.Now().UnixNano()}) //nolint:gosec // G115: a Windows process ID is a DWORD
	}
	return err
}

// member is a process endGroup ended: its id, when it was created and when it
// was ended, in nanoseconds since the Unix epoch.
type member struct {
	pid         uint32
	born, ended int64
}

// endDescendants ends everything root started, looking again until a look
// finds nothing new or endPasses looks have been made.
func endDescendants(root member) {
	known := []member{root}
	seen := map[uint32]bool{root.pid: true}
	for pass := 0; pass < endPasses; pass++ {
		fresh := endChildren(snapshot(), known, seen)
		if len(fresh) == 0 {
			return
		}
		known = append(known, fresh...)
	}
}

// endChildren ends every process in all that one of parents started, and every
// process those started, and says which it ended.
func endChildren(all []syscall.ProcessEntry32, parents []member, seen map[uint32]bool) []member {
	var ended []member
	queue := append([]member(nil), parents...)
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, entry := range all {
			if entry.ParentProcessID != parent.pid || seen[entry.ProcessID] {
				continue
			}
			if child, ok := endIfBornOf(entry.ProcessID, parent); ok {
				seen[child.pid] = true
				ended = append(ended, child)
				queue = append(queue, child)
			}
		}
	}
	return ended
}

// endIfBornOf ends pid when it was born of parent, and says so.
func endIfBornOf(pid uint32, parent member) (member, bool) {
	handle, err := syscall.OpenProcess(processTerminate|processQueryLimitedInfo, false, pid)
	if err != nil {
		// Not ours to end - another account's, or already gone.
		return member{}, false
	}
	defer func() { _ = syscall.CloseHandle(handle) }()
	born, ok := creationOf(handle)
	if !ok || !bornOf(born, parent) {
		return member{}, false
	}
	_ = syscall.TerminateProcess(handle, 1)
	return member{pid: pid, born: born, ended: time.Now().UnixNano()}, true
}

// bornOf says whether a process created at born can be a child of parent: not
// before the parent was created, and not after the parent was ended.
func bornOf(born int64, parent member) bool {
	return born >= parent.born && born <= parent.ended
}

// bornAt is when the process pid was created.
func bornAt(pid uint32) (int64, bool) {
	handle, err := syscall.OpenProcess(processQueryLimitedInfo, false, pid)
	if err != nil {
		return 0, false
	}
	defer func() { _ = syscall.CloseHandle(handle) }()
	return creationOf(handle)
}

// creationOf is when the process behind handle was created.
func creationOf(handle syscall.Handle) (int64, bool) {
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return 0, false
	}
	return created.Nanoseconds(), true
}

// snapshot lists the processes running now, or nothing when the system will not
// say - and then endGroup ends the leader alone, as it did before.
//
// THE SIZE COMES FROM reflect, NOT unsafe. Process32First wants the size of the
// structure written into it, and reflect reads the same number the compiler
// lays out without this file joining unsafeAllowlist.
func snapshot() []syscall.ProcessEntry32 { return listed(syscall.CreateToolhelp32Snapshot) }

// listed is snapshot with the call that takes it handed in, so a test can hand
// in one the system refuses.
func listed(take func(flags, pid uint32) (syscall.Handle, error)) []syscall.ProcessEntry32 {
	handle, err := take(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer func() { _ = syscall.CloseHandle(handle) }()
	entry := syscall.ProcessEntry32{Size: uint32(reflect.TypeFor[syscall.ProcessEntry32]().Size())} //nolint:gosec // G115: the size of one fixed struct
	var all []syscall.ProcessEntry32
	for err := syscall.Process32First(handle, &entry); err == nil; err = syscall.Process32Next(handle, &entry) {
		all = append(all, entry)
	}
	return all
}
