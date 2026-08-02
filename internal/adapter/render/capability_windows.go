package render

import "syscall"

// utf8CodePage is the code page identifier for UTF-8.
//
// Source: the Code Page Identifiers table linked from the GetConsoleOutputCP
// documentation, read 2026-08-02.
const utf8CodePage = 65001

// consoleRendersUnicode asks the console which output code page it is using.
//
// WHY ASK AT ALL. A Windows console on code page 852 or 1250 renders a
// multi-byte marker as two pieces of rubbish, and a report whose status column
// looks corrupted is worse than one with no glyphs in it - the reader stops
// trusting the rest of the page. The ASCII substitute in the appearance
// dictionary exists for exactly this, and this function is what chooses it.
//
// SOURCE FOR THE CALL. GetConsoleOutputCP,
// https://learn.microsoft.com/en-us/windows/console/getconsoleoutputcp, read
// 2026-08-02: exported by Kernel32.dll, takes no parameters, returns a code page
// identifier, and returns zero on failure - which is what a process with no
// console attached gets. Zero is not 65001, so a failure degrades to the safe
// answer without a special case.
//
// WHY LOADING BY BARE NAME IS SAFE HERE, and why that needed checking in a
// security-adjacent tool. Loading a DLL by name searches the application's own
// folder before the system folder, which is a planting vector. It does not
// apply to this one: the documented search order puts Known DLLs at step 5 and
// the application folder at step 7
// (https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order,
// read 2026-08-02), and kernel32.dll was confirmed present in
// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs on the
// development machine on 2026-08-02. A copy planted beside the executable
// therefore cannot win.
//
// WHY NOT A LIBRARY. golang.org/x/sys/windows has NewLazySystemDLL, which
// resolves from System32 explicitly. It is a dependency, and a dependency for a
// checkmark is a poor trade when the search order already settles the question.
// cgo is not an option either: the release binary is built with it disabled and
// has to stay that way.
func consoleRendersUnicode() bool {
	procedure := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleOutputCP")
	if err := procedure.Find(); err != nil {
		return false
	}
	page, _, _ := procedure.Call()
	return page == uintptr(utf8CodePage)
}
