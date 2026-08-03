package render

import (
	"os"
	"syscall"
)

// enableVirtualTerminalProcessing is the console mode flag that makes a console
// parse escape sequences instead of printing them.
//
// SOURCE: SetConsoleMode,
// https://learn.microsoft.com/en-us/windows/console/setconsolemode, read
// 2026-08-03. The value is 0x0004 and the flag is documented as making the
// console interpret ANSI sequences in the text written to it.
const enableVirtualTerminalProcessing = 0x0004

// consoleUnderstandsSequences asks the destination whether it will interpret an
// escape sequence or print it.
//
// MEASURED RATHER THAN ASSUMED, 2026-08-03, by probe S6 on the owner's machine,
// and the measurement settles it rather than merely supporting it. ONE MACHINE,
// ONE DAY, TWO CONSOLE HOSTS, TWO DIFFERENT ANSWERS:
//
//	Windows Terminal          mode 0x0007  - virtual terminal processing IS set
//	conhost.exe with cmd.exe  mode 0x0003  - it is NOT
//
// So this is not a question about the platform, it is a question about the
// window the person happens to be standing in front of, and there is no way to
// answer it except by asking. Colour written to the second one arrives as
// visible rubbish, which makes the report look broken - worse than a report with
// no colour in it at all. Being a character device was treated as enough until
// somebody asked.
//
// IT DOES NOT TURN THE FLAG ON, and that is a rule rather than an omission.
// Setting it would change the state of somebody else's console and leave it
// changed, and this program does not change things - it is the first line of the
// README. Asking costs nothing. Being wrong costs the readability of the one
// artefact this tool produces.
//
// A handle that refuses the question answers no, which degrades to plain text.
// Every default here leans the same way.
func consoleUnderstandsSequences(destination *os.File) bool {
	if destination == nil {
		return false
	}
	var mode uint32
	if err := syscall.GetConsoleMode(syscall.Handle(destination.Fd()), &mode); err != nil {
		return false
	}
	return mode&enableVirtualTerminalProcessing != 0
}

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
