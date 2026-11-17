//go:build windows

package main

import "golang.org/x/sys/windows"

// searchSystemOnly makes every library this process asks for by bare name from
// here on come from the system directory and from nowhere else (OBS214,
// ADR152).
//
// Without it a name goes through the standard search order, whose first
// directory is the one holding the executable
// (https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order,
// read 2026-11-04). The toolkit's GLFW 3.4 asks by name for opengl32.dll,
// dinput8.dll, xinput1_4.dll and dwmapi.dll (win32_init.c and wgl_context.c),
// and the software renderer imports version.dll, which is looked for the same
// way - none of them a Known DLL. So a file of one of those names left next to
// certdoctor-gui.exe, in a downloads folder say, would run inside the window.
// Measured 2026-11-17 with probe S36, on Windows 11 with an AMD driver and on
// Windows Server 2025 with none: without this call every copy beside the
// program was the one loaded, with it none was, and the driver and the
// software renderer both still gave a context.
//
// LOAD_LIBRARY_SEARCH_SYSTEM32 alone rather than the default set the
// documentation recommends, because that set includes the application
// directory, which is the one this is about
// (https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories,
// read 2026-11-17). A library asked for by full path is still loaded from that
// path - the software renderer is - and its loader's request for the renderer
// by name is answered by the copy already loaded.
//
// What it cannot reach: the libraries the executable imports, which the system
// loads before any code of ours runs. Those are Known DLLs and API sets only,
// read off the import table of a released window by the same probe.
//
// Through golang.org/x/sys/windows, typed, as the dialog and the title bar
// are - the owner's decision (ADR152).
func searchSystemOnly() error {
	return windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
}
