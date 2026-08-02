//go:build windows

package privilege

import (
	"syscall"
	"unsafe"
)

// ask reads the elevation flag out of this process's access token.
//
// SOURCE, because this is a claim about somebody else's runtime. The
// TOKEN_ELEVATION structure holds a single member, TokenIsElevated, documented
// as "a nonzero value if the token has elevated privileges; otherwise, a zero
// value", available since Windows Vista:
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_elevation
// Read at the source on 2026-08-03.
//
// MEASURED RATHER THAN ASSUMED, also on 2026-08-03. The information class
// constant is present in the standard library as syscall.TokenElevation with
// the value 20, so this needs no dependency and no cgo - a throwaway probe
// built with CGO_ENABLED=0 answered correctly, and its answer agreed with an
// independent check by SID (S-1-16-12288, the high mandatory level) rather than
// by group name.
//
// The buffer is a single DWORD read into a uint32 rather than a declared
// structure, because the structure has exactly one member and declaring it
// would add a type whose layout we would then be asserting.
func ask() (bool, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false, err
	}
	defer token.Close()

	var elevated uint32
	var returned uint32
	err = syscall.GetTokenInformation(
		token,
		syscall.TokenElevation,
		(*byte)(unsafe.Pointer(&elevated)),
		uint32(unsafe.Sizeof(elevated)),
		&returned,
	)
	if err != nil {
		return false, err
	}
	return elevated != 0, nil
}
