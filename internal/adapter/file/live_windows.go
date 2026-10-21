//go:build windows

package file

import "syscall"

// liveAppAlias reads the reparse point at path and the package out of it.
//
// IT OPENS THE ALIAS AND NOT WHAT THE ALIAS STARTS - FILE_FLAG_OPEN_REPARSE_POINT
// - and asks for no access to the file at all, which FSCTL_GET_REPARSE_POINT
// does not need: measured with probe S28 on the owner's machine 2026-10-21,
// access 0 and GENERIC_READ returned the same bytes on every alias.
// FILE_FLAG_BACKUP_SEMANTICS lets the same call open a directory, so a junction
// is read and refused by the parser rather than failing to open. OPEN_EXISTING
// creates nothing. The calls are the ones os.Readlink makes, in syscall_windows.go
// of Go 1.27.3, and none of them needs unsafe: the buffer is handed over as its
// first byte.
func liveAppAlias(path string) (string, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := syscall.CreateFile(name, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = syscall.CloseHandle(handle) }()
	data := make([]byte, syscall.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var n uint32
	err = syscall.DeviceIoControl(handle, syscall.FSCTL_GET_REPARSE_POINT, nil, 0, &data[0], uint32(len(data)), &n, nil)
	if err != nil {
		return "", err
	}
	return AppAliasPackage(data[:n])
}
