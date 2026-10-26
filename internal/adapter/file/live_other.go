//go:build !windows

package file

import (
	"os"
	"syscall"
)

// openFlags opens without waiting - ADR114. O_NONBLOCK makes the open of a FIFO
// nobody writes to return at once rather than block until a writer comes, so
// liveSource can ask what it opened, and POSIX has a regular file ignore the flag
// for reads.
const openFlags = os.O_RDONLY | syscall.O_NONBLOCK

// liveAppAlias refuses every path: app execution aliases are reparse points
// of Windows, and nothing elsewhere is one.
func liveAppAlias(string) (string, error) { return "", ErrNotAnAppAlias }
