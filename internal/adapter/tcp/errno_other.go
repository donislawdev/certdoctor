//go:build !windows

package tcp

import (
	"errors"
	"syscall"

	coretcp "github.com/donislawdev/certdoctor/internal/core/tcp"
)

// platformFailure names the POSIX errno values this layer tells apart.
//
// The Windows half of this pair uses the WSA* names instead, because the unix
// ones match nothing there - measured rather than assumed, and the comment in
// that file says what the measurement was.
//
// It returns nil for anything it does not recognise, so the caller can carry on
// to the platform-independent cases rather than deciding here.
func platformFailure(err error) error {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return coretcp.ErrRefused
	case errors.Is(err, syscall.ECONNRESET):
		return coretcp.ErrReset
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return coretcp.ErrUnreachable
	case errors.Is(err, syscall.ETIMEDOUT):
		return coretcp.ErrTimeout
	}
	return nil
}
