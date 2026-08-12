//go:build windows

package tcp

import (
	"errors"
	"syscall"

	coretcp "github.com/donislawdev/certdoctor/internal/core/tcp"
)

// The Windows Sockets error codes this layer tells apart.
//
// THEY ARE NUMBERS HERE BECAUSE Go's syscall PACKAGE DOES NOT DEFINE MOST OF
// THEM ON THIS PLATFORM - measured, not assumed: syscall.WSAECONNREFUSED,
// WSAEHOSTUNREACH, WSAENETUNREACH and WSAETIMEDOUT are all undefined and the
// build fails on them, while WSAECONNRESET exists.
//
// Source, read at the address below on 2026-08-12 rather than recalled:
// "Windows Sockets Error Codes", Microsoft Learn -
// https://learn.microsoft.com/windows/win32/winsock/windows-sockets-error-codes-2
//
// AND THE NUMBER FOR A REFUSAL WAS CONFIRMED BY RUNNING IT on this machine: a
// connection to a closed port on loopback arrives as errno 10061. That check
// existed because the FIRST version of this mapping used the unix names alone,
// which match nothing here - so every refused connection, the commonest case
// this layer has, would have been reported as a reset.
const (
	wsaeNetUnreach  = syscall.Errno(10051) // WSAENETUNREACH - no route to the network
	wsaeTimedOut    = syscall.Errno(10060) // WSAETIMEDOUT - the peer did not respond in time
	wsaeConnRefused = syscall.Errno(10061) // WSAECONNREFUSED - the target actively refused it
	wsaeHostUnreach = syscall.Errno(10065) // WSAEHOSTUNREACH - no route to the host
)

// platformFailure names the Windows sockets errors this layer tells apart, or
// returns nil so the caller can carry on to the platform-independent cases.
func platformFailure(err error) error {
	switch {
	case errors.Is(err, wsaeConnRefused):
		return coretcp.ErrRefused
	case errors.Is(err, syscall.WSAECONNRESET):
		return coretcp.ErrReset
	case errors.Is(err, wsaeHostUnreach), errors.Is(err, wsaeNetUnreach):
		return coretcp.ErrUnreachable
	case errors.Is(err, wsaeTimedOut):
		return coretcp.ErrTimeout
	}
	return nil
}
