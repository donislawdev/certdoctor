//go:build !((linux && (amd64 || arm64)) || darwin)

package main

import "io"

// liveKeys never switches a terminal here, so a pasted line is read in the
// line mode. On Windows that is the answer and not a gap: the console took a
// line of 200000 characters, measured 2026-11-12 (OBS229). Elsewhere it is a
// gap - no other system's requests were checked (paste_unix.go).
func liveKeys(io.Reader) (keyTerminal, bool) { return nil, false }
