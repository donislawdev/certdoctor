//go:build cgo

package main

import "os"

// THIS FILE IS ON THE FILE GUARD'S fileReadAllowlist, AND IT IS A FILE OF ITS
// OWN FOR THAT REASON - the owner's decision of 2026-11-10, recorded with
// ADR121 (c). The entry excuses the one question below and nothing else: the
// window opens no file, and the copy Save report makes is written by the
// command line.

// present says whether a file stands at path - what Save report asks before
// the command line replaces it. Only a file counts: a folder or a device of
// that name cannot be replaced by a rename, and the command line refuses one
// in its own words (internal/adapter/output/atomic.go, refuseDevice), so
// asking whether to replace it would ask about something that will not
// happen.
//
// The path is the person's own, typed or chosen in the dialog, as --out is on
// the command line - the reason atomic.go may ask the same question. Asked on
// the toolkit's goroutine: on a network folder that does not answer, the
// window waits for as long as the system takes to give up, as the toolkit's
// own folder dialog does there.
func present(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
