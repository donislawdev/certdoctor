package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// THIS FILE READS A PASTED LINE KEY BY KEY, on the terminals whose line mode
// cuts a long line or stops taking keys on one (ADR143). Linux hands a program
// at most 4095 characters of a line in that mode and drops the rest without a
// word - and a JWT cut inside its signature is still a JWT, so the decoder took
// it. macOS stops taking keys past about 1020, Enter among them, and the program
// waits for good. Measured 2026-11-12 with internal_tools/wklejanie (OBS229).
//
// paste_unix.go switches the terminal. What each key does is decided here,
// where a test can press it.

// keyTerminal is a terminal handing over every key as it is pressed, without
// showing it.
type keyTerminal interface {
	io.Reader
	// restore puts the terminal back as it was, once nothing more has arrived
	// for a moment, and drops what did - so the rest of a paste of several lines
	// does not reach the shell, where each line would run.
	restore() error
	// interrupt does what Ctrl+C does at a terminal in its line mode: an
	// interrupt for every process of this one's group.
	interrupt()
}

// The keys that edit a line, as a terminal with its line mode off sends them.
const (
	keyInterrupt = 0x03 // Ctrl+C
	keyEnd       = 0x04 // Ctrl+D
	keyBackspace = 0x08 // Ctrl+H, what some terminals send for Backspace
	keyTab       = 0x09
	keyLineFeed  = 0x0a
	keyReturn    = 0x0d
	keyKill      = 0x15 // Ctrl+U
	keyEscape    = 0x1b
	keyDelete    = 0x7f // what most terminals send for Backspace
)

// typedLine is what was typed before the key that ended it.
type typedLine struct {
	text        []byte
	over        bool // more than the limit was typed, and none of it is kept
	interrupted bool // Ctrl+C ended it
}

// readKeys reads one pasted line from a terminal that hands over keys.
//
// THE TERMINAL IS PUT BACK BEFORE ANYTHING ELSE IS DECIDED, an interrupt
// included: an interrupt sent first would reach a shell whose terminal still
// shows nothing that is typed.
func readKeys(env environment, tool spec.Tool, in spec.Input, keys keyTerminal) ([]byte, *fault) {
	fmt.Fprintf(env.stderr, "Paste the %s and press Enter - it is not shown:\n", in.Name)
	typed, err := editLine(bufio.NewReader(keys), in.MaxBytes)
	if failed := keys.restore(); failed != nil {
		fmt.Fprintf(env.stderr, "%s: the terminal could not be set back as it was (%v) - stty sane sets it back\n",
			toolName, failed)
	}
	switch {
	case err != nil:
		return nil, configFault("the terminal could not be read: %v", err)
	case typed.interrupted:
		keys.interrupt()
		return nil, &fault{exitcode.Interrupted, "interrupted - nothing was read"}
	case typed.over:
		return nil, configFault("what was pasted is %s, so it was not read", tooLargeWords(tool, in))
	}
	fmt.Fprintf(env.stderr, "%d character(s) read.\n", utf8.RuneCount(typed.text))
	return typed.text, nil
}

// editLine reads keys up to Enter, Ctrl+D or the end of the input, editing
// the line the way a terminal's line mode would: Backspace takes back a
// character, Ctrl+U the whole line. An escape sequence - an arrow key, the
// markers some terminals put around a paste - is skipped, and so is every
// other control key but Tab, so a Ctrl+Z that no longer stops the program does
// not become a character of the token.
//
// NO MORE THAN limit BYTES ARE KEPT. Past it the line is dropped and the rest
// is read to its end all the same, so it does not reach the shell either.
func editLine(r io.ByteReader, limit int) (typedLine, error) {
	var t typedLine
	for {
		b, err := r.ReadByte()
		for err == nil && b == keyEscape {
			b, err = afterEscape(r)
		}
		switch {
		case errors.Is(err, io.EOF):
			return t, nil
		case err != nil:
			return t, err
		}
		switch b {
		case keyReturn, keyLineFeed, keyEnd:
			return t, nil
		case keyInterrupt:
			t.interrupted = true
			return t, nil
		case keyDelete, keyBackspace:
			t.text = withoutLastRune(t.text)
		case keyKill:
			t.text, t.over = t.text[:0], false
		default:
			if b >= 0x20 || b == keyTab {
				t.add(b, limit)
			}
		}
	}
}

// afterEscape skips the rest of an escape sequence and hands back the byte
// after it. A control key inside one ends it and is handed back itself, the
// way a terminal acts on one there - so Escape pressed alone and then Enter
// still ends the line.
func afterEscape(r io.ByteReader) (byte, error) {
	b, err := r.ReadByte()
	if err != nil || b < 0x20 {
		return b, err
	}
	switch b {
	case '[': // a control sequence: parameters, then one final byte
		for b, err = r.ReadByte(); err == nil && b >= 0x20 && (b < 0x40 || b > 0x7e); b, err = r.ReadByte() {
		}
	case 'O': // the keypad and F1-F4: one byte more
		b, err = r.ReadByte()
	}
	if err != nil || b < 0x20 {
		return b, err
	}
	return r.ReadByte()
}

// add keeps b, or drops the line once it would grow past limit.
func (t *typedLine) add(b byte, limit int) {
	switch {
	case t.over:
	case len(t.text) >= limit:
		t.text, t.over = nil, true
	default:
		t.text = append(t.text, b)
	}
}

// withoutLastRune is text without its last character, or its last byte when
// that is not the end of a UTF-8 character.
func withoutLastRune(text []byte) []byte {
	_, size := utf8.DecodeLastRune(text)
	return text[:len(text)-size]
}
