package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/adapter/render"
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
// A VISIBLE INPUT IS SHOWN AS IT IS TYPED - by this program, since the terminal
// shows nothing in this mode (spec.Input.Visible, OBS238): a list or an address
// typed by hand with nothing on screen is typed blind. Any other input might be
// a credential, so it is not shown, and after Enter the count of what arrived
// is.
//
// THE TERMINAL IS PUT BACK BEFORE ANYTHING ELSE IS DECIDED, an interrupt
// included: an interrupt sent first would reach a shell whose terminal still
// shows nothing that is typed.
func readKeys(env environment, tool spec.Tool, in spec.Input, keys keyTerminal) ([]byte, *fault) {
	var shown *echo
	if in.Visible {
		fmt.Fprintf(env.stderr, "Paste the %s and press Enter:\n", in.Name)
		shown = &echo{out: bufio.NewWriter(env.stderr)}
	} else {
		fmt.Fprintf(env.stderr, "Paste the %s and press Enter - it is not shown:\n", in.Name)
	}
	typed, err := editLine(bufio.NewReader(keys), in.MaxBytes, shown)
	shown.end()
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
	if shown == nil {
		fmt.Fprintf(env.stderr, "%d character(s) read.\n", utf8.RuneCount(typed.text))
	}
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
//
// shown, when there is one, is kept showing the line as it stands.
func editLine(r io.ByteReader, limit int, shown *echo) (typedLine, error) {
	var t typedLine
	for {
		shown.flushIfIdle(r)
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
			shown.backTo(len(t.text), t.over)
		case keyKill:
			t.text, t.over = t.text[:0], false
			shown.backTo(0, false)
		default:
			if b >= 0x20 || b == keyTab {
				t.add(b, limit)
				shown.add(b, t.over)
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

// echo shows a line as it is typed, on a terminal that no longer does: each
// character as it arrives - spelled out, the way a report prints it, when a
// terminal would act on it rather than show it (render.Visible) - and taken off
// the screen when Backspace or Ctrl+U takes it off the line, the way the
// terminal's own line mode erases: "\b \b" for every column.
//
// ITS PIECES ARE THE PIECES withoutLastRune TAKES OFF - a whole character, or
// one byte that is not UTF-8 - so the screen and the line stay one. Bytes of a
// character still arriving are not shown until it is whole.
//
// WHAT IT DOES NOT DO, the same as the line mode does not: go back up a line
// that wrapped at the edge of the window, whose width it does not know, and
// count a wide character as two columns. The line read is right either way.
//
// A nil echo shows nothing.
type echo struct {
	out *bufio.Writer
	// pending is the start of a character still arriving.
	pending []byte
	// pieces is every piece on the screen, in order.
	pieces []echoPiece
	// bytes is how much of the line pending and pieces stand for.
	bytes int
}

// echoPiece is one piece of the line on the screen: how many bytes of the line
// it is, and how many columns it takes.
type echoPiece struct{ bytes, columns uint8 }

// add shows b, which the line has just taken - or nothing, past the limit,
// where the line keeps nothing and the screen stays as it was.
func (e *echo) add(b byte, over bool) {
	if e == nil || over {
		return
	}
	e.pending = append(e.pending, b)
	e.bytes++
	for len(e.pending) > 0 && utf8.FullRune(e.pending) {
		_, size := utf8.DecodeRune(e.pending)
		text := render.Visible(string(e.pending[:size]))
		_, _ = e.out.WriteString(text)
		e.pieces = append(e.pieces, echoPiece{uint8(size), uint8(utf8.RuneCountInString(text))})
		e.pending = append(e.pending[:0], e.pending[size:]...)
	}
}

// backTo takes the screen back to the first n bytes of the line - or leaves it
// as it is past the limit, where Backspace takes nothing off the line either.
func (e *echo) backTo(n int, over bool) {
	if e == nil || over {
		return
	}
	for e.bytes > n && len(e.pending) > 0 {
		e.pending = e.pending[:len(e.pending)-1]
		e.bytes--
	}
	for e.bytes > n && len(e.pieces) > 0 {
		last := e.pieces[len(e.pieces)-1]
		e.pieces = e.pieces[:len(e.pieces)-1]
		e.bytes -= int(last.bytes)
		for range last.columns {
			_, _ = e.out.WriteString("\b \b")
		}
	}
}

// flushIfIdle puts what is shown on the screen once r has nothing more read
// ahead - so a long paste is written in a few pieces and not a key at a time,
// and a key typed by hand appears as it is pressed.
func (e *echo) flushIfIdle(r io.ByteReader) {
	if e == nil {
		return
	}
	if ahead, ok := r.(interface{ Buffered() int }); ok && ahead.Buffered() > 0 {
		return
	}
	_ = e.out.Flush()
}

// end moves past the line shown, so what is written next starts a line of its
// own.
func (e *echo) end() {
	if e == nil {
		return
	}
	_, _ = e.out.WriteString("\n")
	_ = e.out.Flush()
}
