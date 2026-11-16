package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

func TestALineIsEditedKeyByKey(t *testing.T) {
	for _, c := range []struct {
		name, keys, want  string
		over, interrupted bool
		left              string // what is still unread after the key that ended the line
	}{
		{name: "ended by Enter", keys: "abc\rnext", want: "abc", left: "next"},
		{name: "ended by a line feed", keys: "abc\nnext", want: "abc", left: "next"},
		{name: "ended by Ctrl+D", keys: "abc\x04next", want: "abc", left: "next"},
		{name: "ended by the end of the input", keys: "abc", want: "abc"},
		{name: "nothing typed", keys: "\r", want: ""},
		{name: "Backspace as DEL", keys: "abcd\x7f\r", want: "abc"},
		{name: "Backspace as Ctrl+H", keys: "abcd\x08\r", want: "abc"},
		{name: "Backspace takes a whole character", keys: "a\xc5\xbc\x7f\r", want: "a"},
		{name: "Backspace on nothing", keys: "\x7f\x7fa\r", want: "a"},
		{name: "Backspace after a broken character takes a byte", keys: "ab\xc5\x7f\r", want: "ab"},
		{name: "Ctrl+U clears the line", keys: "wrong\x15right\r", want: "right"},
		{name: "an arrow key", keys: "ab\x1b[Dc\r", want: "abc"},
		{name: "an arrow key with parameters", keys: "ab\x1b[1;5Cc\r", want: "abc"},
		{name: "the markers around a paste", keys: "\x1b[200~tok.en\x1b[201~\r", want: "tok.en"},
		{name: "a keypad key", keys: "a\x1bOAb\r", want: "ab"},
		{name: "a key with Alt", keys: "a\x1bxb\r", want: "ab"},
		{name: "Escape and then Enter", keys: "ab\x1b\rnext", want: "ab", left: "next"},
		{name: "Enter inside a sequence", keys: "ab\x1b[12\rnext", want: "ab", left: "next"},
		{name: "two sequences in a row", keys: "a\x1b[A\x1b[Bb\r", want: "ab"},
		{name: "a sequence cut by the end of the input", keys: "ab\x1b[1", want: "ab"},
		{name: "Escape at the end of the input", keys: "ab\x1b", want: "ab"},
		{name: "Ctrl+Z and the like are not kept", keys: "a\x1ab\x01c\r", want: "abc"},
		{name: "Tab is kept", keys: "a\tb\r", want: "a\tb"},
		{name: "Ctrl+C", keys: "abc\x03next", want: "abc", interrupted: true, left: "next"},
		{name: "at the limit", keys: "12345678\r", want: "12345678"},
		{name: "past the limit", keys: "123456789\rnext", over: true, left: "next"},
		{name: "past the limit, then edited back", keys: "123456789\x7f\x7f\r", over: true},
		{name: "past the limit, then cleared", keys: "123456789\x15ok\r", want: "ok"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := strings.NewReader(c.keys)
			typed, err := editLine(r, 8, nil)
			if err != nil {
				t.Fatal(err)
			}
			if string(typed.text) != c.want || typed.over != c.over || typed.interrupted != c.interrupted {
				t.Errorf("got %q over %v interrupted %v, want %q over %v interrupted %v",
					typed.text, typed.over, typed.interrupted, c.want, c.over, c.interrupted)
			}
			if left, _ := io.ReadAll(r); string(left) != c.left {
				t.Errorf("left %q unread, want %q", left, c.left)
			}
		})
	}
}

// What a visible input puts on the screen key by key: each character, a
// character a terminal would act on spelled out as a report prints it, and
// "\b \b" for every column Backspace or Ctrl+U takes back - nothing for a
// character not yet whole, nothing past the limit (OBS238).
func TestAVisibleLineIsShownAsItIsEdited(t *testing.T) {
	back := func(columns int) string { return strings.Repeat("\b \b", columns) }
	bidi := "\xe2\x80\xae" // U+202E, which reverses the rest of a line on a terminal
	for _, c := range []struct{ name, keys, want string }{
		{"typed", "abc\rnext", "abc"},
		{"Backspace", "abcd\x7f\r", "abcd" + back(1)},
		{"Backspace takes a whole character", "a\xc5\xbc\x7f\r", "a\xc5\xbc" + back(1)},
		{"a character of four bytes", "\xf0\x9f\x98\x80\x7f\r", "\xf0\x9f\x98\x80" + back(1)},
		{"Backspace on nothing", "\x7f\x7fa\r", "a"},
		{"a character not yet whole is not shown", "ab\xc5\x7f\r", "ab"},
		{"Ctrl+U", "wrong\x15right\r", "wrong" + back(5) + "right"},
		{"an arrow key is not shown", "ab\x1b[Dc\r", "abc"},
		{"Tab is spelled out", "a\tb\x7f\x7f\r", "a" + render.Visible("\t") + "b" + back(1) +
			back(len(render.Visible("\t")))},
		{"a direction override is spelled out", "a" + bidi + "b\x7f\x7f\r", "a" + render.Visible(bidi) + "b" +
			back(1) + back(len(render.Visible(bidi)))},
		{"bytes that are not UTF-8", "\xe2\x80a\x7f\x7f\r", render.Visible("\xe2") + render.Visible("\x80") + "a" +
			back(1) + back(len(render.Visible("\x80")))},
		{"Ctrl+C", "abc\x03", "abc"},
		{"past the limit", "123456789\r", "12345678"},
		{"past the limit, then edited back", "123456789\x7f\x7f\r", "12345678"},
		{"past the limit, then cleared", "123456789\x15ok\r", "12345678" + back(8) + "ok"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var screen bytes.Buffer
			shown := &echo{out: bufio.NewWriter(&screen)}
			if _, err := editLine(strings.NewReader(c.keys), 8, shown); err != nil {
				t.Fatal(err)
			}
			shown.end()
			if got := screen.String(); got != c.want+"\n" {
				t.Errorf("the screen got %q, want %q", got, c.want+"\n")
			}
		})
	}
}

// A long paste is written to the screen whole - in pieces once the keys read
// ahead run out, not a key at a time.
func TestALongVisiblePasteIsShownWhole(t *testing.T) {
	var screen bytes.Buffer
	long := strings.Repeat("x", 100_000)
	shown := &echo{out: bufio.NewWriter(&screen)}
	typed, err := editLine(bufio.NewReader(strings.NewReader(long+"\r")), 256<<10, shown)
	shown.end()
	if err != nil || len(typed.text) != len(long) || screen.String() != long+"\n" {
		t.Errorf("%d bytes read, %d shown (%v)", len(typed.text), screen.Len(), err)
	}
}

// A key typed by hand is on the screen before the next one is waited for -
// shown at the end of the line alone, it would be typed blind all the same.
func TestATypedKeyIsShownBeforeTheNextIsAwaited(t *testing.T) {
	var screen bytes.Buffer
	keys := &watchedKeys{keys: "abc\r", screen: &screen}
	shown := &echo{out: bufio.NewWriter(&screen)}
	if _, err := editLine(bufio.NewReader(keys), 8, shown); err != nil {
		t.Fatal(err)
	}
	if keys.late != "" {
		t.Errorf("waited for a key with %s on the screen", keys.late)
	}
}

// watchedKeys hands over keys one at a time, and notes the first time it is
// asked for a key while the screen does not yet show every key before it.
type watchedKeys struct {
	keys   string
	given  int
	screen *bytes.Buffer
	late   string
}

func (k *watchedKeys) Read(p []byte) (int, error) {
	if k.late == "" && k.screen.String() != k.keys[:k.given] {
		k.late = fmt.Sprintf("%q of %q", k.screen.String(), k.keys[:k.given])
	}
	if k.given >= len(k.keys) {
		return 0, io.EOF
	}
	p[0] = k.keys[k.given]
	k.given++
	return 1, nil
}

// A line longer than both terminals' line modes take - Linux 4095, macOS about
// 1020 - and a read that fails in the middle.
func TestALongLineArrivesWholeAndAFailedReadSaysSo(t *testing.T) {
	long := strings.Repeat("x", 300_000)
	typed, err := editLine(strings.NewReader(long+"\r"), 256<<10, nil)
	if err != nil || !typed.over || typed.text != nil {
		t.Errorf("300000 bytes against 256 KiB: over %v, %d kept, %v", typed.over, len(typed.text), err)
	}
	typed, err = editLine(strings.NewReader(long[:10_000]+"\r"), 256<<10, nil)
	if err != nil || len(typed.text) != 10_000 {
		t.Errorf("10000 bytes arrived as %d (%v)", len(typed.text), err)
	}
	if _, err := editLine(bufio.NewReader(io.MultiReader(strings.NewReader("ab"), failingReader{})), 8, nil); err == nil ||
		!strings.Contains(err.Error(), "the pipe broke") {
		t.Errorf("a failed read answered %v", err)
	}
}

// Neither a pipe nor a reader that is not a file is switched - each is read in
// the line mode, as before. On Linux and macOS the pipe is the request the
// terminal refuses; elsewhere nothing is switched at all.
func TestOnlyATerminalIsSwitched(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, switched := liveKeys(r); switched {
		t.Error("a pipe was switched as if it were a terminal")
	}
	if _, switched := liveKeys(strings.NewReader("x")); switched {
		t.Error("a reader that is not a file was switched")
	}
}

// fakeKeys is a terminal handing over keys, which records what was done to it.
type fakeKeys struct {
	io.Reader
	done       []string
	restoreErr error
}

func (k *fakeKeys) restore() error { k.done = append(k.done, "restore"); return k.restoreErr }
func (k *fakeKeys) interrupt()     { k.done = append(k.done, "interrupt") }

// keysRun runs a tool's command line at a terminal that hands over keys - or,
// with keys nil, at one that cannot be switched and is read in the line mode.
func keysRun(keys *fakeKeys, args ...string) *harness {
	return invokeAdjusted(nil, report.PrivilegeUnknown, func(e *environment) {
		e.stdin = func() (io.Reader, error) { return strings.NewReader(testToken + "\n"), errNothingPiped }
		e.keys = func(io.Reader) (keyTerminal, bool) { return keys, keys != nil }
	}, args...)
}

func TestAPasteIsReadKeyByKeyWhereTheTerminalCanBeSwitched(t *testing.T) {
	for _, c := range []struct {
		name    string
		keys    *fakeKeys
		code    exitcode.Code
		says    []string
		done    string
		decoded bool
	}{
		{"pasted", &fakeKeys{Reader: strings.NewReader("\x1b[200~" + testToken + "\x1b[201~\rls -la\r")},
			exitcode.OK, []string{"it is not shown", fmt.Sprintf("\n%d character(s) read.\n", len(testToken))}, "restore", true},
		{"interrupted", &fakeKeys{Reader: strings.NewReader("abc\x03")}, exitcode.Interrupted,
			[]string{"interrupted - nothing was read"}, "restore interrupt", false},
		{"over the limit", &fakeKeys{Reader: strings.NewReader(strings.Repeat("a", 256<<10+1) + "\r")}, exitcode.Config,
			[]string{"what was pasted is larger than 256 KiB"}, "restore", false},
		{"a terminal that could not be set back", &fakeKeys{Reader: strings.NewReader(testToken + "\r"),
			restoreErr: errors.New("EIO")}, exitcode.OK, []string{"could not be set back as it was (EIO) - stty sane"},
			"restore", true},
		{"a terminal that could not be switched", nil, exitcode.OK, []string{"Paste the token and press Enter:\n"}, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := keysRun(c.keys, "tool", "jwt", "--json")
			if run.code != c.code {
				t.Fatalf("exit %d, want %d: %s", run.code, c.code, run.stderr.String())
			}
			for _, says := range c.says {
				if !strings.Contains(run.stderr.String(), says) {
					t.Errorf("stderr %q does not say %q", run.stderr.String(), says)
				}
			}
			if c.keys != nil && strings.Join(c.keys.done, " ") != c.done {
				t.Errorf("the terminal was handled %v, want %q", c.keys.done, c.done)
			}
			if decoded := bytes.Contains(run.stdout.Bytes(), []byte("MARKERSUBJECT")); decoded != c.decoded {
				t.Errorf("decoded %v, want %v (stdout %q)", decoded, c.decoded, run.stdout.String())
			}
			if strings.Contains(run.stderr.String(), testToken) {
				t.Error("the token was repeated on standard error")
			}
		})
	}
}

// The NO_PROXY tester at a terminal: the list and the address are no
// credentials, so each is shown as it is typed and no count follows - an empty
// list included (OBS237, OBS238). The keys come one at a time, as a terminal
// hands them over, so the reader of the first line does not read the second.
func TestTheListAndTheAddressAreShownAsTheyAreTyped(t *testing.T) {
	keys := &fakeKeys{Reader: iotest.OneByteReader(strings.NewReader("\x1b[200~localhost\x1b[201~\rexample.com\r"))}
	run := keysRun(keys, "tool", "noproxy", "--json")
	if run.code != exitcode.OK {
		t.Fatalf("exit %d: %s", run.code, run.stderr.String())
	}
	want := "Paste the list and press Enter:\nlocalhost\nPaste the address and press Enter:\nexample.com\n"
	if got := run.stderr.String(); got != want {
		t.Errorf("stderr %q, want %q", got, want)
	}
	if strings.Join(keys.done, " ") != "restore restore" {
		t.Errorf("the terminal was handled %v", keys.done)
	}
	empty := &fakeKeys{Reader: iotest.OneByteReader(strings.NewReader("\rlocalhost\r"))}
	if run := keysRun(empty, "tool", "noproxy", "--json"); run.code != exitcode.OK ||
		!strings.HasPrefix(run.stderr.String(), "Paste the list and press Enter:\n\nPaste the address") {
		t.Errorf("an empty list: exit %d, stderr %q", run.code, run.stderr.String())
	}
}
