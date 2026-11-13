package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// THIS FILE IS WHERE A TOOL'S INPUT IS HELD AT THE DOOR (ADR141 point 9),
// once for every tool: no tool reads a byte this did not bound first, and no
// tool sees text this did not check is text. A tool added tomorrow inherits
// all of it by being on the list.
//
// NOTHING HERE REPEATS AN INPUT BACK. A refusal names the input, the switch and
// a position - the input may be a credential, and a message ends up in tickets.

// readToolInputs reads every input of the tool, from a request document or from
// the switches and standard input.
func readToolInputs(o *toolOptions, env environment) (map[string][]byte, *fault) {
	if o.request != "" {
		return readRequestInputs(o, env)
	}
	inputs := map[string][]byte{}
	var lines *stdinLines
	for i, in := range o.tool.Inputs {
		var data []byte
		var f *fault
		switch path, named := o.files[in.Name]; {
		case named:
			data, f = readInputFile(env, o.tool, in, "--"+o.tool.FileSwitch(i), path)
		case i == 0 && !severalLines(o.tool):
			data, f = readInputStdin(env, o.tool, in)
		case in.Shape == spec.Line && severalLines(o.tool):
			if lines == nil {
				lines, f = openLines(env, o.tool)
			}
			if f == nil {
				data, f = lines.next(in)
			}
		default:
			f = usageFault("%s tool %s needs its %s - name a file with --%s", toolName, o.tool.ID, in.Name,
				o.tool.FileSwitch(i))
		}
		if f == nil {
			f = checkText(in, data)
		}
		if f != nil {
			return nil, f
		}
		inputs[in.Name] = data
	}
	if lines != nil {
		if f := lines.end(); f != nil {
			return nil, f
		}
	}
	return inputs, nil
}

// severalLines says the tool reads its inputs from standard input one line
// each (ADR147 point 3): it takes more than one, and the first is a line. A
// tool taking one input reads the whole of standard input as it, and a first
// input of bytes takes the whole of it too, leaving every other to its file.
func severalLines(t spec.Tool) bool {
	return len(t.Inputs) > 1 && t.Inputs[0].Shape == spec.Line
}

// stdinLines hands out standard input one line per input: asked for one by one
// at a terminal, or cut out of what is piped in.
type stdinLines struct {
	env  environment
	tool spec.Tool
	// terminal is standard input when nothing is piped in - nil in a build
	// with no terminal to read - and pipe is it when something is.
	terminal io.Reader
	pipe     *bufio.Reader
	// typed reads the terminal in its line mode, one reader for every input,
	// so a second line typed ahead is not lost in a reader made for the first.
	typed *bufio.Reader
}

// openLines opens standard input for its lines.
func openLines(env environment, tool spec.Tool) (*stdinLines, *fault) {
	if env.stdin == nil {
		return nil, &fault{exitcode.Runtime, "this build has no standard input to read"}
	}
	input, err := env.stdin()
	switch {
	case errors.Is(err, errNothingPiped):
		s := &stdinLines{env: env, tool: tool, terminal: input}
		if input != nil {
			s.typed = bufio.NewReader(input)
		}
		return s, nil
	case err != nil:
		return nil, configFault("standard input could not be read: %v", err)
	}
	return &stdinLines{env: env, tool: tool, pipe: bufio.NewReader(input)}, nil
}

// next is the next line, for in.
func (s *stdinLines) next(in spec.Input) ([]byte, *fault) {
	if s.pipe == nil {
		return readPasted(s.env, s.tool, in, s.terminal, s.typed)
	}
	line, ended, err := lineOf(s.pipe, in.MaxBytes)
	switch {
	case err != nil:
		return nil, configFault("standard input could not be read: %v", err)
	case ended:
		return nil, configFault("standard input ended before the %s - %s tool %s reads one line each: %s",
			in.Name, toolName, s.tool.ID, s.order())
	case len(line) > in.MaxBytes:
		return nil, configFault("the %s line of standard input is %s, so it was not read", in.Name,
			tooLargeWords(s.tool, in))
	}
	return line, nil
}

// lineOf reads one line of r - up to a line feed or the end - without its line
// ending, a CR before the line feed included: the ending of Windows, which a
// pipe from PowerShell carries. ended is the end coming before any byte.
//
// IT STOPS ONE BYTE PAST limit, so a line too long - which the caller refuses
// by its length - is never read whole into memory.
func lineOf(r *bufio.Reader, limit int) (line []byte, ended bool, err error) {
	for {
		c, err := r.ReadByte()
		switch {
		case errors.Is(err, io.EOF):
			return bytes.TrimSuffix(line, []byte("\r")), len(line) == 0, nil
		case err != nil:
			return nil, false, err
		case c == '\n':
			return bytes.TrimSuffix(line, []byte("\r")), false, nil
		}
		// Room for the CR, and one byte more than that is too long already.
		if line = append(line, c); len(line) > limit+1 {
			return line, false, nil
		}
	}
}

// end refuses what is piped in after the last line the tool reads - blank
// lines aside - rather than leave it unread without a word: a line too many is
// as likely a list broken in two as something to ignore.
func (s *stdinLines) end() *fault {
	if s.pipe == nil {
		return nil
	}
	const look = 4 << 10
	rest, err := io.ReadAll(io.LimitReader(s.pipe, look+1))
	if err != nil {
		return configFault("standard input could not be read: %v", err)
	}
	if len(rest) > look || len(bytes.TrimSpace(rest)) > 0 {
		return configFault("standard input carries more lines than %s tool %s reads - one line each: %s",
			toolName, s.tool.ID, s.order())
	}
	return nil
}

// order names the tool's inputs in the order their lines come: "the list,
// then the address".
func (s *stdinLines) order() string {
	names := make([]string, len(s.tool.Inputs))
	for i, in := range s.tool.Inputs {
		names[i] = "the " + in.Name
	}
	return strings.Join(names, ", then ")
}

// readInputFile reads the file a switch named for in, through the guarded
// file port with in's limit - so a path on another machine, a folder, a pipe
// and a file over the limit are refused before a byte reaches the tool.
func readInputFile(env environment, tool spec.Tool, in spec.Input, by, path string) ([]byte, *fault) {
	if env.openFile == nil {
		return nil, &fault{exitcode.Runtime, "this build has no way to read a file, so " + by + " cannot be answered"}
	}
	words := namedFile{by: by, what: in.Name, tooLarge: tooLargeWords(tool, in) + " -"}
	handle, err := env.openFile(int64(in.MaxBytes))(path)
	if err != nil {
		return nil, unreadableNamed(words, path, err)
	}
	defer handle.Close()
	data, err := io.ReadAll(handle)
	if err != nil {
		return nil, unreadableNamed(words, path, err)
	}
	return data, nil
}

// tooLargeWords says how much a tool reads of an input, after "which is".
func tooLargeWords(tool spec.Tool, in spec.Input) string {
	return fmt.Sprintf("larger than %d KiB - the most %s tool %s reads for its %s", in.MaxBytes>>10,
		toolName, tool.ID, in.Name)
}

// readInputStdin reads the first input from standard input: piped in, or
// pasted at a terminal.
func readInputStdin(env environment, tool spec.Tool, in spec.Input) ([]byte, *fault) {
	if env.stdin == nil {
		return nil, &fault{exitcode.Runtime, "this build has no standard input to read"}
	}
	input, err := env.stdin()
	switch {
	case errors.Is(err, errNothingPiped):
		var typed *bufio.Reader
		if input != nil {
			typed = bufio.NewReader(input)
		}
		return readPasted(env, tool, in, input, typed)
	case err != nil:
		return nil, configFault("standard input could not be read: %v", err)
	}
	return readBounded(input, tool, in, "standard input")
}

// readPasted reads one pasted line at a terminal, after saying on standard
// error what is awaited - a terminal that waits in silence looks like a hang.
//
// ONLY A LINE IS READ THIS WAY. Pasting is the way that keeps a token out of
// the shell's history - "echo token |" puts it there - and a line ends with
// Enter, which nobody has to be told. An input of many lines - a chain of
// certificates - has no Enter that ends it, so it is piped in or named with
// --file (ADR146).
//
// A TERMINAL THAT CAN HAND OVER KEYS DOES (paste.go, ADR143): on Linux and
// macOS the line mode cuts a long token or stops taking keys. Anywhere else,
// and when the switch fails, the line is read in the line mode, from typed -
// one reader over the terminal for every input a tool asks for.
func readPasted(env environment, tool spec.Tool, in spec.Input, terminal io.Reader, typed *bufio.Reader) ([]byte,
	*fault) {
	if in.Shape != spec.Line || terminal == nil {
		return nil, configFault("%s tool %s reads its %s from standard input, and nothing is piped in. "+
			"Pipe the %s in or name a file with --%s", toolName, tool.ID, in.Name, in.Name, fileSwitchOf(tool, in))
	}
	if env.keys != nil {
		if keys, switched := env.keys(terminal); switched {
			return readKeys(env, tool, in, keys)
		}
	}
	fmt.Fprintf(env.stderr, "Paste the %s and press Enter:\n", in.Name)
	line, _, err := lineOf(typed, in.MaxBytes)
	if err != nil {
		return nil, configFault("the terminal could not be read: %v", err)
	}
	if len(line) > in.MaxBytes {
		return nil, configFault("what was pasted is %s, so it was not read", tooLargeWords(tool, in))
	}
	return line, nil
}

// fileSwitchOf is the switch, without its dashes, that names a file for in.
func fileSwitchOf(tool spec.Tool, in spec.Input) string {
	for i, each := range tool.Inputs {
		if each.Name == in.Name {
			return tool.FileSwitch(i)
		}
	}
	return "file"
}

// readBounded reads r up to in's limit, refusing more without keeping it.
func readBounded(r io.Reader, tool spec.Tool, in spec.Input, from string) ([]byte, *fault) {
	data, err := io.ReadAll(io.LimitReader(r, int64(in.MaxBytes)+1))
	if err != nil {
		return nil, configFault("%s could not be read: %v", from, err)
	}
	if len(data) > in.MaxBytes {
		return nil, configFault("%s carries more than %d KiB - the most %s tool %s reads for its %s - "+
			"so it was not read", from, in.MaxBytes>>10, toolName, tool.ID, in.Name)
	}
	return data, nil
}

// checkText holds a text input to being text: UTF-8 without a NUL. UTF-16 is
// named for what it is, because Windows PowerShell 5.1 writes it when output
// is redirected with > - the same answer --from gives a report.
//
// An input of the shape bytes is not text - a certificate arrives as DER as
// often as PEM (ADR146) - so it passes as it is, bounded by its limit, and the
// tool reading it says what it is.
func checkText(in spec.Input, data []byte) *fault {
	if in.Shape == spec.Bytes {
		return nil
	}
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xff}) {
		return configFault("the %s is UTF-16 text, and a tool reads UTF-8. Windows PowerShell 5.1 writes "+
			"UTF-16 when output is redirected with >, so save it with Out-File -Encoding utf8, or pipe it in", in.Name)
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return configFault("the %s has a NUL byte at byte %d, so it is not text", in.Name, i+1)
	}
	if !utf8.Valid(data) {
		return configFault("the %s is not UTF-8 text (it stops being UTF-8 at byte %d)", in.Name, invalidAt(data)+1)
	}
	return nil
}

// invalidAt is the offset of the first byte of data that is not UTF-8.
func invalidAt(data []byte) int {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return len(data)
}

// readRequestInputs reads a request document and every input it gives. A
// path in it is read like a file a switch named, so the window never opens one
// itself (ADR141 point 3).
func readRequestInputs(o *toolOptions, env environment) (map[string][]byte, *fault) {
	raw, f := readRequestDocument(o, env)
	if f != nil {
		return nil, f
	}
	request, err := spec.ReadRequest(raw, o.tool)
	if err != nil {
		return nil, configFault("%v", err)
	}
	inputs := map[string][]byte{}
	for _, in := range o.tool.Inputs {
		given := request.Inputs[in.Name]
		data := given.Bytes
		switch {
		case given.Path != "":
			data, f = readInputFile(env, o.tool, in, "the request's "+in.Name, given.Path)
		case given.Text != nil:
			data = []byte(*given.Text)
		}
		if f == nil && len(data) > in.MaxBytes {
			f = configFault("the request gives a %s %s, so it was not read", in.Name, tooLargeWords(o.tool, in))
		}
		if f == nil {
			f = checkText(in, data)
		}
		if f != nil {
			return nil, f
		}
		inputs[in.Name] = data
	}
	return inputs, nil
}

// requestLimit is the most of a request document read: every input of the
// tool at its limit, grown by a third for base64, and room for the rest.
func requestLimit(tool spec.Tool) int {
	total := 64 << 10
	for _, in := range tool.Inputs {
		total += in.MaxBytes/3*4 + 4
	}
	return total
}

// readRequestDocument reads the request --request names.
func readRequestDocument(o *toolOptions, env environment) ([]byte, *fault) {
	limit := requestLimit(o.tool)
	document := spec.Input{Name: "request", MaxBytes: limit}
	if o.request != "-" {
		return readInputFile(env, o.tool, document, "--request", o.request)
	}
	if env.stdin == nil {
		return nil, &fault{exitcode.Runtime, "this build has no standard input to read"}
	}
	input, err := env.stdin()
	switch {
	case errors.Is(err, errNothingPiped):
		return nil, configFault("--request - reads a request document from standard input, and nothing is " +
			"piped in. Pipe one in or name the file")
	case err != nil:
		return nil, configFault("standard input could not be read: %v", err)
	}
	return readBounded(input, o.tool, document, "standard input")
}
