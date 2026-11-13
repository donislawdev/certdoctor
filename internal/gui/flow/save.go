package flow

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// SaveStep is how far one copy of the report has got in the Save report
// dialog.
type SaveStep int

// The steps of a copy. Only Writing runs anything, and only Done means a file
// is there.
const (
	// SaveAsking: the folder and the name are being typed, or were changed
	// since the last press.
	SaveAsking SaveStep = iota
	// SaveUnusable: the folder or the name cannot be saved to, and Said says
	// why. Nothing ran.
	SaveUnusable
	// SaveTaken: a file of that name is in the folder. Pressing again
	// replaces it.
	SaveTaken
	// SaveWriting: the command line is writing it.
	SaveWriting
	// SaveDone: the file is at Path.
	SaveDone
	// SaveFailed: the command line did not write it, and Said says why.
	SaveFailed
)

// Save is one copy of the report being saved: the format chosen in the menu,
// where it is going, and how far it has got. The window's dialog draws it and
// asks nothing of its own (GUI rule 15).
type Save struct {
	format request.Format
	step   SaveStep
	path   string
	said   string
}

// NewSave is a copy in format f, not yet asked for.
func NewSave(f request.Format) *Save { return &Save{format: f} }

// Format is the format the copy is written in.
func (s *Save) Format() request.Format { return s.format }

// Step is how far the copy has got.
func (s *Save) Step() SaveStep { return s.step }

// Path is where the copy goes: the file in the way when the step is Taken,
// and the file written or being written after that.
func (s *Save) Path() string { return s.path }

// Said is why the folder or the name cannot be used, or why the copy was not
// written - empty at every other step.
func (s *Save) Said() string { return s.said }

// SaveReady says whether there is a folder and a name to press Save with.
// Whether they can be saved under is the press's question, answered in a
// sentence.
func SaveReady(folder, name string) bool {
	return strings.TrimSpace(folder) != "" && strings.TrimSpace(name) != ""
}

// Changed is the folder or the name typed again: what was said about the last
// path no longer stands. While the copy is being written, and once it is,
// nothing changes.
func (s *Save) Changed() {
	switch s.step {
	case SaveUnusable, SaveTaken, SaveFailed:
		s.step, s.said = SaveAsking, ""
	}
}

// Press is Save - or Replace - pressed with the folder and the name as they
// stand. present answers whether a file stands at a path already. It answers
// the command line to run, or nil when nothing is to run: the folder or the
// name cannot be used, a file of that name is there and nobody has said to
// replace it yet, or the copy is already being written or written.
//
// Replace is the same press a second time with the same path: what was in the
// way was shown, and pressing again is the answer.
func (s *Save) Press(folder, name string, present func(path string) bool) []string {
	if s.step == SaveWriting || s.step == SaveDone {
		return nil
	}
	path, problem := target(folder, name, s.format)
	if problem != "" {
		s.step, s.said = SaveUnusable, problem
		return nil
	}
	agreed := s.step == SaveTaken && path == s.path
	if !agreed && present(path) {
		s.step, s.path, s.said = SaveTaken, path, ""
		return nil
	}
	s.step, s.path, s.said = SaveWriting, path, ""
	return request.SaveArgs(s.format, path)
}

// Finish takes what came of writing the copy. An answer that comes at any
// other step is not this copy's, and is dropped.
func (s *Save) Finish(p Process) {
	if s.step != SaveWriting {
		return
	}
	if said := notWritten(p); said != "" {
		s.step, s.said = SaveFailed, said
		return
	}
	s.step = SaveDone
}

// notWritten is why a run that was to write the copy did not, or nothing when
// it did. Exit code 0 is the command line's word that the file is in place:
// it writes beside it and renames it over the path only once every byte is on
// disk (internal/adapter/output/atomic.go), so a run that ended any other way
// left the path as it was.
//
// The order is the order of what can be known, as in judge: whether it ran,
// whether it said it wrote the file, then why it did not.
func notWritten(p Process) string {
	switch {
	case p.Missing:
		return fmt.Sprintf(words.T(words.MissingWhat), p.Program)
	case p.StartFailed != nil:
		return fmt.Sprintf(words.T(words.NotStartedWhat), p.Program, withoutFullStop(p.StartFailed.Error()))
	case p.Code == 0:
		return ""
	case p.Stopped != nil:
		return fmt.Sprintf(words.T(words.SaveStopped), seconds(Grace.Seconds()))
	}
	if said := firstSentence(p.Printed); said != "" {
		return said
	}
	if c := exitcode.Code(p.Code); p.Code >= 0 && c.Valid() {
		return fmt.Sprintf(words.T(words.SaveEndedCode), p.Code, c.Name())
	}
	return words.T(words.SaveEnded)
}

// firstSentence is the first line the command line printed, without the name
// it puts before everything it says, as a sentence: it refuses in one line
// (cmd/certdoctor/cli.go, complain), and a panic says what broke in its first.
func firstSentence(printed []byte) string {
	text := strings.ToValidUTF8(string(printed), string(utf8.RuneError))
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), request.Command+":"))
		if line != "" {
			return asSentence(withoutFullStop(line))
		}
	}
	return ""
}

// asSentence ends s in a full stop and starts it with a capital when it
// starts with a word - the command line writes its errors the way Go does,
// in lower case, and the dialog shows one as a sentence. Only a word: a
// drive letter (c:) or a path is left exactly as it was written.
func asSentence(s string) string {
	first, size := utf8.DecodeRuneInString(s)
	second, _ := utf8.DecodeRuneInString(s[size:])
	if first >= 'a' && first <= 'z' && second >= 'a' && second <= 'z' {
		s = string(first-'a'+'A') + s[size:]
	}
	return s + "."
}

// target is the path a copy in format f goes to, from the folder and the name
// as they were typed - or the sentence that says why they cannot be used.
//
// The folder has to be a whole path: the command line runs in a folder of the
// window's choosing, not the person's, so a path relative to it would land
// somewhere nobody looked. The name has to be one every system can hold,
// because a saved report is attached to a ticket and opened on another
// machine: none of the characters Windows keeps for itself, no character
// below a space, and not a name Windows keeps for a device - the rules of
// https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file, read
// 2026-11-10. The ending of the format is added when the name does not end
// with it, so the file opens in the program its format belongs to.
//
// What the system says of the rest - a folder that is not there, a name too
// long, a disk that is full - the command line says in its own words when it
// tries.
func target(folder, name string, f request.Format) (string, string) {
	folder, name = strings.TrimSpace(folder), strings.TrimSpace(name)
	switch {
	case folder == "":
		return "", words.T(words.SaveNoFolder)
	case !filepath.IsAbs(folder):
		return "", words.T(words.SaveNotWhole)
	case name == "":
		return "", words.T(words.SaveNoName)
	case strings.ContainsFunc(name, forbidden):
		return "", words.T(words.SaveForbidden)
	}
	if !strings.EqualFold(filepath.Ext(name), f.Ending) {
		name += f.Ending
	}
	if keptForADevice(name) {
		return "", fmt.Sprintf(words.T(words.SaveDevice), name)
	}
	return filepath.Join(folder, name), ""
}

// forbidden says whether a character may not stand in a file's name on
// Windows: the nine it keeps for itself, and every character below a space.
func forbidden(r rune) bool { return r < ' ' || strings.ContainsRune(`<>:"/\|?*`, r) }

// keptForADevice says whether Windows takes a name for a device, whatever
// follows its first dot: NUL.html is NUL. The superscript one, two and three
// are digits to it as well (the same page).
func keptForADevice(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if rest, ok := strings.CutPrefix(base, "COM"); ok {
		return portDigit(rest)
	}
	if rest, ok := strings.CutPrefix(base, "LPT"); ok {
		return portDigit(rest)
	}
	return false
}

// portDigit says whether s is the one digit after COM or LPT that makes a
// device's name: 1 to 9, or the superscript one, two or three (U+00B9, U+00B2,
// U+00B3), written by their code points so this file stays ASCII.
func portDigit(s string) bool {
	r, size := utf8.DecodeRuneInString(s)
	if size == 0 || size != len(s) {
		return false
	}
	return (r >= '1' && r <= '9') || r == 0xB9 || r == 0xB2 || r == 0xB3
}

// maxHost is the most of the host a suggested name keeps, in bytes: room for
// any name a person types, and a whole file name far below the 255 bytes the
// common file systems allow.
const maxHost = 120

// SuggestedName is what a copy of the report on target is called before a
// person names it: the program, the host the run was about, and when the run
// began in UTC, in ISO 8601's basic form - certdoctor-example.com-20261110T143005Z.html.
// Sorted by name, copies of one host stand in the order they were made, and
// every character of it is one every system takes in a name: the host keeps
// letters, digits, dots and dashes, and anything else - the brackets of an
// IPv6 address, the marker of a masked host - becomes a dash.
func SuggestedName(target string, f request.Format, began time.Time) string {
	parts := []string{request.Command}
	if host := nameOf(target); host != "" {
		parts = append(parts, host)
	}
	parts = append(parts, began.UTC().Format("20060102T150405Z"))
	return strings.Join(parts, "-") + f.Ending
}

// nameOf is the host of target as it may stand in a file's name, or nothing
// when target has none.
func nameOf(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	var b strings.Builder
	dash := false
	for _, r := range u.Hostname() {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash {
			b.WriteRune('-')
			dash = true
		}
	}
	host := strings.Trim(b.String(), "-.")
	for len(host) > maxHost {
		_, size := utf8.DecodeLastRuneInString(host)
		host = host[:len(host)-size]
	}
	return strings.Trim(host, "-.")
}
