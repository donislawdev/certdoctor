package pac

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// A PAC FILE RUNS IN A PROCESS OF ITS OWN - ADR150, closing OBS199.
//
// WHY A PROCESS AND NOT ANOTHER LIMIT. The stopwatch interrupts the engine
// between its own instructions, and a built-in that asks for its whole result
// at once - "x".repeat(1e10), "".padStart(1e10), a deep native recursion - is
// native code that never reaches one. Measured 2026-10-26 in a container with
// 1 GB: one such line ended the whole run with no report. A process can be ended
// in the middle of native code, so the file now runs in one, and this program
// outlives it. Probe S33 measured the cost on 2026-11-16: 4 to 10 ms to start
// the process on Windows, Linux and macOS.
//
// THE CHILD IS THIS SAME PROGRAM, started again by the path os.Executable gives
// and one argument (cmd/certdoctor). A separate binary would double every
// archive, installer, package, bill of materials and signature.
//
// THE CHILD HAS NO NETWORK. When the file asks a resolver, the child asks its
// parent over the pipe, and the parent answers with the resolver it has always
// used, behind the same guard. So the allowed set, the dial guard and the record
// of what the file asked all stay where they were - and that record survives the
// child's death, which is the one piece of evidence a dying file must not take
// with it (docs/14 section 2.1, condition 1).
//
// THE PROTOCOL IS ONE JSON OBJECT PER LINE. The parent writes the request, the
// child writes any number of lookups, each answered by the parent, and then its
// result. Every line is read with a limit, because a line the child writes is
// shaped by a file somebody else wrote.

// Evaluator runs a PAC file and asks it about one URL. Sandbox does it in this
// process, Isolated in a process of its own running a Sandbox.
type Evaluator interface {
	Evaluate(ctx context.Context, source, rawURL, host string) corepac.Result
}

// protocolVersion changes whenever a message changes shape, and the child
// refuses a request of another one - a program file replaced while a run was
// going is the case it exists for.
const protocolVersion = 1

// Exit codes of the sandbox process that mean something to its parent.
//
// THE WATCHDOG ENDS THE PROCESS BY CODE AND WRITES NOTHING. A line written from
// a second goroutine could cross the result the first one is writing, and the
// code needs no sharing to arrive. The values are ours alone: the Go runtime
// ends a process it cannot keep going with 2, os/exec reports a process ended
// by a signal as -1, and Windows ends a terminated one with the code it was
// given, which is 1 for os.Process.Kill.
const (
	// ExitAnswered - the child wrote its result.
	ExitAnswered = 0
	// ExitRefused - the child refused the request and wrote why.
	ExitRefused = 64
	// ExitMemory - the watchdog ended the child for holding more memory than
	// the run allows.
	ExitMemory = 70
	// ExitDeadline - the watchdog ended the child at its own deadline, which
	// only matters once its parent is gone.
	ExitDeadline = 71
)

// Line limits, in bytes.
//
// requestLimit bounds the one line the child reads before anything runs: a
// source of up to a MiB grows by a third as base64, so four leave room for
// any limit a caller is likely to set and refuse a request that is not one.
//
// lineLimit bounds every line the parent reads. A result carries an answer of
// at most Sandbox.MaxAnswer, but its detail can quote what the file threw, and a
// file can throw a string as long as its memory allows - a line that long is
// refused rather than read, which is the parent keeping its own memory out of
// the file's reach.
const (
	requestLimit = 4 << 20
	lineLimit    = 1 << 20
	answerLimit  = 64 << 10
)

// errLineTooLong is a line longer than the reader's limit.
var errLineTooLong = errors.New("a line longer than this program reads")

// request is what the parent asks of the child, once.
//
// THE TEXT FROM OUTSIDE TRAVELS AS BYTES. encoding/json writes a string as
// UTF-8 and replaces what is not, and a PAC file is not obliged to be valid
// UTF-8 - the engine has to see the bytes the server sent, not a repaired copy.
type request struct {
	Protocol      int    `json:"protocol"`
	Program       string `json:"program"`
	Source        []byte `json:"source"`
	URL           []byte `json:"url"`
	Host          []byte `json:"host"`
	Budget        int64  `json:"budget_ns"`
	Ceiling       uint64 `json:"ceiling"`
	MaxSource     int    `json:"max_source"`
	MaxStack      int    `json:"max_stack"`
	MaxLookups    int    `json:"max_lookups"`
	MaxAnswer     int    `json:"max_answer"`
	MaxDirectives int    `json:"max_directives"`
	// Resolver says the parent has a resolver to ask. Without one the child's
	// helpers say nobody could be asked, exactly as they do in this process.
	Resolver bool `json:"resolver"`
	// Clock says the parent has a clock, and Now is its reading in Unix
	// nanoseconds, read back in the child's local zone - the same zone, since
	// the child inherits the parent's environment.
	Clock bool  `json:"clock"`
	Now   int64 `json:"now_unix_ns"`
}

// childLine is one line the child writes: a lookup, its result or a refusal.
type childLine struct {
	Lookup  *string     `json:"lookup,omitempty"`
	Result  *wireResult `json:"result,omitempty"`
	Refused string      `json:"refused,omitempty"`
}

// lookupAnswer is the parent's answer to one lookup.
type lookupAnswer struct {
	Addresses []string `json:"addresses"`
	// Failure is why nobody could answer, empty when somebody did.
	Failure string `json:"failure,omitempty"`
}

// wireResult is corepac.Result as the child sends it. Directives are left
// out: the parent splits the answer itself rather than taking the child's
// word for what the file said.
type wireResult struct {
	Outcome          string   `json:"outcome"`
	Raw              []byte   `json:"raw"`
	Detail           []byte   `json:"detail"`
	UsedRandomness   bool     `json:"used_randomness"`
	UsedClock        bool     `json:"used_clock"`
	Unanswered       []string `json:"unanswered"`
	Asked            []string `json:"asked"`
	LookupsExhausted bool     `json:"lookups_exhausted"`
	LookupsFailed    bool     `json:"lookups_failed"`
}

// wireOf is a result as the child sends it.
func wireOf(r corepac.Result) wireResult {
	return wireResult{
		Outcome:          string(r.Outcome),
		Raw:              []byte(r.Raw),
		Detail:           []byte(r.Detail),
		UsedRandomness:   r.UsedRandomness,
		UsedClock:        r.UsedClock,
		Unanswered:       r.Unanswered,
		Asked:            r.Asked,
		LookupsExhausted: r.LookupsExhausted,
		LookupsFailed:    r.LookupsFailed,
	}
}

// writeLine writes v as one line in one Write, so two writers never interleave
// halves of their lines.
func writeLine(w io.Writer, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

// readLine reads one line of at most limit bytes, without its end. A line the
// stream ended in the middle of is no line.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > limit+1 {
			return nil, errLineTooLong
		}
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case !errors.Is(err, bufio.ErrBufferFull):
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}
