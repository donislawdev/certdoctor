package pac

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// childGrace is how long past its budget the child keeps itself alive before
// its watchdog ends it - longer than the parent's allowance, so the parent's
// clock decides in every case where the parent is still there. The watchdog's
// own deadline only matters once the parent is gone: then nobody else would
// end a file looping in native code.
const childGrace = 2 * time.Second

// hardCeilings is how many times the sandbox's ceiling the child may hold
// before its watchdog ends it.
//
// ABOVE THE STOPWATCH'S OWN STOP, SO THE GENTLE PATH WINS WHEN IT CAN. A file
// that allocates in steps is interrupted by the stopwatch, and probe S12
// measured where it lands: 1.75 to 1.88 times the ceiling. That path keeps the
// evidence - what the file asked, which limit, in which phase. The watchdog is
// for what the stopwatch cannot reach, and probe S33 measured that it does not
// need to be close: a single allocation of ten gigabytes was seen within 2 to
// 45 ms, before its pages were touched, on Windows, Linux and macOS.
const hardCeilings = 4

// Serve is the process a PAC file runs in: it reads one request from in,
// evaluates the file in a Sandbox, writes its result to out and says the code
// the process should end with. exit is how the watchdog ends the process early -
// os.Exit in the program, a recorder in a test.
//
// IT REFUSES A REQUEST FROM ANOTHER PROGRAM FILE. The parent is started from
// one file and the child from whatever os.Executable names a moment later, and
// a package upgrade in between puts a different version there. A refusal is
// written out, and the parent reports it.
func Serve(in io.Reader, out io.Writer, program string, exit func(int)) int {
	r := bufio.NewReaderSize(in, 64<<10)
	line, err := readLine(r, requestLimit)
	if err != nil {
		return refusing(out, fmt.Sprintf("the process running PAC files could not read what it was asked: %v", err))
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return refusing(out, "the process running PAC files was asked something it cannot read")
	}
	if req.Protocol != protocolVersion || req.Program != program {
		return refusing(out, fmt.Sprintf("the program file is certdoctor %s and the run that started it is certdoctor %s, "+
			"so the file was replaced while the run was going", program, req.Program))
	}

	sandbox := req.sandbox()
	if req.Resolver {
		sandbox.Ports.Resolve = askParent(r, out)
	}
	if req.Clock {
		now := time.Unix(0, req.Now)
		sandbox.Ports.Now = func() time.Time { return now }
	}

	watching, stop := context.WithCancel(context.Background())
	defer stop()
	watchdog(watching, heapInUse, hardLimit(req.Ceiling), time.Duration(req.Budget)+childGrace, exit)

	result := sandbox.Evaluate(context.Background(), string(req.Source), string(req.URL), string(req.Host))
	// A FAILED WRITE ENDS THE CHILD THE SAME WAY - its parent is gone or no
	// longer reading, and nobody is left to tell.
	_ = writeLine(out, childLine{Result: ptr(wireOf(result))})
	return ExitAnswered
}

// refusing writes why the child will not run the request and says its code.
func refusing(out io.Writer, why string) int {
	_ = writeLine(out, childLine{Refused: why})
	return ExitRefused
}

// sandbox is the Sandbox the request describes, with no ports yet.
func (req request) sandbox() Sandbox {
	return Sandbox{
		Budget:        time.Duration(req.Budget),
		Ceiling:       req.Ceiling,
		MaxSource:     req.MaxSource,
		MaxStack:      req.MaxStack,
		MaxLookups:    req.MaxLookups,
		MaxAnswer:     req.MaxAnswer,
		MaxDirectives: req.MaxDirectives,
	}
}

// hardLimit is the memory the child may hold, saturating like the stopwatch's
// own limit does: a ceiling set high has to mean loose, never its opposite.
func hardLimit(ceiling uint64) uint64 {
	if ceiling > math.MaxUint64/hardCeilings {
		return math.MaxUint64
	}
	return ceiling * hardCeilings
}

// errParentGone is what a lookup gets once the parent stopped answering.
var errParentGone = errors.New("the run that asked for this evaluation stopped answering")

// askParent is the child's resolver: it asks the parent over the pipe and waits
// for the answer.
//
// IT IS BEHIND THE SANDBOX'S OWN CACHE AND ALLOWANCE, and the parent puts its
// answers behind the same ones, so a name leaves this machine once and the
// allowance holds even if one side were wrong.
func askParent(r *bufio.Reader, out io.Writer) func(string) ([]string, error) {
	return func(host string) ([]string, error) {
		if err := writeLine(out, childLine{Lookup: &host}); err != nil {
			return nil, errParentGone
		}
		line, err := readLine(r, answerLimit)
		if err != nil {
			return nil, errParentGone
		}
		var answer lookupAnswer
		if err := json.Unmarshal(line, &answer); err != nil {
			return nil, errParentGone
		}
		if answer.Failure != "" {
			return nil, errors.New(answer.Failure)
		}
		return answer.Addresses, nil
	}
}

func ptr[T any](v T) *T { return &v }
