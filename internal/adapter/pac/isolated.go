package pac

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// Child is one started sandbox process, as its parent sees it.
type Child struct {
	// In is the child's standard input and Out its standard output.
	In  io.WriteCloser
	Out io.Reader
	// Wait waits for the process to end and says the code it ended with.
	Wait func() int
}

// Start starts the sandbox process. Its standard error goes to stderr. The
// process ends when ctx does.
type Start func(ctx context.Context, stderr io.Writer) (Child, error)

// Isolated evaluates a PAC file in a process of its own - ADR150.
type Isolated struct {
	// Start starts the process. Nil means this build cannot, and every file
	// comes back evaluator_failed rather than being run here.
	Start Start
	// Sandbox is what the child is asked to run, and its Ports stay here: the
	// resolver and the clock are this process's.
	Sandbox Sandbox
	// Program is this program's version, which the child must share.
	Program string
	// Allowance is the time on top of the budget the child gets to start and
	// to say its result. The parent ends it at budget plus allowance.
	Allowance time.Duration
}

// The sentences an evaluation that did not answer is reported with. They name
// no path: the error from starting a process carries the program's own, and
// that is the user's home directory more often than not.
const (
	notStarted   = "the PAC file was not run: the process this program runs PAC files in could not be started"
	unreadable   = "the process running the PAC file answered with something this program cannot read"
	overlong     = "the process running the PAC file answered with a line longer than this program reads"
	stoppedTime  = "the PAC file was stopped for running past the time this run allows"
	stoppedSpace = "the PAC file was stopped for holding more memory than this run allows"
)

// firstLineLimit is how much of the first line the child wrote to its
// standard error a detail quotes.
const firstLineLimit = 200

// Evaluate runs source in a child process and asks it which proxy to use for
// rawURL on host.
//
// LIKE Sandbox.Evaluate IT NEVER RETURNS AN ERROR - condition 5. Every way the
// child can fail to answer is a Result: the parent's clock is time_limit, the
// watchdog's code is memory_ceiling, and anything else is evaluator_failed with
// the exit code and the first line the child wrote.
//
// THE NAMES THE FILE ASKED ABOUT ARE THIS PROCESS'S RECORD, not the child's, on
// every path - they are what left this machine, and a child that died took its
// own record with it.
func (iso Isolated) Evaluate(ctx context.Context, source, rawURL, host string) corepac.Result {
	s := iso.Sandbox
	budget := s.Budget
	// THE LAYER'S DEADLINE CAPS THE BUDGET, as it does in this process - ADR114.
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, max(time.Until(deadline), 0))
	}
	running, stop := context.WithTimeout(ctx, budget+iso.Allowance)
	defer stop()

	ports, record := s.boundedPorts()
	if iso.Start == nil {
		return withRecord(failed(notStarted), record)
	}
	var stderr headWriter
	child, err := iso.Start(running, &stderr)
	if err != nil {
		return withRecord(failed(notStarted), record)
	}

	req := request{
		Protocol: protocolVersion, Program: iso.Program,
		Source: []byte(source), URL: []byte(rawURL), Host: []byte(host),
		Budget: int64(budget), Ceiling: s.Ceiling, MaxSource: s.MaxSource, MaxStack: s.MaxStack,
		MaxLookups: s.MaxLookups, MaxAnswer: s.MaxAnswer, MaxDirectives: s.MaxDirectives,
		Resolver: ports.Resolve != nil, Clock: s.Ports.Now != nil,
	}
	if req.Clock {
		req.Now = s.Ports.Now().UnixNano()
	}
	answer, problem := iso.converse(child, req, ports.Resolve)
	_ = child.In.Close()
	expired := running.Err() != nil
	if answer == nil {
		// A CHILD THAT DID NOT ANSWER IS NOT WAITED FOR. It is ended now, and
		// whether the clock had already run out was read first.
		stop()
	}
	code := child.Wait()

	switch {
	case answer != nil:
		return withRecord(*answer, record)
	case code == ExitMemory:
		return withRecord(corepac.Result{Outcome: corepac.OutcomeMemoryCeiling, Detail: stoppedSpace}, record)
	case expired || code == ExitDeadline:
		return withRecord(corepac.Result{Outcome: corepac.OutcomeTimeLimit, Detail: stoppedTime}, record)
	case problem != "":
		return withRecord(failed(problem), record)
	}
	ended := fmt.Sprintf("the process running the PAC file ended before it answered, with exit code %d", code)
	if said := stderr.firstLine(); said != "" {
		ended += ": " + said
	}
	return withRecord(failed(ended), record)
}

// converse writes the request and answers the child until it writes its
// result. A nil result with no problem means the child ended or stopped
// talking, and how it ended says the rest.
func (iso Isolated) converse(child Child, req request, resolve func(string) ([]string, error)) (*corepac.Result, string) {
	if err := writeLine(child.In, req); err != nil {
		return nil, ""
	}
	r := bufio.NewReaderSize(child.Out, 64<<10)
	for {
		line, err := readLine(r, lineLimit)
		if errors.Is(err, errLineTooLong) {
			return nil, overlong
		}
		if err != nil {
			return nil, ""
		}
		var msg childLine
		if err := json.Unmarshal(line, &msg); err != nil {
			return nil, unreadable
		}
		switch {
		case msg.Result != nil:
			result, ok := iso.accept(*msg.Result)
			if !ok {
				return nil, unreadable
			}
			return &result, ""
		case msg.Refused != "":
			return nil, "the process running the PAC file refused it: " + msg.Refused
		case msg.Lookup != nil && resolve != nil:
			if err := writeLine(child.In, answerFor(resolve, *msg.Lookup)); err != nil {
				return nil, ""
			}
		default:
			return nil, unreadable
		}
	}
}

// answerFor asks the resolver about one name, behind the sandbox's own cache
// and allowance.
func answerFor(resolve func(string) ([]string, error), name string) lookupAnswer {
	addresses, err := resolve(name)
	if err != nil {
		return lookupAnswer{Failure: err.Error()}
	}
	return lookupAnswer{Addresses: addresses}
}

// accept turns what the child sent into a Result, or refuses it.
//
// THE CHILD RAN SOMEBODY ELSE'S FILE, SO ITS WORDS ARE CHECKED, NOT TRUSTED.
// The outcome has to be one this program names, an answer has to be one the
// sandbox would have let through, and the entries are split here from the
// answer rather than taken from the child.
func (iso Isolated) accept(w wireResult) (corepac.Result, bool) {
	outcome := corepac.Outcome(w.Outcome)
	if !slices.Contains(childOutcomes, outcome) {
		return corepac.Result{}, false
	}
	for _, name := range w.Unanswered {
		if !slices.Contains(helperNames, name) {
			return corepac.Result{}, false
		}
	}
	result := corepac.Result{
		Outcome: outcome, Raw: string(w.Raw), Detail: string(w.Detail),
		UsedRandomness: w.UsedRandomness, UsedClock: w.UsedClock, Unanswered: w.Unanswered,
		LookupsExhausted: w.LookupsExhausted, LookupsFailed: w.LookupsFailed,
	}
	if outcome == corepac.OutcomeAnswered {
		result.Directives = corepac.ParseDirectives(result.Raw)
		if len(result.Raw) > iso.Sandbox.MaxAnswer || len(result.Directives) == 0 ||
			len(result.Directives) > iso.Sandbox.MaxDirectives {
			return corepac.Result{}, false
		}
	}
	return result, true
}

// childOutcomes are the outcomes a sandbox can reach - every one but the one
// that says the process running it failed, which only the parent can say.
var childOutcomes = []corepac.Outcome{
	corepac.OutcomeAnswered, corepac.OutcomeNoAnswer, corepac.OutcomeMalformed, corepac.OutcomeTimeLimit,
	corepac.OutcomeMemoryCeiling, corepac.OutcomeStackLimit, corepac.OutcomeTooLarge,
}

// failed is an evaluation the process running it did not finish.
func failed(detail string) corepac.Result {
	return corepac.Result{Outcome: corepac.OutcomeEvaluatorFailed, Detail: detail}
}

// withRecord puts this process's record of the lookups on a result.
func withRecord(result corepac.Result, record func() ([]string, bool, bool)) corepac.Result {
	asked, exhausted, failedLookup := record()
	result.Asked = asked
	result.LookupsExhausted = result.LookupsExhausted || exhausted
	result.LookupsFailed = result.LookupsFailed || failedLookup
	return result
}

// headWriter keeps the start of what the child wrote to its standard error and
// drops the rest, so a child writing without end costs a few kilobytes.
type headWriter struct{ head []byte }

func (w *headWriter) Write(p []byte) (int, error) {
	if room := 4<<10 - len(w.head); room > 0 {
		w.head = append(w.head, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// firstLine is the first line with something on it, cut to firstLineLimit.
//
// IT IS NOT MASKED HERE, AND THAT IS ADR18 RATHER THAN AN OVERSIGHT: masking
// lives on the assembly path, which takes this detail like every other one and
// puts it through the credential floor there.
func (w *headWriter) firstLine() string {
	for _, line := range strings.Split(string(w.head), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return cutAt(line, firstLineLimit)
		}
	}
	return ""
}

// cutAt is s cut to at most limit bytes without splitting a character.
func cutAt(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}
