package pac

import "strings"

// Outcome says what happened to one PAC evaluation.
//
// IT IS THIS PACKAGE'S OWN CLOSED VOCABULARY AND IT IS DELIBERATELY NOT
// status.Reason. Three of the values below have no honest home among the seven
// reasons that vocabulary holds: a file stopped by the memory ceiling did not
// time out, was refused by nobody, produced no output to be unrecognised and
// broke nothing inside this program. Naming an eighth reason is a load-bearing
// change to a public contract, and there is already one such question open for
// the proxy that demands credentials (O15). Both are the same decision about the
// same closed list, so they are answered together, in the slice where the layer
// exists - not settled quietly here by whichever word fits least badly.
//
// So this evaluator says what HAPPENED, and L2 will say what it MEANS.
type Outcome string

const (
	// OutcomeAnswered - the PAC file returned a string. Directives holds it.
	OutcomeAnswered Outcome = "answered"

	// OutcomeNoAnswer - the PAC file returned null or undefined.
	//
	// WHAT THIS MEANS IS AN OPEN DISAGREEMENT AND IT IS RECORDED RATHER THAN
	// RESOLVED HERE. Mozilla's documentation, read 2026-09-02, says a null
	// return means "no proxies should be used", equivalent to DIRECT - that is
	// what the browser does. testbed/pac/files/null.pac, written before this
	// code existed, expects UNKNOWN with a reason instead. Both cannot be right,
	// and the choice is about what certdoctor should REPORT rather than about
	// what a client will DO, which makes it the layer's decision and a change to
	// the wording of a verdict.
	//
	// It is a value of its own precisely so that neither answer can be arrived
	// at by accident: nothing downstream can mistake it for a directive, and
	// nothing can mistake it for a fault either.
	OutcomeNoAnswer Outcome = "no_answer"

	// OutcomeMalformed - the file would not parse, had no FindProxyForURL, or
	// threw. Measured 2026-09-02 by probe S12: goja returns all three as an
	// error value rather than a panic.
	OutcomeMalformed Outcome = "malformed"

	// OutcomeTimeLimit - the evaluation ran past its time budget and was
	// interrupted. Measured: a while(true) loop ends 1 ms past a 50 ms budget.
	OutcomeTimeLimit Outcome = "time_limit"

	// OutcomeMemoryCeiling - the evaluation was interrupted for allocating past
	// the ceiling.
	//
	// THE CEILING IS A CEILING ON WHAT GETS NOTICED, NOT ON WHAT GETS
	// ALLOCATED, and any sentence built on this value has to keep that true.
	// goja exposes no memory limit at all (ADR75), so this is a stopwatch
	// reading the heap, and between two of its reads somebody else's step can
	// double again: measured overshoot was 1.75x and 1.88x on two runs of the
	// same file, so it is a RANGE and not a constant.
	OutcomeMemoryCeiling Outcome = "memory_ceiling"

	// OutcomeStackLimit - the file recursed past the call stack limit.
	//
	// THE LIMIT THAT STOPPED BEING TUNING AND BECAME A CONDITION - ADR75.
	// Measured 2026-09-02: unbounded recursion at goja's defaults was still
	// running after ten seconds with a 213 MiB heap, which is longer than a whole
	// certdoctor run; with the limit set the same file ends in 1 ms.
	OutcomeStackLimit Outcome = "stack_limit"

	// OutcomeTooLarge - the file was refused before it reached the parser.
	//
	// docs/14 section 2.3: the size limit is checked BEFORE the bytes are handed
	// over, because after parsing it is already too late.
	OutcomeTooLarge Outcome = "too_large"
)

// Result is one evaluation's answer.
type Result struct {
	Outcome Outcome
	// Directives is what the PAC file returned, in the order it listed them,
	// and is empty for every outcome but OutcomeAnswered.
	Directives []Directive
	// Raw is the string the file returned, kept so a report can quote the file
	// rather than our reading of it.
	Raw string
	// Detail says what went wrong, in this program's words, for the outcomes
	// that are not an answer.
	Detail string

	// UsedRandomness says the PAC file called Math.random while deciding.
	//
	// IT EXISTS SO A REPORT CANNOT OVERSTATE ITSELF. The sandbox pins the
	// random source so that two runs of one binary agree, which is what the
	// determinism guard requires - but a file that balances load randomly would
	// spread across branches in a browser and always takes one here. The answer
	// is then ONE of the answers the client could give rather than THE answer,
	// and a verdict that did not know the difference would be saying more than
	// it measured.
	UsedRandomness bool

	// Unanswered names the helpers the file called that this run had nothing
	// behind, in the order the sandbox declares them.
	//
	// IT EXISTS BECAUSE THE PAC CONTRACT HAS NOWHERE TO PUT "NOBODY COULD BE
	// ASKED". IsResolvable in this package says so at length: the specification
	// gives that function one boolean, so a run with no resolver has to answer
	// false - a known untruth the function cannot fix alone, and one whose
	// honest report has to be made by the layer. The layer can only make it if
	// something tells it the file went looking, and this field is that
	// something.
	//
	// IT NAMES HELPERS RATHER THAN BEING A BOOLEAN so the sentence a reader gets
	// says what the file wanted. "This script asked isInNet and this run has no
	// resolver behind it" sends somebody somewhere; "the answer may be
	// incomplete" sends them nowhere.
	//
	// IT OVERSTATES IN ONE CASE AND DOES SO IN THE SAFE DIRECTION. DNSResolve
	// returns an IP literal unchanged and asks nobody, so a file calling
	// dnsResolve("10.0.0.1") got a complete answer and is still listed here.
	// Not listing it would mean repeating DNSResolve's own rule at the
	// injection site - one rule in two places, the shape OBS50 measures - in
	// order to turn an UNKNOWN into a PASS. Inviolable rule 15 says which of
	// those two errors to prefer.
	Unanswered []string
}

// Directive is one entry of a PAC file's answer.
type Directive struct {
	// Kind is the keyword as the file spelled it, upper-cased.
	Kind string
	// Endpoint is the "host:port" that followed it, empty for DIRECT.
	Endpoint string
	// Recognised says whether Kind is one this program knows.
	//
	// AN UNKNOWN KEYWORD IS KEPT RATHER THAN DROPPED - inviolable rule 15. A
	// directive silently discarded would make a report say a client goes direct
	// when the file actually named something we failed to read.
	Recognised bool
}

// knownDirectives are the keywords a PAC answer may use.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - DIRECT, PROXY and SOCKS
// are the original three; Firefox additionally accepts HTTP, HTTPS, SOCKS4 and
// SOCKS5. Entries are separated by semicolons and tried left to right.
var knownDirectives = map[string]bool{
	"DIRECT": true,
	"PROXY":  true,
	"SOCKS":  true,
	"SOCKS4": true,
	"SOCKS5": true,
	"HTTP":   true,
	"HTTPS":  true,
}

// ParseDirectives splits a PAC answer into its entries.
//
// AN EMPTY ANSWER IS NOT A DIRECTIVE AND NOT AN ERROR HERE. It comes back as no
// entries at all, so the caller can tell "the file said nothing" from "the file
// said something we could not read" - two states that a single empty slice would
// merge.
func ParseDirectives(answer string) []Directive {
	var directives []Directive
	for _, entry := range strings.Split(answer, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		keyword, endpoint, _ := strings.Cut(entry, " ")
		keyword = strings.ToUpper(strings.TrimSpace(keyword))
		directives = append(directives, Directive{
			Kind:       keyword,
			Endpoint:   strings.TrimSpace(endpoint),
			Recognised: knownDirectives[keyword],
		})
	}
	return directives
}
