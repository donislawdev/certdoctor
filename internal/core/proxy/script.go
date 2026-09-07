package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/pac"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// NamedOnCommandLine is what a script row holds instead of a stack name when
// the user supplied the address.
//
// IT IS DELIBERATELY NOT A Stack VALUE. A Stack is a place a MACHINE keeps
// proxy configuration, and nobody keeps any on a command line - a proxy_stack
// row for it would report a setting that does not exist. So the token lives
// here, beside the only field that carries it, and the closed list of stacks
// stays a list of places.
const NamedOnCommandLine = "command_line"

// ScriptAnswer is what one automatic configuration script came to.
//
// FETCHING AND RUNNING ARE TWO FACTS AND THE TYPE KEEPS THEM APART. pac.Outcome
// is a closed vocabulary about EVALUATION and has no value meaning "the bytes
// never arrived" - naming one would make a web server nobody can reach look
// like a file that answers badly, and those two send a reader to different
// places.
type ScriptAnswer struct {
	// Fetched says whether the bytes arrived at all.
	Fetched bool
	// Detail is why they did not, in this program's words. A false Fetched
	// without one is a defect on our side, and the report contract refuses it.
	Detail string
	// Result is what running them came to. It means nothing unless Fetched.
	Result pac.Result
}

// Evaluate is the port that turns a script's address into what it says.
//
// IT IS ONE PORT AND NOT TWO - fetch then run - because the two halves have no
// caller between them and a layer that held both would be deciding, in the
// core, how long a fetch may take and how big a file may be. Those are the
// adapter's numbers. What this layer needs is the pair the answer comes in.
type Evaluate func(ctx context.Context, url string) ScriptAnswer

// script is one script this run resolved, with everything its row needs.
type script struct {
	url     string
	namedBy []string
	// carried records that the address named a credential which was cut off
	// before anything was fetched or reported.
	carried bool
	answer  ScriptAnswer
}

// settled says whether this script produced an answer a verdict may rest on.
//
// THREE THINGS HAVE TO HOLD AND THE THIRD IS THE ONE THAT IS EASY TO FORGET.
// The bytes arrived, the file answered - and it did not decide by asking
// something this run had nobody to ask. A PAC file calling isInNet on a run
// with no resolver behind it gets a false, because the PAC contract has no way
// to say "nobody could be asked", and it then takes a branch a browser would
// not take. Counting that as settled would let this program report a route it
// worked out from a known untruth.
func (s script) settled() bool {
	return s.answer.Fetched &&
		s.answer.Result.Outcome == pac.OutcomeAnswered &&
		len(s.answer.Result.Unanswered) == 0
}

// scriptReasons maps what the evaluator saw onto the layer's vocabulary.
//
// OutcomeAnswered IS ABSENT ON PURPOSE and its absence is load bearing: an
// answer is not a failure, so asking this table about one has no honest result.
// The lookup below treats a miss as undetermined, which is what an answer that
// still settles nothing - because a helper could not be answered - deserves.
//
// THE BOUNDARY BETWEEN timeout AND limit_exceeded IS ADR80 PART 3 AND IT IS
// BINDING: time stays with timeout, every other ceiling of ours comes to
// limit_exceeded. A file stopped for allocating did not run out of time, and
// one refused for its size was never started.
var scriptReasons = map[pac.Outcome]status.Reason{
	pac.OutcomeMalformed:     status.ReasonUnparseable,
	pac.OutcomeTimeLimit:     status.ReasonTimeout,
	pac.OutcomeMemoryCeiling: status.ReasonLimitExceeded,
	pac.OutcomeStackLimit:    status.ReasonLimitExceeded,
	pac.OutcomeTooLarge:      status.ReasonLimitExceeded,
	// A file that returned null. Mozilla's documentation says that means "no
	// proxies", equivalent to DIRECT, and that is what a browser does -
	// testbed/pac/files/null.pac, written before any of this code existed,
	// expects an UNKNOWN with a reason instead. This program reports rather
	// than routes, and a silent fall back to DIRECT is the behaviour it exists
	// to interrupt: pac-broken.txt forbids the word outright for the same
	// reason. So the answer is recorded as settling nothing.
	pac.OutcomeNoAnswer: status.ReasonUndetermined,
}

// reason says which word this script's failure deserves.
func (s script) reason() status.Reason {
	if !s.answer.Fetched {
		return status.ReasonUndetermined
	}
	if found, ok := scriptReasons[s.answer.Result.Outcome]; ok {
		return found
	}
	return status.ReasonUndetermined
}

// scriptsNamed finds every script this run should ask about, one entry per
// SCRIPT rather than per namer, WITHOUT asking any of them.
//
// THE ASKING IS A SEPARATE FUNCTION AND THE SEAM BETWEEN THEM IS LOAD BEARING.
// Fetching a script opens a connection, and an address read off THIS MACHINE is
// not in the allowed set until somebody puts it there - which may not be this
// layer, because a layer that widens the set for itself makes that set a
// description of what happened rather than a rule about what may. So this half
// runs, the orchestrator authorises what it named, and askScripts runs after.
//
// THE DEDUPLICATION IS NOT TIDINESS. Two Windows stacks routinely hold the same
// AutoConfigURL, so a pass per stack would fetch one file twice, run it twice,
// and print two answers that a file using Math.random is entitled to make
// differ - a report contradicting itself about one file. It also doubles what
// this layer spends of a budget it shares with the machine's own reading.
//
// THE COMMAND LINE COMES FIRST because the user asking about a specific script
// is the strongest statement of intent in the run, and report order is the
// order a reader meets things in.
func scriptsNamed(in Input, lenses []Lens) []script {
	var scripts []script
	position := map[string]int{}

	// THERE IS NO "AND IF IT IS EMPTY" GUARD HERE, AND ITS ABSENCE IS MEASURED
	// RATHER THAN AN OVERSIGHT. The first draft had one. Both callers below
	// already refuse an empty address, and withoutCredentials cannot produce one
	// from a non-empty input - what it returns is either its argument or a
	// string still holding the scheme and the "://". So the branch could not be
	// reached, which makes it the shape OBS112 names: a guard that reads as
	// caution and decides nothing, and which would then take a mutation entry
	// with it by surviving every mutation aimed at it.
	add := func(rawURL, namer string) {
		clean, carried := withoutCredentials(rawURL)
		if at, seen := position[clean]; seen {
			scripts[at].namedBy = append(scripts[at].namedBy, namer)
			scripts[at].carried = scripts[at].carried || carried
			return
		}
		position[clean] = len(scripts)
		scripts = append(scripts, script{url: clean, namedBy: []string{namer}, carried: carried})
	}

	if in.ScriptURL != "" {
		add(in.ScriptURL, NamedOnCommandLine)
	}
	for _, lens := range lenses {
		// A stack that could not be read names nothing, including no script -
		// the same rule findingFor applies to its servers, and for the same
		// reason: reporting what an unreadable place held is inventing it.
		if lens.Read && lens.PACURL != "" {
			add(lens.PACURL, lens.Stack.String())
		}
	}

	return scripts
}

// addresses names the scripts this run will ask about, in report order.
//
// IT IS THE LIST THE ORCHESTRATOR WIDENS THE ALLOWED SET BY, and it exists as a
// function of its own so that "which scripts will be fetched" is answered once,
// beside the code that fetches them. A second reading of it in the wiring could
// drift, and the direction it would drift in is a script this run then fetches
// without anything having authorised the address.
func addresses(scripts []script) []string {
	var out []string
	for _, one := range scripts {
		out = append(out, one.url)
	}
	return out
}

// askScripts puts every named script to the port, in the order they were named.
func askScripts(ctx context.Context, evaluate Evaluate, scripts []script) []script {
	for at := range scripts {
		scripts[at].answer = askScript(ctx, evaluate, scripts[at].url)
	}
	return scripts
}

// askScript puts one script to the port, and answers for a run that has none.
//
// A MISSING PORT IS OUR DEFECT AND THE SENTENCE SAYS SO. It is not a fact about
// somebody's machine - the machine named a script perfectly well - so the row
// must not read as an unreachable server. It still comes back as an unfetched
// script rather than as a broken layer, because the rest of the report is
// worth printing.
func askScript(ctx context.Context, evaluate Evaluate, url string) ScriptAnswer {
	if evaluate == nil {
		return ScriptAnswer{Detail: "this run was given no way to fetch an automatic configuration script, " +
			"which is a gap in certdoctor rather than anything about this machine"}
	}
	return evaluate(ctx, url)
}

// withoutCredentials cuts userinfo out of a script address and says whether
// there was any.
//
// INVIOLABLE RULE 17, AND CUT AT THE POINT OF READING RATHER THAN ON THE WAY
// OUT - ADR89's mechanism, applied to the second field that becomes both a
// connection target and a report field. A password left in here would reach the
// allowed set, the transport, the report and any error quoting the address, and
// only the last of those has masking in front of it.
//
// IT IS NOT parseServer's RULE AND MUST NOT BORROW IT, which is worth stating
// because borrowing rather than copying is this package's habit. That function
// reads a PROXY LIST ENTRY, whose grammar has no path, so it cuts at the first
// "/" before looking for an "@". A script address is a URL where the path is
// the point, and cutting it would turn every script into its own origin.
func withoutCredentials(rawURL string) (string, bool) {
	mark := strings.Index(rawURL, "://")
	if mark < 0 {
		return rawURL, false
	}
	start := mark + len("://")
	// The authority ends at the first "/", "?" or "#"; an "@" after that point
	// belongs to the path and is not a credential.
	end := len(rawURL)
	if cut := strings.IndexAny(rawURL[start:], "/?#"); cut >= 0 {
		end = start + cut
	}
	authority := rawURL[start:end]
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return rawURL, false
	}
	// An empty userinfo carries no credential, so "http://@p/x" is a badly
	// written address rather than a secret - the same reading parseServer makes
	// of the same character.
	return rawURL[:start] + authority[at+1:] + rawURL[end:], at > 0
}

// scriptFinding turns one script into one row.
func scriptFinding(s script, target Target) report.Finding {
	body := report.PACScript{
		URL:     s.url,
		NamedBy: append([]string{}, s.namedBy...),
		Fetched: s.answer.Fetched,
		Detail:  s.answer.Detail,
	}
	if s.answer.Fetched {
		// THE EVALUATOR'S SENTENCE GOES INTO THE SAME FIELD THE FETCHER'S DOES,
		// and the field says so: why it could not be fetched, OR an extra
		// sentence about what was. Found by running the binary rather than by a
		// test: a malformed script came back with outcome "malformed" and a null
		// detail, so the only place saying WHAT was wrong with the file was the
		// summary - a sentence written for people, which a program reading the
		// document would have had to parse.
		//
		// It is empty for an answer, because pac.Result fills it only for the
		// outcomes that are not one.
		body.Detail = s.answer.Result.Detail
		body.Outcome = string(s.answer.Result.Outcome)
		body.Answer = s.answer.Result.Raw
		body.Directives = directivesOf(s.answer.Result.Directives)
		if chosen, ok := firstRecognised(s.answer.Result.Directives); ok {
			body.Selected = &chosen
		}
	}
	body.Caveats = caveatsOfScript(s, body)

	return report.Finding{
		Kind:      report.FindingPACScript,
		Summary:   summaryOfScript(s, body, target),
		Source:    report.SourceDetected,
		PACScript: &body,
	}
}

// directivesOf carries the evaluator's list across. NIL STAYS NIL - ADR20 - and
// here the pair is "nothing was evaluated" against "it was evaluated and named
// no entry", which are the two states pac.Result keeps apart with the same
// distinction.
func directivesOf(directives []pac.Directive) []report.PACDirective {
	if directives == nil {
		return nil
	}
	out := make([]report.PACDirective, 0, len(directives))
	for _, directive := range directives {
		out = append(out, report.PACDirective{
			Kind:       directive.Kind,
			Endpoint:   directive.Endpoint,
			Recognised: directive.Recognised,
		})
	}
	return out
}

// firstRecognised is the entry a client would act on.
//
// LEFT TO RIGHT AND THE FIRST ONE WE KNOW - Mozilla documents the entries as
// tried in the order the file listed them. An unrecognised keyword is SKIPPED
// here and still CARRIED in the list above, which is the pair inviolable rule
// 15 asks for: this program says what it would do without pretending the file
// said nothing else.
func firstRecognised(directives []pac.Directive) (report.PACDirective, bool) {
	for _, directive := range directives {
		if directive.Recognised {
			return report.PACDirective{
				Kind:       directive.Kind,
				Endpoint:   directive.Endpoint,
				Recognised: true,
			}, true
		}
	}
	return report.PACDirective{}, false
}

// caveatsOfScript is what this row does not settle, in our words.
func caveatsOfScript(s script, body report.PACScript) []string {
	caveats := []string{}
	if s.carried {
		// Inviolable rule 17 says the credential goes nowhere. Saying that one
		// was there is half the answer to "why does fetching it fail", and the
		// half that can be said out loud.
		caveats = append(caveats,
			"this address named a user and a password; certdoctor dropped them and did not send them, "+
				"so a script behind a login will not have been fetched")
	}
	if len(s.answer.Result.Unanswered) > 0 {
		// The measured shape pac.Result.Unanswered exists for: the PAC contract
		// gives isResolvable one boolean and no way to say "nobody could be
		// asked", so a run with no resolver hands the file a false and the file
		// takes a branch a browser would not.
		caveats = append(caveats, fmt.Sprintf(
			"this script called %s, and this run had nothing behind those, so it was answered as though "+
				"the names did not resolve and its answer may not be the one a browser would get",
			strings.Join(s.answer.Result.Unanswered, ", ")))
	}
	if s.answer.Result.UsedRandomness {
		// The sandbox pins the random source so two runs of one binary agree.
		// That makes the report reproducible and makes this answer ONE of the
		// answers a client could get rather than THE answer.
		caveats = append(caveats,
			"this script chose with Math.random, so this is one of the answers a client could get "+
				"rather than the only one")
	}
	if body.Selected == nil && len(body.Directives) > 0 {
		caveats = append(caveats,
			"none of the entries this script returned is a keyword certdoctor knows, so it names nothing to act on")
	}
	return caveats
}

// summaryOfScript is the one line a surface prints when it knows nothing about
// this kind.
//
// NO SENTENCE HERE NAMES THE ENDPOINT, which is the same masking rule summaryOf
// states for stacks and it is not brevity. A summary crosses the assembly path
// through Redaction.Text, which finds a host inside a URL and pseudonymises
// names it was told about - and a PAC directive's endpoint is a bare "host:port"
// arriving during the walk, so it is neither. THE SCRIPT'S OWN ADDRESS IS
// DIFFERENT and may be here: it IS a URL, which is the one shape that rule can
// see into.
func summaryOfScript(s script, body report.PACScript, target Target) string {
	where := "the PAC script at " + s.url
	if !s.answer.Fetched {
		return where + " could not be fetched, so what it says about " + describe(target) + " is unknown"
	}
	if s.answer.Result.Outcome != pac.OutcomeAnswered {
		return where + " was fetched and gave no usable answer for " + describe(target) +
			": " + s.answer.Result.Detail
	}
	switch {
	case body.Selected == nil:
		return where + " answered for " + describe(target) + " with nothing certdoctor recognises"
	case body.Selected.Endpoint == "":
		return where + " sends " + describe(target) + " past every proxy this machine names"
	default:
		return where + " sends " + describe(target) + " through a proxy of its own choosing"
	}
}
