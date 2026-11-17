package pac

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// testProgram is the version the tests' parent and child share.
const testProgram = "0.0.0-test"

// inMemory starts Serve on a goroutine of this test process, over pipes, as a
// stand-in for the process the program starts. It cannot be ended from
// outside, so the tests that need the parent's clock use a fake child instead.
func inMemory() Start {
	return func(ctx context.Context, stderr io.Writer) (Child, error) {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		done := make(chan int, 1)
		go func() {
			code := Serve(inR, outW, testProgram, func(int) {})
			_ = outW.Close()
			_ = inR.Close()
			done <- code
		}()
		return Child{In: inW, Out: outR, Wait: func() int { return <-done }}, nil
	}
}

// isolated is Isolated around a sandbox, with the in-memory child.
func isolated(s Sandbox) Isolated {
	return Isolated{Start: inMemory(), Sandbox: s, Program: testProgram, Allowance: time.Second}
}

// fakeResolver answers from a table and counts what it was asked.
type fakeResolver struct {
	table map[string][]string
	asked []string
}

func (f *fakeResolver) resolve(host string) ([]string, error) {
	f.asked = append(f.asked, host)
	if host == "broken.resolver.test" {
		return nil, errors.New("no resolver answered")
	}
	return f.table[host], nil
}

// normal makes the empty and the absent list the same, which JSON keeps apart
// and these tests do not need to.
func normal(r corepac.Result) corepac.Result {
	if len(r.Directives) == 0 {
		r.Directives = nil
	}
	if len(r.Unanswered) == 0 {
		r.Unanswered = nil
	}
	if len(r.Asked) == 0 {
		r.Asked = nil
	}
	return r
}

// TestEveryBenchFileAnswersTheSameInAProcessOfItsOwn is the promise ADR150
// rests on: moving the file out of this process changes nothing it says. Every
// file the bench serves, and a few written here for the edges of the wire - a
// source that is not valid UTF-8, an answer of many entries, a file asking a
// resolver - is evaluated in this process and through the child, and the two
// results have to be equal field by field.
func TestEveryBenchFileAnswersTheSameInAProcessOfItsOwn(t *testing.T) {
	type input struct{ name, source, host string }
	var inputs []input
	for _, c := range []struct{ file, host string }{
		{"proxy.pac", "via.proxy.test"}, {"proxy.pac", "buildbox"}, {"hostile.pac", "via.proxy.test"},
		{"broken.pac", "via.proxy.test"}, {"null.pac", "via.proxy.test"}, {"runaway.pac", "via.proxy.test"},
		{"bomb.pac", "via.proxy.test"}, {"recursion.pac", "via.proxy.test"}, {"lookahead.pac", "app.internal.example"},
		{"clock.pac", "via.proxy.test"}, {"lookups.pac", "via.proxy.test"}, {"resolve.pac", "gw.proxy.test"},
	} {
		inputs = append(inputs, input{c.file + " " + c.host, benchPAC(t, c.file), c.host})
	}
	for name, body := range map[string]string{
		"invalid UTF-8 in the source": "return \"PROXY a\xff.test:1\";",
		"many entries":                "return \"PROXY a:1; PROXY b:2; SOCKS c:3; DIRECT\";",
		"a throw":                     "throw new Error(\"no \" + host);",
		"a lookup that fails":         "return dnsResolve(\"broken.resolver.test\") === null ? \"DIRECT\" : \"PROXY x:1\";",
		"two names, one twice":        "dnsResolve(\"a.test\"); dnsResolve(\"b.test\"); return dnsResolve(\"a.test\") ? \"DIRECT\" : \"PROXY x:1\";",
	} {
		inputs = append(inputs, input{name, "function " + Entry + "(url, host) { " + body + " }", "via.proxy.test"})
	}

	for _, in := range inputs {
		results := [2]corepac.Result{}
		resolvers := [2]*fakeResolver{}
		for i := range results {
			resolvers[i] = &fakeResolver{table: map[string][]string{"gw.proxy.test": {"172.28.0.90"}, "a.test": {"10.0.0.1"}}}
			sandbox := testSandbox()
			sandbox.MaxLookups = 4
			sandbox.Ports.Resolve = resolvers[i].resolve
			if strings.HasPrefix(in.name, "runaway") {
				sandbox.Budget = 300 * time.Millisecond
			}
			var evaluator Evaluator = sandbox
			if i == 1 {
				evaluator = isolated(sandbox)
			}
			results[i] = normal(evaluator.Evaluate(context.Background(), in.source, "http://"+in.host+"/", in.host))
		}
		if !reflect.DeepEqual(results[0], results[1]) {
			t.Errorf("%s answered differently in a process of its own:\n here: %+v\nchild: %+v", in.name, results[0], results[1])
		}
		if !reflect.DeepEqual(resolvers[0].asked, resolvers[1].asked) {
			t.Errorf("%s asked the resolver differently: here %v, child %v", in.name, resolvers[0].asked, resolvers[1].asked)
		}
	}
}

// TestANameLeavesThisMachineOnceAndNoMoreThanTheAllowance holds the parent to
// the sandbox's own cache and allowance: the child asks through the pipe, and
// the parent answers through the same boundedPorts, so a child that asked again
// or past the allowance would still not reach the resolver.
func TestANameLeavesThisMachineOnceAndNoMoreThanTheAllowance(t *testing.T) {
	resolver := &fakeResolver{table: map[string][]string{"a.test": {"10.0.0.1"}}}
	sandbox := testSandbox()
	sandbox.MaxLookups = 2
	sandbox.Ports.Resolve = resolver.resolve
	result := isolated(sandbox).Evaluate(context.Background(), "function "+Entry+`(u, h) {
		dnsResolve("a.test"); dnsResolve("a.test"); dnsResolve("b.test"); dnsResolve("c.test");
		return "DIRECT"; }`, "http://x.test/", "x.test")

	if want := []string{"a.test", "b.test"}; !reflect.DeepEqual(resolver.asked, want) {
		t.Errorf("the resolver was asked %v, want %v", resolver.asked, want)
	}
	if want := []string{"a.test", "b.test"}; !reflect.DeepEqual(result.Asked, want) {
		t.Errorf("the row says the file asked %v, want %v", result.Asked, want)
	}
	if !result.LookupsExhausted {
		t.Error("a file that spent its allowance is not reported as having spent it")
	}
}

// child is a fake sandbox process: what it writes, what it says on standard
// error, and the code it ends with - or, with hang, a process that never ends
// until it is ended, as a real one is when its parent's clock runs out.
type child struct {
	lines  []string
	stderr string
	code   int
	hang   bool
	// asked is the request the parent wrote, as the child read it.
	asked *request
}

func (c *child) start() Start {
	return func(ctx context.Context, stderr io.Writer) (Child, error) {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		done := make(chan int, 1)
		go func() {
			defer func() { _ = outW.Close(); _ = inR.Close() }()
			r := bufio.NewReader(inR)
			if line, err := readLine(r, requestLimit); err == nil {
				var req request
				if json.Unmarshal(line, &req) == nil {
					c.asked = &req
				}
			}
			_, _ = io.WriteString(stderr, c.stderr)
			for _, line := range c.lines {
				if _, err := io.WriteString(outW, line+"\n"); err != nil {
					break
				}
				if strings.HasPrefix(line, `{"lookup"`) {
					_, _ = readLine(r, answerLimit)
				}
			}
			if c.hang {
				<-ctx.Done()
				done <- -1
				return
			}
			done <- c.code
		}()
		return Child{In: inW, Out: outR, Wait: func() int { return <-done }}, nil
	}
}

// evaluateWith runs one evaluation against a fake child with a sandbox that
// has a resolver, so the parent's record is visible on every path.
func evaluateWith(c *child, budget time.Duration) (corepac.Result, time.Duration) {
	sandbox := testSandbox()
	sandbox.Budget = budget
	sandbox.MaxLookups = 4
	sandbox.Ports.Resolve = (&fakeResolver{table: map[string][]string{"seen.test": {"10.0.0.9"}}}).resolve
	iso := Isolated{Start: c.start(), Sandbox: sandbox, Program: testProgram, Allowance: 50 * time.Millisecond}
	start := time.Now()
	result := iso.Evaluate(context.Background(), "function "+Entry+`(u, h) { return "DIRECT"; }`, "http://x.test/", "x.test")
	return result, time.Since(start)
}

// TestEveryWayAChildCanEndIsAnOutcome is condition 5 kept across the process
// boundary: whatever the child does, the parent comes back with a Result that
// says what happened, and the names the file asked about before the end are on
// it.
func TestEveryWayAChildCanEndIsAnOutcome(t *testing.T) {
	asked := `{"lookup":"seen.test"}`
	for _, c := range []struct {
		name    string
		child   child
		outcome corepac.Outcome
		says    string
	}{
		{"the watchdog's code", child{lines: []string{asked}, code: ExitMemory}, corepac.OutcomeMemoryCeiling, stoppedSpace},
		{"the child's own deadline", child{lines: []string{asked}, code: ExitDeadline}, corepac.OutcomeTimeLimit, stoppedTime},
		{"the parent's clock", child{lines: []string{asked}, hang: true}, corepac.OutcomeTimeLimit, stoppedTime},
		{"a death of its own", child{lines: []string{asked}, code: 2,
			stderr: "\n  fatal error: out of memory\n\ngoroutine 1 [running]:\n"},
			corepac.OutcomeEvaluatorFailed, "with exit code 2: fatal error: out of memory"},
		{"an end with nothing said", child{lines: []string{asked}, code: 0}, corepac.OutcomeEvaluatorFailed, "with exit code 0"},
		{"a line that is not JSON", child{lines: []string{asked, "fatal"}, code: 0}, corepac.OutcomeEvaluatorFailed, unreadable},
		{"a line of nothing we know", child{lines: []string{asked, `{}`}, code: 0}, corepac.OutcomeEvaluatorFailed, unreadable},
		{"a line too long", child{lines: []string{asked, `{"refused":"` + strings.Repeat("x", lineLimit) + `"}`}, code: 0},
			corepac.OutcomeEvaluatorFailed, overlong},
		{"a refusal", child{lines: []string{asked, `{"refused":"the file was replaced"}`}, code: ExitRefused},
			corepac.OutcomeEvaluatorFailed, "refused it: the file was replaced"},
		{"an outcome only the parent may give", child{lines: []string{asked, `{"result":{"outcome":"evaluator_failed"}}`}},
			corepac.OutcomeEvaluatorFailed, unreadable},
		{"an outcome nobody named", child{lines: []string{asked, `{"result":{"outcome":"answered_probably"}}`}},
			corepac.OutcomeEvaluatorFailed, unreadable},
		{"an answer the sandbox would have refused", child{lines: []string{asked,
			`{"result":{"outcome":"answered","raw":"` + b64(strings.Repeat("DIRECT;", 100)) + `"}}`}},
			corepac.OutcomeEvaluatorFailed, unreadable},
		{"an answer of nothing", child{lines: []string{asked, `{"result":{"outcome":"answered","raw":""}}`}},
			corepac.OutcomeEvaluatorFailed, unreadable},
		{"a helper the sandbox does not have", child{lines: []string{asked,
			`{"result":{"outcome":"answered","raw":"` + b64("DIRECT") + `","unanswered":["require"]}}`}},
			corepac.OutcomeEvaluatorFailed, unreadable},
		{"an answer", child{lines: []string{asked, `{"result":{"outcome":"answered","raw":"` + b64("PROXY p:1; DIRECT") + `"}}`}},
			corepac.OutcomeAnswered, ""},
	} {
		result, elapsed := evaluateWith(&c.child, 100*time.Millisecond)
		if result.Outcome != c.outcome {
			t.Errorf("%s: outcome %s, want %s (%s)", c.name, result.Outcome, c.outcome, result.Detail)
			continue
		}
		if !strings.Contains(result.Detail, c.says) {
			t.Errorf("%s: detail %q does not say %q", c.name, result.Detail, c.says)
		}
		if want := []string{"seen.test"}; !reflect.DeepEqual(result.Asked, want) {
			t.Errorf("%s: the row says the file asked %v, want %v - the parent's record went with the child", c.name, result.Asked, want)
		}
		if elapsed > 2*time.Second {
			t.Errorf("%s took %v - an ending was waited for past the clock", c.name, elapsed)
		}
	}
}

// TestAnAnswerIsSplitHereNotTakenFromTheChild holds accept to splitting the
// answer itself: the child sends no entries at all, and the row has them.
func TestAnAnswerIsSplitHereNotTakenFromTheChild(t *testing.T) {
	result, _ := evaluateWith(&child{lines: []string{`{"result":{"outcome":"answered","raw":"` + b64("PROXY p:1; DIRECT") + `"}}`}},
		time.Second)
	want := corepac.ParseDirectives("PROXY p:1; DIRECT")
	if !reflect.DeepEqual(result.Directives, want) {
		t.Errorf("entries %+v, want %+v", result.Directives, want)
	}
}

// TestTheLayersDeadlineCapsTheChildsBudget is ADR114 across the process
// boundary: an evaluation started with little of the layer left asks the child
// for that little, not for its whole budget again.
func TestTheLayersDeadlineCapsTheChildsBudget(t *testing.T) {
	c := &child{lines: []string{`{"result":{"outcome":"answered","raw":"` + b64("DIRECT") + `"}}`}}
	sandbox := testSandbox()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	Isolated{Start: c.start(), Sandbox: sandbox, Program: testProgram}.Evaluate(ctx, "x", "http://x.test/", "x.test")
	if c.asked == nil {
		t.Fatal("the child never read a request")
	}
	if got := time.Duration(c.asked.Budget); got <= 0 || got > 200*time.Millisecond {
		t.Errorf("the child was given %v with 200ms of the layer left", got)
	}
}

// TestAChildThatCannotStartSaysSoWithoutAPath: the error from starting a
// process carries the program's own path, which is the account's home more
// often than not, and the report gets a sentence of ours instead.
func TestAChildThatCannotStartSaysSoWithoutAPath(t *testing.T) {
	refusing := func(context.Context, io.Writer) (Child, error) {
		return Child{}, errors.New(`fork/exec C:\Users\jdoe\certdoctor.exe: denied`)
	}
	for name, iso := range map[string]Isolated{
		"a start that fails": {Start: refusing, Sandbox: testSandbox()},
		"no start at all":    {Sandbox: testSandbox()},
	} {
		result := iso.Evaluate(context.Background(), "x", "http://x.test/", "x.test")
		if result.Outcome != corepac.OutcomeEvaluatorFailed || result.Detail != notStarted {
			t.Errorf("%s: %s %q", name, result.Outcome, result.Detail)
		}
	}
}

// TestServeRefusesWhatItWasNotAsked: a request it cannot read, of another
// protocol or from another version of the program is refused with a sentence
// and its own code, and the file in it is never run.
func TestServeRefusesWhatItWasNotAsked(t *testing.T) {
	good := request{Protocol: protocolVersion, Program: testProgram, Source: []byte("throw 1"), Budget: int64(time.Second)}
	for name, c := range map[string]struct {
		in   string
		says string
	}{
		"nothing":          {"", "could not read"},
		"half a line":      {`{"protocol":1`, "could not read"},
		"not JSON":         {"hello\n", "cannot read"},
		"another protocol": {lineOf(t, withProtocol(good, protocolVersion+1)), "replaced"},
		"another version":  {lineOf(t, withProgram(good, "9.9.9")), "certdoctor 9.9.9"},
		"too long":         {strings.Repeat("x", requestLimit+2) + "\n", "could not read"},
	} {
		var out strings.Builder
		code := Serve(strings.NewReader(c.in), &out, testProgram, func(int) { t.Errorf("%s: the watchdog ran", name) })
		if code != ExitRefused {
			t.Errorf("%s: code %d, want %d", name, code, ExitRefused)
		}
		if !strings.Contains(out.String(), `"refused"`) || !strings.Contains(out.String(), c.says) {
			t.Errorf("%s: wrote %q, want a refusal saying %q", name, out.String(), c.says)
		}
	}
}

// TestALookupWithNobodyToAnswerIsNotADeadEnd: a child whose parent stopped
// answering mid-file gets an error for the name - nobody could be asked - and
// finishes, rather than waiting for ever on a pipe.
func TestALookupWithNobodyToAnswerIsNotADeadEnd(t *testing.T) {
	req := request{Protocol: protocolVersion, Program: testProgram, Resolver: true, MaxLookups: 4,
		Source: []byte("function " + Entry + `(u, h) { return dnsResolve("a.test") === null ? "DIRECT" : "PROXY x:1"; }`),
		Budget: int64(time.Second), Ceiling: 64 << 20, MaxSource: 1 << 20, MaxStack: 2000, MaxAnswer: 16 << 10, MaxDirectives: 64}
	var out strings.Builder
	code := Serve(strings.NewReader(lineOf(t, req)), &out, testProgram, func(int) {})
	if code != ExitAnswered || !strings.Contains(out.String(), `"lookup":"a.test"`) ||
		!strings.Contains(out.String(), `"raw":"`+b64("DIRECT")+`"`) {
		t.Errorf("code %d, wrote %q", code, out.String())
	}
}

// TestTheWatchdogEndsTheProcessForMemoryAndForTime, and never once its
// evaluation is over.
func TestTheWatchdogEndsTheProcessForMemoryAndForTime(t *testing.T) {
	for name, c := range map[string]struct {
		held     uint64
		deadline time.Duration
		want     int
	}{
		"memory": {held: 2 << 30, deadline: time.Hour, want: ExitMemory},
		"time":   {held: 0, deadline: 10 * time.Millisecond, want: ExitDeadline},
	} {
		ended := make(chan int, 1)
		watchdog(context.Background(), func() uint64 { return c.held }, 1<<30, c.deadline, func(code int) { ended <- code })
		select {
		case got := <-ended:
			if got != c.want {
				t.Errorf("%s: ended with %d, want %d", name, got, c.want)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s: the watchdog did not end the process", name)
		}
	}

	over, stop := context.WithCancel(context.Background())
	stop()
	ended := make(chan int, 1)
	watchdog(over, func() uint64 { return 2 << 30 }, 1<<30, 0, func(code int) { ended <- code })
	select {
	case got := <-ended:
		t.Errorf("a watchdog whose evaluation was over ended the process with %d", got)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestTheWatchdogReadsFiguresThatExist holds heapMetrics to the runtime: a name
// the toolchain no longer publishes would read as zero for ever, and the
// watchdog would quietly stop watching.
func TestTheWatchdogReadsFiguresThatExist(t *testing.T) {
	if held := heapInUse(); held == 0 {
		t.Error("this process holds nothing, by the watchdog's reading")
	}
	for _, name := range heapMetrics {
		known := false
		for _, d := range metrics.All() {
			if d.Name == name && d.Kind == metrics.KindUint64 {
				known = true
			}
		}
		if !known {
			t.Errorf("%s is not a uint64 figure this toolchain publishes", name)
		}
	}
}

// TestAHighCeilingSaturatesRatherThanWrapping is the stopwatch's own lesson
// for the hard limit: a ceiling meant as loose must not turn into its opposite.
func TestAHighCeilingSaturatesRatherThanWrapping(t *testing.T) {
	if hardLimit(1<<63) != ^uint64(0) || hardLimit(64<<20) != 256<<20 {
		t.Errorf("hardLimit(1<<63) = %d, hardLimit(64 MiB) = %d", hardLimit(1<<63), hardLimit(64<<20))
	}
}

// TestALineIsReadToItsLimitAndNoFurther.
func TestALineIsReadToItsLimitAndNoFurther(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want string
		err  error
	}{
		"at the limit":           {strings.Repeat("x", 100) + "\n", strings.Repeat("x", 100), nil},
		"one past it":            {strings.Repeat("x", 101) + "\n", "", errLineTooLong},
		"cut off":                {"abc", "", io.ErrUnexpectedEOF},
		"nothing at all":         {"", "", io.EOF},
		"longer than the buffer": {strings.Repeat("y", 50) + "\n", strings.Repeat("y", 50), nil},
	} {
		got, err := readLine(bufio.NewReaderSize(strings.NewReader(c.in), 16), 100)
		if string(got) != c.want || !errors.Is(err, c.err) && !(err == nil && c.err == nil) {
			t.Errorf("%s: %q, %v - want %q, %v", name, got, err, c.want, c.err)
		}
	}
}

// TestTheFirstLineIsCutWithoutSplittingACharacter.
func TestTheFirstLineIsCutWithoutSplittingACharacter(t *testing.T) {
	w := &headWriter{}
	_, _ = w.Write([]byte("\n \n" + strings.Repeat("a", firstLineLimit-1) + "\u00e9tail\nsecond"))
	if got := w.firstLine(); got != strings.Repeat("a", firstLineLimit-1) {
		t.Errorf("first line %q", got)
	}
	_, _ = w.Write(make([]byte, 10<<10))
	if len(w.head) > 4<<10 {
		t.Errorf("the head grew to %d bytes", len(w.head))
	}
}

// b64 is s as a []byte field of a line reads: base64.
func b64(s string) string {
	line, _ := json.Marshal([]byte(s))
	return strings.Trim(string(line), `"`)
}

func lineOf(t *testing.T, v any) string {
	t.Helper()
	line, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(line) + "\n"
}

func withProtocol(r request, p int) request   { r.Protocol = p; return r }
func withProgram(r request, p string) request { r.Program = p; return r }
