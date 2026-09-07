// Command certdoctor works out why this machine, or this container, cannot
// reach a given URL.
//
// Nothing is diagnosed yet, and the program says so rather than implying
// otherwise. Every diagnostic layer reports that it could not be assessed, the
// verdict says the same in one sentence, and the run ends with the code that
// means exactly that. There is no point in this program's life at which it
// claims to have checked something it has not.
//
// This file is wiring and nothing else. It gathers the outside world into one
// value, hands it to the command line, and turns the answer into an exit status.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/dial"
	"github.com/donislawdev/certdoctor/internal/adapter/dns"
	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/handshake"
	"github.com/donislawdev/certdoctor/internal/adapter/output"
	"github.com/donislawdev/certdoctor/internal/adapter/pac"
	"github.com/donislawdev/certdoctor/internal/adapter/privilege"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/adapter/probe/curl"
	"github.com/donislawdev/certdoctor/internal/adapter/probe/git"
	"github.com/donislawdev/certdoctor/internal/adapter/probe/java"
	"github.com/donislawdev/certdoctor/internal/adapter/proxyauth"
	"github.com/donislawdev/certdoctor/internal/adapter/proxyconf"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/adapter/tcp"
	"github.com/donislawdev/certdoctor/internal/core/allowed"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	corehandshake "github.com/donislawdev/certdoctor/internal/core/handshake"
	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	coretcp "github.com/donislawdev/certdoctor/internal/core/tcp"
	"github.com/donislawdev/certdoctor/internal/core/trust"
)

func main() {
	os.Exit(mainCode().Int())
}

// mainCode is main with a return value.
func mainCode() exitcode.Code {
	// Only the interrupt is caught. A termination signal is left to its default
	// handling on purpose: the table has separate codes for "stopped by the
	// user" and "stopped by the system", and catching both here would give us
	// one context cancellation with no way to tell them apart - so every
	// termination would be reported as an interrupt, which is a wrong answer
	// rather than a missing one.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// WHAT THIS PROGRAM DOES WHEN THE OUTSIDE WORLD TRIES TO STOP IT, armed in
	// one call and written down in interrupt.go: a second interrupt ends the run
	// instead of being dropped, and a broken pipe becomes an error instead of a
	// death with a status this table does not contain.
	//
	// A PLAIN CALL AND NOT A GO STATEMENT, deliberately: registration is
	// synchronous, so an interrupt arriving in the first millisecond of a run is
	// already counted. The waiting happens inside, in the one file the
	// concurrency guard's fifth list names. The disarm is dropped on purpose -
	// this watch lasts as long as the process does, and there is nothing after
	// it to hand the undo to.
	_ = armSignalDefences(os.Stderr)

	return guarded(ctx, os.Args[1:], liveEnvironment())
}

// guarded runs the command line and turns a panic into a code from the table.
//
// WHY IT EXISTS. Without it a panic anywhere in this program ends the process
// with the Go runtime's own status of 2, which in this tool's table means
// USAGE - so an internal failure would reach a pipeline as the user having
// typed the command wrongly. Every ending has to carry a code from the table
// and mean it.
//
// This catches a defect in our code. It is not a way to survive bad input:
// everything arriving from outside is data, and data that is not understood
// produces an unknown with a reason, never a panic and never a recovery.
//
// Nothing reaches standard output on this path. A run that panicked has no
// report, and a partial one is worse than none.
func guarded(ctx context.Context, args []string, env environment) (code exitcode.Code) {
	defer func() {
		if panicked := recover(); panicked != nil {
			// THROUGH THE CREDENTIAL FLOOR, for the reason complain gives about
			// itself. A panic value is built from whatever was in hand, and what
			// is in hand on this path routinely includes the URL a person typed.
			// This is the one stderr line in the program that nobody wrote on
			// purpose, which is exactly why it may not be the one that leaks.
			said := redact.New(redact.Credentials).Text(fmt.Sprintf("%v", panicked))
			fmt.Fprintf(env.stderr, "%s: internal failure, no report was produced: %s\n", toolName, said)
			code = exitcode.Runtime
		}
	}()
	return execute(ctx, args, env)
}

// liveEnvironment is the real outside world. Every field here is a seam a test
// fills with something inert.
func liveEnvironment() environment {
	return environment{
		stdout: os.Stdout,
		stderr: os.Stderr,
		capability: func(noColorRequested bool) render.Capability {
			return render.DetectCapability(os.Stdout, os.LookupEnv, noColorRequested)
		},
		now: time.Now,
		// WHERE THIS ACCOUNT'S OWN FILES ARE, asked once and only ever compared
		// against a store path. An error is not fatal and is not reported as one:
		// an empty answer makes L5 assume a store is shared, which is the safe
		// direction for a command somebody is about to run.
		home: func() string {
			dir, err := os.UserHomeDir()
			if err != nil {
				return ""
			}
			return dir
		}(),
		platform: report.Platform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
			// Nothing detects a container yet. Left undetermined rather than
			// answered, with a note in the report saying which.
			Container: report.NotDetermined,
		},
		// Read from the process token on Windows and from the effective user id
		// elsewhere, by identifier and never by the name of a group. A question
		// that fails comes back unknown, and the report says so.
		privilege: privilege.Level(),
		lookupEnv: os.LookupEnv,
		writeFile: output.WriteFile,

		// The resolvers this machine uses, read through the guarded file port on
		// the systems where that means a file. The limit is 1 MB and it arrives
		// as an argument rather than as a constant somewhere, because the files
		// this program reads do not share one honest number - ADR25.
		// Where this machine records that it looks names up, which is the second
		// half of what a derived answer has to say about itself - ADR28.
		sources: func() (resolve.NameSources, error) {
			source, resolvePath := file.Live()
			return dns.NameSources(file.Guarded(source, resolvePath, resolverConfigLimit, nil))
		},
		nameservers: func() (dns.Nameservers, error) {
			source, resolvePath := file.Live()
			return dns.Enumerate(file.Guarded(source, resolvePath, resolverConfigLimit, nil))
		},
		// The places this platform keeps proxy configuration in. The command port
		// is probe.Run, which is the ONE place in this program allowed to start
		// somebody else's process - so scutil goes through the same four
		// narrowing rules as keytool and curl, and execAllowlist stays at one
		// entry.
		//
		// IT IS FILLED IN HERE AND NOT INSIDE proxyconf, which declares a port of
		// primitives instead of importing probe: an adapter reaching sideways to
		// another adapter would cost an entry on the layer guard's exception
		// list for a type that fits on one line.
		systemProxy: func(ctx context.Context) []proxy.Lens {
			return proxyconf.Read(ctx, func(ctx context.Context, executable string, args ...string) (string, int, bool, error) {
				out, err := probe.Run(ctx, executable, args...)
				return out.Stdout, out.ExitCode, out.Truncated, err
			})
		},
		// The L5 probes. git reads plain INI and a PEM bundle through the same
		// guarded port everything else uses, so the refusal rule - including "this
		// path would leave the machine" - stays in one place and applies here too.
		trustProbes: func() map[string]trust.Probe {
			source, resolvePath := file.Live()
			guarded := file.Guarded(source, resolvePath, caBundleLimit, nil)
			paths := pathDirectories()
			return map[string]trust.Probe{
				// THE CLOCK GOES IN because "this certificate is out of date" and
				// "nobody here signed it" are two different answers with two
				// different remedies, and only the second is repaired by importing
				// anything. Left to itself crypto/x509 would read the clock behind
				// the probe's back, which is the one thing that stops an assessment
				// being reproducible from its input.
				"git":  git.Probe(guarded, globalGitConfigs(), paths, time.Now),
				"java": java.Probe(guarded, probe.Run, javaCandidates(), os.Getenv("JAVA_HOME"), paths, time.Now),
				"curl": curl.Probe(guarded, probe.Run, paths, os.Getenv("CURL_CA_BUNDLE"), time.Now),
			}
		},
		// L2's automatic configuration script: fetched over the network and then
		// run inside the sandbox. It is the FIFTH place in this program that can
		// open a connection, and it asks the SAME rule as the four below -
		// dial.Permission, consumed rather than copied - so a fifth way to reach
		// the network still did not bring a fifth answer to "may we".
		//
		// THE SANDBOX GETS NO PORTS AND THAT IS THE DECISION OF THIS SLICE, not
		// an omission. Ports.Resolve would let a file this program did not write
		// choose the names this machine asks its resolver about, which is a
		// channel the network guard cannot see: the resolver is in the allowed
		// set, so every query is permitted and only the QUESTIONS are somebody
		// else's. It is also native Go called from JavaScript, which the
		// sandbox's stopwatch provably cannot interrupt - measured, ADR78. Both
		// belong to a slice of their own. Meanwhile pac.Result.Unanswered
		// records that a file went looking, and L2 refuses to rest a verdict on
		// an answer reached that way.
		evaluateScript: func(targets *allowed.Targets, targetURL, targetHost string) proxy.Evaluate {
			return pac.Resolver(
				pac.Fetch(dial.Permission(targets, nil), pacSourceLimit),
				pac.Sandbox{
					Budget:    pacBudget,
					Ceiling:   pacCeiling,
					MaxSource: pacSourceLimit,
					MaxStack:  pacStackLimit,
				},
				targetURL, targetHost)
		},
		// L2's question to a proxy, and the SIXTH place in this program that can
		// open a connection. It asks the SAME rule as the five below -
		// dial.Permission, consumed rather than copied - so a sixth way to reach
		// the network still did not bring a sixth answer to "may we".
		//
		// THE SET IS HELD AND NOT READ HERE, and this is the one port where that
		// distinction bites. Everything else on this list is handed a set that is
		// complete before the walk or widened between two layers; this one is
		// asked AFTER the orchestrator has widened the set from L2's own reading,
		// inside the same layer. dial.Permission closes over the set rather than
		// over its contents, so the entries added during the walk are the ones
		// this call is checked against.
		challengeProxy: func(targets *allowed.Targets, perEndpoint time.Duration) proxy.ChallengeAsk {
			return proxyauth.Ask(dial.Permission(targets, nil), perEndpoint)
		},
		// The real dialler, behind the guard. dns.Socket is the only function in
		// this program that opens a connection, and it is never reached without
		// dial.Guarded having checked the address against what this run derived.
		exchange: func(targets *allowed.Targets) resolve.Exchange {
			return dns.Exchange(dial.Guarded(dns.Socket, targets, nil))
		},
		// The second lens. It gets dial.Permission rather than dial.Guarded
		// because net.Resolver wants a dialler of its own shape - and it gets the
		// SAME rule the line above uses rather than a second copy of it, which is
		// the whole of ADR35 in one argument.
		system: func(targets *allowed.Targets) resolve.SystemLookup {
			return dns.System(dial.Permission(targets, nil))
		},
		// L3's connection, and the third place in this program that can open one.
		// It asks the SAME rule as both lines above - dial.Permission, consumed
		// rather than copied - so the question "may this run reach that address"
		// has one answer in one place for every layer that asks it.
		connect: func(targets *allowed.Targets) coretcp.Connect {
			return tcp.Connect(dial.Permission(targets, nil))
		},
		// L4's handshake, and the fourth place in this program that can open a
		// connection. It asks the SAME rule as all three lines above -
		// dial.Permission, consumed rather than copied - so a fourth way to reach
		// the network did not bring a fourth answer to "may we" with it.
		shake: func(targets *allowed.Targets) corehandshake.Shake {
			return handshake.Shake(dial.Permission(targets, nil))
		},
		queryID: queryID,
	}
}

// The four numbers the PAC sandbox runs under. Every one of them is a ceiling
// certdoctor sets, so every one of them ends in limit_exceeded rather than in a
// claim about somebody's file - which is the whole reason that reason exists.
//
// THE TIME BUDGET IS NOT DIVIDED OUT OF THE LAYER'S, and that is worth saying
// because every other budget in this program is. A PAC file is somebody else's
// code and the only thing standing between it and the run is this number; a
// share of what happens to be left would make the same file answer on a quiet
// machine and time out on a busy one, and the report would blame the file.
//
// 300ms IS THE VALUE P8-K1 MEASURED WITH: testbed/pac/files/runaway.pac, which
// never returns, was stopped at 301ms against it, and the ordinary files answer
// in single milliseconds.
const pacBudget = 300 * time.Millisecond

// pacCeiling is how much heap one evaluation may add before the stopwatch stops
// it.
//
// IT IS A PROCESS FIGURE AND THE PLACEMENT IS WHAT MAKES IT SAFE - the caveat
// pac.Sandbox.Ceiling names and hands to whoever calls it. Measured 2026-09-06
// on Windows and in a container: at the point in the walk where L2 runs, this
// process holds four goroutines and its heap moves by 96 to 160 BYTES over a
// 300ms window. So the neighbour noise this ceiling could mistake for a PAC
// file is six orders of magnitude below it. That measurement is a fact about
// where this evaluation SITS: moving it beside anything that allocates - a
// parallel walk, a layer running alongside - invalidates it and nothing here
// would notice.
//
// 64 MiB IS WHAT PROBE S12 MEASURED THE OVERSHOOT AGAINST, and the overshoot is
// a RANGE rather than a constant: 1.75x and 1.88x on two runs of one file. The
// ceiling bounds what gets NOTICED, never what gets allocated.
const pacCeiling = 64 << 20

// pacSourceLimit is the largest script this run accepts, checked before the
// bytes reach the parser - docs/14 section 2.3, because afterwards it is too
// late. It is the resolver config number for the same reason ADR25 chose it:
// real PAC files are kilobytes, so this caps memory rather than the parser.
const pacSourceLimit = 1 << 20

// pacStackLimit is a CONDITION and not tuning - ADR75. Measured 2026-09-02:
// with goja's default, unbounded recursion was still running after ten seconds
// on a 213 MiB heap; with this set the same file ends in 1 ms.
const pacStackLimit = 2000

// resolverConfigLimit is the 1 MB from ADR25, measured rather than chosen: the
// real files are 172 to 526 bytes and the parser costs are linear, so this caps
// memory rather than the parser. The hosts file will need its own number.
const resolverConfigLimit = 1 << 20

// queryID picks the identifier of one DNS query.
//
// IT IS CRYPTOGRAPHIC RANDOMNESS AND NOT A COUNTER, and the reason is the only
// defence this program has against an answer that did not come from the resolver
// it asked. A predictable identifier makes an off-path reply trivial to forge,
// and the parser believes any packet whose identifier matches.
//
// crypto/rand.Read never returns an error and always fills the slice, so there
// is no failure branch here - one would be a branch nothing can execute, which
// is the shape the mutation register has caught in this tree more than once.
func queryID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return uint16(b[0])<<8 | uint16(b[1])
}

// caBundleLimit is the cap for the files L5 reads, and it is a DIFFERENT number
// from the resolver one on purpose - ADR25 says these files do not share one
// honest limit. Measured 2026-08-18: the bundle git ships on this machine is
// 229042 bytes, so 8 MB is two orders of magnitude of headroom and still caps
// memory against a file that is not what it claims to be.
const caBundleLimit = 8 << 20

// globalGitConfigs names the user-level git config files, in git's own
// precedence order.
//
// THEY ARE COMPUTED HERE AND HANDED IN because the probe reads no environment -
// the same rule redact follows, so an assessment stays reproducible from its
// input. A home directory that cannot be determined yields no paths rather than
// a guess, and the probe then reports what the system level alone decides.
func globalGitConfigs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, ".config", "git", "config"),
	}
}

// pathDirectories splits PATH into the directories a typed command searches.
//
// IT IS READ HERE AND HANDED IN, like the git config paths beside it, so the
// probe reads no environment of its own and an assessment stays reproducible
// from its input. An empty PATH yields no directories rather than a guess, and
// every install then reports that nothing selects it - which is true.
func pathDirectories() []string {
	value, present := os.LookupEnv("PATH")
	if !present || value == "" {
		return nil
	}
	var dirs []string
	for _, dir := range filepath.SplitList(value) {
		if dir != "" {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// javaParents are the directories Java installations are grouped under.
//
// SEARCHED RATHER THAN DERIVED FROM JAVA_HOME - ADR48 part 4, measured: that
// variable names one of the six installations on this machine. Listing happens
// here because it needs the filesystem, which the probe is not allowed to touch.
var javaParents = []string{
	`C:\Program Files\Java`,
	`C:\Program Files (x86)\Java`,
	`C:\Program Files\OpenJDK`,
	`C:\Program Files\Eclipse Adoptium`,
	`C:\Program Files\Microsoft`,
	`C:\Program Files\Amazon Corretto`,
	`C:\Program Files\Zulu`,
	"/usr/lib/jvm",
	"/Library/Java/JavaVirtualMachines",
}

// javaCandidates lists every directory that might be a Java installation.
//
// IT DOES NOT DECIDE WHETHER ONE IS - the probe does that, by asking whether a
// store and a keytool are actually there. Measured on this machine: two of these
// candidates are directories named latest with no store inside, and treating a
// candidate as an install would have invented two rows.
//
// The macOS bundle layout puts the runtime under Contents/Home, so both spellings
// are offered and the probe keeps whichever answers.
func javaCandidates() []string {
	var candidates []string
	_, resolvePath := file.Live()
	list := file.GuardedList(file.LiveList(), resolvePath, nil)
	for _, parent := range javaParents {
		roots, err := list(parent)
		if err != nil {
			continue
		}
		for _, root := range roots {
			candidates = append(candidates, root, filepath.Join(root, "Contents", "Home"))
		}
	}
	return candidates
}
