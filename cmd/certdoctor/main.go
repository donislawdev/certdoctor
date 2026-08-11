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
	"runtime"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/dial"
	"github.com/donislawdev/certdoctor/internal/adapter/dns"
	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/output"
	"github.com/donislawdev/certdoctor/internal/adapter/privilege"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/allowed"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
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
			fmt.Fprintf(env.stderr, "%s: internal failure, no report was produced: %v\n", toolName, panicked)
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
		queryID: queryID,
	}
}

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
