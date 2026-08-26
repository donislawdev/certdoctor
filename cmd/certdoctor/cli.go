package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"strconv"
	"strings"
	"time"

	certdoctor "github.com/donislawdev/certdoctor"
	"github.com/donislawdev/certdoctor/internal/adapter/dns"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/adapter/tcp"
	"github.com/donislawdev/certdoctor/internal/app/run"
	"github.com/donislawdev/certdoctor/internal/core/allowed"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	corehandshake "github.com/donislawdev/certdoctor/internal/core/handshake"
	"github.com/donislawdev/certdoctor/internal/core/idna"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	coretcp "github.com/donislawdev/certdoctor/internal/core/tcp"
	"github.com/donislawdev/certdoctor/internal/core/trust"
)

const (
	toolName    = certdoctor.Name
	toolVersion = certdoctor.Version
)

// environment is everything outside this process that a run may look at,
// gathered into one value that tests supply themselves.
//
// It exists so that the whole command line can be exercised without a terminal,
// without a clock and above all without a file system. The fuzz target over the
// command line depends on that last one: fuzzing a program that can create
// files is fuzzing a program that will eventually create a surprising one.
type environment struct {
	stdout io.Writer
	stderr io.Writer
	// capability answers what the report destination can render, given whether
	// colour was refused on the command line.
	capability func(noColorRequested bool) render.Capability
	now        func() time.Time
	platform   report.Platform
	privilege  report.PrivilegeLevel
	// home is this account's own directory, used for ONE question: whether a
	// remediation command needs elevated rights, because a store outside it
	// belongs to every account on the machine. It is a seam for the same reason
	// the clock is - a test reading the real one would answer differently on
	// somebody else's machine. Empty is a legitimate value and L5 answers it in
	// the safe direction, which is "assume elevation is needed".
	home string
	// lookupEnv is how L0 sees this machine's environment. It is a seam for the
	// same reason the clock is: a test reading the real environment would pass
	// or fail depending on whose machine it ran on, and the one variable that
	// would change its mind is exactly the sort this layer reports.
	lookupEnv func(name string) (string, bool)
	// writeFile puts a finished report at a path the user named. It is the only
	// way this package can reach the file system.
	writeFile func(path string, data []byte) error

	// nameservers enumerates the resolvers this machine is configured to use.
	//
	// IT IS CALLED BEFORE THE WALK AND NOT INSIDE L1, and that ordering is
	// forced by masking: a pseudonym is issued once per report, so the redaction
	// has to be told about every resolver address before the first one can appear
	// anywhere - ADR32. It also has to happen before the allowed set is built,
	// because a query to a resolver nobody allowed is a query dial.Guarded
	// refuses.
	//
	// A nil one is legal and means this build has no way to look, which L1
	// reports as unknown with a reason rather than as a machine with no DNS.
	nameservers func() (dns.Nameservers, error)
	// trustProbes are the L5 probes, built with a file port of their own because
	// the files they read are a different size class from a resolver config.
	trustProbes func() map[string]trust.Probe
	// sources reads what this machine records about WHERE it looks names up.
	//
	// A nil one, and an error, both mean the same thing to the layer: nothing was
	// declared. That is deliberate - on Windows there is no such file at all, and
	// on alpine there is none either, so "absent" is the common case rather than
	// the broken one and must not read as a failure of the run.
	sources func() (resolve.NameSources, error)
	// exchange builds the way L1 sends a query, given the set of places this run
	// may connect to.
	//
	// It takes the set rather than closing over one, because the set is built
	// from what this particular run derived - the target, then this machine's
	// resolvers - and handing the dialler a set assembled elsewhere is how a
	// guard ends up checking against something other than what is dialled.
	exchange func(*allowed.Targets) resolve.Exchange
	// connect builds the way L3 opens a connection, given the same set. It is a
	// seam for the same reason exchange is: a test that really dialled would
	// pass or fail depending on whose network it ran on.
	connect func(*allowed.Targets) coretcp.Connect
	// system builds the second lens: the platform asked the way any other program
	// on this machine would ask it.
	//
	// It takes the set for the same reason exchange does, and it matters more
	// here: this dialler is handed to net.Resolver, which decides on its own how
	// many addresses to try and in what order, so the only thing standing between
	// it and an address nobody derived is the set built for THIS run.
	//
	// A nil one is legal and means the run holds one lens. The layer says so in
	// its own sentence rather than leaving a reader to count views.
	system func(*allowed.Targets) resolve.SystemLookup
	// shake builds the way L4 completes a handshake, given the same set. It is a
	// seam for the same reason connect is: a test that really hand shook would
	// pass or fail depending on whose network it ran on.
	//
	// A nil one is legal and means this build has no way to hand shake, which L4
	// reports as unknown with a reason rather than as a server that refused.
	shake func(*allowed.Targets) corehandshake.Shake
	// queryID picks the identifier of one DNS query. Unpredictable in the real
	// build, because that is the only thing making an off-path answer detectable.
	queryID func() uint16
}

// execute runs one command line from beginning to end and returns the code the
// process ends with.
//
// STANDARD OUTPUT IS WRITTEN ONCE, AT THE VERY END, OR NOT AT ALL. Every path
// that does not produce a complete report returns before touching it. A script
// that redirected standard output into a file gets an empty file rather than
// half a report, because half a report looks exactly like a whole one to
// whatever reads it next.
func execute(ctx context.Context, args []string, env environment) exitcode.Code {
	o, parseFault := parse(args)
	if parseFault != nil {
		return complain(env, parseFault)
	}
	if code, handled := answerMetaSwitch(o, env); handled {
		return code
	}
	return diagnose(ctx, o, env)
}

// diagnose is the path that produces a report: work out what to look at, walk
// the layers, check the result against its own rules, render it, deliver it.
func diagnose(ctx context.Context, o *options, env environment) exitcode.Code {
	// parsed is the spelling that goes on the wire and typed is the one the
	// person wrote. They are the same for every ASCII name.
	parsed, typed, targetFault := readTarget(o)
	if targetFault != nil {
		return complain(env, targetFault)
	}

	// THE ORDER OF THE NEXT FOUR LINES IS THE WHOLE OF THE L1 WIRING AND IT IS
	// NOT FREE. The resolvers have to be known before the masking is built, so a
	// pseudonym covers every address that can appear. The masking has to exist
	// before the target is reduced. The allowed set has to be complete before
	// anything can be dialled. Swapping any pair produces a run that looks
	// correct and either leaks an address or refuses every query.
	found, foundErr := enumerate(env)
	// THE REPORT SHOWS WHAT THE PERSON TYPED, and the masking is told about both
	// spellings. Showing the converted form would put a URL nobody wrote at the
	// top of the document; masking only the typed one would let the xn-- form
	// walk out through L1's rows under --redact, which is the same host by
	// another name and the whole point of that switch.
	redaction := redactionFor(o, parsed, found)
	shown, removed := redaction.Target(typed.String())
	targets := allowedTargets(parsed, found)

	finished, walkFault := walk(ctx, o, env, targetReduction{target: shown, removed: removed}, redaction,
		run.Wiring{
			Environment: env.lookupEnv,
			Resolution:  resolutionInput(o, env, parsed, found, foundErr, targets),
			Reach:       reachInput(o, env, parsed, targets),
			Handshake:   handshakeInput(o, env, parsed, targets),
			Trust:       trustInput(env),
			Authorise:   authoriser(parsed, targets),
		})
	if walkFault != nil {
		return complain(env, walkFault)
	}

	document, renderFault := renderReport(o, env, finished)
	if renderFault != nil {
		return complain(env, renderFault)
	}
	if deliverFault := deliver(o, env, document); deliverFault != nil {
		return complain(env, deliverFault)
	}
	return finished.Verdict.ExitCode
}

// walk runs the layers and hands back a report that has already been checked
// against its own invariants.
//
// The check happens here rather than at the point of printing, so that there is
// no arrangement of this file in which an unchecked report reaches a renderer. A
// verdict that disagrees with the rows beneath it is an internal failure, never
// something to print and let the reader sort out.
func walk(ctx context.Context, o *options, env environment, shown targetReduction, redaction *redact.Redaction,
	wiring run.Wiring) (report.Report, *fault) {
	finished, err := run.Execute(ctx, run.Options{
		Tool:        report.Tool{Name: toolName, Version: toolVersion},
		Target:      shown.target,
		Platform:    env.platform,
		Privilege:   env.privilege,
		Redaction:   redaction,
		Budget:      budget(o.timeout),
		LayerBudget: budget(o.probeTimeout),
		Now:         env.now,
		Layers:      run.Wire(wiring),
		Notes:       pendingNotes(shown, env.privilege),
	})
	if err != nil {
		if ctx.Err() != nil {
			return report.Report{}, &fault{exitcode.Interrupted, "interrupted before the run finished"}
		}
		return report.Report{}, &fault{exitcode.Runtime, err.Error()}
	}
	if err := report.Validate(finished); err != nil {
		return report.Report{}, &fault{exitcode.Runtime,
			fmt.Sprintf("the assembled report failed its own checks and was not printed:\n%v", err)}
	}
	return finished, nil
}

// answerMetaSwitch handles the switches that describe the tool rather than a
// machine. Each of them is a complete answer, so each writes to standard output
// and ends successfully.
func answerMetaSwitch(o *options, env environment) (exitcode.Code, bool) {
	switch {
	case o.showHelp:
		fmt.Fprint(env.stdout, helpText())
	case o.showVersion:
		fmt.Fprint(env.stdout, versionText())
	case o.showLicense:
		fmt.Fprint(env.stdout, certdoctor.License)
	default:
		return exitcode.OK, false
	}
	return exitcode.OK, true
}

// complain writes the reason to the log channel and returns its code. It never
// touches standard output.
func complain(env environment, f *fault) exitcode.Code {
	fmt.Fprintf(env.stderr, "%s: %s\n", toolName, f.message)
	return f.code
}

// targetReduction records what the report shows as the target and whether
// anything was taken out of it.
type targetReduction struct {
	target string
	// removed says something was dropped, so the report can say so rather than
	// present a shortened URL as if it were the whole one.
	removed bool
}

// readTarget validates the URL, masks it, and hands back the redaction the whole
// run will use.
//
// THE TARGET IS MASKED BY POSITION, NOT BY NAME, and it is the only thing in
// this program that is. Everything else arrives from the machine, where a value
// that looks ordinary usually is. This one is typed by a person under time
// pressure and can be a secret in three places at once: user info, a token in
// the query, a session identifier in the path. There is no name to ask about, so
// the rule is positional - user info replaced, every query VALUE replaced with
// its name kept, the whole path reduced to one marker, the fragment dropped
// without one because it never reaches a server.
//
// It used to be reduced to its origin instead, with the report saying so, for
// the length of time between the entry point existing and the masking function
// being wired to it. That is over: the origin was strictly narrower than this,
// so the change can only show more.
//
// The redaction is built here because this is where the mode is known, and it is
// ONE instance for the whole report - a pseudonym has to mean the same machine
// wherever it appears.
//
// The scheme is required rather than guessed. Guessing would have to cope with
// "localhost:8080", which the URL parser reads as the scheme "localhost" and
// the opaque part "8080", and a tool that quietly diagnoses a different address
// than the one asked about is worse than one that asks for a clearer question.
// It returns TWO urls: the one the run uses and the one the report shows. They
// are the same object for every ASCII name, which is every name this program
// could diagnose before 2026-08-26.
func readTarget(o *options) (wire *url.URL, typed *url.URL, f *fault) {
	raw := o.target
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, nil, usageFault(
			"%q is not a URL certdoctor can read: %v. Give one like https://example.com", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		// The suggestion is quoted rather than pasted in. It contains what the
		// user typed, and %s reproduced that byte for byte onto a terminal:
		// a bidirectional override or a zero width character in a URL from a
		// ticket came straight back out, unescaped, into somebody's console and
		// their log. The parser refuses ASCII control characters, which is why
		// this looked safe - it does not refuse the ones above them.
		return nil, nil, usageFault(
			"%q has no http:// or https:// scheme. Without one a host name cannot be told from a port number, so write it out, for example %q",
			raw, "https://"+raw)
	}
	if parsed.Host == "" {
		return nil, nil, usageFault("%q names no host. Give one like https://example.com", raw)
	}

	// A PORT OUTSIDE 1-65535 IS REFUSED HERE, WHERE IT IS STILL A TYPING MISTAKE.
	//
	// url.Parse accepts any run of digits after the colon, so ":99999" arrived
	// intact and was carried all the way into a finding - where the report
	// contract refuses it, correctly, as a port that is not a port. Measured on
	// this binary: L3 was thrown away whole and reported as "the layer broke its
	// own contract", which says THIS PROGRAM is defective about an input a person
	// mistyped, and L4 then said the name had resolved to no address about a name
	// that had resolved to four.
	//
	// The upper bound is not ours to choose: a TCP port is sixteen bits, and zero
	// is reserved rather than dialable.
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, nil, usageFault(
				"%q asks for port %s, and a port is a number from 1 to 65535", raw, port)
		}
	}

	// The host is lower cased and nothing else is. Names in DNS are case
	// insensitive, so EXAMPLE.COM and example.com are one machine - and left
	// alone they became two: two different targets in two reports of the same
	// run, a difference --compare would report where nothing had changed, and
	// two different pseudonyms under --redact for one host. A path and a query
	// are case sensitive and are left exactly as they were.
	//
	// It is done HERE rather than inside the masking rule, so that the rule for
	// the target stays the rule the owner approved and nothing else.
	parsed.Host = strings.ToLower(parsed.Host)

	// TWO SPELLINGS FROM HERE ON, AND WHICH ONE A CALLER GETS IS DECIDED BY THE
	// ORDER THEY COME BACK IN. The first is what every query, connection and SNI
	// extension uses; the second is what the person typed and what the report
	// shows. Everything downstream takes the first, so a call site added later
	// gets the wire spelling without having to know this paragraph exists - and
	// the two that need the typed one ask for it by name.
	//
	// It is the shape ADR34 already uses for a resolver address, for the same
	// reason: one machine, two ways of writing it, and a guard comparing strings
	// in between.
	// Assigned rather than declared: wire is one of the named results, and err
	// came back from url.Parse at the top.
	wire, err = wireForm(parsed)
	if err != nil {
		return nil, nil, usageFault("%q cannot be asked about: %v", raw, err)
	}
	return wire, parsed, nil
}

// wireForm is the target with its host in the spelling that goes on the wire.
//
// AN ASCII NAME COMES BACK AS THE SAME URL, and that is what keeps this change
// off the path every name this program has ever diagnosed. Only a host carrying
// a code point above 0x7F is converted at all.
func wireForm(typed *url.URL) (*url.URL, error) {
	host := typed.Hostname()
	ascii, err := idna.ToASCII(host)
	if err != nil {
		return nil, err
	}
	wire := *typed
	if ascii == host {
		return &wire, nil
	}
	// THE PORT IS REJOINED BY HAND RATHER THAN WITH net.JoinHostPort, and the
	// reason is that the brackets that function adds are for a host containing a
	// colon. An A-label cannot: it is the ACE prefix followed by letters, digits
	// and hyphens. Doing it here also keeps package net out of this file, which
	// is the one place the dial allowlist is not the thing stopping it.
	wire.Host = ascii
	if port := typed.Port(); port != "" {
		wire.Host = ascii + ":" + port
	}
	return &wire, nil
}

// enumerate asks this machine which resolvers it uses, tolerating a build that
// has no way to look.
//
// A nil port is not silently an empty list. An empty list means "this machine
// lists no resolver", which is a statement about somebody's machine, and a build
// that could not look has no business making it.
func enumerate(env environment) (dns.Nameservers, error) {
	if env.nameservers == nil {
		return dns.Nameservers{}, errors.New("this build has no way to enumerate the resolvers this machine uses")
	}
	return env.nameservers()
}

// redactionFor builds the one masking the whole report will use.
//
// THE TARGET HOST IS HANDED OVER AS SENSITIVE, AND ADR26 IS WHY. Masking finds a
// host inside a URL by pattern, which covered every host in this report until L1
// - that layer reports a BARE name in a field of its own, and no pattern finds
// those without guessing which dotted words are names. This is the one host we
// never have to guess about, so it is handed over by name.
//
// EVERY RESOLVER GOES OVER TOO, AS A DIFFERENT KIND - ADR32. An address the
// target resolved to is the answer somebody came for and stays visible. A
// resolver address is infrastructure: it does not say why anything is broken, it
// says what the machines in somebody's network are called, and the person
// reaching for --redact is the one about to paste this into a ticket.
//
// THE WIDER LIST IS USED, not the one L1 will ask. A resolver written down on
// this machine and not currently in use is still an internal address, and it can
// still reach the report - the layer names the ones it asked, and the enumeration
// names where the list came from.
//
// Both go over in both modes. Names are only masked under Everything, so this
// costs nothing in the weaker one, and a conditional here would be a second place
// where the mode decides something.
// THE HOST HANDED OVER IS THE ONE THAT GOES ON THE WIRE, AND THE TYPED SPELLING
// NEEDS NOTHING - which is the opposite of what it looks like and was MEASURED
// rather than reasoned, 2026-08-26. An international name reaches the report
// twice: the typed spelling inside the target URL at the top, and the A-label
// bare in every row of L1. Only the second needs naming here, because a bare
// name is precisely what no pattern can find - ADR26 - while the one inside a
// URL is found by the pattern rule whether or not anybody registered it.
//
// The obvious-looking second registration was written, and then a deliberate
// break of it changed nothing: with it removed, --redact still left neither
// spelling anywhere in the document. It was caution that decided nothing, which
// is the shape the mutation register keeps finding in this tree, so it is not
// here. If a surface ever prints the TYPED name bare - a note about the
// conversion would be one - this becomes wrong and that surface must add it.
func redactionFor(o *options, parsed *url.URL, found dns.Nameservers) *redact.Redaction {
	mode := redact.Credentials
	if o.redact {
		mode = redact.Everything
	}
	sensitive := make([]redact.Sensitive, 0, len(found.Known)+1)
	sensitive = append(sensitive, redact.Host(parsed.Hostname()))
	for _, resolver := range found.Known {
		sensitive = append(sensitive, redact.Resolver(resolver))
	}
	return redact.New(mode, sensitive...)
}

// allowedTargets builds the finite set of places this run may connect to.
//
// INVIOLABLE RULE 16, ASSEMBLED IN THE ONE PLACE THAT KNOWS WHAT THE USER ASKED.
// Two of the five permitted derivations are available this early: the target
// itself, and the resolvers this machine records. The addresses the target
// resolves to are a third and they arrive during the walk - nothing dials them
// yet, so adding them here would be an entry with no consumer.
//
// The set is built from the WIDER resolver list on purpose. A query goes only to
// the narrower one, so every address dialled is certain to be in here, and the
// difference between the two lists cannot turn into a refusal on a working
// machine.
func allowedTargets(parsed *url.URL, found dns.Nameservers) *allowed.Targets {
	targets := allowed.New()
	// The error is ignored on purpose and only here: Allow refuses an empty
	// target, and readTarget has already refused a URL with no host.
	_ = targets.Allow(parsed.Host, allowed.ReasonTarget)

	for _, resolver := range found.Known {
		address, err := dns.Target(resolver)
		if err != nil {
			// Something that is not an address cannot be dialled, so leaving it
			// out of the set changes nothing about what this run can reach. It is
			// not swallowed either: L1 asks it anyway and reports the refusal in
			// its own row, which is where a reader would look for it.
			continue
		}
		_ = targets.Allow(address, allowed.ReasonResolver)

		// AND THE SAME ADDRESS SPELLED THE WAY THE PLATFORM WILL SPELL IT - ADR34.
		// Go joins the raw token from resolv.conf with the port, so a machine
		// writing "2001:0DB8::1" makes it ask for a string our canonical form does
		// not match, and the guard would refuse a resolver that is answering
		// (S11, OBS54). It goes in only for a token that PARSES, deliberately:
		// Go's own reader skips a nameserver line that is not an address, so the
		// raw form of a broken token is a place nobody will ever dial.
		if raw := dns.RawTarget(resolver); raw != address {
			_ = targets.Allow(raw, allowed.ReasonResolver)
		}
	}

	// A machine that lists no resolver still has one, and it is the one the
	// platform falls back to - ADR34. Adding these only when the list is empty
	// keeps the set as narrow as the measurement requires: a machine with its own
	// resolver never sends the platform to loopback, so an entry for it would
	// widen what this program may reach for no reason anybody measured.
	if len(found.Known) == 0 {
		for _, fallback := range dns.PlatformFallbackResolvers() {
			_ = targets.Allow(fallback, allowed.ReasonResolver)
		}
	}
	return targets
}

// nameSources asks the environment where this machine looks names up, and
// answers "nothing was declared" for every way of not knowing.
//
// THE ERROR IS DROPPED ON PURPOSE AND ONLY HERE. A missing nsswitch.conf is the
// normal state of a Windows machine and of alpine, so turning it into a failure
// would put a broken run in front of somebody whose machine is fine. What the
// layer needs is the distinction between "this file said files and dns" and
// "nothing said anything", and the zero value carries the second one exactly.
func nameSources(env environment) (resolve.NameSources, error) {
	if env.sources == nil {
		return resolve.NameSources{}, nil
	}
	sources, err := env.sources()
	if errors.Is(err, fs.ErrNotExist) {
		// THE ONE FAILURE THAT IS NOT ONE. Windows has no such file and neither
		// does alpine, so absence is the ordinary state of a working machine and
		// must not read as something going wrong.
		return resolve.NameSources{}, nil
	}
	return sources, err
}

// resolutionInput assembles everything L1 needs for one walk.
func resolutionInput(o *options, env environment, parsed *url.URL, found dns.Nameservers, foundErr error,
	targets *allowed.Targets) resolve.Input {
	var exchange resolve.Exchange
	if env.exchange != nil {
		exchange = env.exchange(targets)
	}
	sources, sourcesErr := nameSources(env)
	var system resolve.SystemLookup
	if env.system != nil {
		// THE ONE LENS THAT GETS A FROZEN COPY, AND THE ONE READ FROM GOROUTINES
		// THIS PROGRAM DID NOT START. net.Resolver calls the dialler behind this
		// lens from goroutines of its own, and they outlive the lookup - so the
		// read can land while L1's closure is widening the live set with the
		// addresses it has just found, which in Go is a fatal error recover does
		// not catch.
		//
		// IT LOSES NOTHING: this lens only ever dials this machine's resolvers,
		// and they are in the set before the walk starts. The other three lenses
		// keep the live set on purpose - L3 and L4 must see the addresses L1
		// authorised, and a copy would have this run refuse the very target the
		// user typed, by its own guard.
		system = env.system(targets.Freeze())
	}
	return resolve.Input{
		// THE RAW HOST, NOT run.Options.Target. That field carries the target
		// after masking, so a layer fed from it would spend the run under
		// --redact resolving the literal name [host-1]. A test pins this.
		Name:           parsed.Hostname(),
		Resolvers:      found.ToAsk,
		ResolversFrom:  found.From,
		ResolversError: foundErr,
		Exchange:       exchange,
		System:         system,
		Sources:        sources,
		SourcesError:   sourcesErr,
		QueryID:        env.queryID,
		Now:            env.now,
		PerQuery:       budget(o.probeTimeout),
	}
}

// reachInput is everything L3 was given, except the addresses - those do not
// exist until L1 has run, and the orchestrator supplies them.
func reachInput(o *options, env environment, parsed *url.URL, targets *allowed.Targets) coretcp.Input {
	var connect coretcp.Connect
	if env.connect != nil {
		connect = env.connect(targets)
	}
	return coretcp.Input{
		Port:       portOf(parsed),
		Connect:    connect,
		Now:        env.now,
		PerAddress: budget(o.probeTimeout),
	}
}

// handshakeInput is everything L4 was given, except the addresses - those are
// the ones L3 reached, and the orchestrator supplies them.
func handshakeInput(o *options, env environment, parsed *url.URL, targets *allowed.Targets) corehandshake.Input {
	var shake corehandshake.Shake
	if env.shake != nil {
		shake = env.shake(targets)
	}
	return corehandshake.Input{
		Port: portOf(parsed),
		// THE RAW HOST, EXACTLY AS THE USER TYPED IT, and never the reduced one.
		// This name goes out in SNI and decides which certificate the server
		// chooses. Feeding it the masked target would ask every server for a
		// certificate issued to [host-1] - the same trap resolutionInput records
		// one layer up, arriving here through a different field. A test pins it.
		ServerName: parsed.Hostname(),
		Shake:      shake,
		Now:        env.now,
		PerAddress: budget(o.probeTimeout),
	}
}

// authoriser widens the allowed set by the addresses the target resolved to -
// the third of the five derivations rule 16 permits, and the first that cannot
// be known before the run starts.
//
// IT JOINS THE PORT HERE, in the one place that knows what the user asked for.
// The set compares strings, so the address it holds has to be spelled exactly as
// the dialler will spell it - which is why both sides go through tcp.Target
// rather than joining a host and a port twice.
//
// AN ADDRESS THAT WILL NOT PARSE IS LEFT OUT rather than swallowed: nothing can
// dial it, so leaving it out changes nothing about what this run can reach, and
// L3 still produces a row saying it was refused.
func authoriser(parsed *url.URL, targets *allowed.Targets) func([]string) {
	port := portOf(parsed)
	return func(addresses []string) {
		for _, address := range addresses {
			dialable, err := tcp.Target(address, port)
			if err != nil {
				continue
			}
			_ = targets.Allow(dialable, allowed.ReasonResolvedAddress)
		}
	}
}

// portOf is the port this run will try, from the URL or from its scheme.
//
// A URL WITHOUT A PORT IS THE ORDINARY CASE and the scheme is what decides it.
// Guessing wrong here would mean connecting somewhere the user did not ask
// about, so the two schemes this program accepts are the two named below and
// there is no third default.
// THE RANGE IS GUARANTEED BY readTarget AND IS NOT RE-CHECKED HERE. A second
// check would be a second place where the same rule lives, and the one that
// matters is the one standing between a person's typing and a finding.
func portOf(parsed *url.URL) int {
	if explicit := parsed.Port(); explicit != "" {
		if port, err := strconv.Atoi(explicit); err == nil {
			return port
		}
	}
	if parsed.Scheme == "http" {
		return 80
	}
	return 443
}

// standingNotes are the shortfalls this build has no matter what it is asked to
// do.
//
// Each entry names one thing that is not built or not established, and each
// disappears the day that thing arrives - this list is meant to shrink to
// nothing. An empty notes array claims the run held nothing back, so these are
// not decoration: they are what will make that claim mean something when it is
// finally true.
// The blanket note that used to head this list is GONE, and its removal is the
// point rather than a tidy-up. It read "no diagnostic layer is implemented yet",
// which stopped being true the day L0 started reading this machine's context. A
// note kept past the arrival of the thing it announced is worse than no note:
// it teaches people that notes are boilerplate, and then the one that mattered
// goes unread with the rest. What it used to say is now COUNTED rather than
// asserted - the verdict names how many layers could not be assessed, and each
// of those layers says so in its own row, with a reason.
var standingNotes = []report.Note{
	{
		Kind:   report.NoteUndetermined,
		Field:  "run.platform.container",
		Detail: "certdoctor does not detect containers yet, so this is left empty rather than answered no",
	},
	// THE DOCUMENT SAYS OUT LOUD THAT IT IS NOT STABLE YET, and it says it HERE
	// rather than only in a document nobody reading --json will ever open.
	//
	// The schema moved three times in one day - a field for silence, a field for
	// the divergence of the two views, a seventh reason - and every one of those
	// was the right call precisely because nothing is released. A consumer who
	// pins this version has no way to know that from the number alone, and
	// finding out from a broken pipeline is the expensive way to be told.
	//
	// IT DISAPPEARS AT THE FIRST RELEASE, and that is the whole design: a note
	// that never goes away teaches people that notes are boilerplate, and then
	// the one that mattered goes unread with the rest.
	{
		Kind:  report.NoteUndetermined,
		Field: "schema_version",
		Detail: "this schema is still moving and will keep moving until certdoctor reaches 1.0.0 - " +
			"pin this version only if you are prepared to update, and read the technical changelog before you do",
	},
}

// pendingNotes is the standing list plus whatever this particular invocation
// added to it.
func pendingNotes(shown targetReduction, privilege report.PrivilegeLevel) []report.Note {
	notes := append([]report.Note{}, standingNotes...)
	notes = append(notes, trustCoverageNote())
	// An unknown privilege level is a legitimate answer and it is also the one
	// that makes a later comparison of two reports meaningless, so it is never
	// left to be noticed in the field alone. When the level IS established this
	// note disappears - a note that never goes away teaches people to skip
	// notes, and then the one that mattered goes with them.
	if privilege == report.PrivilegeUnknown {
		notes = append(notes, report.Note{
			Kind:   report.NoteUndetermined,
			Field:  "run.privilege_level",
			Detail: "the operating system did not answer when asked what privilege this process runs with, so the level is left unknown rather than guessed",
		})
	}
	if shown.removed {
		notes = append(notes, report.Note{
			Kind:  report.NoteReduced,
			Field: "run.target",
			Detail: "parts of the target were masked out of the report: user info, the values of any query parameters, " +
				"and the path, which is shown as a marker because deciding which path segments are identifiers would take a threshold nobody has measured",
		})
	}
	return notes
}

// renderReport turns the report into the bytes that will be delivered.
//
// It renders into memory in full before anything is delivered anywhere, and the
// machine readable document is checked against its declared schema on the way
// out. A document that does not match the contract we published is an internal
// failure: whoever parses it would get a different answer from the same run
// than we did.
func renderReport(o *options, env environment, finished report.Report) ([]byte, *fault) {
	var buffer bytes.Buffer

	if o.format == "json" {
		document, err := render.Encode(finished)
		if err != nil {
			return nil, &fault{exitcode.Runtime, fmt.Sprintf("the report could not be encoded: %v", err)}
		}
		if err := render.ValidateDocument(document); err != nil {
			return nil, &fault{exitcode.Runtime,
				fmt.Sprintf("the encoded report does not match its declared schema and was not printed:\n%v", err)}
		}
		return document, nil
	}

	terminal := render.Terminal{}
	// Colour and glyphs are for a person at a console. A report going into a
	// file gets neither, whatever the console behind this process can do.
	if o.out == "-" {
		capability := env.capability(o.noColor)
		terminal = render.Terminal{Color: capability.Color, Glyph: capability.Glyph}
	}
	if err := terminal.Render(&buffer, finished); err != nil {
		return nil, &fault{exitcode.Runtime, fmt.Sprintf("the report could not be rendered: %v", err)}
	}
	return buffer.Bytes(), nil
}

// deliver puts the finished bytes where they were asked for.
func deliver(o *options, env environment, document []byte) *fault {
	if o.out == "-" {
		if _, err := env.stdout.Write(document); err != nil {
			return &fault{exitcode.IO, fmt.Sprintf("the report could not be written to standard output: %v", err)}
		}
		return nil
	}
	if err := env.writeFile(o.out, document); err != nil {
		return &fault{exitcode.IO, err.Error()}
	}
	// Say where it went. Writing the file was the only thing this run did that
	// a person cannot see, and it is also the only irreversible thing this
	// program does - an existing file at that path has just been replaced. A run
	// that ended in complete silence gave no way to tell a report from a typo
	// in a path until somebody went looking for the file.
	fmt.Fprintf(env.stderr, "%s: report written to %s, %d bytes\n", toolName, o.out, len(document))
	return nil
}

// trustInput builds what L5 was given, minus the presented chain, which Wire
// supplies once L4 has run.
//
// A MISSING PORT PRODUCES AN EMPTY MAP RATHER THAN A PANIC, and L5 reports that
// as "nothing was asked" - our own omission named as ours, never as a machine
// with no runtimes on it.
func trustInput(env environment) trust.Input {
	if env.trustProbes == nil {
		return trust.Input{}
	}
	return trust.Input{
		Probes: env.trustProbes(),
		// What a remediation command needs to know about where it will be run.
		// Both values come from this environment rather than being read inside
		// the layer, so an assessment stays reproducible from its input.
		Machine: trust.Machine{OS: env.platform.OS, Home: env.home},
	}
}

// trustCoverageNote says which runtimes this build is able to ask.
//
// IT REPLACED A NOTE THAT WENT STALE THE MOMENT L5 STARTED WORKING, and the
// replacement is derived rather than written. The old one said the matrix "is
// not built yet and is absent from this report" - which the binary then printed
// three lines below a matrix. That is the exact failure the comment on
// standingNotes warns about, and it was caught by running the program rather
// than by any test.
//
// DELETING IT OUTRIGHT WOULD HAVE BEEN THE OTHER MISTAKE. The matrix is real and
// it is PARTIAL: docs/20 describes thirteen runtime families and this build has
// probes for some of them. A report that showed a partial matrix and said
// nothing would be a run that did less than it promised while looking complete -
// inviolable rule 1. So the note stays and tells the truth instead, and it is
// built FROM THE REGISTRY, so the day a probe arrives this sentence changes by
// itself rather than waiting for somebody to remember it.
// The registry is a parameter so BOTH branches can be reached from a test - a
// build with no probes at all is a real state during a port to a new platform,
// and a branch nothing can execute is a branch nothing proves.
func trustCoverageNote() report.Note { return coverageNoteFor(trust.All()) }

func coverageNoteFor(descriptors []trust.Descriptor) report.Note {
	asked := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		asked = append(asked, descriptor.Runtime)
	}
	if len(asked) == 0 {
		return report.Note{
			Kind:   report.NoteNotImplemented,
			Field:  "trust_matrix",
			Detail: "this build has no runtime probes, so the trust matrix is empty rather than complete",
		}
	}
	return report.Note{
		Kind:  report.NoteNotImplemented,
		Field: "trust_matrix",
		Detail: fmt.Sprintf(
			"the trust matrix asks only the runtimes this build has probes for (%s) - the other families are not asked yet, "+
				"so an absent runtime here means nobody looked rather than nothing was found",
			strings.Join(asked, ", ")),
	}
}
