// Package proxyconf asks a machine where it keeps its proxy configuration.
//
// IT IS TRANSPORT AND ALMOST NOTHING ELSE, AND THAT IS THE DESIGN RATHER THAN A
// THIN FIRST DRAFT. Everything that is text - the six exception list rules, the
// scutil dictionary, the precedence between two spellings of one environment
// variable, and the conversion of each platform reading into a proxy.Lens -
// lives in internal/core/proxy, in files with no build tag on them. Two measured
// reasons put it there and both point the same way: the mutation register runs
// on Windows, so a rule behind //go:build !windows can never have an entry in it
// (OBS102), and a coverage floor is the lower bound of two platforms, so a rule
// only one of them compiles has half its branches unmeasured (OBS100).
//
// WHAT IS LEFT HERE IS THE PART THAT NEEDS A REAL MACHINE: calling somebody
// else's API and handing back strings. The coverage floor for this package is
// LOW and says so out loud in tools/coverage-floor.txt - that is the consequence
// of the split rather than a gap in the testing (OBS107).
//
// THIS PACKAGE ANSWERS ABOUT SYSTEM STACKS ONLY. The environment is a stack too
// and it is read by proxy.EnvironmentLens, which needs no platform code at all -
// so the caller composes the two rather than this package pretending to own one
// it does not have to touch.
package proxyconf

import (
	"context"
	"fmt"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// Command is how this package asks for a program to be run.
//
// IT IS A PORT OF PRIMITIVES AND DELIBERATELY NOT internal/adapter/probe.Runner,
// even though probe.Run is what the entry point will fill it with. Importing
// that package would be an adapter reaching sideways to another adapter, which
// the layer guard forbids by default and which would cost an entry in
// intraLayerEdges - a standing guard widened for a type this file can declare in
// one line.
//
// TRUNCATION IS IN THE SIGNATURE BECAUSE SILENCE IS FORBIDDEN. probe.Run caps a
// child's output as it arrives, and a capped dictionary parses perfectly well
// into an answer that is missing keys. A run that did less than it promised has
// to be able to say so - inviolable rule 1 - and it cannot say what it was never
// told.
type Command func(ctx context.Context, executable string, args ...string) (stdout string, exitCode int, truncated bool, err error)

// errorFileNotFound is ERROR_FILE_NOT_FOUND.
//
// Source: winerror.h, the same kind of reading as the ERROR_NO_MORE_ITEMS
// constant in internal/adapter/dns - the standard library does not carry this
// one either, so the number is written down here with a note saying where it is
// from rather than reached for in a dependency.
const errorFileNotFound = 2

// ieSettingsAbsent says whether a FALSE from WinHttpGetIEProxyConfigForCurrentUser
// is the machine answering rather than a reading that failed.
//
// SOURCE: Microsoft, WinHttpGetIEProxyConfigForCurrentUser, read 2026-09-06,
// lists ERROR_FILE_NOT_FOUND with the meaning "No Internet Explorer proxy
// settings can be found".
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetieproxyconfigforcurrentuser
//
// IT SITS IN THE FILE EVERY PLATFORM COMPILES, one line long, and that is worth
// the indirection: it is the only JUDGEMENT on the Windows path, and behind a
// build tag it would be a decision no test on this machine could reach and no
// mutation entry could aim at.
func ieSettingsAbsent(errno uintptr) bool { return errno == errorFileNotFound }

// askSCUtil runs the macOS proxy query and turns what came back into a lens.
//
// IT IS HERE AND NOT IN proxyconf_darwin.go ON PURPOSE, and it is the same move
// that put ParseSCUtil in the core one layer down. Every branch below is
// plumbing around a port - a missing port, a command that would not start, a
// non-zero exit, output that was cut short - so none of it needs a Mac to
// exercise. Behind a build tag every one of them would be a branch no test on
// this machine could reach and no mutation entry could aim at (OBS102), for no
// gain at all: the darwin file is then one line long and holds nothing but the
// fact that this platform has this stack.
//
// A FAILURE BECOMES AN UNREADABLE LENS RATHER THAN AN ERROR RETURN. "This stack
// could not be read" is an answer the type already has a shape for, and it is a
// different answer from "this machine has no proxy" - keeping those two apart is
// what Lens exists for, so handing the caller an error to re-encode would be
// asking it to make the same distinction a second time.
func askSCUtil(ctx context.Context, run Command) proxy.Lens {
	if run == nil {
		return proxy.UnreadableLens(proxy.StackMacSystem, proxy.SourceSCUtil,
			"no way to run "+proxy.SCUtilPath+" was supplied, so this machine's system proxy settings were never asked for")
	}

	stdout, exitCode, truncated, err := run(ctx, proxy.SCUtilPath, proxy.SCUtilArg)
	switch {
	case err != nil:
		return proxy.UnreadableLens(proxy.StackMacSystem, proxy.SourceSCUtil,
			fmt.Sprintf("the question could not be put to %s at all: %v", proxy.SCUtilPath, err))
	case exitCode != 0:
		// The number and never the wording - inviolable rule 19. What the command
		// printed on the way out is on a machine whose language we do not choose.
		return proxy.UnreadableLens(proxy.StackMacSystem, proxy.SourceSCUtil,
			fmt.Sprintf("%s exited with %d, so what it would have reported is unknown", proxy.SCUtilPath, exitCode))
	case truncated:
		// A cut dictionary parses cleanly into an answer with keys missing, which
		// is the shape of a report that did less than it promised and looks
		// complete - inviolable rule 1.
		return proxy.UnreadableLens(proxy.StackMacSystem, proxy.SourceSCUtil,
			fmt.Sprintf("the output of %s was longer than this program keeps, and a dictionary read from part of it would look whole", proxy.SCUtilPath))
	}
	return proxy.LensFromSCUtil(proxy.ParseSCUtil(stdout))
}
