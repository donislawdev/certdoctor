// Package node is the L5 probe for Node.js - ADR111, decided by the owner
// 2026-10-20 after probe S27.
//
// IT JUDGES NODE'S OWN LISTS, BECAUSE NOTHING ELSE HOLDS THEM. The list Node
// trusts by default is Mozilla's, compiled into the binary, and on Windows its
// system list keeps rules of its own - stores and key usages the system-store
// row does not follow. So each node on PATH is asked once, with a constant
// script and no network, and the chain is judged here, in Go, by the rule Node
// was measured to keep: only a self-signed certificate ends a chain.
package node

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Probe builds the L5 probe for node.
//
// start makes the runner, from the variables to withhold, and this package
// names those - probe.Without is what the entry point hands in, so the list
// lives beside its sources and never in main. env is read at the entry point,
// so this package reads no environment of its own.
func Probe(source file.Source, resolve file.Resolve, start func(withheld ...string) probe.Runner, pathDirs []string,
	env Environment, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		// THE WALK IS CONSUMED, NOT WRITTEN - probe.Binaries, OBS50. A row per
		// binary, like git's in ADR74: two node on PATH are two answers.
		binaries := probe.Binaries(source, resolve, pathDirs, "node.exe", "node")
		if len(binaries) == 0 {
			// NOT AN ERROR - docs/20 rule 1. No node is not a fact about trust.
			return nil, nil
		}
		run := start(withheld...)
		stores := make([]report.TrustStore, 0, len(binaries))
		for _, binary := range binaries {
			stores = append(stores, storeFor(ctx, run, binary, env, chain, now()))
		}
		return stores, nil
	}
}

// storeFor turns one binary into one row of the matrix.
func storeFor(ctx context.Context, run probe.Runner, binary string, env Environment, chain [][]byte,
	now time.Time) report.TrustStore {
	store := report.TrustStore{
		Runtime: report.RuntimeNode,
		// THE PATH IS THE IDENTITY, as for curl - two node binaries differ by
		// nothing else a person could tell them apart by.
		Instance:   binary,
		SelectedBy: []string{"PATH"},
		StoreForm:  report.StoreBuiltin,
	}

	args, err := splitOptions(env.Options)
	if err != nil {
		store.NotAssessed = fmt.Sprintf("%v, which Node refuses to start with, so no list decides anything", err)
		return store
	}
	flags := flagsIn(args)
	a, why := ask(ctx, run, binary, flags)
	if why == "" {
		why = unjudged(a, flags)
	}
	if why != "" {
		store.NotAssessed = why
		return store
	}

	probe.VerifySelfSignedAnchors(&store, a.bundle(a.Lists.Default), chain, now)
	store.SelectedBy = selectedBy(a, flags, env)
	store.PlatformListCloses = store.TrustFailure == report.UnknownAuthority && systemListCloses(a, flags, env, chain, now)
	return store
}

// systemListCloses says NODE_USE_SYSTEM_CA=1 would make this node trust the
// chain it refused - ADR111 part 7, the fact the first of its three commands is
// chosen by.
//
// EACH CONDITION IS A WAY THE COMMAND WOULD CHANGE NOTHING. A --use-system-ca
// in NODE_OPTIONS either turned the list on already or, as --no-use-system-ca,
// beats the variable - measured with node v26.9.0 on 2026-10-20. A
// NODE_USE_SYSTEM_CA already set holds somebody's value, and a command
// overwriting it would be a change rather than an addition, so only an unset one
// qualifies. A node that does not read the variable ignores it.
//
// A SYSTEM LIST ALREADY IN EFFECT, OR AN EMPTY ONE, NEEDS NO CONDITION: the
// wider list is then the very list that refused, and closes nothing.
//
// THE WIDER LIST IS JUDGED BY THE SAME RULE, only self-signed anchors, so a
// lone intermediate in the platform's store closes nothing here either.
func systemListCloses(a answer, flags map[string]bool, env Environment, chain [][]byte, now time.Time) bool {
	_, mentioned := flags[flagSystem]
	if mentioned || env.UseSystemCA != "" || !knowsUseSystemCA(a.Node) {
		return false
	}
	var widened report.TrustStore
	probe.VerifySelfSignedAnchors(&widened, a.bundle(slices.Concat(a.Lists.Default, a.Lists.System)), chain, now)
	return widened.TrustsPresentedChain != nil && *widened.TrustsPresentedChain
}

// knowsUseSystemCA says this node reads NODE_USE_SYSTEM_CA. The variable arrived
// in v22.19.0 and v24.6.0, and the v23 line is not among them - Node.js
// doc/api/cli.md of v26.x, read 2026-10-20 at
// https://github.com/nodejs/node/blob/v26.x/doc/api/cli.md - so every line from
// v25 on has it. A version this cannot read is one it does not vouch for.
func knowsUseSystemCA(version string) bool {
	var major, minor int
	if _, err := fmt.Sscanf(version, "v%d.%d", &major, &minor); err != nil {
		return false
	}
	switch major {
	case 22:
		return minor >= 19
	case 24:
		return minor >= 6
	}
	return major >= 25
}

// unjudged names why a list node did send is still not what it trusts, or
// returns the empty string - ADR111 part 5. Each case is said on its own, so a
// person reading the row knows what to look at.
//
// THE BUILD IS ASKED ABOUT BEFORE THE LISTS. A node built to read OpenSSL's
// store does not trust these lists whatever they say, and Debian 13's v20.19.2
// has no lists at all - S27 - so its row names the build rather than the
// missing function.
func unjudged(a answer, flags map[string]bool) string {
	switch {
	case a.CertStore:
		return "this node was built to trust OpenSSL's default store - NODE_OPENSSL_CERT_STORE, which is how " +
			"distributions build it - so its own lists are not what it trusts"
	case a.SystemCAPath != "":
		return fmt.Sprintf("this node was built to read its system certificates from %s, which this program does not follow",
			a.SystemCAPath)
	case a.Lists == nil:
		return fmt.Sprintf("node %s has no tls.getCACertificates, which arrived in v22.15.0 and v23.10.0, so the list it "+
			"trusts cannot be read", a.Node)
	case flags[flagOpenSSL]:
		// MEASURED with node v26.9.0 on 2026-10-20: with --use-openssl-ca the
		// default list came back empty while Node trusted OpenSSL's store.
		return "NODE_OPTIONS carries --use-openssl-ca, so node trusts OpenSSL's default store and the list it reports is empty"
	}
	return ""
}

// selectedBy names what made a typed node use THIS list: PATH, which found the
// binary, and every variable that extended the list - ADR111 part 4.
//
// THE EVIDENCE DECIDES, NOT THE VARIABLE. A node that does not know
// NODE_USE_SYSTEM_CA ignores it, and NODE_EXTRA_CA_CERTS naming a file node
// could not read adds nothing, so a variable is named only when the list node
// sent shows its effect. When NODE_OPTIONS turned the system list on, it is
// named rather than the variable, because an explicit flag wins over
// NODE_USE_SYSTEM_CA - measured with node v26.9.0 on 2026-10-20.
func selectedBy(a answer, flags map[string]bool, env Environment) []string {
	by := []string{"PATH"}
	if a.systemInEffect() {
		switch {
		case flags[flagSystem]:
			by = append(by, "NODE_OPTIONS")
		case env.UseSystemCA == "1":
			by = append(by, "NODE_USE_SYSTEM_CA")
		}
	}
	if len(a.Lists.Extra) > 0 {
		by = append(by, "NODE_EXTRA_CA_CERTS")
	}
	return by
}
