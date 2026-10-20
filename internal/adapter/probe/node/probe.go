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
		// The deferral's rpm runs through the same runner and loses the same
		// variables, which a child may always do.
		ports := probe.Ports{Source: source, Resolve: resolve, Run: start(withheld...)}
		stores := make([]report.TrustStore, 0, len(binaries))
		for _, binary := range binaries {
			stores = append(stores, storeFor(ctx, ports, binary, env, chain, now()))
		}
		return stores, nil
	}
}

// storeFor turns one binary into one row of the matrix.
func storeFor(ctx context.Context, ports probe.Ports, binary string, env Environment, chain [][]byte,
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
	said := mentions(args)
	flags := flagsIn(said)
	a, why := ask(ctx, ports.Run, binary, said)
	if why == "" && a.SystemCAPath == "" && openSSLStore(said, a.CertStore) {
		return judgedByOpenSSL(ctx, store, ports, binary, a, env)
	}
	if why == "" {
		why = unjudged(a)
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
// A FILE THE BUILD LOADS ITSELF COMES FIRST, whatever store is in use: Node
// loads it into every store it makes - NewRootCertStore in
// src/crypto/crypto_context.cc of v26.x, read 2026-10-20 at
// https://github.com/nodejs/node/blob/v26.x/src/crypto/crypto_context.cc
func unjudged(a answer) string {
	switch {
	case a.SystemCAPath != "":
		return fmt.Sprintf("this node was built to read its system certificates from %s, which this program does not follow",
			a.SystemCAPath)
	case a.Lists == nil:
		return fmt.Sprintf("node %s has no tls.getCACertificates, which arrived in v22.15.0 and v23.10.0, so the list it "+
			"trusts cannot be read", a.Node)
	}
	return ""
}

// judgedByOpenSSL writes the row of a node that trusts OpenSSL's default store
// rather than its own lists - ADR111 parts 5 and 6. The store is the
// platform's, so the row says so rather than "builtin".
//
// A DISTRIBUTION'S BUILD DEFERS TO THE PLATFORM'S OWN STORE: Node then calls
// X509_STORE_set_default_paths (NewRootCertStore, the same file), which reads
// OpenSSL's default file and directory, and on a distribution in
// probe.OpenSSLBuilds that file is the one the platform store's row judges.
// Its lists say nothing about it - S27 measured them wrong in both directions.
//
// AN OFFICIAL BUILD TOLD TO USE THAT STORE IS NOT ANSWERED: its OpenSSL is its
// own, and which default file it reads no distribution's recipe says.
func judgedByOpenSSL(ctx context.Context, store report.TrustStore, ports probe.Ports, binary string, a answer,
	env Environment) report.TrustStore {
	store.StoreForm = report.StoreSystem
	if !a.CertStore {
		// MEASURED with node v26.9.0 on 2026-10-20: with --use-openssl-ca the
		// default list came back empty while Node trusted OpenSSL's store.
		store.NotAssessed = "NODE_OPTIONS carries --use-openssl-ca, so node trusts OpenSSL's default store rather than " +
			"the list it reports"
		return store
	}
	const builtTo = "this node was built with NODE_OPENSSL_CERT_STORE to trust OpenSSL's default store rather than " +
		"its own lists, the way distributions build it"
	if why := notTheDefaultFile(a, env); why != "" {
		store.NotAssessed = builtTo + " - " + why
		return store
	}
	if env.Platform != "linux" {
		store.NotAssessed = builtTo
		return store
	}
	return probe.DeferToThePlatform(ctx, store, ports, probe.OpenSSLBuilds, binary, "nodejs", builtTo)
}

// notTheDefaultFile names what makes this node trust something other than the
// default file of the distribution's OpenSSL, or returns the empty string -
// ADR111 part 6, condition 4, and each is said on its own.
//
// SSL_CERT_FILE AND SSL_CERT_DIR REPLACE THE DEFAULTS, even set to nothing -
// EnvironmentFrom has the source. NODE_EXTRA_CA_CERTS adds to whatever store is
// in use (NewRootCertStore again), so the platform's store alone is not what
// such a node trusts.
func notTheDefaultFile(a answer, env Environment) string {
	switch {
	case !a.SharedOpenSSL:
		return "it carries an OpenSSL of its own rather than the distribution's, and which default file that one " +
			"reads is not known"
	case env.CertFileSet:
		return "SSL_CERT_FILE is set, and OpenSSL reads the file it names in place of its default one"
	case env.CertDirSet:
		return "SSL_CERT_DIR is set, and OpenSSL looks in the directories it names in place of its default one"
	case env.ExtraCACerts != "":
		return "NODE_EXTRA_CA_CERTS adds the certificates of another file to that store"
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
