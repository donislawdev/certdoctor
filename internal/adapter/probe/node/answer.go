package node

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
)

// script is what node is asked to run, and it is a CONSTANT - nothing from the
// target, the machine or the command line reaches it, the rule ADR49 sets for
// every argument a probe passes. It makes no connection and writes nothing but
// its answer: the build facts, then three of Node's own lists, each certificate
// sent once and every list as positions in that one array. On the owner's
// machine the answer is about 390 kB and arrives in about 100 ms - S27.
//
// THE LISTS COME FROM tls.getCACertificates, which arrived in v22.15.0 and
// v23.10.0 - Node.js doc/api/tls.md of v26.x, read 2026-10-20 at
// https://github.com/nodejs/node/blob/v26.x/doc/api/tls.md - so on an older node
// lists is null and the row says so. "default" is what Node trusts, "system" is
// the platform's list whether or not Node uses it, and "extra" is what
// NODE_EXTRA_CA_CERTS added.
//
// THE BUILD FACTS COME FIRST because they decide whether the lists mean
// anything: probe S27 found NODE_OPENSSL_CERT_STORE among the build's defines
// in every distribution's package it measured, and OpenSSL's store rather than
// these lists is what such a node trusts. Each of those packages had
// node_shared_openssl true as well - the distribution's own OpenSSL, whose
// default file its recipe names - and so did RHEL 9.8's, measured 2026-10-20.
const script = `'use strict';
const tls = require('tls');
const config = process.config || {};
const defines = (config.target_defaults || {}).defines || [];
const variables = config.variables || {};
const answer = {
  node: process.version,
  cert_store: defines.includes('NODE_OPENSSL_CERT_STORE'),
  shared_openssl: variables.node_shared_openssl === true,
  system_ca_path: String(variables.openssl_system_ca_path || ''),
  lists: null,
  pem: [],
};
if (typeof tls.getCACertificates === 'function') {
  const seen = new Map();
  const list = (name) => tls.getCACertificates(name).map((pem) => {
    if (!seen.has(pem)) {
      seen.set(pem, answer.pem.length);
      answer.pem.push(pem);
    }
    return seen.get(pem);
  });
  answer.lists = { default: list('default'), system: list('system'), extra: list('extra') };
}
process.stdout.write(JSON.stringify(answer));
`

// answer is what the script prints.
type answer struct {
	Node          string `json:"node"`
	CertStore     bool   `json:"cert_store"`
	SharedOpenSSL bool   `json:"shared_openssl"`
	SystemCAPath  string `json:"system_ca_path"`
	Lists         *lists `json:"lists"`
	// PEM holds every certificate once, and the lists point into it.
	PEM []string `json:"pem"`
}

type lists struct {
	Default []int `json:"default"`
	System  []int `json:"system"`
	Extra   []int `json:"extra"`
}

// ask runs the script and returns its answer, or the sentence a row says when
// there is none. args are the CA flags NODE_OPTIONS mentions, as mentions
// spells them.
func ask(ctx context.Context, run probe.Runner, binary string, args []string) (answer, string) {
	out, err := run(ctx, binary, append(slices.Clone(args), "-e", script)...)
	switch {
	case err != nil:
		return answer{}, fmt.Sprintf("node could not be asked for its certificate lists: %v", err)
	case out.Truncated:
		return answer{}, "node answered with more than this program keeps, so the lists it sent are incomplete"
	case out.ExitCode != 0 && len(args) > 0:
		// NODE_OPTIONS put these flags here, so this is how node starts for the
		// person too - the exit code alone is the answer, never the message.
		return answer{}, fmt.Sprintf("node exited with %d when started with %s, the CA options NODE_OPTIONS carries, "+
			"so it does not start that way and no list decides anything", out.ExitCode, strings.Join(args, " "))
	case out.ExitCode != 0:
		return answer{}, fmt.Sprintf("node exited with %d when asked for its certificate lists", out.ExitCode)
	}
	var a answer
	if err := json.Unmarshal([]byte(out.Stdout), &a); err != nil {
		return answer{}, fmt.Sprintf("node's answer was not the JSON this program asked for: %v", err)
	}
	if a.Node == "" || !a.consistent() {
		return answer{}, "node's answer was not the JSON this program asked for: a version or a certificate it points at is missing"
	}
	return a, ""
}

// consistent says every position in every list names a certificate the answer
// carries - an answer is input from somebody else's program, rule 35.
func (a answer) consistent() bool {
	if a.Lists == nil {
		return true
	}
	for _, list := range [][]int{a.Lists.Default, a.Lists.System, a.Lists.Extra} {
		for _, at := range list {
			if at < 0 || at >= len(a.PEM) {
				return false
			}
		}
	}
	return true
}

// bundle is one list written out as the PEM bundle the verifier reads, each
// certificate once.
//
// NODE'S LIST REPEATS ITSELF - tls.md says the array may hold one certificate
// from several sources - and the verifier counts every block it reads. Measured
// with this program's binary on the owner's machine 2026-10-20: with the system
// list on, the count came out 282 where the certificates were far fewer, since
// the Windows stores Node reads hold many of the same roots.
func (a answer) bundle(list []int) []byte {
	var b strings.Builder
	written := map[int]bool{}
	for _, at := range list {
		if written[at] {
			continue
		}
		written[at] = true
		b.WriteString(a.PEM[at])
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// systemInEffect says Node trusts its system list - every certificate on it is
// in the default list. An empty system list extends nothing.
func (a answer) systemInEffect() bool {
	if len(a.Lists.System) == 0 {
		return false
	}
	trusted := map[int]bool{}
	for _, at := range a.Lists.Default {
		trusted[at] = true
	}
	for _, at := range a.Lists.System {
		if !trusted[at] {
			return false
		}
	}
	return true
}
