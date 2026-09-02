# The testbed

A machine that knows the truth, so that certdoctor's answers can be checked
against something other than certdoctor.

It holds four benches now, built in that order: **DNS**, a **certificate chain**,
an **interception path**, and a **proxy with a PAC file**. Each one exists
because a layer needed an answer it could not get by asking itself.

```bash
docker compose -f testbed/compose.yml up -d
bash testbed/verify.sh
```

The first command starts a CoreDNS server authoritative for four zones, a server
that presents a leaf without its intermediate, a middlebox that re-signs traffic,
a proxy, and an HTTP server handing out PAC files. The second builds certdoctor,
runs it inside a container whose resolver IS that DNS server, and compares what
it said with `expected/`.

## The rule this directory exists to enforce

**Expected verdicts are written from the configuration, before certdoctor is
pointed at the bench.** The zone file decides what these names resolve to, so
the right answer is known without running anything.

The reverse order - run it, capture the output, call that the expectation -
produces a golden file that enshrines whatever the program did on the day it was
written, and then defends it for years. Every file in `expected/` was written
before the first run, and one of them predicted a disagreement that turned out to
be real.

## Two layers of oracle, and neither is our code

`dig` runs first in every DNS scenario and its answer is printed whatever
happens. It shares no line of code with the thing under test, so when it
disagrees with the bench's own expectation, the bench is the first suspect. Then
certdoctor runs, and only then is anything compared. `openssl` plays the same
part for the chain, and `curl` for the trust matrix - there the witness is the
runtime the claim is ABOUT, which is stronger again.

Two runs of our own code prove nothing beyond the first.

## The proxy bench, where the witness is a log

"This proxy will be used" is the one claim with no independent tool on a real
machine. Here there is one, in two halves.

**What the PAC means** is answered by `libproxy`, somebody else's implementation
of the same PAC helper functions certdoctor has to write for itself. It runs in a
container of its own, beside the bench rather than inside it, with its own
resolver - so the thing being measured cannot reach the instrument. It is handed
the bytes the bench is actually serving, never the copy in this working tree,
because those two have come apart here three times.

**Whether the request arrived** is answered by squid's access log, which is not
our code and not our claim.

The part that makes it evidence rather than theatre: **the client is driven by
the evaluator's answer, not by an address written into the script.** If the PAC
had said something else, libproxy would have said so and the request would have
gone elsewhere. That is why the negative half counts - a target the PAC sends
`DIRECT` must be ABSENT from the proxy log, and an absence only means something
when the presence was reachable by the same path. Every request carries a token
unique to the run, because the log is cumulative.

What this still does not establish is whether a particular runtime would read
this PAC and obey it. No client on this bench reads a PAC by itself. That gap is
named rather than papered over.

## Why certdoctor runs in a container here

It asks the resolvers a machine is **configured** to use. There is no switch for
"ask that server over there", by design - inviolable rule 16 says a run reaches
only what it was pointed at, and a flag that widened that would widen it for
everybody. So the only honest way to aim it at this bench is to run it where the
bench IS the configured resolver.

It also sidesteps a measured trap: Docker's embedded resolver rewrites answers.
`SERVFAIL` comes back as `NXDOMAIN` and `AAAA` records vanish - which are exactly
the facts this bench produces on purpose. Queries go straight to the bench's
address instead.

## What is in git and what is not

Configuration, zone files, scripts and **expected verdicts** are committed.
Private keys and generated certificates never are - and `.gitignore` carries an
explicit exception for `expected/`, because a pattern that sweeps up "anything
generated" would take the golden data with it and leave the guards green with
nothing to check.

Every name here is under `.test` or `example.net`, both reserved and delegated to
nobody. Most addresses are from the documentation ranges of RFC 5737 and RFC
3849, so that a run cannot connect to anything by accident.

**Three zones are a deliberate exception and they are named rather than
discovered later.** `partner.test`, `example.net` and `proxy.test` point into
this compose file's own subnet, because what a server PRESENTS during a
handshake, and whether a request REACHED a proxy, cannot be asked of an address
nobody listens on. That subnet is unreachable from anywhere else, so the
exception stops here.

The proxy's credential is committed in the open, in `proxy/certdoctor-passwd`,
and says so at the top of the file. A fixture nobody can guess is a fixture the
next reader wastes an hour on.

## Reading the output

`UNSETTLED` marks a gap between what the contract asks for and what the code
does, where the difference is **recorded and waiting on a decision** rather than
on a fix. It is printed in full and does not redden the run: a gate that is red
every time teaches that red means nothing. The observation number beside it says
where the decision is being tracked.

`NOT CHECKED` is different again and the distinction is worth keeping: it waits
on a **reader**, not on a decision. An expectation nothing can judge yet, or a
witness that was unavailable this run - a missing witness is reported as missing
rather than counted as a pass.

`AWAITING A DECISION` appears beside an expectation that has parked a question
for the owner. It is printed on every run because the mechanism that turns a
difference into a note cannot fire for a layer nothing reads yet, and a question
nobody prints is a question nobody answers.

`DIFFERS` is an ordinary disagreement and does redden the run. It means either
the product is wrong or our understanding of the scenario is, and both are worth
finding before a release.
