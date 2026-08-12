# The testbed

A machine that knows the truth, so that certdoctor's answers can be checked
against something other than certdoctor.

Today it holds one bench: **DNS**. It is what `L1` needed and never had - every
run before this compared the program with itself.

```bash
docker compose -f testbed/compose.yml up -d
bash testbed/verify.sh
```

The first command starts a CoreDNS server that is authoritative for `ok.test`
and answers `SERVFAIL`, `REFUSED` and `NXDOMAIN` on demand. The second builds
certdoctor, runs it inside a container whose resolver IS that server, and
compares what it said with `expected/`.

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

`dig` runs first in every scenario and its answer is printed whatever happens.
It shares no line of code with the thing under test, so when it disagrees with
the bench's own expectation, the bench is the first suspect. Then certdoctor
runs, and only then is anything compared.

Two runs of our own code prove nothing beyond the first.

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

Every name here is under `.test`, reserved by RFC 2606 and delegated to nobody.
Every address is from the documentation ranges of RFC 5737 and RFC 3849. A bench
must never hand out an address somebody actually answers on.

## Reading the output

`UNSETTLED` marks a gap between what the contract asks for and what the code
does, where the difference is **recorded and waiting on a decision** rather than
on a fix. It is printed in full and does not redden the run: a gate that is red
every time teaches that red means nothing. The observation number beside it says
where the decision is being tracked.

`DIFFERS` is an ordinary disagreement and does redden the run. It means either
the product is wrong or our understanding of the scenario is, and both are worth
finding before a release.
