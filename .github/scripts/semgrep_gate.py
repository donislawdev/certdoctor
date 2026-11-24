#!/usr/bin/env python3
"""Decide a run from a Semgrep JSON report.

    semgrep scan --config p/default --json --output semgrep.json
    python .github/scripts/semgrep_gate.py semgrep.json

Why this exists rather than `semgrep --severity ERROR --error`
--------------------------------------------------------------
Because that flag does not mean what it reads like. `--severity` accepts INFO,
WARNING and ERROR only, while a rule may declare the newer scale, and rules in
the registry do. A gate built on the flag would ignore exactly the severities
it was asked to block.

Why the exit code of the scanner is not the answer
---------------------------------------------------
A semgrep whose core fails can print its errors, exit 0 and write a short file
that is not JSON - measured in a sister project on semgrep 1.175.0. A gate
reading that exit code would report a clean tree. This one reads the file,
fails to parse it and exits 2: a scanner that fails can succeed, so the report
is the answer and the exit code is not.

What blocks
-----------
Any finding whose severity is ERROR, HIGH or CRITICAL. Everything else is
printed and passes, because a WARNING is usually a rule seeing a shape it
cannot resolve, and a gate that fires on those is a gate nobody reads.

A scan error blocks too. A rule that failed to run is not a rule that found
nothing, and "the scan was green" must never mean "the scan did not happen".
Only entries at level "error" count. Measured on this repository on 2026-11-23:
a healthy run carries 43 entries at level "warn", semgrep declining to parse
snippets it does not understand, and none of them a reason to stop anybody.

Findings decided once and recorded
-----------------------------------
Nothing is suppressed here. A finding this project has looked at and settled
carries a `nosemgrep` comment at the line, with the reason beside it, so the
decision stands next to the code it is about and the rule keeps watching every
other line.
"""
import argparse
import json
import sys

BLOCKING = ("ERROR", "HIGH", "CRITICAL")


def split(report):
    """(blocking, passing, scan_errors) out of a semgrep JSON report."""
    blocking, passing = [], []
    for result in report.get("results") or []:
        severity = str((result.get("extra") or {}).get("severity", "")).upper()
        (blocking if severity in BLOCKING else passing).append(result)
    errors = [e for e in report.get("errors") or []
              if str(e.get("level", "")).lower() == "error"]
    return blocking, passing, errors


def describe(result):
    extra = result.get("extra") or {}
    start = result.get("start") or {}
    message = " ".join(str(extra.get("message", "")).split())
    return "%s:%s  [%s] %s\n      %s" % (
        result.get("path", "?"), start.get("line", "?"),
        extra.get("severity", "?"), result.get("check_id", "?"), message[:300])


def report_lines(blocking, passing, errors):
    lines = []
    if errors:
        lines.append("scan errors (a rule that could not run is not a rule that passed):")
        lines += ["  %s: %s" % (e.get("type", "?"),
                                " ".join(str(e.get("message", "")).split())[:200])
                  for e in errors]
    if blocking:
        lines.append("blocking findings (%s):" % ", ".join(BLOCKING))
        lines += ["  " + describe(r) for r in blocking]
        lines.append("")
        lines.append("If one of these is settled rather than wrong, put a nosemgrep comment on")
        lines.append("the line with the reason beside it.")
    if passing:
        lines.append("other findings (reported, not blocking):")
        lines += ["  " + describe(r) for r in passing]
    lines.append("semgrep: %d blocking, %d other, %d scan error(s)"
                 % (len(blocking), len(passing), len(errors)))
    return lines


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", help="the JSON file semgrep --output wrote")
    args = parser.parse_args(argv)
    try:
        with open(args.report, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError) as exc:
        # A missing or unparsable report is a failed gate, never a pass. It
        # means the scan step did not produce what this one was promised.
        print("semgrep gate: cannot read %s: %s" % (args.report, exc), file=sys.stderr)
        return 2
    if not isinstance(report, dict):
        print("semgrep gate: expected a report object, got %s"
              % type(report).__name__, file=sys.stderr)
        return 2
    # A scan that looked at nothing is not a clean scan. A wrong working
    # directory or a configuration that resolved to nothing still writes a
    # valid report with an empty list of results, and every reader downstream
    # would call that a pass. This does not prove how many rules ran, because
    # the report does not carry that number. It proves that files were read.
    scanned = (report.get("paths") or {}).get("scanned") or []
    if not scanned:
        print("semgrep gate: the report says no file was scanned, so nothing was checked.\n"
              "A clean run of this repository scans hundreds of files. An empty list means "
              "the scan ran somewhere else or against nothing, not that the tree is clean.",
              file=sys.stderr)
        return 2
    blocking, passing, errors = split(report)
    for line in report_lines(blocking, passing, errors):
        print(line)
    return 1 if (blocking or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
