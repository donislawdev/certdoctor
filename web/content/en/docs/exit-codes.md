---
title: Exit codes
seoTitle: Cert Doctor exit codes - what each ending means
description: "The exit codes of Cert Doctor: 0 OK, 4 a failure was found, 5 something could not be assessed, and the codes for usage, configuration, output and interruption."
lead: "Every way a run can end has its own code, and the set is complete: a pipeline can branch on it."
---

{{< exit-codes >}}

## Which of them say something about your machine

`4` and `5` are about the machine and the URL under test. `4` means the run succeeded and found at least one `FAIL` - something on the path to the URL is wrong. `5` means it found no failure, but at least one thing could not be assessed, and the report says which and why. Neither means the program itself went wrong: that is `1`.

## Warnings

A `WARN` alone ends with `0`. A machine behind a corporate proxy would otherwise end every run in failure while its connection works perfectly. The warnings stay in the report, and in the JSON for a pipeline that wants to decide for itself.

## A page made from a saved report

`certdoctor --from report.json --format html --out report.html` ends with `0` once the page is written, whatever the report found. The run's own code stays in the report as `verdict.exit_code`.
