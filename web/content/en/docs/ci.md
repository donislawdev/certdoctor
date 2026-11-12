---
title: Using it in CI
seoTitle: certdoctor in CI - exit codes and JSON for pipelines
description: "Check that a build agent can reach a registry or an API: certdoctor exit codes, JSON validated against its schema, and a report kept as an artifact."
lead: "Can this build agent reach the registry? One step answers it, with an exit code a pipeline can branch on."
---

## One step

```yaml
- name: can the build agent reach the registry
  run: certdoctor https://registry.example.com/ --redact --json --out certdoctor.json
```

The JSON is checked against its schema before anything is written, so a pipeline never reads a half-made document. Keep it as an artifact, and turn it into a page for a human with `--from` when somebody needs to read it.

## Exit codes

Every ending has its own code:

{{< exit-codes >}}

A `WARN` alone does not fail a build: a machine behind a corporate proxy would otherwise fail every run while its connection works. `4` means the run found something wrong with the path to the URL. `5` means nothing was wrong that it could see, but at least one thing could not be assessed - a pipeline that wants certainty treats it as a failure, one that wants only real failures lets it pass.

## A report for people, after the fact

A later step can make a page from the saved JSON without running the diagnosis again:

```
certdoctor --from certdoctor.json --format html --out certdoctor.html
```

It ends with `0` once the page is written, so a step that only makes a page does not fail the build a second time. The verdict's own code stays in the report as `verdict.exit_code`.

## Windows PowerShell 5.1

Save the JSON with `--out` rather than with `>`. In Windows PowerShell 5.1, `>` writes UTF-16, which is not the file a JSON reader expects.

## Every version in the log

```
certdoctor --version
```

prints the version of the tool, of the report schema, of Go it was built with, and the platform, one per line, so a log from months ago still says what produced a verdict.
