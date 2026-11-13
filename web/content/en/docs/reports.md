---
title: Reports and formats
seoTitle: Cert Doctor reports - Markdown, HTML, JSON and redaction
description: "Write a Cert Doctor report as Markdown for a ticket, one self-contained HTML page or JSON, mask host names with --redact, and turn saved JSON into a page later."
lead: "One run, four ways to keep what it found, and a mask for the parts that should not leave the building."
---

## Four formats

| Format | Switch | What it is |
|---|---|---|
| terminal | the default | the report as you read it, 100 columns wide, in colour when the output is a terminal |
| Markdown | `--format md` | the same report for a ticket or a chat |
| HTML | `--format html` | one self-contained page, with no script in it and nothing fetched from anywhere |
| JSON | `--format json`, or `--json` | the report as data, checked against its schema before it is printed |

Every format carries the same findings. A report written in one says nothing another would leave out.

## Writing to a file

`--out` writes the report to the path you give instead of printing it:

```
certdoctor https://api.example.com/ --format html --out report.html
```

This is the only file Cert Doctor ever writes. If it cannot be written - no space, no permission - the run ends with exit code `6` and says why.

## Masking internal names

A report holds internal host names, file system paths and user names, because that is what makes it useful in a ticket. `--redact` masks them:

```
certdoctor https://api.example.com/ --redact --format md --out report.md
```

Credentials are different. Proxy passwords, authorization headers and cookies are masked always, with or without `--redact`, because a mask that depends on a switch is one forgotten switch away from a leak.

> Read a report before you paste it somewhere public. Masking is a filter, not a guarantee.

## A page from a saved report

`--from` takes a report saved earlier with `--json` and writes it again in another format, without running anything:

```
certdoctor https://api.example.com/ --json --out report.json
certdoctor --from report.json --format html --out report.html
```

A single dash reads the JSON from standard input. `--from` ends with exit code `0` once the page is written, whatever the report found, and the run's own verdict stays in the report.

## The JSON schema

`certdoctor --version` prints the version of the tool and of the report schema it emits, so a JSON file from six months ago still says what produced it:

```
certdoctor --version
```
