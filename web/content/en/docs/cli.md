---
title: Command line reference
linkTitle: Command line
seoTitle: certdoctor command line - every switch
description: "Every switch of the certdoctor command line: the URL, --pac-url, --from, --format, --json, --out, --redact, --quiet, --verbose, timeouts and more."
lead: "Every switch the command line takes, in the groups and the order `certdoctor --help` prints them."
---

## Usage

```
certdoctor <url> [options]
certdoctor --from <file> [options]
```

The URL needs an explicit `http://` or `https://` scheme. Without one there is no way to tell a host name from a port number. `--from` takes the place of the URL: it runs nothing, writes a saved report in the format asked for, and ends with `0` once it is written.

{{< switches >}}

## Environment

`NO_COLOR`, set to any non-empty value, turns colour off. It is the only variable that changes what certdoctor does, and it changes only how the report looks. Proxy and trust store variables are read as things to diagnose, never as configuration for certdoctor.

## Exit codes

Every ending has its own code. [Exit codes](/docs/exit-codes/) lists them.
