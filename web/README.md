# The project website

The source of `certdoctor.donislawdev.com`, built with [Hugo](https://gohugo.io/). It is the
product page, the documentation, and pages about the error messages people search for, in English
and Polish, and in more languages as each one is finished.

## What it may say

Only what is true of the program. What the program can say about itself, the site reads from the
program or from the files the release reads, and never writes by hand:

| What | From | Kept true by |
|---|---|---|
| every switch, its group and its summary as `--help` prints it, every exit code with its name and meaning, the six layers, the four statuses, every variable L0 reads, every family of trust store L5 asks, and the version | `data/facts/certdoctor.json` | `go test ./cmd/sitefacts`, in CI |
| the archives of a release | the download tables of `../README.md`, mounted | `internal/guard` holds the README to the release scripts |
| the commands that check a download | the section of `../README.md` that shows them | the release note and the guards read the same section |
| the oldest Go a build from source takes | `../go.mod`, mounted | the module itself |

When the program changes, that test fails until the facts are written again, from the repository
root:

```
go run ./cmd/sitefacts > web/data/facts/certdoctor.json
```

Then look at the site's diff before committing it. In Windows PowerShell 5.1, `>` writes UTF-16, so
run it from another shell there.

The excerpt of a real run on the home page, `assets/runs/untrusted-root-windows.txt`, is cut line for
line from what the program printed, with `...` where lines were left out.

## The picture a shared link shows

One picture, 1280 by 640, for the site's `og:image` and for the repository's social preview on
GitHub. `../assets/social-preview/social_preview.py` draws it, and the site reads it through a mount
in `hugo.toml`. It names every trust store the program asks, from the facts, and refuses to draw
when a store has no name in its `LABELS`. The picture carries the stores it names and the digest of
the script that drew it, and `go test ./cmd/sitefacts` fails when either is no longer true. After the
facts change, or after any edit to the script:

```
python assets/social-preview/social_preview.py
```

Then look at the picture, commit it, and upload it to GitHub by hand under Settings, General, Social
preview. GitHub keeps its own copy, and nothing here writes to it or compares with it.

## Building it

```
cd web
hugo --printI18nWarnings --panicOnWarning
python ../.github/scripts/site_check.py public --config hugo.toml
```

The version of Hugo is the one `.github/workflows/site.yml` pins with its digest. The build refuses,
rather than writing a page with a hole in it, when a page links to a path with no page, a language
file lacks a word, a translation of the program's words is missing, or the README no longer holds
the archives or the check commands where the site reads them. `site_check.py` then reads every page
it wrote: one `h1`, title and description lengths, canonical addresses, `hreflang` that names back,
the sitemap, every internal link and fragment, and nothing loaded from another host.

## Languages

English is served at the root and every other language under its own prefix, with its paths
translated. A language goes live only when every page is translated: an English page under another
language's address is a duplicate to a search engine.

A language lives in two places:

- `content/<language>/`, its pages, with the same file names as under `content/en/` (that is how
  Hugo pairs a page with its translations) and a `slug` where the path is translated,
- `i18n/<language>.toml`, the words of the site's interface, and the translations of what the
  program prints: its switches, exit codes and layers, which the English pages show from the facts.

A new language takes an entry under `[languages]` in `hugo.toml`, with `disableKinds` naming `404`
as well as the site's own three kinds, because GitHub Pages serves one 404 page, at the root, then
its two places, a build and `site_check.py`, which names every page the new language does not have.

The program's own output - a report, an error message - stays English on every page, because that
is what the program prints.

## Publishing

`.github/workflows/site.yml` builds and checks the site on every pull request and publishes nothing
there. It publishes after CI has passed on `main`, for the commit CI passed on, so a page never goes
up while the test that compares its facts with the program is red. Starting the workflow by hand
from `main` publishes `main` again. GitHub Pages serves the site from the address in its settings,
and `static/CNAME` holds the same address.
