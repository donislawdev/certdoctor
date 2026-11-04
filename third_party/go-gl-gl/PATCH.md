# A copy of github.com/go-gl/gl with one change

This directory is the module `github.com/go-gl/gl` at version
`v0.0.0-20260331235117-4566fea9a276`, module sum
`h1:IO5P06Pcj9K04d+l4nrf3c2U56+dAotIFG6u4P1wAHI=`, the version the window's
toolkit asks for. It keeps the module's `go.mod`, its `LICENSE` and the two
packages the toolkit imports, `v2.1/gl` and `v3.1/gles2`, and changes one of
them. The `go.mod` at the root of this repository points the module path here
with a `replace` directive, so every build of the window takes the binding
from this directory. The command line does not link it at all.

## What was changed

In `v2.1/gl`, two files lose the line
`#cgo !gles2,windows LDFLAGS: -lopengl32` - `procaddr.go` and the generated
`package.go` both carry it. The Windows branch of `GlowGetProcAddress` in
`procaddr.go` finds `wglGetProcAddress` with `GetProcAddress` after
`LoadLibraryA("opengl32.dll")` instead of calling it as a linked symbol.
Nothing else differs from the published module, and a guard in
`internal/guard` holds the copy to that: it fetches the pinned version, checks
its sum against the one above and compares every file here with the published
one plus exactly this change.

## Why

With the link, the window names `opengl32.dll` in its import table, so the
Windows loader maps the system's copy before any code of ours runs - measured
on 2026-11-04 on the window built from the published module. Windows then
hands that library to every later request for the same name, so a software
renderer loaded from a path afterwards can never be the `opengl32.dll` the
toolkit draws with.

Without it, the first request for `opengl32.dll` is the one the windowing
library makes by name when it creates its context, and by then the window has
had its chance to load a renderer of its own. That is what lets the window
start again with a software renderer on a machine whose graphics driver offers
no OpenGL, and it is the only reason this copy exists.

## What was left as it was

`v3.1/gles2` is carried unchanged. No release of the window links it, but the
toolkit imports it on arm64, and `go mod tidy` reads every platform - without
this package it stops looking for a module that provides it, measured on
2026-11-04.

The lookup by name goes through the same search order the windowing library
already uses for the same file, so it opens no door that was not open before.

## Licence

MIT, as published. The `LICENSE` file beside this one is the module's own,
carried unchanged.
