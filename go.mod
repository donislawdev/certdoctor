module github.com/donislawdev/certdoctor

// A FLOOR, NOT A PIN, and the difference matters because this line used to
// claim otherwise.
//
// certdoctor's verdicts rest on crypto/x509 and crypto/tls: what chains verify,
// which TLS versions and cipher suites are offered, what a verification failure
// is called. Those change between Go releases - probe S3 measured one such
// behaviour and overturned the prediction written before it. A release built on
// a different toolchain can therefore reach a different verdict about the same
// machine, and nothing in the report would say so.
//
// WHAT THIS DIRECTIVE ACTUALLY DOES. It states the lowest version that may build
// this module. A newer toolchain already installed is used without asking, and
// Go has no way to declare a maximum - so this line cannot, on its own, make two
// builds of one commit agree. Saying it did was a claim about somebody else's
// runtime made without checking, which is the mistake this project treats as its
// most expensive one.
//
// WHAT ACTUALLY HOLDS THE VERSION STILL: CI installs exactly this version, via
// go-version-file in the workflow. That is a property of the pipeline, not of
// this file, and a release built anywhere else is not covered by it.
//
// Updating this line is a change like any other: it goes through the same
// analysis, and the release binary is rebuilt and re-measured rather than
// assumed equivalent.
//
// MOVED 1.26.5 -> 1.27.0 ON 2026-09-01, AND THE REASON WAS THE FORMATTER RATHER
// THAN THE LIBRARY. gofmt does not follow the toolchain switch the go command
// makes: it is whichever binary sits in the Go installation on PATH. When that
// installation went to 1.27.0 while this line still said 1.26.5, the local
// format gate and the one in CI began measuring with two different instruments,
// and they disagreed IN BOTH DIRECTIONS over one construct in one file -
// measured the same day, three gofmt versions against internal/app/run/run.go.
// No formatting of that file is green under both, so the versions had to meet.
// go1.27.0 was the current stable release, read at https://go.dev/dl/ on
// 2026-09-01.
//
// MOVED 1.27.0 -> 1.27.2 ON 2026-10-14, AND THIS TIME THE REASON WAS THE
// LIBRARY. go1.27.2 carries security fixes to crypto/tls, net/http,
// html/template, net/textproto and os, and the binary links four of the five -
// all but html/template, measured with "go list -deps ./cmd/certdoctor".
// The same release fixed cmd/cover, which under 1.27.0 counted some statements
// twice and so reported coverage higher than it was (golang/go#81832). That is
// how the gap was noticed: the installation on PATH had already moved, and two
// floors in tools/coverage-floor.txt, measured with the old instrument, fell
// below themselves on code nobody had touched. go1.27.2 was the current stable
// release, read at https://go.dev/doc/devel/release on 2026-10-14.
//
// MOVED 1.27.2 -> 1.27.3 ON 2026-10-21, FOR ONE PACKAGE. go1.27.3 changes
// crypto/x509 and nothing else, read at https://go.dev/doc/devel/release on
// 2026-10-21. It fixes GO-2026-6809: Certificate.Verify now drops every chain
// holding one of eight intermediates, picked out by the SHA-256 of their public
// key, whatever pool of roots the caller hands in (golang/go#82345, commit
// 7f86f957633e). govulncheck found it on the path every row of the trust matrix
// is judged on, and that path judges OTHER programs' trust - programs that do
// not carry the list. So a chain through one of the eight reads as refused on
// every row while the program judged may well accept it. ADR113 decides what
// such a row says instead.
//
// MOVED 1.27.3 -> 1.27.4 ON 2026-11-11, by the maintainer's decision. go1.27.4,
// released 2026-11-10, carries security fixes to cgo, the go command, the
// compiler, the linker and net/http, read at https://go.dev/doc/devel/release
// on 2026-11-11. govulncheck v1.9.0 on this tree with go1.27.3 that day found
// one of them reachable: GO-2026-6859 in net/http, through the PAC download and
// the proxy challenge. The window is built with cgo and the linker, which the
// other fixes are to.
go 1.27.4

require (
	fyne.io/fyne/v2 v2.8.2
	github.com/dop251/goja v0.0.0-20261021125811-a6ef56644a78
	golang.org/x/sys v0.49.0
)

require (
	fyne.io/systray v1.12.3-0.20260810170012-af4e8e793ec4 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/FyshOS/fancyfs v0.0.1 // indirect
	github.com/anthonynsimon/bild v0.17.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dlclark/regexp2/v2 v2.10.1 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/fyne-io/gl-js v0.2.1-0.20260315212741-029c47fd27e8 // indirect
	github.com/fyne-io/glfw-js v0.4.0 // indirect
	github.com/fyne-io/image v0.1.1 // indirect
	github.com/fyne-io/oksvg v0.2.1-0.20260918172519-a9af55fa95d9 // indirect
	github.com/go-gl/gl v0.0.0-20260331235117-4566fea9a276 // indirect
	github.com/go-gl/glfw/v3.4/glfw v0.1.0-pre.2 // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/go-text/render v0.2.1 // indirect
	github.com/go-text/typesetting v0.3.5 // indirect
	github.com/godbus/dbus/v5 v5.2.4 // indirect
	github.com/google/pprof v0.0.0-20261016150608-1facf8f91b50 // indirect
	github.com/hack-pad/go-indexeddb v0.3.2 // indirect
	github.com/hack-pad/safejs v0.1.0 // indirect
	github.com/jeandeaual/go-locale v0.0.0-20250612000132-0ef82f21eade // indirect
	github.com/jsummers/gobmp v0.0.0-20230614200233-a9de23ed2e25 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.31 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/nicksnyder/go-i18n/v2 v2.7.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rymdport/portal v0.4.2 // indirect
	github.com/srwiley/oksvg v0.0.0-20221011165216-be6e8873101c // indirect
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/yuin/goldmark v1.8.7 // indirect
	golang.org/x/image v0.47.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// THE OPENGL BINDING OF THE WINDOW IS A COPY WITH ONE CHANGE, AND THE COMMAND
// LINE DOES NOT LINK IT. The published module links opengl32.dll on Windows, so
// the window imports it at load time and the system's copy is mapped before any
// code of ours runs - measured 2026-11-04 on the window binary. A window that
// has to start again with a software renderer on a machine with no OpenGL
// (ADR125) needs that name free until it loads the renderer itself.
//
// What changed, why, and the sum of the version copied are in
// third_party/go-gl-gl/PATCH.md. go.sum no longer carries this module, so the
// pin lives there and a guard in internal/guard holds the copy to the published
// version plus exactly that change. The version required above stays the one
// the toolkit asks for, and moving it means taking a new copy, not editing this.
replace github.com/go-gl/gl => ./third_party/go-gl-gl
