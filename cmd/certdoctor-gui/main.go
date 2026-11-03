// Command certdoctor-gui is the window (D21): a second program beside the
// command line, which is to run certdoctor --json from its own folder and draw
// what it said (ADR121).
//
// A program of its own because the graphics toolkit draws through OpenGL and
// reaches it through C, so it needs cgo and a C compiler - and the command line
// is built without cgo for every release target and links nothing of the
// toolkit. The code that opens a window sits behind the cgo build tag, and a
// build without cgo says it has no window in it.
package main

import "os"

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }
