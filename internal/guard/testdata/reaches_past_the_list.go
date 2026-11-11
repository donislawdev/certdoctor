// Package planted is a fixture, never compiled and never part of the build. It
// imports what the old list of forbidden packages let through, for the guard
// that gives the core and the orchestrator a closed list instead.
package planted

import (
	_ "crypto/tls"
	_ "os/exec"
	_ "path/filepath"
	_ "strings"

	_ "github.com/dop251/goja"
)
