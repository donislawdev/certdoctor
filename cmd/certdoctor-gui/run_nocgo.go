//go:build !cgo

package main

import (
	"fmt"
	"io"

	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// run answers a build with no window in it. With cgo disabled the code that
// opens a window was never compiled, so this says so rather than starting and
// doing nothing - and exits 1, the code the window gives every refusal.
// Arguments are not read, the same as in the build that has a window.
func run(_ []string, errOut io.Writer) int {
	fmt.Fprintln(errOut, words.T(words.NoWindowInThisBuild))
	return 1
}
