// This file is a fixture, never compiled and never part of the build. It
// breaks every rule of package hygiene but one at once. The blank line below
// keeps this comment from being read as the package comment it lacks.

package wrongname

import (
	_ "os"
	. "strings"
)

var shouting = ToUpper("x")

func init() {}
