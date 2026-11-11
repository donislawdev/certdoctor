// Package planted is a fixture, never compiled and never part of the build. It
// goes through some of the doors the layer map declares and leaves the others
// shut, for the guard that says every door is used.
package planted

import (
	_ "strings"

	_ "github.com/donislawdev/certdoctor/internal/core/status"
	_ "github.com/donislawdev/certdoctor/internal/gui/look"
	_ "github.com/donislawdev/certdoctor/internal/gui/words"
)
