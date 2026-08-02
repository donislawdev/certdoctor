// This file is a fixture, never compiled and never part of the build. It holds
// exactly one shape: an import between two packages of the SAME layer.
//
// Its own file, because a fixture that also breaks the direction rule would let
// the sideways assertion pass on the wrong finding.
package probe

import (
	_ "github.com/donislawdev/certdoctor/internal/adapter/render"
)
