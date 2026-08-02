// This file is a fixture, never compiled and never part of the build. It exists
// so the layer guard can be proved to fail on violations known to be present.
package status

import (
	_ "os/exec"

	_ "github.com/donislawdev/certdoctor/internal/adapter/render"
)
