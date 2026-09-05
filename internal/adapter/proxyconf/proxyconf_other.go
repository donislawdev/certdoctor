//go:build !windows && !darwin

package proxyconf

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// Read reports that this platform keeps no system proxy configuration, and
// NOTHING is the honest answer rather than a gap in this file.
//
// Linux has no one place every program reads for proxy settings. Command line
// tools read the environment, and a desktop environment keeps its own settings
// that those tools never consult - so there is no second stack here to compare
// the environment against.
//
// IT RETURNS NO LENSES RATHER THAN ONE SAYING "NO PROXY", and the difference is
// the whole point of the type. A lens with Read false would claim this program
// tried and was refused; a lens with Read true and no servers would claim this
// machine has a system stack that names nothing. Both are untrue. No lens at all
// means proxy.Compare has one stack to look at, answers DivergeUnreadable, and
// says out loud that nothing was compared - which is exactly what happened.
func Read(context.Context, Command) []proxy.Lens { return nil }
