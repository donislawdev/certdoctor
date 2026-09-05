//go:build darwin

package proxyconf

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// Read asks macOS where it keeps its proxy configuration.
//
// THERE IS ONE SYSTEM STACK HERE AND THE WORK IS ONE LINE, which is what the
// split was for: everything this could get wrong - a missing port, a command
// that would not start, a non-zero exit, output cut short, and the dictionary
// itself - is in files every platform compiles, so all of it is measured on a
// machine that is not a Mac.
func Read(ctx context.Context, run Command) []proxy.Lens {
	return []proxy.Lens{askSCUtil(ctx, run)}
}
