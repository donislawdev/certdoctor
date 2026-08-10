//go:build !windows

package dns

import (
	"fmt"
	"io"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
)

// ResolverConfPath is the file every unix-like system writes its resolvers to.
//
// It is a constant and not something discovered, which is why L1 does NOT wake
// the failure mode about paths from somebody else's configuration - docs/22 row
// 17 is about a path we were told, and this one we already knew.
const ResolverConfPath = "/etc/resolv.conf"

// Enumerate reads this machine's resolvers out of resolv.conf.
//
// BOTH LISTS ARE THE SAME HERE AND THAT IS HONEST. The two-list shape exists
// because Windows can be asked two different questions with two different
// answers. This system records its resolvers in one place and uses what it
// records, so claiming a difference would be inventing one.
//
// The file arrives through the port rather than through os.Open, and the port is
// the guarded one: it judges the path as written, resolves symbolic links, judges
// what they led to and caps the size - in that order. That is not ceremony here.
// /etc/resolv.conf IS A SYMBOLIC LINK on WSL and on any systemd machine, and a
// link into a mount from another host is a remote path wearing a local name.
func Enumerate(open file.Source) (Nameservers, error) {
	if open == nil {
		return Nameservers{}, fmt.Errorf("no way to read %s was supplied, so this machine's resolvers are unknown",
			ResolverConfPath)
	}

	handle, err := open(ResolverConfPath)
	if err != nil {
		return Nameservers{}, fmt.Errorf("reading %s: %w", ResolverConfPath, err)
	}
	defer handle.Close()

	data, err := io.ReadAll(handle)
	if err != nil {
		return Nameservers{}, fmt.Errorf("reading %s: %w", ResolverConfPath, err)
	}

	// The parser lives in the core because it is a pure function of bytes, and
	// because a refusal - a file in UTF-16, a value that is not text - is an
	// ANSWER there rather than a crash here (ADR27).
	config, err := resolve.ParseResolverConfig(data)
	if err != nil {
		return Nameservers{}, fmt.Errorf("reading %s: %w", ResolverConfPath, err)
	}

	return Nameservers{
		ToAsk: config.Nameservers,
		Known: config.Nameservers,
		From:  ResolverConfPath,
	}, nil
}
