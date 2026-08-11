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

// NameSourcesPath is where this system records WHERE it looks a name up, as
// opposed to which server it asks.
//
// It is a constant for the same reason ResolverConfPath is: we already knew it,
// so reading it does not wake the failure mode about paths that arrive from
// somebody else's configuration.
const NameSourcesPath = "/etc/nsswitch.conf"

// NameSources reads the hosts line of nsswitch.conf.
//
// WHY THIS FILE MATTERS AT ALL, AND IT IS MEASURED RATHER THAN ASSUMED. Probe
// S10 changed that line to "hosts: dns" and watched an entry in the hosts file
// STOP resolving - so this line decides whether the platform looks in the hosts
// file, and our own view never looks there under any configuration. That is the
// difference D13 saw on localhost and recorded as a fact about our instrument
// rather than about the user's machine. ADR28 says a derived answer has to say
// what it was derived FROM, and this is half of that sentence.
//
// A MISSING FILE IS AN ANSWER, NOT AN ERROR. alpine ships without one and Go
// then uses its own default, so "there is no such file" is a fact about this
// machine that the report can carry - and it is told apart from "the file is
// there and names no hosts line", which is a different fact again.
func NameSources(open file.Source) (resolve.NameSources, error) {
	if open == nil {
		return resolve.NameSources{}, fmt.Errorf("no way to read %s was supplied", NameSourcesPath)
	}

	handle, err := open(NameSourcesPath)
	if err != nil {
		// Not wrapped as a failure of the run: the caller decides, and for this
		// file "absent" is the common case rather than the broken one.
		return resolve.NameSources{}, err
	}
	defer handle.Close()

	data, err := io.ReadAll(handle)
	if err != nil {
		return resolve.NameSources{}, fmt.Errorf("reading %s: %w", NameSourcesPath, err)
	}
	return resolve.ParseNameSources(data)
}
