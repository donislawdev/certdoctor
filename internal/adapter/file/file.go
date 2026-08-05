// Package file is the only way this program is allowed to turn a path into
// bytes.
//
// WHY A SECOND PORT, WHEN THERE IS ALREADY ONE FOR THE NETWORK. Because the
// file layer IS a route to the network and the network port cannot see it. On
// Windows a UNC path opened like an ordinary file is a connection to a host
// nobody named, authenticated with the token of whoever ran this - and nothing
// passes through a network package on the way there. That is docs/14 section
// 3a, and it is not our reasoning: a measured review of a neighbouring project
// found a guard watching network packages while its input and output went over
// SMB, invisibly, at 21 seconds per existence check against 1.2 ms locally.
//
// certdoctor is exactly the program this happens to, because the paths it reads
// come from SOMEBODY ELSE'S CONFIGURATION - NODE_EXTRA_CA_CERTS, git's
// http.sslCAInfo, cafile in an .npmrc that arrived with a cloned repository.
//
// NOTHING HERE IMPORTS os, for the same reason the dial package imports no net:
// this holds the rule, the plumbing arrives as a parameter.
package file

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// Source turns a path into something readable.
type Source func(path string) (io.ReadCloser, error)

// Resolve turns a path into the path it actually names, following symbolic
// links.
//
// IT IS A SECOND PORT BECAUSE RESOLVING TOUCHES THE FILESYSTEM, and this
// package is not allowed to - the same reason Source is a port rather than a
// call to os.Open.
//
// WHY IT EXISTS AT ALL, and it is a measurement rather than a worry.
// docs/14 section 2.2 says plainly that a check on the TEXT of a path does not
// catch symbolic links and that the judgement has to happen after resolution.
// IsRemote below reads text. On 2026-08-05 the first real file this program is
// going to read was looked at on two systems: in WSL /etc/resolv.conf is a
// symbolic link to /mnt/wsl/resolv.conf, and on a systemd machine it is
// normally a link to /run/systemd/resolve/stub-resolv.conf. A link whose target
// sits under a mount from another host is a remote path wearing a local name,
// and without this port nothing here could tell.
type Resolve func(path string) (string, error)

// Record is told about every path a guarded source was ASKED for, and whether
// it was opened. The refusals are the half worth having.
type Record func(path string, opened bool)

// RemotePath is returned for a path that would leave this machine.
//
// IT IS A FINDING, NOT AN ERROR TO SWALLOW. "Your git configuration points at a
// bundle on a file server" is a real answer to why a runtime cannot verify a
// certificate, and it is one no other tool will give. The path is refused and
// reported, never opened.
type RemotePath struct {
	Path string
	// Via is the path Path resolved to, when a symbolic link is what made it
	// remote. It is empty when the path was remote as written.
	//
	// BOTH ARE REPORTED AND THAT IS THE POINT. "Your resolv.conf is a link to a
	// file on a share" is the answer somebody came here for, and naming only the
	// resolved path would hide which of their files to go and look at.
	Via string
}

func (r *RemotePath) Error() string {
	if r.Via != "" {
		return fmt.Sprintf("%s leads to %s, which is not on this machine - opening it would connect to another host "+
			"and authenticate as whoever is running this, so it was reported instead of opened", r.Path, r.Via)
	}
	return fmt.Sprintf("%s is not on this machine - opening it would connect to another host and authenticate as "+
		"whoever is running this, so it was reported instead of opened", r.Path)
}

// TooLarge is returned when a file exceeds the limit it was read under.
type TooLarge struct {
	Path  string
	Limit int64
}

func (t *TooLarge) Error() string {
	return fmt.Sprintf("%s is larger than the %d bytes this may be read under, so it was not handed to a parser",
		t.Path, t.Limit)
}

// IsRemote reports whether a path would leave this machine.
//
// IT IS DELIBERATELY NARROW AND SAYS SO. It knows two shapes: a UNC path in
// either slash spelling, and a path carrying a URL scheme. What it does NOT
// know is a mapped drive letter - Z: pointing at a share is remote and looks
// exactly like a local disk from here, and answering that needs the operating
// system, which this package is not allowed to ask.
//
// A guard believed to be wider than it is reads as permission to stop looking,
// so the limit is written here rather than discovered later.
func IsRemote(path string) bool {
	trimmed := strings.TrimSpace(path)
	if strings.HasPrefix(trimmed, `\\`) || strings.HasPrefix(trimmed, "//") {
		return true
	}
	// A scheme means somebody wrote a URL where a path was expected. Checked
	// before the separator so that "http://host/x" is caught by both rules and
	// reported once.
	if at := strings.Index(trimmed, "://"); at > 0 {
		return true
	}
	return false
}

// Guarded puts the remote check and the size limit in front of a source.
//
// THE ORDER IS THE WHOLE POINT AND IT IS NOT ARBITRARY. It runs in four steps
// and swapping any two of them gives away what the step before it bought:
//
//  1. Judge the path AS WRITTEN. Nothing has been touched yet.
//  2. Only then resolve symbolic links, which DOES touch the filesystem.
//  3. Judge what it resolved to, because a link can point off this machine.
//  4. Open, and cap the bytes before they reach a parser.
//
// STEP 1 HAS TO COME BEFORE STEP 2 AND IT IS EASY TO GET BACKWARDS. Resolving
// a path is itself a filesystem operation, so resolving first would perform the
// expensive, identity-leaking act on exactly the path we are trying not to
// touch - the twenty-one seconds measured in the review behind docs/14 section
// 3a were spent asking about a UNC path, not reading one. Judging the text
// first costs nothing and is the only step that is safe to do blind.
//
// Step 3 exists because step 1 reads TEXT, and docs/14 section 2.2 says text
// does not catch links. That is not theoretical here: /etc/resolv.conf, the
// first real file this program reads, is a symbolic link in WSL and on any
// systemd machine.
//
// A limit of zero or less means no limit, and the number is a parameter rather
// than a constant on purpose: docs/14 section 2.3 wants it measured per parser,
// and the files this program reads do not share one honest figure - a hosts
// file is legitimately megabytes where a resolv.conf is a few hundred bytes.
func Guarded(inner Source, resolve Resolve, limit int64, record Record) Source {
	return func(path string) (io.ReadCloser, error) {
		refuse := func(err error) (io.ReadCloser, error) {
			if record != nil {
				record(path, false)
			}
			return nil, err
		}

		if IsRemote(path) {
			return refuse(&RemotePath{Path: path})
		}
		// A missing resolver refuses everything rather than quietly skipping the
		// link check, for the same reason a nil allowed set refuses every dial:
		// a forgotten port must not read as an absence of restrictions.
		if resolve == nil {
			return refuse(fmt.Errorf("no way to resolve symbolic links was supplied, so %s was not opened - a link "+
				"can point off this machine and the check for that cannot be skipped", path))
		}

		resolved, err := resolve(path)
		switch {
		case err == nil:
			if resolved != path && IsRemote(resolved) {
				return refuse(&RemotePath{Path: path, Via: resolved})
			}
		case errors.Is(err, fs.ErrNotExist):
			// A path that is not there cannot be a link to somewhere else. This
			// is handed on so the source reports the absence, because "your
			// configuration names a file that does not exist" is a fact about
			// the machine being diagnosed and refusing it here would report it
			// as a problem of ours.
		default:
			return refuse(fmt.Errorf("%s could not be resolved, so whether it leads off this machine is unknown "+
				"and it was not opened: %w", path, err))
		}

		if inner == nil {
			return refuse(fmt.Errorf("no file source was supplied, so %s could not be read", path))
		}

		handle, err := inner(path)
		if record != nil {
			record(path, err == nil)
		}
		if err != nil || limit <= 0 {
			return handle, err
		}
		return &capped{inner: handle, path: path, limit: limit}, nil
	}
}

// capped stops a read at the limit instead of trusting whoever supplied the
// file to be reasonable.
//
// It reports the overrun as an error rather than truncating, and that choice
// matters: a parser handed a silently shortened file produces a confident wrong
// answer about somebody's configuration, which is worse than no answer at all.
// ONE BYTE OF HEADROOM, AND IT IS NOT A DETAIL. Reaching the limit and going
// past it are different facts, and the first version could not tell them apart:
// a file of exactly the permitted size was refused, because "no room left"
// arrived before the reader had a chance to say it was finished. So this reads
// up to limit+1 bytes and calls it too large only when that extra byte actually
// turns up - and never hands the extra byte on.
// THERE IS NO "ALREADY EXCEEDED" FLAG, AND THERE USED TO BE ONE. It latched
// after the first overrun so a caller reading again could not get more bytes -
// which sounded necessary and was not: once read has passed limit it stays
// past it, so the comparison below already refuses every later call. The
// mutation register found it, by deleting the flag with every test still green.
type capped struct {
	inner io.ReadCloser
	path  string
	limit int64
	read  int64
}

func (c *capped) Read(p []byte) (int, error) {
	room := c.limit + 1 - c.read
	if int64(len(p)) > room {
		p = p[:room]
	}

	n, err := c.inner.Read(p)
	c.read += int64(n)
	if c.read <= c.limit {
		return n, err
	}

	// The file is bigger than it was allowed to be. Everything past the limit
	// is dropped rather than passed along, because a parser handed part of an
	// oversized file produces a confident wrong answer about it.
	if over := int(c.read - c.limit); over <= n {
		n -= over
	} else {
		n = 0
	}
	return n, &TooLarge{Path: c.path, Limit: c.limit}
}

func (c *capped) Close() error { return c.inner.Close() }
