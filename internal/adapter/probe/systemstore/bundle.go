package systemstore

import (
	"context"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// This file is the platform store where the platform keeps it as FILES - Linux,
// ADR104. It carries no build tag, so every rule in it is tested on every
// platform the tests run on, and probe_linux.go only wires it.
//
// THERE IS NO PLATFORM API TO ASK, SO THE STORE IS WHAT THE PROGRAMS READ. Go
// reads the first bundle on a fixed list, and OpenSSL's own default bundle led
// to that same file in every image probe S24 opened on 2026-10-15 - Debian,
// Ubuntu, Alpine and RHEL. So the row reads the first bundle on that list,
// through the same guarded port every other probe reads through, and judges the
// chain with the verifier git and java share.
//
// SSL_CERT_FILE AND SSL_CERT_DIR ARE NOT FOLLOWED, decided by the owner
// 2026-10-15. They point a program AWAY from the platform store, L0 already
// reports both, and the openssl slice of M2 is where a row for the file they
// name belongs - this probe reads no environment at all.

// layout is where a platform keeps the store its programs read from disk.
type layout struct {
	// bundles are the candidates in the order they are asked, and the first one
	// that exists is the store.
	bundles []string
	// directories are read only when the bundle refused for want of a signer.
	directories probe.CADirectories
	// releases name the distribution, in precedence order.
	releases []string
}

// linuxLayout is Go's own list, so the row reads exactly what a Go program on
// the machine reads.
//
// ALL THREE LIVE IN PACKAGE probe, with their sources, because curl and git ask
// the same questions - the directories when a named file refuses (ADR110 part
// 1), the bundle and the distribution when they defer to this row (ADR110).
var linuxLayout = layout{
	bundles:     probe.LinuxBundles,
	directories: probe.LinuxCADirectories,
	releases:    probe.LinuxReleases,
}

// noBundle is the row on a machine with no bundle anywhere. Measured by S24:
// debian:trixie-slim and ubuntu:24.04 hold none, and Go's own pool there is
// empty - the ca-certificates package is the thing not installed, measured there on
// 2026-08-05 and 2026-09-23.
//
// IT IS UNDETERMINED RATHER THAN A REFUSAL, the same answer the shared verifier
// gives an empty store. A refusal would feed the count of stores that do not
// hold the signer, and every sentence built on that count is about who SIGNED
// the chain - here the fault is that nothing is installed to trust anybody.
const noBundle = "there is no CA bundle at any of the places Go and the common distributions keep one, so this " +
	"platform has no store to judge the chain with - on Debian and Ubuntu the ca-certificates package is what installs it"

// bundleProbe builds the probe that reads a platform store kept as files.
func bundleProbe(source file.Source, files file.List, l layout, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		store := report.TrustStore{
			Runtime:   report.RuntimeSystemStore,
			Instance:  probe.FallbackDistribution,
			StoreForm: report.StoreSystem,
			// NOTHING SELECTS A PLATFORM STORE, the same answer the Windows rows
			// give - SSL_CERT_FILE selects something ELSE, and is not followed.
			SelectedBy: []string{},
		}
		// The context is asked once, before anything is read - every read below
		// is a local file of a few hundred kilobytes.
		if err := ctx.Err(); err != nil {
			store.NotAssessed = fmt.Sprintf("this store was not asked: %v", err)
			return []report.TrustStore{store}, nil
		}
		if source == nil || files == nil {
			// A FORGOTTEN PORT IS OUR DEFECT AND IS SAID AS ONE, never read as a
			// machine with nothing installed.
			store.NotAssessed = "this program was built without a way to read files here, so the store was not read"
			return []report.TrustStore{store}, nil
		}
		store.Instance = probe.Distribution(source, l.releases)
		assess(&store, source, files, l, chain, now())
		return []report.TrustStore{store}, nil
	}
}

// assess fills in what the first bundle - and, when it refuses, the
// directories beside it - make of the chain.
func assess(store *report.TrustStore, source file.Source, files file.List, l layout, chain [][]byte, at time.Time) {
	path, bundle, err := probe.FirstBundle(source, l.bundles)
	if path == "" {
		store.NotAssessed = noBundle
		return
	}
	// THE PATH IS THE ONE ON GO'S LIST, NOT WHERE ITS LINKS LEAD. It is the name
	// a person and their tools use, and appending through a link appends to
	// whatever it leads to - measured on RHEL, where it is a link.
	store.StoreForm, store.StorePath = report.StoreFile, path
	if err != nil {
		// A BUNDLE THAT EXISTS AND CANNOT BE READ IS NOT SKIPPED - why is on
		// probe.FirstBundle.
		store.NotAssessed = fmt.Sprintf("the CA bundle at %s could not be read: %v", path, err)
		return
	}
	probe.Verify(store, bundle, chain, at)
	probe.WeighDirectories(store, source, files, l.directories, bundle, chain, at, directorySentences)
}

// The sentences a row carries when the directories stop a refusal from being
// proven - decided by the owner 2026-10-15.
const (
	directoryCloses = "the bundle does not close this chain and a certificate in %s does - programs that read that " +
		"directory trust it and programs that read only the bundle do not, so what this store makes of the chain " +
		"depends on the program asking"
	directoryUnreadable = "the bundle does not close this chain and %s could not be read in full (%v), so whether a " +
		"certificate there closes it is undetermined"
	directoryTooLarge = "the bundle does not close this chain and %s holds more than this program reads, so whether a " +
		"certificate there closes it is undetermined"
)

var directorySentences = probe.DirectorySentences{
	Closes: directoryCloses, Unreadable: directoryUnreadable, TooLarge: directoryTooLarge,
}
