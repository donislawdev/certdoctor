package java

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Probe builds the L5 probe for Java.
//
// candidates are installation directories to examine and are passed in rather
// than discovered here, because listing directories is not something the file
// port offers and a probe must not reach for the filesystem behind it.
// javaHome and pathDirs enrich the rows and NEVER select them - ADR48 part 4.
func Probe(source file.Source, run probe.Runner, candidates []string, javaHome string, pathDirs []string, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error) {
		installs := find(source, candidates)
		if len(installs) == 0 {
			// NOT AN ERROR - docs/20 rule 1. A machine without Java sits outside
			// the matrix, and "there is no Java here" is not a fact about trust.
			return nil, nil
		}

		stores := make([]report.TrustStore, 0, len(installs))
		for _, install := range installs {
			stores = append(stores, storeFor(ctx, run, install, chain, javaHome, pathDirs, now()))
		}
		return stores, nil
	}
}

// storeFor turns one installation into one row of the matrix.
func storeFor(ctx context.Context, run probe.Runner, install Install, chain [][]byte, javaHome string, pathDirs []string, now time.Time) report.TrustStore {
	store := report.TrustStore{
		Runtime:      "java",
		Instance:     install.Root,
		Variant:      install.Variant,
		Architecture: install.Architecture,
		StorePath:    install.Store,
		StoreForm:    report.StoreFile,
		SelectedBy:   selectedBy(install, javaHome, pathDirs),
	}

	anchors, err := anchorsOf(ctx, run, install)
	if err != nil {
		// A store that will not open is UNKNOWN with a reason. The commonest
		// cause is a changed store password, and calling that a trust failure
		// would send somebody to fix a store that is perfectly fine.
		store.NotAssessed = fmt.Sprintf("the trust store could not be read: %v", err)
		return store
	}
	probe.Verify(&store, anchors, chain, now)
	return store
}

// selectedBy names what points at THIS installation.
//
// JAVA_HOME NAMES ONE OF SIX ON THIS MACHINE - measured - which is exactly why
// it may enrich a row and may never find one. An install nothing selects is
// perfectly real: it is the one an application launches by absolute path while
// the console uses another.
func selectedBy(install Install, javaHome string, pathDirs []string) []string {
	var by []string
	root := filepath.Clean(install.Root)

	if javaHome != "" && filepath.Clean(javaHome) == root {
		by = append(by, "JAVA_HOME")
	}
	for _, dir := range pathDirs {
		cleaned := filepath.Clean(dir)
		// THE SAME SEGMENT RULE AS THE git PROBE, and for the same measured
		// reason: a neighbouring install whose name differs by one character
		// starts with this one's path as TEXT.
		if cleaned == root || strings.HasPrefix(cleaned, root+string(filepath.Separator)) {
			by = append(by, "PATH")
			break
		}
	}
	if by == nil {
		return []string{}
	}
	return by
}
