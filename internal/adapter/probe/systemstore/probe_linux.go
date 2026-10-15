//go:build linux && !android

package systemstore

import (
	"context"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// platformProbe reads the distribution's bundle - ADR104. Everything it does is
// in bundle.go, which carries no build tag and is tested everywhere.
func platformProbe(source file.Source, files file.List, now func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return bundleProbe(source, files, linuxLayout, now)
}
