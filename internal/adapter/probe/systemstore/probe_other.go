//go:build !windows && (!linux || android)

package systemstore

import (
	"context"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// platformProbe has nothing to offer here yet - ADR103, ADR104. Android builds
// carry the linux constraint too, and Go adds two directories of its own there,
// so they stay here rather than inherit a list written for distributions.
func platformProbe(file.Source, file.List, func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return nil
}
