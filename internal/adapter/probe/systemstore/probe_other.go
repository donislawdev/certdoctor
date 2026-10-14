//go:build !windows

package systemstore

import (
	"context"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// platformProbe has nothing to offer here yet - ADR103.
func platformProbe(func() time.Time) func(context.Context, [][]byte) ([]report.TrustStore, error) {
	return nil
}
