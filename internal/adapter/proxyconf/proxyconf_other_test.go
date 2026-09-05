//go:build !windows && !darwin

package proxyconf

import (
	"context"
	"testing"
)

// TestThisPlatformHasNoSystemStackAndSaysSoWithNoLensAtAll pins the difference
// between the three answers that look alike from a distance.
//
// A lens with Read false would say this program tried and was refused. A lens
// with Read true and no servers would say this machine has a system stack that
// names nothing. Neither is true here: there is no one place a Linux machine
// keeps proxy settings for every program, so there is nothing to be refused by
// and nothing to be empty. No lens at all leaves proxy.Compare with one stack,
// which answers that nothing was compared - which is what happened.
func TestThisPlatformHasNoSystemStackAndSaysSoWithNoLensAtAll(t *testing.T) {
	got := Read(context.Background(), nil)
	if got != nil {
		t.Errorf("Read gave %+v, and this platform has no system proxy stack to report", got)
	}
}
