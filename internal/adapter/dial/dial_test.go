package dial

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/allowed"
)

// spy is an inner dialler that records what it was asked to reach and never
// touches a network. Nothing in this package's tests can open a socket, which
// is the property that makes them runnable anywhere.
type spy struct{ asked []string }

func (s *spy) dial(_ context.Context, address string) (io.ReadWriteCloser, error) {
	s.asked = append(s.asked, address)
	return nopCloser{}, nil
}

type nopCloser struct{}

func (nopCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopCloser) Close() error                { return nil }

func setWith(t *testing.T, targets ...string) *allowed.Targets {
	t.Helper()
	set := allowed.New()
	for _, target := range targets {
		if err := set.Allow(target, allowed.ReasonTarget); err != nil {
			t.Fatalf("building the set: %v", err)
		}
	}
	return set
}

// TestAPermittedAddressReachesTheInnerDialler is the ordinary path, and it has
// to be here so the test below means something: a guard that refused everything
// would satisfy every other test in this file.
func TestAPermittedAddressReachesTheInnerDialler(t *testing.T) {
	inner := &spy{}
	guarded := Guarded(inner.dial, setWith(t, "example.com:443"), nil)

	conn, err := guarded(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("a permitted address was refused: %v", err)
	}
	if conn == nil {
		t.Fatal("no connection came back for a permitted address")
	}
	if len(inner.asked) != 1 || inner.asked[0] != "example.com:443" {
		t.Errorf("the inner dialler was asked for %v", inner.asked)
	}
}

// TestAnAddressOutsideTheSetNeverReachesTheDialler is inviolable rule 16 at the
// only place it can be enforced.
//
// The assertion that matters is not the error - it is that the inner dialler
// was NOT CALLED. An implementation that connected first and complained
// afterwards would satisfy an error check and would already have phoned home.
func TestAnAddressOutsideTheSetNeverReachesTheDialler(t *testing.T) {
	inner := &spy{}
	guarded := Guarded(inner.dial, setWith(t, "example.com:443"), nil)

	conn, err := guarded(context.Background(), "telemetry.example.com:443")

	if len(inner.asked) != 0 {
		t.Fatalf("a refused address still reached the dialler: %v", inner.asked)
	}
	if conn != nil {
		t.Error("a connection came back for a refused address")
	}
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("the refusal is not distinguishable from an ordinary failure: %v", err)
	}
	if refusal.Address != "telemetry.example.com:443" {
		t.Errorf("the refusal names %q", refusal.Address)
	}
	if !strings.Contains(err.Error(), "derived") {
		t.Errorf("the refusal does not say why it refused: %v", err)
	}
}

// TestAMissingSetRefusesEverythingRatherThanPermittingIt is the direction a
// forgotten assignment has to fail in.
//
// A nil set standing for "no restrictions" would turn rule 16 into a rule that
// applies when somebody remembered to apply it - and it would fail silently,
// looking exactly like a working program.
func TestAMissingSetRefusesEverythingRatherThanPermittingIt(t *testing.T) {
	inner := &spy{}
	guarded := Guarded(inner.dial, nil, nil)

	if _, err := guarded(context.Background(), "example.com:443"); err == nil {
		t.Fatal("with no allowed set at all, a connection was permitted")
	}
	if len(inner.asked) != 0 {
		t.Errorf("the dialler was reached with no set in place: %v", inner.asked)
	}
}

// TestTheRecorderSeesRefusalsAndNotOnlySuccesses covers the half that would
// otherwise show a clean sheet in exactly the case worth seeing.
func TestTheRecorderSeesRefusalsAndNotOnlySuccesses(t *testing.T) {
	type attempt struct {
		address   string
		permitted bool
	}
	var seen []attempt
	guarded := Guarded((&spy{}).dial, setWith(t, "example.com:443"),
		func(address string, permitted bool) { seen = append(seen, attempt{address, permitted}) })

	_, _ = guarded(context.Background(), "example.com:443")
	_, _ = guarded(context.Background(), "telemetry.example.com:443")

	if len(seen) != 2 {
		t.Fatalf("the recorder saw %d attempts, want 2: %v", len(seen), seen)
	}
	if !seen[0].permitted {
		t.Error("the permitted attempt was recorded as refused")
	}
	if seen[1].permitted {
		t.Error("the refused attempt was recorded as permitted")
	}
	if seen[1].address != "telemetry.example.com:443" {
		t.Errorf("the refused attempt was recorded as %q", seen[1].address)
	}
}

// TestNoDiallerAtAllIsAnErrorRatherThanAPanic keeps a defect on our side from
// taking the process down. Everything else in this program degrades with a
// reason; this has to as well.
func TestNoDiallerAtAllIsAnErrorRatherThanAPanic(t *testing.T) {
	guarded := Guarded(nil, setWith(t, "example.com:443"), nil)

	conn, err := guarded(context.Background(), "example.com:443")
	if err == nil {
		t.Fatal("a missing dialler reported success")
	}
	if conn != nil {
		t.Error("a connection came back from a dialler that does not exist")
	}
	var refusal *Refusal
	if errors.As(err, &refusal) {
		t.Error("a defect on our side was reported as a refusal, which blames the set instead of us")
	}
}

// TestHostCaseDoesNotDecideWhetherAConnectionHappens is the divergence the set
// normalises away, checked through the guard rather than only inside the set -
// because this is where the two could disagree in practice.
func TestHostCaseDoesNotDecideWhetherAConnectionHappens(t *testing.T) {
	inner := &spy{}
	guarded := Guarded(inner.dial, setWith(t, "EXAMPLE.COM:443"), nil)

	if _, err := guarded(context.Background(), "example.com:443"); err != nil {
		t.Fatalf("the same host in another case was refused: %v", err)
	}
	if len(inner.asked) != 1 {
		t.Error("the connection did not happen")
	}
	// AND THE ADDRESS HANDED ON IS THE ONE ASKED FOR, not the normalised one.
	// The set exists to answer yes or no; rewriting what the caller reaches
	// would make the guard decide the destination, which is a different job.
	if inner.asked[0] != "example.com:443" {
		t.Errorf("the guard handed on %q instead of what it was asked for", inner.asked[0])
	}
}
