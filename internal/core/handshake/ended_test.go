package handshake

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// libraryWords is what crypto/tls said on the bench with probe S30.
const libraryWords = "tls: failed to parse certificate from server: x509: negative serial number"

// shakeBy answers each address with what the table says about it, and with a
// completed handshake over a whole chain for any address it does not name.
func shakeBy(answers map[string]error) Shake {
	completed := shakeReturning(completeChain("aa"))
	return func(ctx context.Context, address string, port int, name string) (Presented, error) {
		if err, ok := answers[address]; ok {
			return Presented{}, err
		}
		return completed(ctx, address, port, name)
	}
}

// TestAHandshakeOurLibraryEndedIsNotBlamedOnTheServer is ADR129 in the layer,
// closing OBS211.
//
// Measured with probe S30 on 2026-11-09: a server whose chain carried a
// certificate with a negative serial number, every other client on the machine
// completing the handshake, and this layer saying FAIL - "none of the 1
// address(es) completed a TLS handshake" - which put the server at the top of
// the report with the exit code of a diagnosis.
func TestAHandshakeOurLibraryEndedIsNotBlamedOnTheServer(t *testing.T) {
	in := workingInput(shakeBy(map[string]error{
		"192.0.2.10": EndedHere{Words: libraryWords},
		"192.0.2.11": EndedHere{Words: "tls: the second address's words"},
	}))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	got := Ask(context.Background(), in)
	if got.Status != status.Unknown || got.Reason != status.ReasonUndetermined {
		t.Fatalf("handshakes our own library ended left the layer at %s/%s, want %s/%s",
			got.Status, got.Reason, status.Unknown, status.ReasonUndetermined)
	}
	for _, want := range []string{"own TLS library", "2 of 2", libraryWords, "cannot be told here"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("the layer's line does not say %q: %q", want, got.Detail)
		}
	}
	if strings.Contains(got.Detail, "second address") {
		t.Errorf("the layer's line quotes a later address rather than the first: %q", got.Detail)
	}
	rows := rowsOf(got)
	if len(rows) != 2 {
		t.Fatalf("%d rows for two addresses", len(rows))
	}
	if !strings.Contains(rows[0].NotCompleted, libraryWords) || !strings.Contains(rows[0].NotCompleted, "cannot be told here") {
		t.Errorf("the row does not say what our library said, or what that leaves open: %q", rows[0].NotCompleted)
	}
	if len(got.Presented) != 0 || got.Leaf != nil {
		t.Error("a handshake that never completed handed L5 something to judge")
	}
}

// TestOneAddressOurLibraryEndedBesideAServerThatRefused is the mixed walk: the
// layer cannot say every server refused while one of them was never heard.
func TestOneAddressOurLibraryEndedBesideAServerThatRefused(t *testing.T) {
	in := workingInput(shakeBy(map[string]error{
		"192.0.2.10": ErrRejected,
		"192.0.2.11": EndedHere{Words: libraryWords},
	}))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	got := Ask(context.Background(), in)
	if got.Status != status.Unknown || got.Reason != status.ReasonUndetermined {
		t.Errorf("one refusal beside one handshake our library ended left the layer at %s/%s", got.Status, got.Reason)
	}
	if !strings.Contains(got.Detail, "1 of 2") {
		t.Errorf("the layer's line does not count the address our library ended: %q", got.Detail)
	}
	if rows := rowsOf(got); len(rows) != 2 || !strings.Contains(rows[0].NotCompleted, "did not complete") {
		t.Errorf("the refusing server's own row lost what it said: %+v", rows)
	}
}

// TestAWalkThatFinishedNowhereKeepsItsOwnSentence: an address this layer never
// spoke to says more about this run than one our library ended, so ADR58's
// sentence stays first.
func TestAWalkThatFinishedNowhereKeepsItsOwnSentence(t *testing.T) {
	in := workingInput(shakeBy(map[string]error{
		"192.0.2.10": EndedHere{Words: libraryWords},
		"192.0.2.11": ErrRefusedByRule,
	}))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	got := Ask(context.Background(), in)
	if got.Status != status.Unknown || !strings.Contains(got.Detail, "did not finish trying") {
		t.Errorf("a walk our own rule cut short answered %s: %q", got.Status, got.Detail)
	}
}

// TestACompletedHandshakeStillGradesTheLayer: one address our library ended
// beside one that presented a whole chain is not a layer that knows nothing.
// The row says what happened, as a refusing server's row does.
func TestACompletedHandshakeStillGradesTheLayer(t *testing.T) {
	in := workingInput(shakeBy(map[string]error{"192.0.2.11": EndedHere{Words: libraryWords}}))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	got := Ask(context.Background(), in)
	if got.Status == status.Unknown {
		t.Errorf("a layer with a completed handshake over a whole chain answered %s/%s: %q", got.Status, got.Reason, got.Detail)
	}
	if rows := rowsOf(got); len(rows) != 2 || !strings.Contains(rows[1].NotCompleted, libraryWords) {
		t.Errorf("the address our library ended does not say so: %+v", rows)
	}
}
