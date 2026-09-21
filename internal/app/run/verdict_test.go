package run

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// TestTheVerdictIsBuiltFromTheMaskedRowsAndNeverFromTheRawOnes.
//
// Until ADR99 the verdict was arithmetic and carried no word from anybody's
// machine, so masking left it alone and the comment above mask said so. Now
// the sentence at the top quotes the decisive layer - an issuer's name, a
// runtime, a proxy - and the ORDER of the two phases in Execute is what keeps
// a redacted report redacted: mask first, assemble second, so Assess only ever
// sees the words the report may show. This test goes through Execute and pins
// that order by measuring its effect, which is the only thing a reader of the
// report can measure.
func TestTheVerdictIsBuiltFromTheMaskedRowsAndNeverFromTheRawOnes(t *testing.T) {
	no := false
	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything, redact.Host("jdoe"))
	o.Layers[layer.TrustMatrix] = func(context.Context) Answer {
		return Answer{Status: status.Fail, Detail: "1 of 2 store(s) do not trust the presented chain",
			Findings: []report.Finding{
				{Kind: report.FindingSigningAuthority, Source: report.SourceDetected,
					Summary: "CN=jdoe corp CA signed this certificate and is an authority local to this machine - 1 store(s) here hold it and 1 do not",
					SigningAuthority: &report.SigningAuthority{Issuer: "CN=jdoe corp CA", LeafFingerprint: "aa:bb",
						HeldBy: report.HeldBySomeStores, TrustingStores: []string{"curl"}, RefusingStores: []string{"git"},
						Caveat: "a caveat, because the contract demands one"}},
				{Kind: report.FindingTrustStore, Source: report.SourceDetected, Summary: "git does NOT trust the presented chain",
					TrustStore: &report.TrustStore{Runtime: "git", Instance: `C:\Users\jdoe\git.exe`, StorePath: `C:\Users\jdoe\ca.crt`,
						StoreForm: report.StoreFile, TrustsPresentedChain: &no, TrustFailure: report.UnknownAuthority, SelectedBy: []string{}}},
			}}
	}

	got, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the run failed: %v", err)
	}

	// The raw rows WOULD put the name on the top line - otherwise this test
	// could pass over a sentence that never quoted anything.
	if raw := report.Assess([]report.LayerResult{{ID: layer.TrustMatrix, Status: status.Fail,
		Detail: "x", Findings: o.Layers[layer.TrustMatrix](context.Background()).Findings}}).Sentence; !strings.Contains(raw, "jdoe") {
		t.Fatalf("the unmasked verdict does not even carry the name, so this test measures nothing: %q", raw)
	}
	if strings.Contains(got.Verdict.Sentence, "jdoe") {
		t.Errorf("the account name reached the one line everybody reads: %q", got.Verdict.Sentence)
	}
	if !strings.Contains(got.Verdict.Sentence, "signed this certificate") || !strings.Contains(got.Verdict.Sentence, "Without it: git.") {
		t.Errorf("masking took more than the name - the cause itself is gone: %q", got.Verdict.Sentence)
	}
	// And the validator's own check - the sentence recomputed from the rows it
	// is printed over - must agree, which is what fires if the two phases are
	// ever swapped: a verdict built from raw rows over masked ones.
	if want := report.Assess(got.Layers).Sentence; want != got.Verdict.Sentence {
		t.Errorf("the verdict %q disagrees with the rows beneath it, which call for %q", got.Verdict.Sentence, want)
	}
}
