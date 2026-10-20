package report

import (
	"strings"
	"testing"
)

// The prohibitions of the trust store body, one case each.
//
// THE ONE THIS FILE EXISTS FOR IS THE THIRD STATE. "This store does not trust
// the chain" and "this store could not be read" send a person to two different
// places - the first to their administrator, the second to a file permission -
// and a body that lets them collapse into one boolean would make L5 lie in the
// most expensive direction available to it. Both halves are checked, because a
// rule enforced in one direction can be satisfied by a function that refuses
// everything.

func trusts(v bool) *bool { return &v }

// aReadableStore is the shape measured on the owner's machine 2026-08-18 - one
// of the six Java stores, with the path read off the machine rather than
// templated.
func aReadableStore() TrustStore {
	return TrustStore{
		Runtime:              "java",
		Instance:             "jdk-25",
		Variant:              "jdk",
		Architecture:         "x64",
		StorePath:            `C:\Program Files\OpenJDK\jdk-25\lib\security\cacerts`,
		StoreForm:            StoreFile,
		TrustAnchorCount:     158,
		TrustsPresentedChain: trusts(true),
		SelectedBy:           []string{"JAVA_HOME"},
	}
}

func TestAWellFormedTrustStoreIsAccepted(t *testing.T) {
	store := aReadableStore()
	if got := store.breach(); got != "" {
		t.Errorf("a well formed store was refused: %q", got)
	}
}

// A store nothing selects is ORDINARY, not broken. Five of the six Java stores
// measured on this machine are in exactly this position, and refusing them
// would drop most of the matrix.
func TestAStoreSelectedByNothingIsAccepted(t *testing.T) {
	store := aReadableStore()
	store.SelectedBy = []string{}
	if got := store.breach(); got != "" {
		t.Errorf("a store nothing selects was refused: %q", got)
	}
}

// The system store has no path to hand out, and that is the whole reason
// StoreForm exists rather than being inferred from an empty path.
func TestTheSystemStoreNeedsNoPath(t *testing.T) {
	store := aReadableStore()
	store.StoreForm = StoreSystem
	store.StorePath = ""
	if got := store.breach(); got != "" {
		t.Errorf("the system store was refused for having no path: %q", got)
	}
}

// A list compiled into the program has no path either, and the row is whole
// without one - ADR111 part 4.
func TestACompiledInListNeedsNoPath(t *testing.T) {
	store := aReadableStore()
	store.Runtime = "node"
	store.Instance = `C:\Program Files\nodejs\node.exe`
	store.Variant = ""
	store.Architecture = ""
	store.StoreForm = StoreBuiltin
	store.StorePath = ""
	store.SelectedBy = []string{"PATH", "NODE_EXTRA_CA_CERTS"}
	if got := store.breach(); got != "" {
		t.Errorf("a compiled-in list was refused for having no path: %q", got)
	}
}

// A runtime without variants leaves the field empty, and curl is one.
func TestARuntimeWithNoVariantIsAccepted(t *testing.T) {
	store := aReadableStore()
	store.Runtime = "curl"
	store.Instance = `C:\Windows\system32\curl.exe`
	store.Variant = ""
	store.Backend = "schannel"
	store.StoreForm = StoreSystem
	store.StorePath = ""
	if got := store.breach(); got != "" {
		t.Errorf("a runtime with no variant was refused: %q", got)
	}
}

// A store that could not be read carries a reason and NO verdict. This is the
// UNKNOWN of docs/20 - failing to open a keystore with the default password is
// never a fact about trust.
func TestAnUnreadableStoreCarriesAReasonAndNoVerdict(t *testing.T) {
	store := aReadableStore()
	store.TrustsPresentedChain = nil
	store.NotAssessed = "the keystore did not open with the default password"
	store.TrustAnchorCount = 0
	if got := store.breach(); got != "" {
		t.Errorf("an honestly unassessed store was refused: %q", got)
	}
}

// A store that does NOT trust the chain is a verdict, not a failure, and it is
// the answer the whole matrix exists to produce.
func TestDistrustIsAVerdictAndNotAFailure(t *testing.T) {
	store := aRefusingStore()
	if got := store.breach(); got != "" {
		t.Errorf("a store that distrusts the chain was refused: %q", got)
	}
}

// aRefusingStore is the same measured store, refusing the chain because it holds
// nothing that signed it - the one failure a remediation command addresses.
func aRefusingStore() TrustStore {
	store := aReadableStore()
	store.TrustsPresentedChain = trusts(false)
	store.TrustFailure = UnknownAuthority
	return store
}

// aFix is a well formed remediation for the store above, with the real path in
// it and the one thing this program cannot know left as a named placeholder.
func aFix() *Fix {
	return &Fix{
		Command: `keytool -importcert -trustcacerts -keystore "C:\Program Files\OpenJDK\jdk-25\lib\security\cacerts" ` +
			`-storepass changeit -alias <alias> -file <certificate.pem>`,
		Placeholders:      []string{"<alias>", "<certificate.pem>"},
		RequiresElevation: true,
		Elevation:         "this store is shared by every account on the machine",
	}
}

// THE POSITIVE TWIN, AND IT IS HERE BECAUSE OF OBS56. Every test below asserts
// that some malformed remediation is REFUSED, and a validator that refused every
// remediation would pass all of them. This one fails the moment the rule stops
// letting a correct fix through, which is the failure the other direction cannot
// see.
func TestARefusalMayCarryARemediation(t *testing.T) {
	store := aRefusingStore()
	store.Fix = aFix()
	if got := store.breach(); got != "" {
		t.Errorf("a well formed remediation on a refusing store was rejected: %q", got)
	}
}

// NODE'S COMPILED-IN LIST TAKES A COMMAND WITH NO PATH ON THE ROW - ADR111
// part 7 - and only Node's: the same row under another runtime is refused by
// the file rule, in the table further down.
func TestNodesCompiledInListMayCarryARemediation(t *testing.T) {
	store := aRefusingStore()
	store.Runtime = RuntimeNode
	store.Instance = `C:\Program Files\nodejs\node.exe`
	store.Variant = ""
	store.StoreForm = StoreBuiltin
	store.StorePath = ""
	store.Fix = &Fix{Command: `setx NODE_EXTRA_CA_CERTS "<certificate.pem>"`, Placeholders: []string{"<certificate.pem>"}}
	if got := store.breach(); got != "" {
		t.Errorf("a command for node's own list was rejected: %q", got)
	}
}

// A refusal for an unknown authority may say that the platform's list would
// close the chain - ADR111 part 7. The positive twin of the two cases in the
// table below, for the reason OBS56 gives.
func TestARefusalMaySayThePlatformListWouldCloseIt(t *testing.T) {
	store := aRefusingStore()
	store.PlatformListCloses = true
	if got := store.breach(); got != "" {
		t.Errorf("a refusal the platform's list would close was rejected: %q", got)
	}
}

// A command with nothing to fill in is legitimate and must not be mistaken for
// an incomplete one - the empty slice is the answer, the nil is the defect.
func TestARemediationWithNothingToFillInIsAccepted(t *testing.T) {
	store := aRefusingStore()
	store.Fix = &Fix{
		Command:      `git config --global http.sslBackend schannel`,
		Placeholders: []string{},
	}
	if got := store.breach(); got != "" {
		t.Errorf("a remediation that is ready to paste was rejected: %q", got)
	}
}

// The registry of trust failures, checked the same way every other closed list
// in this package is.
func TestEveryTrustFailureHasAMeaning(t *testing.T) {
	for _, failure := range []TrustFailure{UnknownAuthority, Expired, NotYetValid, OtherFailure, NoRevocationInfo} {
		if !failure.Valid() {
			t.Errorf("%q is declared and does not report itself valid", failure)
		}
		if failure.Meaning() == "" {
			t.Errorf("%q has no meaning, and a closed list nobody can explain is a list nobody can act on", failure)
		}
		if failure.String() != string(failure) {
			t.Errorf("%q does not print as itself", failure)
		}
	}
	if TrustFailure("unfixable").Valid() {
		t.Error("a failure outside the registry reported itself valid")
	}
}

func TestTheTrustStoreRefusesWhatItMustRefuse(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(*TrustStore)
		says  string
	}{
		{
			name:  "no runtime",
			spoil: func(s *TrustStore) { s.Runtime = "" },
			says:  "runtime",
		},
		{
			name:  "no instance",
			spoil: func(s *TrustStore) { s.Instance = "" },
			says:  "instance",
		},
		{
			name:  "a store form outside the registry",
			spoil: func(s *TrustStore) { s.StoreForm = StoreForm("registry") },
			says:  "outside the registry",
		},
		{
			name:  "a file store with no path",
			spoil: func(s *TrustStore) { s.StorePath = "" },
			says:  "path",
		},
		{
			// The path left over from the file store is the spoiling: Node's list
			// lives in the binary, and a path would name a file it never reads.
			name:  "a compiled-in list with a path",
			spoil: func(s *TrustStore) { s.StoreForm = StoreBuiltin },
			says:  "compiled into the program",
		},
		{
			name:  "a negative anchor count",
			spoil: func(s *TrustStore) { s.TrustAnchorCount = -1 },
			says:  "not a count",
		},
		{
			// nil is a statement about US - that nobody looked - wearing the
			// clothes of a statement about the machine.
			name:  "a nil selection list",
			spoil: func(s *TrustStore) { s.SelectedBy = nil },
			says:  "empty one is the answer",
		},
		{
			name: "no verdict and no reason",
			spoil: func(s *TrustStore) {
				s.TrustsPresentedChain = nil
				s.NotAssessed = ""
			},
			says: "silence about a failure is forbidden",
		},
		{
			name:  "a verdict and a reason at once",
			spoil: func(s *TrustStore) { s.NotAssessed = "the keystore did not open" },
			says:  "also says why it could not",
		},
		{
			name: "anchors counted in a store that was never read",
			spoil: func(s *TrustStore) {
				s.TrustsPresentedChain = nil
				s.NotAssessed = "the keystore did not open"
			},
			says: "still counts anchors",
		},
		{
			// A refusal with no reason is the same silence NotAssessed exists to
			// prevent, one field over - and it is the one that decides whether a
			// command can honestly be offered at all.
			name:  "a refusal that does not say which way",
			spoil: func(s *TrustStore) { s.TrustsPresentedChain = trusts(false) },
			says:  "in which way",
		},
		{
			name:  "a way of refusing named by a store that accepted",
			spoil: func(s *TrustStore) { s.TrustFailure = UnknownAuthority },
			says:  "did not refuse",
		},
		{
			name: "a trust failure outside the registry",
			spoil: func(s *TrustStore) {
				s.TrustsPresentedChain = trusts(false)
				s.TrustFailure = TrustFailure("gremlins")
			},
			says: "outside the registry",
		},
		{
			name:  "the platform's list closing a chain the store accepted",
			spoil: func(s *TrustStore) { s.PlatformListCloses = true },
			says:  "unknown authority",
		},
		{
			// More certificates do not move a clock, so a list cannot close this.
			name: "the platform's list closing an expired chain",
			spoil: func(s *TrustStore) {
				s.TrustsPresentedChain = trusts(false)
				s.TrustFailure = Expired
				s.PlatformListCloses = true
			},
			says: "unknown authority",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := aReadableStore()
			c.spoil(&store)
			got := store.breach()
			if got == "" {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(got, c.says) {
				t.Errorf("the refusal does not name what it defends: %q, wanted it to mention %q", got, c.says)
			}
		})
	}
}

// TestTheContractRefusesARemediationThatWouldWasteSomebodysTime is the half of
// this file that defends a person rather than a document.
//
// EVERY CASE HERE IS A COMMAND THAT LOOKS REASONABLE AND DOES NOTHING. That is
// the failure mode docs/20 calls the most expensive in the whole registry, and
// it was measured twice: CURL_CA_BUNDLE on a Schannel build, and - on the bench
// 2026-08-19 - a store fix offered for a chain the server had broken. A person
// who runs one of these waits for an effect that is never coming, and the tool
// looks like it answered.
func TestTheContractRefusesARemediationThatWouldWasteSomebodysTime(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(*TrustStore)
		says  string
	}{
		{
			name: "a command for a store that accepted the chain",
			spoil: func(s *TrustStore) {
				s.TrustsPresentedChain = trusts(true)
				s.TrustFailure = ""
			},
			says: "did not refuse",
		},
		{
			// Importing a certificate does not move a clock. This is the case the
			// three-way failure registry exists for.
			name:  "a command for a chain that expired",
			spoil: func(s *TrustStore) { s.TrustFailure = Expired },
			says:  "does not repair",
		},
		{
			name: "a command for the platform store",
			spoil: func(s *TrustStore) {
				s.StoreForm = StoreSystem
				s.StorePath = ""
			},
			says: "not a file",
		},
		{
			// ADR111 part 7 gives Node's list an exception of its own, and only
			// Node's - the same row under this store's runtime meets the file rule.
			name: "a command for a compiled-in list",
			spoil: func(s *TrustStore) {
				s.StoreForm = StoreBuiltin
				s.StorePath = ""
			},
			says: "not a file",
		},
		{
			name:  "a command with nothing in it",
			spoil: func(s *TrustStore) { s.Fix.Command = "" },
			says:  "no command",
		},
		{
			name:  "a command whose placeholder list was never filled in",
			spoil: func(s *TrustStore) { s.Fix.Placeholders = nil },
			says:  "empty one is the answer",
		},
		{
			name:  "elevation demanded without a reason",
			spoil: func(s *TrustStore) { s.Fix.Elevation = "" },
			says:  "does not say why",
		},
		{
			name: "a reason for elevation nobody needs",
			spoil: func(s *TrustStore) {
				s.Fix.RequiresElevation = false
			},
			says: "needs no elevated rights",
		},
		{
			// A list of things to replace that names something not in the command
			// is a list nobody can act on, and it reads as though the command were
			// less ready than it is.
			name:  "a placeholder that is not in the command",
			spoil: func(s *TrustStore) { s.Fix.Placeholders = []string{"<hostname>"} },
			says:  "does not appear in the command",
		},
		{
			name:  "an empty placeholder",
			spoil: func(s *TrustStore) { s.Fix.Placeholders = []string{""} },
			says:  "empty placeholder",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := aRefusingStore()
			store.Fix = aFix()
			c.spoil(&store)
			got := store.breach()
			if got == "" {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(got, c.says) {
				t.Errorf("the refusal does not name what it defends: %q, wanted it to mention %q", got, c.says)
			}
		})
	}
}

// aDeferringRow is curl on Schannel as the trust layer writes it once the
// platform's own row has answered - ADR108 part 4, measured with probe S25.
func aDeferringRow() TrustStore {
	return TrustStore{
		Runtime:              "curl",
		Instance:             `C:\Windows\system32\curl.exe`,
		StoreForm:            StoreSystem,
		Backend:              "schannel",
		DefersTo:             &StoreRef{Runtime: RuntimeSystemStore, Instance: InstanceCurrentUser},
		TrustAnchorCount:     91,
		TrustsPresentedChain: trusts(true),
		SelectedBy:           []string{"PATH"},
	}
}

// THE POSITIVE TWINS, for the reason TestARefusalMayCarryARemediation gives:
// every case in the table below is a refusal, and a contract refusing every
// deferring row would pass all of them.
func TestARowDeferringToThePlatformStoreIsAccepted(t *testing.T) {
	store := aDeferringRow()
	if got := store.breach(); got != "" {
		t.Errorf("a row deferring to the platform's own store was refused: %q", got)
	}
	store.TrustsPresentedChain = trusts(false)
	store.TrustFailure = NoRevocationInfo
	if got := store.breach(); got != "" {
		t.Errorf("a deferring row refusing for want of a revocation address was refused: %q", got)
	}
}

func TestADeferringRowRefusesWhatItMustRefuse(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(*TrustStore)
		says  string
	}{
		{
			name:  "a row deferring to another runtime",
			spoil: func(s *TrustStore) { s.DefersTo.Runtime = "java" },
			says:  "only the platform's own store",
		},
		{
			name:  "a row deferring to no instance",
			spoil: func(s *TrustStore) { s.DefersTo.Instance = "" },
			says:  "which instance",
		},
		{
			name:  "the platform's own row deferring to itself",
			spoil: func(s *TrustStore) { s.Runtime = RuntimeSystemStore },
			says:  "judges one store twice",
		},
		{
			name: "a deferring row naming a file of its own",
			spoil: func(s *TrustStore) {
				s.StoreForm = StoreFile
				s.StorePath = `C:\curl\curl-ca-bundle.crt`
			},
			says: "names a file of its own",
		},
		{
			// The platform row has no path, so a path beside a system form is the
			// half the form alone cannot catch.
			name:  "a deferring row with a path and a system form",
			spoil: func(s *TrustStore) { s.StorePath = `C:\curl\curl-ca-bundle.crt` },
			says:  "names a file of its own",
		},
		{
			// No store repairs a certificate that names nowhere to check it, so a
			// command beside this refusal would be one more command that does
			// nothing.
			name: "a command beside a refusal no store repairs",
			spoil: func(s *TrustStore) {
				s.TrustsPresentedChain = trusts(false)
				s.TrustFailure = NoRevocationInfo
				s.Fix = &Fix{Command: `certutil -user -addstore Root "<certificate.pem>"`, Placeholders: []string{"<certificate.pem>"}}
			},
			says: "does not repair",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := aDeferringRow()
			c.spoil(&store)
			got := store.breach()
			if got == "" {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(got, c.says) {
				t.Errorf("the refusal does not name what it defends: %q, wanted it to mention %q", got, c.says)
			}
		})
	}
}

// The registry of store forms, checked the same way every other closed list in
// this package is: a value outside it is a defect in our translation, not news.
func TestEveryStoreFormHasAMeaning(t *testing.T) {
	for _, form := range []StoreForm{StoreFile, StoreSystem, StoreBuiltin} {
		if !form.Valid() {
			t.Errorf("%q is declared and not in the registry", form)
		}
		if form.Meaning() == "" {
			t.Errorf("%q is in the registry with no meaning", form)
		}
		if form.String() != string(form) {
			t.Errorf("%q does not print as itself", form)
		}
	}
	if StoreForm("keychain").Valid() {
		t.Error("an undeclared store form was accepted")
	}
}

// The envelope has to route a trust store finding to the body that checks it.
// Without this the body above could be perfect and never consulted.
func TestAFindingRoutesToTheTrustStoreBody(t *testing.T) {
	store := aReadableStore()
	store.Runtime = ""

	f := Finding{
		Kind:       FindingTrustStore,
		Summary:    "one store",
		Source:     SourceDetected,
		TrustStore: &store,
	}
	got := f.Breach()
	if got == "" {
		t.Fatal("a finding carrying a broken trust store was accepted")
	}
	if !strings.Contains(got, "runtime") {
		t.Errorf("the finding did not report the body's own complaint: %q", got)
	}
}
