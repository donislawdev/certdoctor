package report

import (
	"strings"
	"testing"
)

// THE ONE EXCEPTION TO "A COMMAND NEEDS A FILE" - ADR103. The platform's own
// store is added to by its name, so its command names no file, and the rule that
// refuses a command on a platform store exists for the OTHER rows - a
// file-shaped command handed to Schannel is the measured trap that does
// nothing. These tests pin both halves: the exception holds, and it reaches no
// further than the runtime it was written for.

func aPlatformStoreWithACommand() TrustStore {
	store := aRefusingStore()
	store.Runtime = RuntimeSystemStore
	store.Instance = InstanceLocalMachine
	store.StoreForm = StoreSystem
	store.StorePath = ""
	store.Fix = aFix()
	return store
}

func TestThePlatformsOwnStoreMayCarryACommand(t *testing.T) {
	store := aPlatformStoreWithACommand()
	if got := store.breach(); got != "" {
		t.Errorf("the platform's own store was refused a command: %q", got)
	}
}

func TestTheExceptionReachesNoFurtherThanThePlatformsOwnRow(t *testing.T) {
	twin := aPlatformStoreWithACommand()
	if got := twin.breach(); got != "" {
		t.Fatalf("the positive twin was refused (%q), so every case below proves nothing", got)
	}
	cases := []struct {
		name  string
		spoil func(*TrustStore)
		says  string
	}{
		{
			// Schannel's curl reads this same store and still gets nothing: what it
			// would be handed is the measured trap.
			name:  "another runtime on the platform store",
			spoil: func(s *TrustStore) { s.Runtime = "curl" },
			says:  "not a file",
		},
		{
			name:  "the platform store with a path beside it",
			spoil: func(s *TrustStore) { s.StorePath = `C:\somewhere\store.crt` },
			says:  "has no path to name",
		},
		{
			// The runtime alone does not open the exception. A file-shaped row
			// under this runtime still needs its real path.
			name: "the platform runtime on a file row with no path",
			spoil: func(s *TrustStore) {
				s.StoreForm = StoreFile
				s.StorePath = ""
			},
			says: "no path",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := aPlatformStoreWithACommand()
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
