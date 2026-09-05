package proxy

import "testing"

// readable builds a lens that was read and names the given proxy list.
func readable(s Stack, list string) Lens {
	return Lens{Stack: s, Source: "test", Read: true, Servers: ParseServerList(list)}
}

// unreadable builds a lens that could not be read, with the reason a real one
// would carry.
func unreadable(s Stack) Lens {
	return Lens{Stack: s, Source: "test", Detail: "the test says this one could not be read"}
}

func TestTheStackListIsClosedAtFour(t *testing.T) {
	if len(AllStacks) != 4 {
		t.Fatalf("AllStacks has %d entries and the vocabulary is four", len(AllStacks))
	}
	seen := map[Stack]bool{}
	for _, s := range AllStacks {
		if seen[s] {
			t.Errorf("AllStacks lists %q twice", s)
		}
		seen[s] = true
		if !s.Valid() || s.Meaning() == "" || s.String() != string(s) {
			t.Errorf("stack %q is incompletely declared", s)
		}
	}
	if Stack("registry").Valid() || Stack("registry").Meaning() != "" {
		t.Error("a stack outside the list was accepted")
	}
}

func TestTheDivergenceListIsClosedAtFive(t *testing.T) {
	if len(AllDivergences) != 5 {
		t.Fatalf("AllDivergences has %d entries and the vocabulary is five", len(AllDivergences))
	}
	seen := map[Divergence]bool{}
	for _, d := range AllDivergences {
		if seen[d] {
			t.Errorf("AllDivergences lists %q twice", d)
		}
		seen[d] = true
		if !d.Valid() || d.Meaning() == "" || d.String() != string(d) {
			t.Errorf("divergence %q is incompletely declared", d)
		}
	}
	if Divergence("overlap").Valid() || Divergence("overlap").Meaning() != "" {
		t.Error("a divergence outside the list was accepted")
	}
}

// TestTheMeasuredWindowsDisagreementIsOneSided is the measurement turned into a
// test. On 2026-09-05, with a proxy in the current user's Internet Settings, the
// IE view returned it and the machine default WinHTTP view still said no proxy.
// If this row ever stops being one_sided, the reason L2 exists has gone with it.
func TestTheMeasuredWindowsDisagreementIsOneSided(t *testing.T) {
	lenses := []Lens{
		readable(StackWinINET, "127.0.0.1:65535"),
		readable(StackWinHTTP, ""),
	}
	got, classified := Compare(lenses)
	if !classified {
		t.Fatal("two readable stacks produced no class")
	}
	if got != DivergeOneSided {
		t.Errorf("the measured Windows disagreement classified as %q, want %q", got, DivergeOneSided)
	}
}

func TestCompareSaysHowStacksDiffer(t *testing.T) {
	cases := []struct {
		name       string
		lenses     []Lens
		want       Divergence
		classified bool
	}{
		{
			name:       "nobody configured anything",
			lenses:     []Lens{readable(StackEnvironment, ""), readable(StackWinINET, "")},
			want:       DivergeAgreeDirect,
			classified: true,
		},
		{
			name:       "the same proxy everywhere",
			lenses:     []Lens{readable(StackEnvironment, "p.corp:8080"), readable(StackWinINET, "p.corp:8080")},
			want:       DivergeAgree,
			classified: true,
		},
		{
			name:       "the same proxies in a different order",
			lenses:     []Lens{readable(StackWinINET, "http=a;https=b"), readable(StackWinHTTP, "https=b;http=a")},
			want:       DivergeAgree,
			classified: true,
		},
		{
			name:       "different proxies",
			lenses:     []Lens{readable(StackWinINET, "a.corp:8080"), readable(StackWinHTTP, "b.corp:8080")},
			want:       DivergeConflicting,
			classified: true,
		},
		{
			name:       "one names a proxy and one does not",
			lenses:     []Lens{readable(StackEnvironment, ""), readable(StackWinINET, "p.corp:8080")},
			want:       DivergeOneSided,
			classified: true,
		},
		{
			name:       "three stacks, one silent",
			lenses:     []Lens{readable(StackEnvironment, "p:1"), readable(StackWinINET, "p:1"), readable(StackWinHTTP, "")},
			want:       DivergeOneSided,
			classified: true,
		},
		{
			name:       "only one stack could be read",
			lenses:     []Lens{readable(StackEnvironment, "p.corp:8080"), unreadable(StackWinINET)},
			want:       DivergeUnreadable,
			classified: false,
		},
		{
			name:       "one stack on this platform",
			lenses:     []Lens{readable(StackEnvironment, "p.corp:8080")},
			want:       DivergeUnreadable,
			classified: false,
		},
		{
			name:       "nothing at all",
			lenses:     nil,
			want:       DivergeUnreadable,
			classified: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, classified := Compare(c.lenses)
			if got != c.want || classified != c.classified {
				t.Errorf("got %q (classified %v), want %q (classified %v)", got, classified, c.want, c.classified)
			}
		})
	}
}

// TestAStackThatCouldNotBeReadIsNotASilentOne is inviolable rule 15 read from
// the other end. Counting an unreadable stack as "names no proxy" would
// manufacture a one_sided finding out of our own failure to look, and the person
// reading the report would go hunting for a disagreement that is not there.
func TestAStackThatCouldNotBeReadIsNotASilentOne(t *testing.T) {
	lenses := []Lens{
		readable(StackEnvironment, "p.corp:8080"),
		readable(StackWinINET, "p.corp:8080"),
		unreadable(StackWinHTTP),
	}
	got, classified := Compare(lenses)
	if !classified {
		t.Fatal("two readable stacks produced no class")
	}
	if got == DivergeOneSided {
		t.Error("an unreadable stack was counted as one that names no proxy")
	}
	if got != DivergeAgree {
		t.Errorf("got %q, want %q - the two readable stacks name the same proxy", got, DivergeAgree)
	}
}

// TestAPACURLAloneIsNotAProxy keeps a stack that holds only an autoconfig
// address out of the "names a proxy" count. It has named a script that MIGHT
// name one, and this program does not fetch it until P8-K3 - counting it would
// make two stacks look as though they agreed when one has not answered.
func TestAPACURLAloneIsNotAProxy(t *testing.T) {
	withPAC := Lens{Stack: StackWinINET, Source: "test", Read: true, Servers: []Server{}, PACURL: "http://wpad.corp/proxy.pac"}
	if withPAC.NamesAProxy() {
		t.Error("a lens holding only a PAC address was counted as naming a proxy")
	}
	got, classified := Compare([]Lens{withPAC, readable(StackWinHTTP, "")})
	if !classified || got != DivergeAgreeDirect {
		t.Errorf("got %q (classified %v), want %q", got, classified, DivergeAgreeDirect)
	}
}

// TestTheZeroLensWasNeverAsked pins the safe direction. A forgotten assignment
// has to report "not read" rather than "no proxy configured", because those two
// are the pair this type exists to keep apart.
func TestTheZeroLensWasNeverAsked(t *testing.T) {
	var l Lens
	if l.Read {
		t.Error("the zero lens claims it was read")
	}
	if l.NamesAProxy() {
		t.Error("the zero lens claims it names a proxy")
	}
	if l.Servers != nil {
		t.Error("the zero lens has a non-nil server list, so nil no longer means nobody looked")
	}
	if l.BypassSet {
		t.Error("the zero lens claims it held an exception list")
	}
	if l.AutoDetect != Unasked {
		t.Errorf("the zero lens answers auto-detect as %q", l.AutoDetect)
	}
}

func TestATristateSaysWhichOfTheTwoNegativesItMeans(t *testing.T) {
	if Unasked.String() == Off.String() {
		t.Error("an unasked question and a setting that is off print the same, and they are different facts")
	}
	if On.String() != "on" || Off.String() != "off" {
		t.Errorf("on printed %q and off printed %q", On.String(), Off.String())
	}
	if Tristate(9).String() != Unasked.String() {
		t.Error("a value outside the three does not fall back to the safe reading")
	}
}
