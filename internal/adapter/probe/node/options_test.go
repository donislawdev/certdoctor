package node

import (
	"errors"
	"slices"
	"testing"
)

// TestSplitOptionsReadsNodeOptionsTheWayNodeDoes pins the tokenizer to
// ParseNodeOptionsEnvVar of v26.x and to what node v26.9.0 did with the same
// strings on 2026-10-20. A token this splits differently is a flag this probe
// hands over that Node would not have read, or the reverse.
func TestSplitOptionsReadsNodeOptionsTheWayNodeDoes(t *testing.T) {
	// Two letters outside ASCII, built from their code points so this file stays
	// ASCII - the tokenizer works on bytes and has to pass their UTF-8 through.
	e, u := string(rune(0xe9)), string(rune(0xfc))
	cases := []struct {
		name    string
		options string
		want    []string
	}{
		{"nothing", "", nil},
		{"one option", "--use-system-ca", []string{"--use-system-ca"}},
		{"runs of spaces", "  --a   --b ", []string{"--a", "--b"}},
		{"a quoted value with a space", `--require "./my path/file.js"`, []string{"--require", "./my path/file.js"}},
		{"quotes inside a word", `--use-sys"tem-ca"`, []string{"--use-system-ca"}},
		{"a tab does not separate", "--a\t--b", []string{"--a\t--b"}},
		{"a backslash outside a string is a byte", `--x\`, []string{`--x\`}},
		{"an escaped quote", `"a\"b"`, []string{`a"b`}},
		{"an escaped backslash", `"a\\b"`, []string{`a\b`}},
		{"an empty string is no argument", `"" --a`, []string{"--a"}},
		{"an empty string joins nothing apart", `a""b`, []string{"ab"}},
		{"UTF-8 passes whole", "--title=caf" + e + " \"" + u + "ber\"", []string{"--title=caf" + e, u + "ber"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := splitOptions(c.options)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("split %q into %q, want %q", c.options, got, c.want)
			}
		})
	}
}

// The two inputs on which Node does not start at all - measured with node
// v26.9.0: "invalid value for NODE_OPTIONS (unterminated string)", exit 9.
func TestSplitOptionsRefusesWhatNodeRefuses(t *testing.T) {
	cases := []struct {
		options string
		want    error
	}{
		{`--use-system-ca "unfinished`, errUnterminated},
		{`"--a\`, errEscapeAtTheEnd},
	}
	for _, c := range cases {
		if _, err := splitOptions(c.options); !errors.Is(err, c.want) {
			t.Errorf("%q gave %v, want %v", c.options, err, c.want)
		}
	}
}

// TestFlagsInKeepsWhatNodeKeeps: each row is a measurement with node v26.9.0 on
// 2026-10-20, through NODE_OPTIONS and on the command line alike.
func TestFlagsInKeepsWhatNodeKeeps(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want map[string]bool
	}{
		{"named", []string{"--use-system-ca"}, map[string]bool{flagSystem: true}},
		{"with underscores", []string{"--use_system_ca"}, map[string]bool{flagSystem: true}},
		{"the last mention wins", []string{"--use-system-ca", "--no-use-system-ca"}, map[string]bool{flagSystem: false}},
		{"a value is ignored", []string{"--no_use_system_ca", "--use-system-ca=false"}, map[string]bool{flagSystem: true}},
		{"a value after no- is ignored too", []string{"--no-use-system-ca=1"}, map[string]bool{flagSystem: false}},
		{"case matters", []string{"--USE-SYSTEM-CA"}, map[string]bool{}},
		{"one dash is not an option", []string{"-use-system-ca"}, map[string]bool{}},
		{"a longer name is another option", []string{"--use-system-ca-extra"}, map[string]bool{}},
		{"the other two", []string{"--use-openssl-ca", "--use-bundled-ca"},
			map[string]bool{flagOpenSSL: true, flagBundled: true}},
		{"everything else is left alone", []string{"--max-old-space-size=100", "foo", "--require", "./x.js"},
			map[string]bool{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := flagsIn(mentions(c.args))
			if len(got) != len(c.want) {
				t.Fatalf("read %v, want %v", got, c.want)
			}
			for flag, on := range c.want {
				if value, present := got[flag]; !present || value != on {
					t.Errorf("read %v, want %v", got, c.want)
				}
			}
		})
	}
}

// EVERY MENTION IS HANDED OVER, IN ITS ORDER, spelled as node's own argument -
// OBS190: the order decides which store node trusts. A flag turned off is
// handed over turned off, which is what keeps a NODE_USE_SYSTEM_CA=1
// overridden, and a flag nobody mentioned is not handed over at all.
func TestMentionsSpellEveryMentionInOrder(t *testing.T) {
	got := mentions([]string{"--use_system_ca=false", "--max-old-space-size=1", "--use-openssl-ca", "--USE-BUNDLED-CA",
		"--no-use-openssl-ca", "--no-use-system-ca"})
	if want := []string{"--use-system-ca", "--use-openssl-ca", "--no-use-openssl-ca", "--no-use-system-ca"}; !slices.Equal(got, want) {
		t.Errorf("handed over %q, want %q", got, want)
	}
	if got := mentions([]string{"--require", "./x.js"}); len(got) != 0 {
		t.Errorf("handed over %q for flags nobody mentioned", got)
	}
}

// THE STORE IS THE LAST OF THE TWO SWITCHES TURNED ON, and a --no- after it
// takes nothing back - OBS190, measured with node v26.9.0 on 2026-10-20 for the
// official build. built is the build's own default.
func TestOpenSSLStoreIsTheLastOfTheTwoSwitchesTurnedOn(t *testing.T) {
	cases := []struct {
		name  string
		said  []string
		built bool
		want  bool
	}{
		{"an official build left alone", nil, false, false},
		{"a distribution's build left alone", nil, true, true},
		{"the store asked for", []string{"--use-openssl-ca"}, false, true},
		{"the store asked for and turned off again", []string{"--use-openssl-ca", "--no-use-openssl-ca"}, false, true},
		{"turned off alone changes nothing", []string{"--no-use-openssl-ca"}, true, true},
		{"the list asked for on a distribution's build", []string{"--use-bundled-ca"}, true, false},
		{"the list asked for and turned off again", []string{"--use-bundled-ca", "--no-use-bundled-ca"}, true, false},
		{"the list after the store", []string{"--use-openssl-ca", "--use-bundled-ca"}, false, false},
		{"the store after the list", []string{"--use-bundled-ca", "--use-openssl-ca"}, true, true},
		{"the system list is neither", []string{"--use-system-ca"}, true, true},
	}
	for _, c := range cases {
		if got := openSSLStore(c.said, c.built); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// UNSET AND EMPTY ARE ONE ANSWER FOR WHAT NODE READS, and two for what OpenSSL
// reads - a variable set to nothing still replaces its default.
func TestEnvironmentFromReadsTheVariables(t *testing.T) {
	set := map[string]string{"NODE_OPTIONS": "--use-system-ca", "NODE_USE_SYSTEM_CA": "1",
		"NODE_EXTRA_CA_CERTS": "/extra.pem", "SSL_CERT_FILE": ""}
	env := EnvironmentFrom(func(name string) (string, bool) {
		value, ok := set[name]
		return value, ok
	}, "linux")
	want := Environment{Options: "--use-system-ca", UseSystemCA: "1", ExtraCACerts: "/extra.pem", CertFileSet: true,
		Platform: "linux"}
	if env != want {
		t.Errorf("read %+v, want %+v", env, want)
	}
}
