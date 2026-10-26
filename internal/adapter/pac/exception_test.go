package pac

import (
	"context"
	"strings"
	"testing"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// TestAScriptsErrorNamesTheScriptsOwnPositionAndNeverOurs closes OBS136.
//
// Two shapes of error, two things each must and must not say. A helper of OURS
// refusing a shape it cannot read used to put the Go symbol path of this
// package on the terminal and into --json, and to drop the one coordinate the
// reader could act on - where in THEIR file the call stands. A script's own
// throw keeps the frame goja gives it, minus the program counter.
func TestAScriptsErrorNamesTheScriptsOwnPositionAndNeverOurs(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wants     []string
		forbidden []string
	}{
		{
			name: "our helper refuses a shape: the message names the helper, the script's function and its position",
			body: ` return weekdayRange(7) ? "PROXY p.test:1" : "DIRECT"; `,
			wants: []string{
				"TypeError: certdoctor does not understand this form of weekdayRange and will not guess an answer",
				"at " + Entry + " (<eval>:1:",
			},
			forbidden: []string{"github.com", "internal/adapter", "(native)", "func1"},
		},
		{
			name:      "the script throws: its own words and its own position, nothing of ours",
			body:      ` throw new Error("no proxy for you"); `,
			wants:     []string{"Error: no proxy for you", "at " + Entry + " (<eval>:1:"},
			forbidden: []string{"github.com", "(native)"},
		},
		{
			name:      "the script dereferences nothing: goja's own message, at the script's position",
			body:      ` var x; return x.y; `,
			wants:     []string{"TypeError: Cannot read property 'y' of undefined", "at " + Entry + " (<eval>:1:"},
			forbidden: []string{"github.com", "(native)"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := answer(t, c.body)
			if result.Outcome != corepac.OutcomeMalformed {
				t.Fatalf("outcome %s, want malformed: %s", result.Outcome, result.Detail)
			}
			for _, want := range c.wants {
				if !strings.Contains(result.Detail, want) {
					t.Errorf("the detail %q does not say %q", result.Detail, want)
				}
			}
			for _, bad := range c.forbidden {
				if strings.Contains(result.Detail, bad) {
					t.Errorf("the detail %q says %q, which is not the reader's business", result.Detail, bad)
				}
			}
			// goja appends "(3)" - a program counter - after the position; that
			// number means nothing to anybody outside the engine.
			if strings.Contains(result.Detail, ")(") || strings.HasSuffix(strings.TrimSpace(result.Detail), "))") {
				t.Errorf("the detail %q still carries goja's program counter", result.Detail)
			}
		})
	}
}

// TestASyntaxErrorKeepsItsOwnText: a file that does not parse is refused at
// load time by a different error type, which names line and column itself and
// never a frame - describe leaves it alone.
func TestASyntaxErrorKeepsItsOwnText(t *testing.T) {
	result := testSandbox().Evaluate(context.Background(), "function "+Entry+"(url, host) { return ; ; ; ]", "http://a.test/", "a.test")
	if result.Outcome != corepac.OutcomeMalformed {
		t.Fatalf("outcome %s, want malformed: %s", result.Outcome, result.Detail)
	}
	if !strings.HasPrefix(result.Detail, "the PAC file could not be loaded: SyntaxError") {
		t.Errorf("a syntax error lost its own text: %q", result.Detail)
	}
	if strings.Contains(result.Detail, "github.com") {
		t.Errorf("a syntax error names this program's packages: %q", result.Detail)
	}
}
