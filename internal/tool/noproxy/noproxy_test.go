package noproxy

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

func ask(t *testing.T, list, address string) (spec.Outcome, Data) {
	t.Helper()
	out, err := Ask([]byte(list), []byte(address))
	if err != nil {
		t.Fatalf("Ask(%q, %q): %v", list, address, err)
	}
	return out, out.Data.(Data)
}

// TestEveryReadingIsAskedInItsOrder holds the tool to the readings it asks: one
// answer per reading of NO_PROXY, in their order, each the very answer
// proxy.Decide gives - so the tool can only say what L2's readings say.
func TestEveryReadingIsAskedInItsOrder(t *testing.T) {
	for _, c := range []struct{ list, address string }{
		{".example.com", "example.com"},
		{"*", "https://a.example.com:8443/x"},
		{"10.0.0.0/8,localhost", "http://10.1.2.3"},
		{"", "localhost"},
		{"example.com:8080", "http://example.com:8080"},
	} {
		_, d := ask(t, c.list, c.address)
		a, _, err := readAddress([]byte(c.address))
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Readings) != len(proxy.NoProxyRules) {
			t.Fatalf("%q: %d readings, and there are %d", c.list, len(d.Readings), len(proxy.NoProxyRules))
		}
		for i, r := range proxy.NoProxyRules {
			want, _ := proxy.Decide(r, c.list, a.target)
			got := d.Readings[i]
			if got.Program != r.ProgramKey() || got.Name != r.Program() || got.Versions != r.Versions() ||
				got.Direct != want.Direct || got.Basis != string(want.Basis) || deref(got.Entry) != want.Entry ||
				deref(got.Condition) != r.Condition() {
				t.Errorf("%q for %q, reading %d (%s): %+v, and the reading says %+v", c.list, c.address, i, r,
					got, want)
			}
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TestTheProgramKeysAreTheContract pins the keys a script reads. A key that
// changes breaks somebody's script without a word, so this list changes only
// by a decision (ADR147).
func TestTheProgramKeysAreTheContract(t *testing.T) {
	_, d := ask(t, "", "example.com")
	var keys []string
	for _, r := range d.Readings {
		if !slices.Contains(keys, r.Program) {
			keys = append(keys, r.Program)
		}
	}
	want := []string{"curl", "dotnet", "go", "python", "requests", "node_http", "node_fetch"}
	if !slices.Equal(keys, want) {
		t.Errorf("the program keys are %v, and the contract is %v", keys, want)
	}
}

// TestTheDataMarshalsAsTheContractSays checks the names and the nulls a script
// reads, on the document the command line writes.
func TestTheDataMarshalsAsTheContractSays(t *testing.T) {
	out, _ := ask(t, ".corp.example", "https://API.corp.example:8443/path")
	raw, err := json.Marshal(out.Data)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		`"address":{"scheme":"https","host":"API.corp.example","port":8443}`,
		`{"program":"curl","name":"curl and git","versions":"8.23.0","condition":null,"direct":true,` +
			`"entry":".corp.example","basis":"entry"}`,
		`"program":"node_fetch","name":"Node.js fetch","versions":"26.11 and later",` +
			`"condition":"NODE_USE_ENV_PROXY=1"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the data does not carry %s:\n%s", want, text)
		}
	}
	_, none := ask(t, "", "example.com")
	raw, _ = json.Marshal(none)
	if !strings.Contains(string(raw), `"port":null`) || !strings.Contains(string(raw), `"entry":null,"basis":"no_entry"`) {
		t.Errorf("an address without a port, or an answer without an entry, is not null:\n%s", raw)
	}
}

// TestTheAgreementSaysWhoGoesWhere covers the one judgement: one answer from
// every program passes whichever it is, and a split names how many programs
// went each way - counting a program whose releases disagree once, apart.
func TestTheAgreementSaysWhoGoesWhere(t *testing.T) {
	for _, c := range []struct {
		name, list, address string
		status              status.Status
		says                string
	}{
		{"all direct", ".corp.example", "api.corp.example", status.Pass,
			"Every program that reads NO_PROXY goes to api.corp.example directly, without the proxy."},
		{"all through", "other.example", "api.corp.example", status.Pass,
			"Every program that reads NO_PROXY goes to api.corp.example through the proxy."},
		// Go never sends localhost to a proxy, whatever the list says.
		{"one apart", "", "localhost", status.Warn,
			"The programs disagree about localhost: 1 of the 7 goes to it directly and 6 through the proxy."},
		// A leading dot reaches the domain itself in curl, .NET, Python,
		// requests and Node.js http, never in Go, and in fetch only from
		// 24.14.1.
		{"by release", ".example.com", "example.com", status.Warn,
			"The programs disagree about example.com: 5 of the 7 go to it directly, 1 through the proxy and " +
				"for 1 it depends on the release."},
		{"in brackets", "", "[::1]", status.Warn, "The programs disagree about [::1]: 1 of the 7 goes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, _ := ask(t, c.list, c.address)
			if len(out.Checks) != 1 || out.Checks[0].ID != "agreement" {
				t.Fatalf("checks %+v, want the one agreement check", out.Checks)
			}
			got := out.Checks[0]
			if got.Status != c.status || !strings.HasPrefix(got.Summary, c.says) {
				t.Errorf("%s %q, want %s %q", got.Status, got.Summary, c.status, c.says)
			}
		})
	}
}

// TestAProgramSplitByItsReleasesIsCountedOnce builds answers no list gives
// today - every program but one silent, and that one's releases split - so the
// sentence for a split with nothing else in it is held too, and a program is
// counted once however many readings it has.
func TestAProgramSplitByItsReleasesIsCountedOnce(t *testing.T) {
	a := asked{address: address{target: proxy.Target{Host: "example.com"}}, answers: []answer{
		{rule: proxy.RuleNoProxyNodeFetch, decision: proxy.Decision{Direct: true, Basis: proxy.BasisEntry}},
		{rule: proxy.RuleNoProxyNodeFetchApex, decision: proxy.Decision{Basis: proxy.BasisNoEntry}},
		{rule: proxy.RuleNoProxyNodeFetchWildcard, decision: proxy.Decision{Basis: proxy.BasisNoEntry}},
	}}
	got := a.agreement()
	if got.Status != status.Warn || got.Summary != "The programs disagree about example.com: for 1 of the 1 "+
		"it depends on the release." {
		t.Errorf("%s %q", got.Status, got.Summary)
	}
}

// TestTheViewGroupsTheProgramsByTheirAnswer holds the page to the two groups,
// each row a program with its releases beside it, and the two paragraphs the
// answers need.
func TestTheViewGroupsTheProgramsByTheirAnswer(t *testing.T) {
	out, _ := ask(t, ".example.com", "example.com")
	var titles []string
	rows := map[string][]spec.Field{}
	for _, b := range out.View {
		titles = append(titles, b.Title)
		rows[b.Title] = b.Fields
	}
	want := []string{"Address", "Directly, without the proxy", "Through the proxy", "When this applies", "Java"}
	if !slices.Equal(titles, want) {
		t.Fatalf("blocks %v, want %v", titles, want)
	}
	if n := len(rows["Directly, without the proxy"]) + len(rows["Through the proxy"]); n != len(proxy.NoProxyRules) {
		t.Errorf("the two groups hold %d rows, and there are %d readings", n, len(proxy.NoProxyRules))
	}
	goRow := rows["Through the proxy"][0]
	if goRow.Label != "Go" || goRow.Value != "no entry applies" || goRow.Note != "1.27" {
		t.Errorf("the first row through the proxy is %+v, want Go's", goRow)
	}
	first := rows["Directly, without the proxy"][0]
	if first.Label != "curl and git" || first.Value != `entry ".example.com"` {
		t.Errorf("the first row going directly is %+v", first)
	}
	for _, f := range append(rows["Directly, without the proxy"], rows["Through the proxy"]...) {
		node := strings.HasPrefix(f.Label, "Node.js")
		if node != strings.HasSuffix(f.Note, ", only with NODE_USE_ENV_PROXY=1") {
			t.Errorf("the row %+v says the condition %v, and Node.js alone has it", f, !node)
		}
	}

	out, _ = ask(t, ".example.com", "a.example.com")
	for _, b := range out.View {
		if b.Title == "Through the proxy" {
			t.Errorf("a group nobody is in is shown: %+v", b)
		}
	}
}

// TestTheAddressBlockSaysWhatWasRead covers the port a program fills in when
// the address names none, and the reason each of the other answers rests on.
func TestTheAddressBlockSaysWhatWasRead(t *testing.T) {
	for _, c := range []struct {
		address, port, note string
	}{
		{"example.com", "443", "the https default - the address names none"},
		{"http://example.com", "80", "the http default - the address names none"},
		{"http://example.com:8080", "8080", ""},
	} {
		out, _ := ask(t, "", c.address)
		port := out.View[0].Fields[2]
		if port.Label != "Port" || port.Value != c.port || port.Note != c.note {
			t.Errorf("%q: the port row is %+v, want %s and %q", c.address, port, c.port, c.note)
		}
	}
	for _, c := range []struct{ list, address, value string }{
		{"*", "example.com", "the whole list is *"},
		{"", "localhost", "localhost is never proxied"},
		{"", "127.0.0.1", "a loopback address is never proxied"},
	} {
		out, _ := ask(t, c.list, c.address)
		if got := out.View[1].Fields[0].Value; !slices.ContainsFunc(out.View[1].Fields, func(f spec.Field) bool {
			return f.Value == c.value
		}) {
			t.Errorf("%q for %q: no row going directly says %q (the first says %q)", c.list, c.address, c.value, got)
		}
	}
}

// TestWhatIsTakenOffIsSaid holds the tool to changing nothing without a note.
func TestWhatIsTakenOffIsSaid(t *testing.T) {
	for _, c := range []struct {
		list, address string
		notes         []string
	}{
		{"NO_PROXY=.corp", "https://example.com", []string{`Took off "NO_PROXY=" in front of the list.`}},
		{"no_proxy=.corp\r\n", "https://example.com\n", []string{`Took off "no_proxy=" in front of the list.`}},
		{".corp", "example.com", []string{"The address names no scheme, so it is read as an https:// address."}},
		{".corp", "https://example.com/a?b#c", []string{"Only the scheme, host and port of the address are read"}},
		{".corp", "https://example.com/a", []string{"Only the scheme, host and port"}},
		// A slash alone is how an address is copied, and sets nothing aside.
		{".corp", "https://example.com/", nil},
		{".corp", "  https://example.com  ", nil},
	} {
		out, _ := ask(t, c.list, c.address)
		if len(out.Notes) != len(c.notes) {
			t.Errorf("%q, %q: notes %q, want %q", c.list, c.address, out.Notes, c.notes)
			continue
		}
		for i := range c.notes {
			if !strings.HasPrefix(out.Notes[i], c.notes[i]) {
				t.Errorf("%q, %q: note %q, want %q", c.list, c.address, out.Notes[i], c.notes[i])
			}
		}
	}
	_, d := ask(t, "no_proxy=*", "example.com")
	if d.Readings[0].Basis != "whole_value" {
		t.Errorf("the list after its name is not what was asked: curl read %+v", d.Readings[0])
	}
	// One line ending is the end of the line. A second is a line of its own.
	if _, d := ask(t, "*\n", "example.com"); d.Readings[0].Basis != "whole_value" {
		t.Errorf("a list with its line ending was not read as the line: %+v", d.Readings[0])
	}
}

// TestTheAddressIsReadInEveryShapeItArrives covers the forms an address takes
// and what each is read as.
func TestTheAddressIsReadInEveryShapeItArrives(t *testing.T) {
	for _, c := range []struct {
		address string
		want    Address
	}{
		{"example.com", Address{"https", "example.com", nil}},
		{"example.com:8080", Address{"https", "example.com", port(8080)}},
		{"HTTP://Example.COM:80/x", Address{"http", "Example.COM", port(80)}},
		{"https://[2001:db8::1]:8443/", Address{"https", "2001:db8::1", port(8443)}},
		{"[::1]", Address{"https", "::1", nil}},
		{"[2001:DB8::1]", Address{"https", "2001:DB8::1", nil}},
		{"10.0.0.1", Address{"https", "10.0.0.1", nil}},
		{"localhost.", Address{"https", "localhost.", nil}},
		{"my_host.corp", Address{"https", "my_host.corp", nil}},
		{"https://example.com:65535", Address{"https", "example.com", port(65535)}},
		{"https://example.com?q=1", Address{"https", "example.com", nil}},
	} {
		_, d := ask(t, "", c.address)
		got, _ := json.Marshal(d.Address)
		want, _ := json.Marshal(c.want)
		if string(got) != string(want) {
			t.Errorf("%q is read as %s, want %s", c.address, got, want)
		}
	}
}

func port(n int) *int { return &n }

// TestWhatTheProgramsReadDifferentlyIsRefused holds every refusal to its
// reason and to never quoting the input: the marker in each address and list
// may not come back in the reason.
func TestWhatTheProgramsReadDifferentlyIsRefused(t *testing.T) {
	for _, c := range []struct {
		name, list, address, says string
	}{
		{"a line break in the list", "a.marker\nb", "example.com", "breaks onto a new line at character 9"},
		{"a CR in the list", "a.marker\rb", "example.com", "new line at character 9"},
		{"a name outside ASCII", "b\u00fccher.marker", "example.com", "outside ASCII at character 2"},
		{"a control character", "a.marker\x01", "example.com", "control character at character 9"},
		{"DEL", "a.marker\x7f", "example.com", "control character at character 9"},
		{"an empty address", "", "  \r\n", "the address is empty"},
		{"an address outside ASCII", "", "b\u00fccher.marker", "the address has a character outside ASCII at character 2"},
		{"a space inside", "", "https://a marker", "space or a control character at character 10"},
		{"another scheme", "", "ftp://marker.example", "other than http:// and https://"},
		{"a user name", "", "https://user:marker@example.com", "user name before @"},
		{"an unclosed bracket", "", "https://[::1:marker", "does not close it"},
		{"after the bracket", "", "https://[::1]marker", "something other than a port after the ]"},
		{"not IPv6 in brackets", "", "https://[marker]", "not an IPv6 address"},
		{"IPv4 in brackets", "", "[10.0.0.1]", "not an IPv6 address"},
		{"a zone", "", "https://[fe80::1%25marker]", "IPv6 zone"},
		{"mapped IPv4", "", "[::ffff:10.0.0.1]", "IPv4 address written as IPv6"},
		{"a long IPv6", "", "[0:0:0:0:0:0:0:1]", "long form. The programs shorten it"},
		{"bare IPv6", "", "2001:db8::1", "more than one colon"},
		{"no host", "", "https://:8080", "names no host"},
		{"no host at all", "", "https://", "names no host"},
		{"a colon and no port", "", "example.com:", "colon and no port"},
		{"a port of letters", "", "example.com:http", "port that is not a number"},
		{"a leading zero", "", "example.com:0443", "leading zero"},
		{"port zero", "", "example.com:0", "outside 1 to 65535"},
		{"port too high", "", "example.com:65536", "outside 1 to 65535"},
		{"a port beyond any number", "", "example.com:99999999999999999999999", "outside 1 to 65535"},
		{"a star", "", "*.marker.example", "character no host name has"},
		{"a percent", "", "ex%61mple.marker", "character no host name has"},
		{"a backslash", "", "https://marker.example\\x", "character no host name has"},
		{"a short IPv4", "", "10.1", "ends in a number but is not an IPv4 address"},
		{"a hexadecimal IPv4", "", "0x7f.0.0.1", "ends in a number"},
		{"an octal IPv4", "", "010.0.0.1", "ends in a number"},
		{"an IPv4 with a dot after it", "", "10.0.0.1.", "ends in a number"},
		{"a name ending in a number", "", "marker.123", "ends in a number"},
		{"a name ending in hexadecimal", "", "marker.0x1f", "ends in a number"},
		{"a bare 0x", "", "marker.0x", "ends in a number"},
		{"one number", "", "167772161", "ends in a number"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Ask([]byte(c.list), []byte(c.address))
			var refusal *spec.Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("got %v, want a refusal", err)
			}
			if !strings.Contains(refusal.Reason, c.says) {
				t.Errorf("the refusal says %q, want %q", refusal.Reason, c.says)
			}
			if strings.Contains(refusal.Reason, "marker") {
				t.Errorf("the refusal repeats the input: %q", refusal.Reason)
			}
		})
	}
}

// TestWhatEveryProgramReadsTheSameWayIsAnswered is the other side of the
// refusals: the spellings next to the refused ones pass.
func TestWhatEveryProgramReadsTheSameWayIsAnswered(t *testing.T) {
	for _, address := range []string{
		"example.123a", "a.b0x", "0x7g.example", "10.0.0.255", "example.com:1", "[::1]:443", "a\tb",
	} {
		_, err := Ask([]byte("x"), []byte(address))
		if address == "a\tb" {
			if err == nil {
				t.Error("a tab inside the address was answered")
			}
			continue
		}
		if err != nil {
			t.Errorf("%q was refused: %v", address, err)
		}
	}
	// A tab is a blank to every program that reads the list, so it stays in it.
	if _, err := Ask([]byte("a,\tb"), []byte("b")); err != nil {
		t.Errorf("a tab in the list was refused: %v", err)
	}
}
