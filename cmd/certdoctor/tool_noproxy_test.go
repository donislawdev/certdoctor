package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// noproxyAnswer is what a test reads back from the NO_PROXY tester's document:
// the host it was asked about and what curl, the first reading, answered.
type noproxyAnswer struct {
	Address  struct{ Host string } `json:"address"`
	Readings []struct {
		Entry *string `json:"entry"`
	} `json:"readings"`
}

// TestSeveralInputsAreReadOneLineEach covers ADR147 point 3: a tool taking
// several inputs reads each from its own line of standard input, asks for each
// at a terminal, or takes each from its file - and the ways can be mixed.
func TestSeveralInputsAreReadOneLineEach(t *testing.T) {
	files := map[string]string{"list.txt": "NO_PROXY=.corp.example\n", "address.txt": "https://api.corp.example\r\n"}
	for _, c := range []struct {
		name    string
		run     *harness
		prompts []string
	}{
		{"piped", toolRun(ptr(".corp.example\napi.corp.example\n"), nil, nil, "tool", "noproxy", "--json"), nil},
		{"piped from PowerShell", toolRun(ptr(".corp.example\r\napi.corp.example\r\n"), nil, nil,
			"tool", "noproxy", "--json"), nil},
		{"piped without a last line ending", toolRun(ptr(".corp.example\napi.corp.example"), nil, nil,
			"tool", "noproxy", "--json"), nil},
		{"piped with blank lines after", toolRun(ptr(".corp.example\napi.corp.example\n\n \r\n"), nil, nil,
			"tool", "noproxy", "--json"), nil},
		// Both lines arrive at once, as a paste of two lines does: the second
		// is the second input, not lost in a reader made for the first.
		{"pasted", toolRun(nil, ptr(".corp.example\r\napi.corp.example\r\n"), nil, "tool", "noproxy", "--json"),
			[]string{"Paste the list and press Enter:", "Paste the address and press Enter:"}},
		{"both files", toolRun(nil, nil, files, "tool", "noproxy", "--file", "list.txt", "--address-file",
			"address.txt", "--json"), nil},
		{"the list from a file", toolRun(ptr("api.corp.example\n"), nil, files, "tool", "noproxy", "--file",
			"list.txt", "--json"), nil},
		{"the address from a file", toolRun(ptr(".corp.example\n"), nil, files, "tool", "noproxy",
			"--address-file", "address.txt", "--json"), nil},
		{"the address from a file, the list pasted", toolRun(nil, ptr(".corp.example\n"), files, "tool", "noproxy",
			"--address-file", "address.txt", "--json"), []string{"Paste the list and press Enter:"}},
		{"a request", toolRun(ptr(`{"schema_version":"1.0","tool":"noproxy","inputs":{"list":{"text":".corp.example"},`+
			`"address":{"text":"api.corp.example"}}}`), nil, nil, "tool", "noproxy", "--request", "-", "--json"), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.run.code != exitcode.OK {
				t.Fatalf("exit %d: %s", c.run.code, c.run.stderr.String())
			}
			doc, err := spec.ReadDocument(c.run.stdout.Bytes())
			if err != nil {
				t.Fatalf("the window could not read what the command line wrote: %v", err)
			}
			var got noproxyAnswer
			if err := json.Unmarshal(doc.Data, &got); err != nil || got.Address.Host != "api.corp.example" ||
				len(got.Readings) == 0 || got.Readings[0].Entry == nil || *got.Readings[0].Entry != ".corp.example" {
				t.Errorf("data %s (%v)", doc.Data, err)
			}
			stderr := c.run.stderr.String()
			if strings.Count(stderr, "Paste the") != len(c.prompts) {
				t.Errorf("asked %d time(s), want %d: %q", strings.Count(stderr, "Paste the"), len(c.prompts), stderr)
			}
			for _, prompt := range c.prompts {
				if !strings.Contains(stderr, prompt) {
					t.Errorf("did not ask %q: %q", prompt, stderr)
				}
			}
		})
	}
}

// TestSeveralInputsRefuseWhatDoesNotLineUp covers the lines that are too few,
// too many or too long, and the inputs that cannot be asked for.
func TestSeveralInputsRefuseWhatDoesNotLineUp(t *testing.T) {
	long := strings.Repeat("a", 64<<10+1)
	for _, c := range []struct {
		name string
		run  *harness
		says string
	}{
		{"one line", toolRun(ptr(".corp.marker\n"), nil, nil, "tool", "noproxy"),
			"standard input ended before the address - certdoctor tool noproxy reads one line each: the list, " +
				"then the address"},
		{"nothing", toolRun(ptr(""), nil, nil, "tool", "noproxy"), "ended before the list"},
		{"a line too many", toolRun(ptr(".corp.marker\napi.marker\nmore.marker\n"), nil, nil, "tool", "noproxy"),
			"standard input carries more lines than certdoctor tool noproxy reads"},
		{"a list too long", toolRun(ptr(long+"\nexample.com\n"), nil, nil, "tool", "noproxy"),
			"the list line of standard input is larger than 64 KiB"},
		{"an address too long", toolRun(ptr("x\n"+long), nil, nil, "tool", "noproxy"),
			"the address line of standard input is larger than 64 KiB"},
		{"pasted too long", toolRun(nil, ptr(long+"\n"), nil, "tool", "noproxy"), "what was pasted is larger"},
		{"no terminal", toolRun(nil, nil, nil, "tool", "noproxy"),
			"reads its list from standard input, and nothing is piped in"},
		{"no terminal for the address", toolRun(nil, nil, map[string]string{"l": "x"}, "tool", "noproxy",
			"--file", "l"), "Pipe the address in or name a file with --address-file"},
		{"the tool refuses", toolRun(ptr("x\nhttps://user:marker@example.com\n"), nil, nil, "tool", "noproxy"),
			"the address has a user name before @"},
		{"a NUL in a line", toolRun(ptr("a\x00b\nexample.com\n"), nil, nil, "tool", "noproxy"),
			"the list has a NUL byte at byte 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.run.code != exitcode.Config || !strings.Contains(c.run.stderr.String(), c.says) {
				t.Errorf("exit %d, stderr %q - want %d saying %q", c.run.code, c.run.stderr.String(),
					exitcode.Config, c.says)
			}
			if c.run.stdout.Len() != 0 || strings.Contains(c.run.stderr.String(), "marker") {
				t.Errorf("a refusal wrote to standard output or repeated the input: %q", c.run.stderr.String())
			}
		})
	}
}

// TestTheNoproxyPageAndHelpSayHowToAsk reads the page a person sees and the
// help that tells them how to give two inputs.
func TestTheNoproxyPageAndHelpSayHowToAsk(t *testing.T) {
	run := toolRun(ptr("NO_PROXY=.example.com\nexample.com\n"), nil, nil, "tool", "noproxy")
	if run.code != exitcode.OK {
		t.Fatalf("exit %d: %s", run.code, run.stderr.String())
	}
	for _, want := range []string{
		"tool noproxy - NO_PROXY tester", `NOTES\n  Took off "NO_PROXY=" in front of the list.`,
		"WARN  The programs disagree about example.com: 5 of the 7 go to it directly, 1 through the proxy\n" +
			"          and for 1 it depends on the release.",
		"DIRECTLY, WITHOUT THE PROXY\n  curl and git", "THROUGH THE PROXY\n  Go ", "JAVA\n  Java does not read NO_PROXY.",
	} {
		if !strings.Contains(run.stdout.String(), strings.ReplaceAll(want, `\n`, "\n")) {
			t.Errorf("the page does not say %q:\n%s", want, run.stdout.String())
		}
	}
	help := toolRun(nil, nil, nil, "tool", "noproxy", "--help").stdout.String()
	for _, want := range []string{
		"certdoctor tool noproxy              paste the list and the address, each followed by Enter",
		"certdoctor tool noproxy < input.txt  one line each: the list, then the address",
		"certdoctor tool noproxy --file no_proxy.txt --address-file address.txt",
		"The list and the address are never taken as arguments",
		"--address-file <path>  read the address from this file",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("the help does not say %q:\n%s", want, help)
		}
	}
	if list := toolRun(nil, nil, nil, "tool").stdout.String(); !strings.Contains(list, "PROXY\n  noproxy  NO_PROXY tester") {
		t.Errorf("the list of tools does not show the tester under PROXY:\n%s", list)
	}
}
