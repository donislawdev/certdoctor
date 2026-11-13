package spec

import (
	"encoding/base64"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// publicName is how an id and an input's name may be spelled: they are words
// in a command line and keys of a document, so lower case, digits and dashes.
var publicName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func TestEveryToolIsDescribedCompletely(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range All {
		if !publicName.MatchString(tool.ID) || seen[tool.ID] {
			t.Errorf("tool id %q is not a lower case word, or is used twice", tool.ID)
		}
		seen[tool.ID] = true
		if !slices.Contains(Categories, tool.Category) || tool.Title == "" || !strings.HasSuffix(tool.Summary, ".") {
			t.Errorf("%s: category %q, title %q, summary %q", tool.ID, tool.Category, tool.Title, tool.Summary)
		}
		if len(tool.Inputs) == 0 {
			t.Errorf("%s takes nothing", tool.ID)
		}
		names := map[string]bool{}
		for _, in := range tool.Inputs {
			if !publicName.MatchString(in.Name) || names[in.Name] || in.MaxBytes <= 0 ||
				!slices.Contains(Shapes, in.Shape) || !strings.Contains(in.File, ".") {
				t.Errorf("%s: input %+v", tool.ID, in)
			}
			names[in.Name] = true
		}
		if found, ok := Find(tool.ID); !ok || found.ID != tool.ID {
			t.Errorf("Find(%q) does not find it", tool.ID)
		}
	}
	if _, ok := Find("no-such-tool"); ok {
		t.Error("Find found a tool that is not there")
	}
}

func TestTheFirstInputIsReadWithFileAndEveryOtherByItsName(t *testing.T) {
	tool := Tool{Inputs: []Input{{Name: "token"}, {Name: "key"}}}
	if got := tool.FileSwitch(0); got != "file" {
		t.Errorf("the first input's switch is %q, want file", got)
	}
	if got := tool.FileSwitch(1); got != "key-file" {
		t.Errorf("the second input's switch is %q, want key-file", got)
	}
}

func TestAToolIsFoundByAnyOfItsWords(t *testing.T) {
	jwt, _ := Find("jwt")
	for query, want := range map[string]bool{
		"": true, "JWT": true, "bearer": true, "  decoder   jwt ": true, "id_token": true, "SIGNATURE": true,
		"certificate": false, "jwt certificate": false, "my words": false,
	} {
		if got := jwt.Match(query); got != want {
			t.Errorf("Match(%q) = %v, want %v", query, got, want)
		}
	}
	if !jwt.Match("my words", "what the window calls it - my words") {
		t.Error("the words another surface calls a tool by are not searched")
	}
}

// sample is an outcome with every kind of block and every optional part.
func sample() Outcome {
	return Outcome{
		Notes:  []string{"Took off the quotes."},
		Checks: []Check{{ID: "expiry", Status: status.Fail, Summary: "Expired <1 h> ago & more."}},
		Data:   map[string]any{"form": "jws", "n": 3},
		View: []Block{
			{Kind: Fields, Title: "Token", Fields: []Field{
				{Label: "Form", Value: "Signed"},
				{Label: "Expires", Value: "2026-11-12", Note: "1 hour ago", Status: status.Warn},
			}},
			{Kind: Code, Title: "Header", Language: "json", Body: "{\n  \"alg\": \"HS256\"\n}"},
			{Kind: Text, Title: "Payload", Body: ""},
		},
	}
}

func TestADocumentReadsBackAsWritten(t *testing.T) {
	d, err := NewDocument(mustFind(t, "jwt"), "0.1.0", "2026-11-12T12:00:00Z", sample())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "<1 h> ago & more") {
		t.Errorf("<, > and & were escaped for HTML: %s", raw)
	}
	back, err := ReadDocument(raw)
	if err != nil {
		t.Fatalf("ReadDocument refused its own document: %v\n%s", err, raw)
	}
	if !reflect.DeepEqual(back, d) {
		t.Errorf("read back as\n%+v\nwritten\n%+v", back, d)
	}
	if string(back.Data) != `{"form":"jws","n":3}` {
		t.Errorf("data %s", back.Data)
	}
}

func TestADocumentOutsideTheContractIsRefused(t *testing.T) {
	d, _ := NewDocument(mustFind(t, "jwt"), "0.1.0", "2026-11-12T12:00:00Z", sample())
	good, _ := d.Marshal()
	for _, c := range []struct{ name, from, to string }{
		{"a status outside the four", `"status": "FAIL"`, `"status": "BAD"`},
		{"a field status outside the four", `"status": "WARN"`, `"status": "OK"`},
		{"an unknown key", `"tool": "jwt"`, `"tool": "jwt", "extra": 1`},
		{"a name twice", `"tool": "jwt"`, `"tool": "jwt", "tool": "jwt"`},
		{"a kind outside the list", `"kind": "text"`, `"kind": "table"`},
		{"a code block without a language", `"language": "json",`, ``},
		{"a text block with fields", `"kind": "text",`, `"kind": "text", "fields": [],`},
		{"no checks", `"checks": [`, `"nochecks": [`},
		{"a check with no id", `"id": "expiry"`, `"id": ""`},
		{"more after the document", "\n}\n", "\n}\n{}"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := strings.Replace(string(good), c.from, c.to, 1)
			if bad == string(good) {
				t.Fatalf("the case changed nothing - %q is not in the document", c.from)
			}
			if _, err := ReadDocument([]byte(bad)); err == nil {
				t.Errorf("read:\n%s", bad)
			}
		})
	}
}

func TestARequestGivesEachInputOneWay(t *testing.T) {
	jwt, _ := Find("jwt")
	for _, c := range []struct{ name, doc, want string }{
		{"text", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"text":"abc"}}}`, "text abc"},
		{"bytes", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"base64":"` +
			base64.StdEncoding.EncodeToString([]byte("a\x00b")) + `"}}}`, "bytes a\x00b"},
		{"a path", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"path":"t.txt"}}}`, "path t.txt"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, err := ReadRequest([]byte(c.doc), jwt)
			if err != nil {
				t.Fatal(err)
			}
			in := r.Inputs["token"]
			got := "path " + in.Path
			if in.Text != nil {
				got = "text " + *in.Text
			} else if in.Bytes != nil {
				got = "bytes " + string(in.Bytes)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestARequestOutsideTheContractIsRefused(t *testing.T) {
	jwt, _ := Find("jwt")
	for _, c := range []struct{ name, doc, says string }{
		{"another version", `{"schema_version":"2.0","tool":"jwt","inputs":{"token":{"text":"a"}}}`, "schema_version"},
		{"another tool", `{"schema_version":"1.0","tool":"pem","inputs":{"token":{"text":"a"}}}`, `for the tool "pem"`},
		{"an input it does not take", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"text":"a"},"key":{"text":"k"}}}`,
			`gives "key"`},
		{"no input", `{"schema_version":"1.0","tool":"jwt","inputs":{}}`, `no "token"`},
		{"two ways", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"text":"a","path":"p"}}}`, "2 ways"},
		{"no way", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{}}}`, "0 ways"},
		{"bad base64", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"base64":"a$"}}}`, "not standard base64"},
		{"an empty path", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"path":""}}}`, "empty path"},
		{"a name twice", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"text":"a"},"token":{"text":"b"}}}`, "twice"},
		{"an unknown key", `{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"text":"a"}},"x":1}`, "shape"},
		{"not JSON", `{"schema_version":`, "ends before"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ReadRequest([]byte(c.doc), jwt)
			if err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("got %v, want an error saying %q", err, c.says)
			}
		})
	}
}

// FuzzReadDocument: whatever the window is handed, reading it does not fall
// over, and a document it accepts writes back as one it accepts the same.
func FuzzReadDocument(f *testing.F) {
	d, _ := NewDocument(mustFind(f, "jwt"), "0.1.0", "2026-11-12T12:00:00Z", sample())
	good, _ := d.Marshal()
	f.Add(good)
	f.Add([]byte(`{"schema_version":"1.0"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := ReadDocument(data)
		if err != nil {
			return
		}
		again, err := doc.Marshal()
		if err != nil {
			t.Fatalf("an accepted document does not marshal: %v", err)
		}
		back, err := ReadDocument(again)
		if err != nil || !reflect.DeepEqual(back, doc) {
			t.Fatalf("an accepted document written back reads differently (%v)", err)
		}
	})
}

// FuzzReadRequest: whatever a script or the window hands the command line,
// reading it does not fall over, and what it accepts gives every input of the
// tool exactly one way.
func FuzzReadRequest(f *testing.F) {
	jwt, _ := Find("jwt")
	f.Add([]byte(`{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"text":"abc"}}}`))
	f.Add([]byte(`{"schema_version":"1.0","tool":"jwt","inputs":{"token":{"base64":"YWJj"}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ReadRequest(data, jwt)
		if err != nil {
			return
		}
		for _, in := range jwt.Inputs {
			got, ok := r.Inputs[in.Name]
			ways := 0
			for _, given := range []bool{got.Text != nil, got.Bytes != nil, got.Path != ""} {
				if given {
					ways++
				}
			}
			if !ok || ways > 1 {
				t.Fatalf("input %q accepted %d ways", in.Name, ways)
			}
		}
	})
}

// mustFind is the tool id, which the cases here are written for.
func mustFind(t testing.TB, id string) Tool {
	t.Helper()
	tool, ok := Find(id)
	if !ok {
		t.Fatalf("no tool %q", id)
	}
	return tool
}

// TestChecksAreListedWorstFirstThenInTheToolsOrder holds the one order every
// tool lists its checks in: the order of status.All, and within a status the
// tool's own order of ids, with an id it did not name last.
func TestChecksAreListedWorstFirstThenInTheToolsOrder(t *testing.T) {
	checks := []Check{
		{ID: "b", Status: status.Pass}, {ID: "unnamed", Status: status.Warn}, {ID: "a", Status: status.Pass},
		{ID: "c", Status: status.Warn}, {ID: "d", Status: status.Unknown}, {ID: "e", Status: status.Fail},
	}
	var got []string
	for _, c := range SortChecks(checks, []string{"a", "b", "c", "d", "e"}) {
		got = append(got, c.ID)
	}
	if want := []string{"e", "c", "unnamed", "d", "a", "b"}; !slices.Equal(got, want) {
		t.Errorf("order %q, want %q", got, want)
	}
}
