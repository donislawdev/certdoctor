package jsontext

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestMembersKeepTheirOrderAndNumbersTheirText(t *testing.T) {
	v, dups, err := Parse([]byte(`{"z":1,"a":12345678901234567890,"m":[1e400,-0.0,true,null,"x"]}`))
	if err != nil || len(dups) != 0 {
		t.Fatalf("Parse: %v, duplicates %v", err, dups)
	}
	var names []string
	for _, m := range v.Members {
		names = append(names, m.Name)
	}
	if strings.Join(names, ",") != "z,a,m" {
		t.Errorf("members in the order %v, written z, a, m", names)
	}
	if a, _ := v.Get("a"); a.Text != "12345678901234567890" {
		t.Errorf("a is %q, written 12345678901234567890", a.Text)
	}
	m, _ := v.Get("m")
	if got := m.Compact(); got != `[1e400,-0.0,true,null,"x"]` {
		t.Errorf("the array comes back as %s", got)
	}
}

func TestANameCarriedTwiceIsFoundWhereverItIs(t *testing.T) {
	v, dups, err := Parse([]byte(`{"a":1,"a":2,"b":{"c":1,"c":2},"x/y~":{"d":[{"e":1,"e":2}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []Duplicate{{Path: "", Name: "a"}, {Path: "/b", Name: "c"}, {Path: "/x~1y~0/d/0", Name: "e"}}
	if !reflect.DeepEqual(dups, want) {
		t.Errorf("duplicates %v, want %v", dups, want)
	}
	if a, _ := v.Get("a"); a.Text != "2" {
		t.Errorf("Get takes %q, and the reading RFC 7515 allows is the last one, 2", a.Text)
	}
	if got := v.Compact(); !strings.HasPrefix(got, `{"a":1,"a":2,`) {
		t.Errorf("both members are not kept: %s", got)
	}
}

func TestWhatIsNotJSONIsRefusedByPositionAlone(t *testing.T) {
	for _, c := range []struct {
		name, text, problem string
		offset              int64
	}{
		{"a stray word", `{"a": secretword}`, "is not valid JSON", -1},
		{"invalid UTF-8", "{\"a\":\"ok\xffsecret\"}", "is not valid UTF-8", 9},
		{"more after the value", `{"a":1} {"b":2}`, "goes on after its JSON value", -1},
		{"cut short", `{"a":[1,2`, "ends before its JSON value does", -1},
		{"nothing", ``, "ends before its JSON value does", -1},
		{"a byte order mark", "\xef\xbb\xbf{}", "is not valid JSON", -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Parse([]byte(c.text))
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("Parse gave %v, want *Error", err)
			}
			if e.Problem != c.problem || c.offset >= 0 && e.Offset != c.offset {
				t.Errorf("got %q at %d, want %q", e.Problem, e.Offset, c.problem)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "'") {
				t.Errorf("the message quotes the input: %s", err)
			}
		})
	}
}

func TestNestingStopsAtMaxDepth(t *testing.T) {
	if _, _, err := Parse([]byte(strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth))); err != nil {
		t.Errorf("%d levels refused: %v", MaxDepth, err)
	}
	deep := strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)
	if _, _, err := Parse([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nests deeper") {
		t.Errorf("%d levels: %v", MaxDepth+1, err)
	}
	// A hostile depth costs nothing: it is refused at the 65th bracket, not
	// after reading a million.
	if _, _, err := Parse([]byte(strings.Repeat("[", 1<<20))); err == nil {
		t.Error("a million brackets were read")
	}
}

func TestIndentEscapesWhatCouldMoveACursor(t *testing.T) {
	v, _, err := Parse([]byte(`{"a\u001b[2J":"line\nbreak\u0007\u` + `2028<&>"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"a\\u001b[2J\": \"line\\nbreak\\u0007\\u2028<&>\"\n}"
	if got := v.Indent(); got != want {
		t.Errorf("Indent:\n%s\nwant:\n%s", got, want)
	}
	if got := (Value{Kind: Object}).Indent() + (Value{Kind: Array}).Compact(); got != "{}[]" {
		t.Errorf("empty containers: %s", got)
	}
}

// FuzzParse holds the two promises a reader of hostile bytes makes: it does not
// fall over, and what it writes back is JSON that reads as the same value.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{`{"a":1,"a":[2,{"b":"\u` + `00e9"}]}`, `[]`, `"x"`, `1e400`, "{\"\xff\":1}", `{"a":`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, _, err := Parse(data)
		if err != nil {
			return
		}
		for _, text := range []string{v.Compact(), v.Indent()} {
			if !json.Valid([]byte(text)) {
				t.Fatalf("wrote back invalid JSON: %q", text)
			}
			again, _, err := Parse([]byte(text))
			if err != nil || !reflect.DeepEqual(again, v) {
				t.Fatalf("written back as %q, read again as a different value (%v)", text, err)
			}
		}
	})
}
