package render

import (
	"encoding/json"
	"strings"
	"testing"
)

func encodedReport(t *testing.T) []byte {
	t.Helper()
	document, err := Encode(everyStatusReport())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	return document
}

// TestARealDocumentValidatesAgainstTheDeclaredSchema is the line the regression
// surface has carried since before there was any JSON to check. It is only true
// now.
func TestARealDocumentValidatesAgainstTheDeclaredSchema(t *testing.T) {
	if err := ValidateDocument(encodedReport(t)); err != nil {
		t.Fatalf("the encoder produced a document its own schema refuses:\n%v", err)
	}
}

// mutate decodes a document, lets a function change it, and encodes it again.
// It is how a defect is planted without hand writing a whole document that
// would then have to be kept up to date alongside the real one.
func mutate(t *testing.T, document []byte, change func(map[string]any)) []byte {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	change(decoded)
	changed, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("the changed document does not encode: %v", err)
	}
	return changed
}

// TestTheValidatorRejectsAPlantedDefect is the canary.
//
// Without it the check above would pass just as happily against a schema that
// accepted everything, and a schema that accepts everything is prose wearing a
// test's clothes. Every entry here is a way the contract could break in a
// release, and each has to be caught for a different reason.
func TestTheValidatorRejectsAPlantedDefect(t *testing.T) {
	original := encodedReport(t)

	cases := []struct {
		name   string
		change func(map[string]any)
		expect string
	}{
		{
			name:   "a renamed field",
			change: func(d map[string]any) { d["schemaVersion"] = d["schema_version"]; delete(d, "schema_version") },
			expect: "schema_version",
		},
		{
			name:   "a field that vanished",
			change: func(d map[string]any) { delete(d, "verdict") },
			expect: "verdict",
		},
		{
			name:   "a field nobody declared",
			change: func(d map[string]any) { d["confidence"] = 0.9 },
			expect: "confidence",
		},
		{
			name:   "a number where a string belongs",
			change: func(d map[string]any) { d["schema_version"] = 1 },
			expect: "schema declares a string",
		},
		{
			name: "a null in a field that may not be null",
			change: func(d map[string]any) {
				d["verdict"].(map[string]any)["sentence"] = nil
			},
			expect: "null",
		},
		{
			name: "a nested field that changed shape",
			change: func(d map[string]any) {
				d["run"].(map[string]any)["platform"] = "windows/amd64"
			},
			expect: "schema declares an object",
		},
		{
			name:   "an array that became a single value",
			change: func(d map[string]any) { d["layers"] = d["layers"].([]any)[0] },
			expect: "schema declares an array",
		},
		{
			name: "a row inside an array losing a field",
			change: func(d map[string]any) {
				first := d["layers"].([]any)[0].(map[string]any)
				delete(first, "status")
			},
			expect: "layers[0]",
		},
	}

	for _, c := range cases {
		err := ValidateDocument(mutate(t, original, c.change))
		if err == nil {
			t.Errorf("%s was accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.expect) {
			t.Errorf("%s was rejected for something else:\n%v\nexpected a mention of %q", c.name, err, c.expect)
		}
	}
}

func TestTheValidatorRejectsSomethingThatIsNotJSONAtAll(t *testing.T) {
	for _, document := range []string{"", "null", "[]", "{", "certdoctor 0.1.0"} {
		if err := ValidateDocument([]byte(document)); err == nil {
			t.Errorf("%q was accepted as a report", document)
		}
	}
}

// TestTheValidatorReportsEveryProblemRatherThanTheFirst matters because this
// runs before anything is printed. Stopping at the first problem would turn
// fixing a broken document into a sequence of runs instead of one reading.
func TestTheValidatorReportsEveryProblemRatherThanTheFirst(t *testing.T) {
	broken := mutate(t, encodedReport(t), func(d map[string]any) {
		delete(d, "tool")
		delete(d, "notes")
		d["extra"] = true
		d["schema_version"] = 2
	})

	err := ValidateDocument(broken)
	if err == nil {
		t.Fatal("a document with four separate problems was accepted")
	}
	if got := strings.Count(err.Error(), "\n") + 1; got < 4 {
		t.Errorf("the validator reported %d problems, want at least 4:\n%v", got, err)
	}
}

// TestTheSchemaVersionIsTheFirstThingInTheDocument pins the one ordering rule
// of the contract. A consumer has to read it before trying anything else, and
// that is only reliable if it is there before anything else is.
func TestTheSchemaVersionIsTheFirstThingInTheDocument(t *testing.T) {
	document := string(encodedReport(t))
	first := strings.Index(document, `"schema_version"`)
	if first < 0 {
		t.Fatal("the document carries no schema version")
	}
	for _, later := range []string{`"tool"`, `"run"`, `"verdict"`, `"layers"`, `"notes"`} {
		if at := strings.Index(document, later); at >= 0 && at < first {
			t.Errorf("%s appears before the schema version", later)
		}
	}
}

// TestAnEmptyCollectionEncodesAsAnEmptyArrayRatherThanNull keeps two different
// claims apart. An empty array says there were none of these. A null says the
// field was never filled in, and a consumer counting rows would treat the second
// as the first.
func TestAnEmptyCollectionEncodesAsAnEmptyArrayRatherThanNull(t *testing.T) {
	bare := everyStatusReport()
	bare.Layers = nil
	bare.Notes = nil

	document, err := Encode(bare)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if strings.Contains(string(document), `"layers": null`) || strings.Contains(string(document), `"notes": null`) {
		t.Errorf("an empty collection encoded as null:\n%s", document)
	}
	if err := ValidateDocument(document); err != nil {
		t.Errorf("a report with no rows does not match the schema:\n%v", err)
	}
}
