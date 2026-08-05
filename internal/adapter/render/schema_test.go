package render

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// TestTheStartTimeKeepsItsSubSecondPrecision covers a timestamp that resolved to
// the second.
//
// Two runs inside one second carried the same started_at, so a pair of saved
// reports could not be put in order - and putting two reports side by side is
// what --compare exists for. RFC3339Nano is still RFC3339, so nothing parsing
// the field has to change.
func TestTheStartTimeKeepsItsSubSecondPrecision(t *testing.T) {
	r := everyStatusReport()
	r.Run.StartedAt = r.Run.StartedAt.Add(123456789 * time.Nanosecond)

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if !strings.Contains(string(document), ".123456789Z") {
		t.Errorf("the start time lost everything below a second:\n%s", firstLinesOf(string(document), 6))
	}
	if err := ValidateDocument(document); err != nil {
		t.Errorf("a document with a precise timestamp no longer matches the schema: %v", err)
	}
}

// TestTheTimestampDoesNotDependOnTheReaderOrTheWriterTimeZone pins a property
// that is easy to have and easy to lose.
//
// A report is written on one machine and read on another, and it ends up in a
// ticket next to a report from a third. A timestamp carrying whatever offset the
// writer's machine happened to be set to would make two runs impossible to order
// without knowing where each was taken - and the offset is exactly the sort of
// thing that arrives later, when somebody formats a time without saying UTC.
//
// Both renderers are checked, because there are two of them and only one is
// covered by the schema.
func TestTheTimestampDoesNotDependOnTheReaderOrTheWriterTimeZone(t *testing.T) {
	// One instant, written down in a zone nine hours ahead. The UTC rendering of
	// it is fixed and known.
	tokyo := time.FixedZone("Asia/Tokyo", 9*60*60)
	r := everyStatusReport()
	r.Run.StartedAt = time.Date(2026, 8, 3, 21, 0, 0, 0, tokyo)
	const wantInstant = "2026-08-03T12:00:00Z"

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if !strings.Contains(string(document), wantInstant) {
		t.Errorf("the machine readable report did not carry %s:\n%s", wantInstant, firstLinesOf(string(document), 6))
	}
	if strings.Contains(string(document), "+09:00") {
		t.Errorf("the machine readable report carried the writer's offset:\n%s", firstLinesOf(string(document), 6))
	}

	var screen strings.Builder
	if err := (Terminal{}).Render(&screen, r); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if !strings.Contains(screen.String(), wantInstant) {
		t.Errorf("the terminal report did not carry %s:\n%s", wantInstant, firstLinesOf(screen.String(), 3))
	}
}

func firstLinesOf(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

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
		{
			name: "a finding losing the line every surface renders",
			change: func(d map[string]any) {
				findings := d["layers"].([]any)[0].(map[string]any)["findings"].([]any)
				delete(findings[0].(map[string]any), "summary")
			},
			expect: "summary",
		},
		{
			name: "a finding body that changed shape",
			change: func(d map[string]any) {
				findings := d["layers"].([]any)[0].(map[string]any)["findings"].([]any)
				findings[0].(map[string]any)["environment_variable"] = "HTTPS_PROXY=http://proxy:8080"
			},
			expect: "schema declares an object",
		},
		{
			name: "a findings list that became a single finding",
			change: func(d map[string]any) {
				first := d["layers"].([]any)[0].(map[string]any)
				first["findings"] = first["findings"].([]any)[0]
			},
			expect: "schema declares an array",
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

// TestALayerThatNeverLookedIsNotRenderedAsOneThatFoundNothing is the difference
// this field was shaped to carry, checked on the document a consumer parses.
//
// An empty array says "this was looked at and there was nothing", so emitting
// one under every layer nobody has written yet would put seven false claims in
// every report this build produces. Null says nobody looked. The two encode the
// same way in Go unless something asks first, which is why this is a test and
// not a comment.
func TestALayerThatNeverLookedIsNotRenderedAsOneThatFoundNothing(t *testing.T) {
	document := string(encodedReport(t))

	if !strings.Contains(document, `"findings": null`) {
		t.Errorf("no layer renders its findings as null, and six of the eight never looked:\n%s", document)
	}
	if !strings.Contains(document, `"findings": []`) {
		t.Errorf("the layer that looked and found nothing does not render an empty array:\n%s", document)
	}
	if !strings.Contains(document, `"carried_credentials": true`) {
		t.Errorf("the fact that a value carried a credential did not reach the document:\n%s", document)
	}
	// A variable that is not set has no value, and a null is how that is said.
	// An empty string there would mean it is set to nothing, which is a different
	// answer and changes whether some tools proxy at all.
	if !strings.Contains(document, `"value": null`) {
		t.Errorf("a variable that is not set does not render a null value:\n%s", document)
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

// resolutionReport is a report carrying the second kind of finding, both views.
//
// It is separate from everyStatusReport rather than folded into it, because the
// tests above pin the environment variable body and would start describing two
// things at once.
func resolutionReport() report.Report {
	r := everyStatusReport()
	for i := range r.Layers {
		if r.Layers[i].ID != layer.Resolution {
			continue
		}
		r.Layers[i].Findings = []report.Finding{
			{
				Kind:    report.FindingNameResolution,
				Summary: "this system resolves example.com to 2 addresses",
				Source:  report.SourceDetected,
				NameResolution: &report.NameResolution{
					Name:       "example.com",
					View:       report.ViewSystem,
					Addresses:  []string{"192.0.2.10", "2001:db8::10"},
					DurationMS: 27,
				},
			},
			{
				Kind:    report.FindingNameResolution,
				Summary: "192.0.2.53 answered NODATA for example.com AAAA",
				Source:  report.SourceDetected,
				NameResolution: &report.NameResolution{
					Name:         "example.com",
					View:         report.ViewDirect,
					Resolver:     "192.0.2.53",
					QueryType:    "AAAA",
					ResponseCode: "NODATA",
					// NIL, NOT AN EMPTY SLICE, AND THE MUTATION REGISTER IS WHY.
					// A layer that got no addresses hands back nil, and nil is
					// what the encoder has to turn into an empty array. Written
					// as []string{} this fixture encoded identically whether or
					// not the encoder copied, so the mutation that dropped the
					// copy survived - the test could not see the difference the
					// code exists to make.
					Addresses:  nil,
					DurationMS: 4,
				},
			},
		}
	}
	return r
}

// TestADocumentCarryingTheSecondKindValidates is the whole point of this slice:
// the contract grew a second body and the schema still describes what the encoder
// produces.
func TestADocumentCarryingTheSecondKindValidates(t *testing.T) {
	document, err := Encode(resolutionReport())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if err := ValidateDocument(document); err != nil {
		t.Fatalf("a document with a resolution finding is refused by its own schema:\n%v", err)
	}

	text := string(document)
	// The body key equals the kind, so a reader with the document and no schema
	// can tell which body they are looking at.
	if !strings.Contains(text, `"name_resolution"`) {
		t.Errorf("the resolution body is not under its own key:\n%s", text)
	}
	// The system view carries three nulls, and each of them is a refusal to
	// invent the most useful column in the row.
	if !strings.Contains(text, `"resolver": null`) {
		t.Error("the system view names a resolver, which this system does not report")
	}
	if !strings.Contains(text, `"response_code": null`) {
		t.Error("the system view carries a response code, which the system resolver does not hand back")
	}
	// A direct view that found nothing renders an empty array rather than null.
	// Null would say "did not look", and this view looked and was told there is
	// nothing of that type.
	if !strings.Contains(text, `"addresses": []`) {
		t.Errorf("an answer of NODATA does not render an empty address array:\n%s", text)
	}
}

// TestTheSchemaRefusesAResolutionBodyThatChangedShape keeps the second
// declaration honest, the same way the first one is kept honest above.
func TestTheSchemaRefusesAResolutionBodyThatChangedShape(t *testing.T) {
	document, err := Encode(resolutionReport())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}

	cases := []struct {
		name   string
		change func(map[string]any)
		expect string
	}{
		{"the addresses became one string", func(d map[string]any) {
			body := resolutionBody(d)
			body["addresses"] = "192.0.2.10"
		}, "schema declares an array"},
		{"the duration became text", func(d map[string]any) {
			body := resolutionBody(d)
			body["duration_ms"] = "27ms"
		}, "duration_ms"},
		{"the view went missing", func(d map[string]any) {
			delete(resolutionBody(d), "view")
		}, "view"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateDocument(mutate(t, document, c.change))
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.expect) {
				t.Errorf("the refusal reads %q and does not mention %q", err, c.expect)
			}
		})
	}
}

// resolutionBody digs out the first resolution body in a decoded document.
func resolutionBody(d map[string]any) map[string]any {
	for _, row := range d["layers"].([]any) {
		findings, ok := row.(map[string]any)["findings"].([]any)
		if !ok {
			continue
		}
		for _, finding := range findings {
			if body, ok := finding.(map[string]any)["name_resolution"].(map[string]any); ok {
				return body
			}
		}
	}
	return nil
}
