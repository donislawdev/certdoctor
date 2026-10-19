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

// bodyFixtures is one well formed finding per declared kind.
//
// IT IS CHECKED AGAINST THE REGISTRY rather than maintained by hand, so a fourth
// kind of finding cannot be declared without somebody meeting this list.
// fixtureTrusts exists because the verdict is a pointer: nil is a third state
// meaning the store could not be read, which is not what this fixture shows.
var fixtureTrusts = true

var bodyFixtures = map[report.FindingKind]report.Finding{
	report.FindingEnvironmentVariable: {
		Kind:                report.FindingEnvironmentVariable,
		Summary:             "HTTPS_PROXY is set",
		Source:              report.SourceDetected,
		EnvironmentVariable: &report.EnvironmentVariable{Name: "HTTPS_PROXY", Value: "http://proxy.example:8080", Set: true},
	},
	report.FindingNameResolution: {
		Kind:    report.FindingNameResolution,
		Summary: "192.0.2.53 answered NOERROR for example.com A",
		Source:  report.SourceDetected,
		NameResolution: &report.NameResolution{
			Name: "example.com", View: report.ViewDirect, Resolver: "192.0.2.53",
			QueryType: "A", ResponseCode: "NOERROR", Addresses: []string{"192.0.2.10"}, DurationMS: 12,
		},
	},
	report.FindingTCPConnect: {
		Kind:    report.FindingTCPConnect,
		Summary: "192.0.2.10 accepted a connection on port 443",
		Source:  report.SourceDetected,
		TCPConnect: &report.TCPConnect{
			Address: "192.0.2.10", Port: 443, Outcome: report.OutcomeConnected, DurationMS: 12,
		},
	},
	// THE FIXTURE CARRIES A CHAIN RATHER THAN THE SMALLEST VALID ROW, and that
	// is the whole of OBS43 applied here. The chain is the part of this body
	// with its own nested shape, its own null, and its own block in the terminal
	// renderer; a fixture without one would satisfy this guard while leaving
	// every one of those paths unexecuted.
	report.FindingTLSHandshake: {
		Kind:    report.FindingTLSHandshake,
		Summary: "192.0.2.10 on port 443 presented 2 certificate(s)",
		Source:  report.SourceDetected,
		TLSHandshake: &report.TLSHandshake{
			Address:                    "192.0.2.10",
			Port:                       443,
			Completed:                  true,
			Version:                    "TLS 1.3",
			CipherSuite:                4865,
			CipherSuiteName:            "TLS_AES_128_GCM_SHA256",
			ALPN:                       "h2",
			ServerName:                 "example.com",
			ClientCertificateRequested: false,
			LeafFingerprintSHA256:      leafFingerprint,
			ChainComplete:              true,
			NameCovered:                nameCovered(),
			Chain: []report.Certificate{
				{
					Subject: "CN=example.com",
					Issuer:  "C=US, O=Example CA, CN=Example Issuing CA",
					// The field a modern client actually matches on - ADR47. A
					// fixture without it would leave every path that renders the
					// names unexecuted while looking complete.
					DNSNames:          []string{"example.com", "www.example.com"},
					NotBefore:         time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
					NotAfter:          time.Date(2026, 9, 1, 23, 59, 59, 0, time.UTC),
					FingerprintSHA256: leafFingerprint,
				},
				{
					Subject:           "C=US, O=Example CA, CN=Example Issuing CA",
					Issuer:            "C=US, O=Example CA, CN=Example Root CA",
					NotBefore:         time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
					NotAfter:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
					FingerprintSHA256: issuerFingerprint,
					IsCA:              true,
				},
			},
		},
	},
	// One of the six Java stores measured on the owner's machine 2026-08-18. The
	// account name is invented, as the guard in internal/guard requires of any
	// path in this repository.
	report.FindingTrustStore: {
		Kind:    report.FindingTrustStore,
		Summary: "OpenJDK 25 trusts the presented chain",
		Source:  report.SourceDetected,
		TrustStore: &report.TrustStore{
			Runtime:              "java",
			Instance:             "jdk-25",
			Variant:              "jdk",
			Architecture:         "x64",
			StorePath:            `C:\Users\jdoe\OpenJDK\jdk-25\lib\security\cacerts`,
			StoreForm:            report.StoreFile,
			TrustAnchorCount:     158,
			TrustsPresentedChain: &fixtureTrusts,
			SelectedBy:           []string{"JAVA_HOME"},
		},
	},
	// The sixth body, in the state that matters: a signer some stores here hold
	// and others do not. That is the shape a middlebox produces AND the shape a
	// company's own certificate authority produces, which is why the caveat is
	// part of the fixture rather than decoration on it.
	report.FindingSigningAuthority: {
		Kind:    report.FindingSigningAuthority,
		Summary: "C=US, O=Example CA, CN=Example Root CA signed this certificate and is an authority local to this machine",
		Source:  report.SourceDetected,
		SigningAuthority: &report.SigningAuthority{
			Issuer:          "C=US, O=Example CA, CN=Example Root CA",
			LeafFingerprint: leafFingerprint,
			HeldBy:          report.HeldBySomeStores,
			TrustingStores:  []string{"curl /usr/bin/curl"},
			RefusingStores:  []string{"java jdk-25"},
			Caveat:          "TLS inspection looks exactly like this and so does an organisation's own certificate authority",
			// LEFT nil ON PURPOSE, and it is the state nearly every run is in:
			// nothing was named. The populated shape is exercised by the test
			// below, which is a separate document rather than a second fixture
			// here - a nested object nobody ever renders is a set of key names
			// the validator never compares against anything.
			Inspection: nil,
		},
	},
	report.FindingProxyStack: {
		Kind:    report.FindingProxyStack,
		Summary: "the proxy environment variables this process was started with name proxy.example:8080 for https://api.example.com",
		Source:  report.SourceDetected,
		ProxyStack: &report.ProxyStack{
			Stack: "environment",
			Read:  true,
			Servers: []report.ProxyServer{
				{Protocol: "https", Scheme: "http", Address: "proxy.example:8080", CarriedCredentials: true},
			},
			Selected:  &report.ProxyServer{Protocol: "https", Scheme: "http", Address: "proxy.example:8080", CarriedCredentials: true},
			Bypass:    "localhost,.internal.example",
			BypassSet: true,
			BypassRules: []report.ProxyBypassRule{
				{Rule: "no_proxy_curl", Bypasses: false},
				{Rule: "no_proxy_dotnet", Bypasses: false},
			},
			// THE FIXTURE CARRIES BOTH CAVEATS AND A PAC URL ON PURPOSE, because
			// the row that is easiest to get wrong is the full one: an absent
			// key here would pass the schema and never be noticed.
			PACURL:     "http://wpad.example/proxy.pac",
			AutoDetect: report.DeterminedTrue,
			Caveats:    []string{"naming an automatic configuration script is not proof that anything uses it"},
		},
	},
	report.FindingStackDivergence: {
		Kind:    report.FindingStackDivergence,
		Summary: "comparing 2 place(s) this machine keeps proxy settings in: one stack names a proxy and another names none",
		Source:  report.SourceDerived,
		StackDivergence: &report.StackDivergence{
			Class:  "one_sided",
			Stacks: []string{"wininet", "winhttp"},
		},
	},
	// THE FIXTURE IS A SCRIPT THAT ANSWERED, not the smallest valid row, and it
	// is OBS43 applied the way the handshake fixture above applies it. An
	// unfetched script has no directives, no selected entry and no answer - so a
	// fixture built from one would satisfy this guard while leaving the nested
	// array, its null, the selected pointer and the terminal renderer's line for
	// it entirely unexecuted. Two directives rather than one, because the first
	// RECOGNISED entry is what selection means and one entry cannot show an
	// order being applied.
	report.FindingPACScript: {
		Kind:    report.FindingPACScript,
		Summary: "the PAC script at http://wpad.example/proxy.pac sends https://api.example.com through a proxy of its own choosing",
		Source:  report.SourceDetected,
		PACScript: &report.PACScript{
			URL:     "http://wpad.example/proxy.pac",
			NamedBy: []string{"wininet", "winhttp"},
			Fetched: true,
			Outcome: "answered",
			Answer:  "SOCKS5 socks.example:1080; PROXY proxy.example:8080; DIRECT",
			Directives: []report.PACDirective{
				{Kind: "SOCKS5", Endpoint: "socks.example:1080", Recognised: true},
				{Kind: "PROXY", Endpoint: "proxy.example:8080", Recognised: true},
				{Kind: "DIRECT", Recognised: true},
			},
			Selected: &report.PACDirective{Kind: "SOCKS5", Endpoint: "socks.example:1080", Recognised: true},
			// THE NAMES THE FILE SENT TO A RESOLVER, ADDED 2026-09-08 WITH THE
			// PARITY GUARD. Empty here until then, which meant no surface was
			// ever asked whether it prints them - and this is the one channel in
			// the program no guard can see, so the printing IS the answer to it.
			Asked:   []string{"intranet.example", "api.example.com"},
			Caveats: []string{},
		},
	},
	// A proxy that ASKED FOR CREDENTIALS and named two ways of supplying them,
	// which is the row this kind exists for and the one every field is exercised
	// by. Two namers, because one endpoint reached from a stack and from a
	// script is the ordinary shape and a single namer would leave the merge
	// unexecuted. Two schemes, because a proxy offering Negotiate beside Basic
	// is what a domain joined network looks like - and the second carries no
	// realm, which is the state a fixture with one scheme could not show.
	report.FindingProxyChallenge: {
		Kind:    report.FindingProxyChallenge,
		Summary: "a proxy https://api.example.com goes through demands credentials before it will pass a request",
		Source:  report.SourceDetected,
		ProxyChallenge: &report.ProxyChallenge{
			Endpoint: "proxy.example:8080",
			NamedBy:  []string{"wininet", "pac"},
			Asked:    true,
			Query:    "connect",
			Status:   407,
			Schemes: []report.ProxyAuthScheme{
				{Scheme: "Basic", Realm: "corporate proxy"},
				{Scheme: "Negotiate"},
			},
			CarriedCredentials: true,
			Caveats: []string{
				"the configuration naming this proxy carries a credential, which certdoctor cut off " +
					"where it read it and did not send",
			},
		},
	},
}

// The two fingerprints the handshake fixture is built from. They are full length
// because the contract says a fingerprint is never shortened, and they are
// constants because the leaf's has to appear in two places at once - the body
// and the first certificate of its own chain - which the core refuses to let
// disagree.
const (
	leafFingerprint   = "6153a96f6c53d1a2b9a44b1bd8dbbeaa9e1cbd0b1a25c2d0e8f4a7b3c6d9e2f0"
	issuerFingerprint = "0f2e9d6c3b7a4e8d1c0a5b7f2e9d6c3b7a4e8d1c0a5b7f2e9d6c3b7a4e8d1c0a"
)

// TestTheNamedInspectionBodyReachesBothSurfaces renders the one shape the
// fixture above deliberately leaves empty.
//
// WITHOUT IT THE NESTED KEY NAMES ARE DECLARED TWICE AND COMPARED NEVER. The
// schema is written out separately from the encoder precisely so that renaming a
// field on one side goes red - and that check only bites on a field some
// document actually carries. This is the finding where a silently missing key is
// worst: the consumer branching on it is the one deciding whether to raise an
// alarm.
//
// IT CHECKS THE TERMINAL TOO, because inviolable rule 12 asks for every finding
// to be expressible on every surface, and the terminal is where a person decides
// whether to be alarmed.
func TestTheNamedInspectionBodyReachesBothSurfaces(t *testing.T) {
	finding := bodyFixtures[report.FindingSigningAuthority]
	body := *finding.SigningAuthority
	body.Inspection = &report.Inspection{Product: "mitmproxy", MatchedAttribute: "CN"}
	finding.SigningAuthority = &body
	finding.Summary = "C=US, O=Example CA, CN=Example Root CA signed this certificate - and that issuer " +
		"names mitmproxy, a TLS inspection product, so this connection is being intercepted"

	if broken := finding.Breach(); broken != "" {
		t.Fatalf("the named fixture is not a valid finding: %s", broken)
	}

	r := everyStatusReport()
	for i := range r.Layers {
		if r.Layers[i].ID == layer.Resolution {
			r.Layers[i].Findings = []report.Finding{finding}
		}
	}

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if err := ValidateDocument(document); err != nil {
		t.Errorf("a document naming an inspection product does not match its own schema: %v", err)
	}
	if !strings.Contains(string(document), `"product": "mitmproxy"`) {
		t.Error("the product name never reached the document")
	}
	if !strings.Contains(string(document), `"matched_attribute": "CN"`) {
		t.Error("the matched attribute never reached the document")
	}

	var page strings.Builder
	if err := (Terminal{}).Render(&page, r); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if !strings.Contains(page.String(), "inspection product: mitmproxy, named in the issuer's CN") {
		t.Errorf("the terminal does not say where the name came from:\n%s", page.String())
	}
}

// TestAnUnnamedAuthorityRendersInspectionAsNull is the other direction, and it
// is the state nearly every run is in.
//
// A KEY THAT DISAPPEARS WHEN THERE IS NOTHING TO SAY IS A CONSUMER CRASH. The
// same distinction findings, selected_by and dns_names carry: an absent key says
// nobody looked, and null says we looked and there is nothing. Here it also has
// to stay OUT of the terminal, because a line reading "inspection product:" with
// nothing after it is exactly the alarm this whole slice is shaped to avoid.
func TestAnUnnamedAuthorityRendersInspectionAsNull(t *testing.T) {
	finding := bodyFixtures[report.FindingSigningAuthority]
	if finding.SigningAuthority.Inspection != nil {
		t.Fatal("the fixture is meant to be the unnamed one")
	}

	r := everyStatusReport()
	for i := range r.Layers {
		if r.Layers[i].ID == layer.Resolution {
			r.Layers[i].Findings = []report.Finding{finding}
		}
	}

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if !strings.Contains(string(document), `"inspection": null`) {
		t.Errorf("an unnamed authority did not carry a null inspection key: %s", document)
	}

	var page strings.Builder
	if err := (Terminal{}).Render(&page, r); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if strings.Contains(page.String(), "inspection product:") {
		t.Errorf("the terminal named a product where nothing was named:\n%s", page.String())
	}
}

func TestEveryKindOfFindingReachesBothSurfaces(t *testing.T) {
	if len(bodyFixtures) != len(report.AllFindingKinds) {
		t.Fatalf("%d kinds are declared and %d have a fixture here - one list was edited alone",
			len(report.AllFindingKinds), len(bodyFixtures))
	}

	for _, kind := range report.AllFindingKinds {
		finding, present := bodyFixtures[kind]
		if !present {
			t.Errorf("the kind %q has no fixture, so nothing here says it can be rendered at all", kind)
			continue
		}
		if broken := finding.Breach(); broken != "" {
			t.Errorf("the fixture for %q is not a valid finding: %s", kind, broken)
			continue
		}

		r := everyStatusReport()
		for i := range r.Layers {
			if r.Layers[i].ID == layer.Resolution {
				r.Layers[i].Findings = []report.Finding{finding}
			}
		}

		document, err := Encode(r)
		if err != nil {
			t.Errorf("%q: encoding failed: %v", kind, err)
			continue
		}
		if err := ValidateDocument(document); err != nil {
			t.Errorf("%q: the document no longer matches its own schema: %v", kind, err)
		}

		var decoded map[string]any
		if err := json.Unmarshal(document, &decoded); err != nil {
			t.Fatalf("%q: decoding: %v", kind, err)
		}
		if body := bodyOfKind(decoded, string(kind)); body == nil {
			t.Errorf("%q: the encoder produced no body under that key, so the finding is null in --json", kind)
		}

		var page strings.Builder
		if err := (Terminal{}).Render(&page, r); err != nil {
			t.Errorf("%q: the terminal renderer failed: %v", kind, err)
			continue
		}
		if !strings.Contains(page.String(), finding.Summary) {
			t.Errorf("%q: the summary never reaches the terminal page", kind)
		}
	}
}

// bodyOfKind digs out the first body sitting under the given key.
func bodyOfKind(d map[string]any, key string) map[string]any {
	for _, row := range d["layers"].([]any) {
		findings, ok := row.(map[string]any)["findings"].([]any)
		if !ok {
			continue
		}
		for _, finding := range findings {
			if body, ok := finding.(map[string]any)[key].(map[string]any); ok {
				return body
			}
		}
	}
	return nil
}
