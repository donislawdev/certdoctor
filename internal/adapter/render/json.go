package render

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// SchemaVersion is the version of the machine readable contract.
//
// People keep this output in their repositories for years, so the number is a
// promise: adding a field raises the minor, and removing one, renaming one or
// changing what one means raises the major. A consumer must ignore fields it
// does not know, and that is written in the README rather than assumed.
//
// IT STOOD AT 1.0 THROUGH THREE FIELD ADDITIONS AND STOPPED DOING SO ON
// 2026-08-10 - ADR30. The argument for holding it was that nothing is released
// and nobody consumes it, so counting up before the first user exists is noise
// dressed as diligence. That argument was granted once, in writing, as a ONE-OFF
// - docs/00 section F - and a one-off used a fourth time is not a decision any
// more, it is a habit with a footnote.
//
// So the minor moves with the field that caused it. L1 adds the reason a query
// has no response code, which is the first thing in this document a consumer
// could read as an answer when it is the absence of one.
//
// 1.4 MOVES FOR A VALUE RATHER THAN A FIELD, and that is the precedent ADR39
// set when the seventh reason for UNKNOWN arrived: a consumer branching on a
// closed list has to learn one more case, and the schema itself will not tell
// them - divergence is declared as text rather than as an enumeration, so a
// validator accepts the new class in silence. The version is the only place
// that says it out loud.
//
// 1.5 MOVES FOR SOMETHING SUBTLER AND ARGUABLY WORSE FOR A CONSUMER: no field
// changed, no value was added or removed, and two of them changed WHAT THEY
// MEAN - ADR42. agree_none now covers a run where only one lens answered, and
// one_sided covers a lens that answered without finding an address. Code
// branching on either keeps compiling and starts seeing those values in
// situations it did not before.
//
// WHY MINOR AND NOT MAJOR, since the rule above reserves major for changed
// meaning. That rule is written about FIELDS - a renamed or repurposed key
// breaks a reader outright. Here the document's shape is untouched and the
// closed list is the same seven, so a consumer that ignores what it does not
// know is unaffected and one that branches gets a truer answer in a case where
// the old one was measurably wrong. Nothing is released, which is the reason
// this costs nothing today and will not be true at the first release.
const SchemaVersion = "1.5"

// JSON renders the machine readable report.
//
// Its shape is declared twice on purpose: once as the struct tags below, which
// produce the document, and once as the schema in schema.go, which checks it.
// Two declarations of one contract is normally how drift starts. Here it is the
// point - a rename that only happens in one of them is exactly what the guard
// is for, and a schema derived from the structs would agree with them even when
// both are wrong.
type JSON struct{}

type jsonReport struct {
	// SchemaVersion is first because a consumer has to read it before trying
	// anything else with the document.
	SchemaVersion string      `json:"schema_version"`
	Tool          jsonTool    `json:"tool"`
	Run           jsonRun     `json:"run"`
	Verdict       jsonVerdict `json:"verdict"`
	Layers        []jsonLayer `json:"layers"`
	Notes         []jsonNote  `json:"notes"`
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonRun struct {
	StartedAt      string       `json:"started_at"`
	DurationMS     int64        `json:"duration_ms"`
	Target         string       `json:"target"`
	PrivilegeLevel string       `json:"privilege_level"`
	Platform       jsonPlatform `json:"platform"`
	Redacted       bool         `json:"redacted"`
	BudgetExceeded bool         `json:"budget_exceeded"`
}

type jsonPlatform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// Container is null rather than false when nothing has established it. A
	// false here would state a measurement nobody took, and the accompanying
	// note says which.
	Container *bool `json:"container"`
}

type jsonVerdict struct {
	Status   string `json:"status"`
	Sentence string `json:"sentence"`
	// ExitCode repeats what the process returns. The redundancy is deliberate:
	// a report saved to a file keeps information the process exit status
	// cannot.
	ExitCode int `json:"exit_code"`
}

type jsonLayer struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Status string  `json:"status"`
	Reason *string `json:"reason"`
	Detail *string `json:"detail"`
	// Findings is null when this layer never looked and an array when it did,
	// including when it looked and found nothing. A consumer counting rows over
	// a null would otherwise read every unwritten layer as a clean bill of
	// health.
	Findings *[]jsonFinding `json:"findings"`
}

// jsonFinding is the envelope every finding shares plus the body of its kind.
//
// The body sits under a key equal to the kind rather than under a fixed "body",
// and the redundancy is deliberate: this document gets pasted into tickets and
// has to be readable without the schema next to it.
type jsonFinding struct {
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
	Source  string `json:"source"`
	// Exactly one of these is set and the rest are null. The key equals the kind,
	// so a reader with the document and no schema can still tell which body they
	// are looking at.
	EnvironmentVariable *jsonEnvironmentVariable `json:"environment_variable"`
	NameResolution      *jsonNameResolution      `json:"name_resolution"`
	TCPConnect          *jsonTCPConnect          `json:"tcp_connect"`
}

type jsonNameResolution struct {
	Name string `json:"name"`
	View string `json:"view"`
	// Null rather than empty for the system view. An empty string would read as
	// "asked nobody" where the truth is "this system does not say whom".
	Resolver     *string `json:"resolver"`
	QueryType    *string `json:"query_type"`
	ResponseCode *string `json:"response_code"`
	// Null when there was an answer. Exactly one of this and ResponseCode is set
	// for the direct view, which the core refuses to break - ADR30.
	NoAnswer *string `json:"no_answer"`
	// Never null. A view that answered with nothing renders an empty array,
	// which is a statement - the same distinction findings themselves carry.
	Addresses  []string `json:"addresses"`
	DurationMS int64    `json:"duration_ms"`
	// Null on every direct row and on a run holding one lens - ADR37. It is the
	// class of the ONE comparison this layer makes, so it sits on the row that
	// completes it rather than being copied onto each of the others.
	Divergence *string `json:"divergence"`
}

type jsonTCPConnect struct {
	// Address is where the connection went, and is always an address rather than
	// a name - the core refuses a name here, because answering "what does this
	// resolve to" is the previous layer's job.
	Address string `json:"address"`
	Port    int    `json:"port"`
	// Outcome is from a closed list, unlike a DNS response code: this word is one
	// WE choose for what the operating system told us, so an unknown value is a
	// defect here rather than news from a network.
	Outcome    string `json:"outcome"`
	DurationMS int64  `json:"duration_ms"`
}

type jsonEnvironmentVariable struct {
	Name string `json:"name"`
	// Value is null when the variable is not set, and an empty string when it is
	// set to nothing. Those are different facts: HTTPS_PROXY= switches proxying
	// off in some tools while an absent HTTPS_PROXY leaves it alone.
	Value              *string `json:"value"`
	Set                bool    `json:"set"`
	CarriedCredentials bool    `json:"carried_credentials"`
}

type jsonNote struct {
	Kind   string  `json:"kind"`
	Layer  *string `json:"layer"`
	Field  *string `json:"field"`
	Reason *string `json:"reason"`
	Detail string  `json:"detail"`
}

// Render writes the whole document, or nothing.
func (JSON) Render(w io.Writer, r report.Report) error {
	document, err := Encode(r)
	if err != nil {
		return err
	}
	_, err = w.Write(document)
	return err
}

// Encode turns a report into the bytes of the machine readable document.
//
// It is separate from Render so that the schema guard can check the document
// without a writer, and so that the caller can hold the finished bytes before
// deciding where they go. Nothing half written ever reaches a destination.
func Encode(r report.Report) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")

	// HTML escaping is left on. Certificate subjects arrive from the network
	// and this renderer is not the place to decide what is safe to drop into a
	// page - turning it off here would buy slightly prettier output and hand a
	// footgun to whoever embeds the result somewhere else.
	if err := encoder.Encode(documentFor(r)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func documentFor(r report.Report) jsonReport {
	return jsonReport{
		SchemaVersion: SchemaVersion,
		Tool:          jsonTool{Name: r.Tool.Name, Version: r.Tool.Version},
		Run: jsonRun{
			// RFC3339Nano rather than RFC3339, which resolves to the second. Two
			// runs inside one second carried the same timestamp, so a pair of
			// saved reports could not be put in order - and putting two reports
			// side by side is what --compare exists for.
			StartedAt:      r.Run.StartedAt.UTC().Format(time.RFC3339Nano),
			DurationMS:     r.Run.Duration.Milliseconds(),
			Target:         r.Run.Target,
			PrivilegeLevel: r.Run.PrivilegeLevel.String(),
			Platform: jsonPlatform{
				OS:        r.Run.Platform.OS,
				Arch:      r.Run.Platform.Arch,
				Container: tristate(r.Run.Platform.Container),
			},
			Redacted:       r.Run.Redacted,
			BudgetExceeded: r.Run.BudgetExceeded,
		},
		Verdict: jsonVerdict{
			Status:   Label(r.Verdict.Status),
			Sentence: r.Verdict.Sentence,
			ExitCode: r.Verdict.ExitCode.Int(),
		},
		Layers: layersOf(r),
		Notes:  notesOf(r),
	}
}

func layersOf(r report.Report) []jsonLayer {
	// A non-nil empty slice encodes as [] rather than null. An empty array says
	// "there were none of these", null says "this field was never filled in",
	// and those are different claims.
	rows := make([]jsonLayer, 0, len(r.Layers))
	for _, row := range r.Layers {
		rows = append(rows, jsonLayer{
			ID:       row.ID.String(),
			Name:     row.ID.Name(),
			Status:   Label(row.Status),
			Reason:   optional(row.Reason.String()),
			Detail:   optional(row.Detail),
			Findings: findingsOf(row),
		})
	}
	return rows
}

// findingsOf keeps the difference between a layer that looked and one that did
// not, which is the difference between an empty array and a null.
//
// The pointer is what carries it. Encoding a slice directly would give null for
// both, because a slice of length zero and a nil slice encode the same way
// unless something asks first.
func findingsOf(row report.LayerResult) *[]jsonFinding {
	if row.Findings == nil {
		return nil
	}
	found := make([]jsonFinding, 0, len(row.Findings))
	for _, finding := range row.Findings {
		found = append(found, jsonFinding{
			Kind:                finding.Kind.String(),
			Summary:             finding.Summary,
			Source:              finding.Source.String(),
			EnvironmentVariable: environmentVariableOf(finding),
			NameResolution:      nameResolutionOf(finding),
			TCPConnect:          tcpConnectOf(finding),
		})
	}
	return &found
}

// tcpConnectOf encodes the connection body.
//
// Every field is present on every row: an address, a port, an outcome and a
// duration are established for each attempt, including the ones that never left
// this machine - where the duration is zero and the contract refuses anything
// else.
func tcpConnectOf(finding report.Finding) *jsonTCPConnect {
	if finding.TCPConnect == nil {
		return nil
	}
	attempt := *finding.TCPConnect
	return &jsonTCPConnect{
		Address:    attempt.Address,
		Port:       attempt.Port,
		Outcome:    attempt.Outcome.String(),
		DurationMS: attempt.DurationMS,
	}
}

func nameResolutionOf(finding report.Finding) *jsonNameResolution {
	if finding.NameResolution == nil {
		return nil
	}
	answer := *finding.NameResolution
	body := jsonNameResolution{
		Name: answer.Name,
		View: answer.View.String(),
		// Never nil, so a view that answered with nothing renders [] rather than
		// null. Null here would say "did not look", and this view did.
		Addresses:  append([]string{}, answer.Addresses...),
		DurationMS: answer.DurationMS,
	}
	// Taken through locals so each pointer is to this row's value rather than to
	// the loop's, the same shape the environment body uses one function up.
	if answer.Resolver != "" {
		resolver := answer.Resolver
		body.Resolver = &resolver
	}
	if answer.Divergence != "" {
		divergence := answer.Divergence.String()
		body.Divergence = &divergence
	}
	if answer.QueryType != "" {
		queryType := answer.QueryType
		body.QueryType = &queryType
	}
	if answer.NoAnswer != "" {
		noAnswer := answer.NoAnswer.String()
		body.NoAnswer = &noAnswer
	}
	if answer.ResponseCode != "" {
		code := answer.ResponseCode
		body.ResponseCode = &code
	}
	return &body
}

func environmentVariableOf(finding report.Finding) *jsonEnvironmentVariable {
	if finding.EnvironmentVariable == nil {
		return nil
	}
	variable := *finding.EnvironmentVariable
	body := jsonEnvironmentVariable{
		Name:               variable.Name,
		Set:                variable.Set,
		CarriedCredentials: variable.CarriedCredentials,
	}
	if variable.Set {
		// Taken through a local so that the pointer is to this row's value and
		// not to the loop's, and set even when the value is the empty string -
		// which is the case this null is meant to be told apart from.
		value := variable.Value
		body.Value = &value
	}
	return &body
}

func notesOf(r report.Report) []jsonNote {
	notes := make([]jsonNote, 0, len(r.Notes))
	for _, note := range r.Notes {
		notes = append(notes, jsonNote{
			Kind:   note.Kind.String(),
			Layer:  optional(note.Layer.String()),
			Field:  optional(note.Field),
			Reason: optional(note.Reason.String()),
			Detail: note.Detail,
		})
	}
	return notes
}

// optional turns an empty string into a JSON null, so that "this does not apply
// here" and "this is the empty string" are not the same document.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func tristate(t report.Tristate) *bool {
	switch t {
	case report.DeterminedTrue:
		yes := true
		return &yes
	case report.DeterminedFalse:
		no := false
		return &no
	default:
		return nil
	}
}
