package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Decode reads a document this package wrote back into the report it was
// written from - ADR121 (c), so that a report saved with --json can be written
// again in another format without running anything.
//
// THE BYTES ARE SOMEBODY ELSE'S FILE BY THE TIME THEY ARRIVE HERE (inviolable
// rule 35). The caller bounds their size before this is called, and this
// refuses everything it cannot vouch for, with a sentence saying why, rather
// than drawing a page from a document no run of this program produced.
//
// IT ACCEPTS A DOCUMENT ONLY WHEN WRITING ITS REPORT AGAIN GIVES THE SAME
// DOCUMENT, and that one rule does the work of many. The document says some
// things twice - a layer's name beside its identifier, a null beside an empty
// string, a time in one spelling of several - and a field read one way and
// written another would be a page saying something the document does not. So
// the report read back is encoded again and compared with what was read, value
// by value, and any difference is a refusal naming where it is. A field added
// to the document tomorrow is covered by that without anybody remembering it.
//
// WHAT IT CHECKS, IN ORDER, each step the precondition of the next:
//
//  1. Text: UTF-8, with or without a byte order mark. UTF-16 is refused with
//     the advice that fits how such a file is made.
//  2. The schema version, before anything else is read, because a document of
//     another version fails every later check for a reason none of them names.
//  3. The shape, through ValidateDocument - the same check a run makes before
//     printing its document.
//  4. The values, converted into a report.
//  5. The invariants every report keeps (report.Validate), which recompute the
//     verdict from the rows - a document whose sentence, status, layer or exit
//     code disagrees with its rows is refused, never drawn.
//  6. The document written again, compared with the one read.
//
// THE FIELDS OF A REPORT THAT ARE NOT PART OF THE DOCUMENT STAY ZERO, and that
// is safe rather than lossy: RefusalDetail, PlatformListCloses, FileEnd,
// UnreadableCount and SelfSigned are read while a run is being judged and
// written into its sentences, and no renderer and no invariant reads them -
// which TestASavedReportIsWrittenAgainAsTheRunWroteIt holds by rendering every
// fixture both ways.
func Decode(document []byte) (report.Report, error) {
	text, err := asText(document)
	if err != nil {
		return report.Report{}, err
	}
	if err := sameSchema(text); err != nil {
		return report.Report{}, err
	}
	if err := ValidateDocument(text); err != nil {
		return report.Report{}, fmt.Errorf("it does not have the shape of a report of schema %s:\n%w",
			SchemaVersion, fewOf(err))
	}
	var saved jsonReport
	if err := json.Unmarshal(text, &saved); err != nil {
		return report.Report{}, fmt.Errorf("it holds a value of the wrong kind for a report: %w", err)
	}
	read, err := reportFrom(saved)
	if err != nil {
		return report.Report{}, err
	}
	if err := report.Validate(read); err != nil {
		return report.Report{}, fmt.Errorf("it breaks the rules every report keeps:\n%w", fewOf(err))
	}
	if err := writesBackTheSame(text, read); err != nil {
		return report.Report{}, err
	}
	return read, nil
}

// The byte order marks a text file may start with.
var (
	markUTF8    = []byte{0xEF, 0xBB, 0xBF}
	markUTF16LE = []byte{0xFF, 0xFE}
	markUTF16BE = []byte{0xFE, 0xFF}
)

// asText hands back the document as UTF-8 without a byte order mark, or says
// why it is not.
//
// A MARK IS DROPPED RATHER THAN REFUSED: an editor that saved the file adds one,
// and nothing about the report changed. UTF-16 IS REFUSED RATHER THAN CONVERTED,
// and the advice names the commonest way it is made. Measured on this project's
// machine 2026-11-09: Windows PowerShell 5.1.26100 wrote ff fe at the start of
// a file made with >. Source: Out-File for 5.1 says "-Encoding ... The default
// value is unicode", which it defines as UTF-16 little-endian, and
// about_Redirection says > is "functionally equivalent to piping to Out-File
// with no extra parameters" (learn.microsoft.com, read 2026-11-09).
func asText(document []byte) ([]byte, error) {
	if bytes.HasPrefix(document, markUTF16LE) || bytes.HasPrefix(document, markUTF16BE) {
		return nil, errors.New("it is UTF-16 text, and certdoctor writes UTF-8. Windows PowerShell 5.1 writes " +
			"UTF-16 when output is redirected with >, so save the report with --out instead")
	}
	text := bytes.TrimPrefix(document, markUTF8)
	if len(bytes.TrimSpace(text)) == 0 {
		return nil, errors.New("it is empty")
	}
	if !utf8.Valid(text) {
		return nil, errors.New("it is not UTF-8 text, and every report certdoctor writes is")
	}
	return text, nil
}

// sameSchema refuses a document of another schema before its shape is
// checked, so the refusal names the version rather than listing every field
// the two versions spell differently.
func sameSchema(text []byte) error {
	if !json.Valid(text) {
		return errors.New("it is not JSON. Save a report with --json, or with --format json")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(text, &top); err != nil {
		return errors.New("it is JSON but not an object, and a report is one")
	}
	raw, found := top["schema_version"]
	var version string
	if !found || json.Unmarshal(raw, &version) != nil {
		return errors.New("it carries no schema_version, so nothing in it says it is a report certdoctor wrote")
	}
	if version != SchemaVersion {
		return fmt.Errorf("it was written with report schema %q and this certdoctor writes %q. Write it again "+
			"with the certdoctor that saved it - its tool.version names which one", version, SchemaVersion)
	}
	return nil
}

// fewOf keeps the first few of several joined problems.
//
// A file that is not a report at all breaks every rule there is, and printing
// each of them would bury the one sentence that matters under hundreds - the
// count of the rest is enough to say there were more.
func fewOf(err error) error {
	const shown = 5
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) <= shown {
		return err
	}
	all := joined.Unwrap()
	return errors.Join(append(all[:shown:shown], fmt.Errorf("and %d more", len(all)-shown))...)
}

// writesBackTheSame is step 6 of Decode: the report read is encoded again and
// has to give the document it was read from.
//
// THE COMPARISON IS OF VALUES, NOT BYTES. The indentation, the order of keys
// and the escaping of characters are how a document is spelled, and a report
// saved by this program and passed through a tool that reformats JSON is still
// the same report. Numbers are compared as they were written, so 443.0 and 443
// differ - this program writes the second.
func writesBackTheSame(text []byte, read report.Report) error {
	again, err := Encode(read)
	if err != nil {
		return fmt.Errorf("it could not be written again: %w", err)
	}
	was, err := valueOf(text)
	if err != nil {
		return fmt.Errorf("it could not be read again: %w", err)
	}
	is, err := valueOf(again)
	if err != nil {
		return fmt.Errorf("it could not be read again once written: %w", err)
	}
	if where := firstDifference("", was, is); where != "" {
		return fmt.Errorf("%s holds a value certdoctor would write differently, so it is not a document "+
			"certdoctor wrote", where)
	}
	return nil
}

// valueOf reads JSON into plain values, keeping numbers as they were written.
func valueOf(text []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(text))
	decoder.UseNumber()
	var value any
	err := decoder.Decode(&value)
	return value, err
}

// firstDifference names the first place two plain JSON values differ, or
// answers empty when they do not. Keys are visited in order, so the same two
// documents always name the same place.
func firstDifference(path string, was, is any) string {
	where := path
	if where == "" {
		where = "the document"
	}
	switch a := was.(type) {
	case map[string]any:
		b, ok := is.(map[string]any)
		if !ok {
			return where
		}
		keys := make([]string, 0, len(a)+len(b))
		for key := range a {
			keys = append(keys, key)
		}
		for key := range b {
			if _, seen := a[key]; !seen {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if found := firstDifference(join(path, key), a[key], b[key]); found != "" {
				return found
			}
		}
		return ""
	case []any:
		b, ok := is.([]any)
		if !ok || len(a) != len(b) {
			return where
		}
		for i := range a {
			if found := firstDifference(fmt.Sprintf("%s[%d]", where, i), a[i], b[i]); found != "" {
				return found
			}
		}
		return ""
	default:
		if was != is {
			return where
		}
		return ""
	}
}

// reportFrom turns the document's values into a report. What it checks here
// is only what a cast cannot carry - a time, a duration in range. Every value
// of a closed list is cast as it is and judged by report.Validate, which holds
// the one copy of each of those rules.
func reportFrom(saved jsonReport) (report.Report, error) {
	var problems []error
	started, err := time.Parse(time.RFC3339Nano, saved.Run.StartedAt)
	if err != nil {
		problems = append(problems, fmt.Errorf("run.started_at is not a time: %q", saved.Run.StartedAt))
	}
	duration, err := millisecondsOf("run.duration_ms", saved.Run.DurationMS)
	if err != nil {
		problems = append(problems, err)
	}

	read := report.Report{
		Tool: report.Tool{Name: saved.Tool.Name, Version: saved.Tool.Version},
		Run: report.Run{
			StartedAt:      started,
			Duration:       duration,
			Target:         saved.Run.Target,
			PrivilegeLevel: report.PrivilegeLevel(saved.Run.PrivilegeLevel),
			Platform: report.Platform{
				OS:        saved.Run.Platform.OS,
				Arch:      saved.Run.Platform.Arch,
				Container: tristateOf(saved.Run.Platform.Container),
			},
			Redacted:       saved.Run.Redacted,
			BudgetExceeded: saved.Run.BudgetExceeded,
		},
		Verdict: report.Verdict{
			Status:   status.Status(saved.Verdict.Status),
			Sentence: saved.Verdict.Sentence,
			Layer:    layer.ID(orEmpty(saved.Verdict.Layer)),
			ExitCode: exitcode.Code(saved.Verdict.ExitCode),
		},
		Notes: notesFrom(saved.Notes),
	}
	for i, row := range saved.Layers {
		converted, err := layerFrom(i, row)
		problems = append(problems, err...)
		read.Layers = append(read.Layers, converted)
	}
	if len(problems) > 0 {
		return report.Report{}, fmt.Errorf("it holds values that are not what they claim to be:\n%w",
			fewOf(errors.Join(problems...)))
	}
	return read, nil
}

// millisecondsOf turns a count of milliseconds into a duration, refusing one
// a duration cannot hold. A count past about 292 years overflows the
// nanoseconds a duration is made of and would come back negative or small.
func millisecondsOf(field string, ms int64) (time.Duration, error) {
	if ms < 0 || ms > math.MaxInt64/int64(time.Millisecond) {
		return 0, fmt.Errorf("%s is %d, which is not a length of time a run can take", field, ms)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func layerFrom(i int, row jsonLayer) (report.LayerResult, []error) {
	converted := report.LayerResult{
		ID:     layer.ID(row.ID),
		Status: status.Status(row.Status),
		Reason: status.Reason(orEmpty(row.Reason)),
		Detail: orEmpty(row.Detail),
	}
	if row.Findings == nil {
		return converted, nil
	}
	var problems []error
	converted.Findings = make([]report.Finding, 0, len(*row.Findings))
	for j, finding := range *row.Findings {
		body, err := findingFrom(fmt.Sprintf("layers[%d].findings[%d]", i, j), finding)
		problems = append(problems, err...)
		converted.Findings = append(converted.Findings, body)
	}
	return converted, problems
}

func findingFrom(where string, f jsonFinding) (report.Finding, []error) {
	chain, problems := tlsHandshakeFrom(where, f.TLSHandshake)
	return report.Finding{
		Kind:                report.FindingKind(f.Kind),
		Summary:             f.Summary,
		Source:              report.Source(f.Source),
		EnvironmentVariable: environmentVariableFrom(f.EnvironmentVariable),
		NameResolution:      nameResolutionFrom(f.NameResolution),
		TCPConnect:          tcpConnectFrom(f.TCPConnect),
		TLSHandshake:        chain,
		TrustStore:          trustStoreFrom(f.TrustStore),
		SigningAuthority:    signingAuthorityFrom(f.SigningAuthority),
		ProxyStack:          proxyStackFrom(f.ProxyStack),
		StackDivergence:     stackDivergenceFrom(f.StackDivergence),
		PACScript:           pacScriptFrom(f.PACScript),
		ProxyChallenge:      proxyChallengeFrom(f.ProxyChallenge),
	}, problems
}

func environmentVariableFrom(j *jsonEnvironmentVariable) *report.EnvironmentVariable {
	if j == nil {
		return nil
	}
	return &report.EnvironmentVariable{
		Name: j.Name, Value: orEmpty(j.Value), Set: j.Set, CarriedCredentials: j.CarriedCredentials,
	}
}

func nameResolutionFrom(j *jsonNameResolution) *report.NameResolution {
	if j == nil {
		return nil
	}
	return &report.NameResolution{
		Name:         j.Name,
		View:         report.ResolutionView(j.View),
		Resolver:     orEmpty(j.Resolver),
		QueryType:    orEmpty(j.QueryType),
		ResponseCode: orEmpty(j.ResponseCode),
		NoAnswer:     report.NoAnswer(orEmpty(j.NoAnswer)),
		Addresses:    copied(j.Addresses),
		DurationMS:   j.DurationMS,
		Divergence:   report.Divergence(orEmpty(j.Divergence)),
	}
}

func tcpConnectFrom(j *jsonTCPConnect) *report.TCPConnect {
	if j == nil {
		return nil
	}
	return &report.TCPConnect{
		Address: j.Address, Port: j.Port, Outcome: report.ConnectOutcome(j.Outcome), DurationMS: j.DurationMS,
	}
}

// tlsHandshakeFrom is the one body with values a cast cannot carry: the
// validity of each certificate is a time.
func tlsHandshakeFrom(where string, j *jsonTLSHandshake) (*report.TLSHandshake, []error) {
	if j == nil {
		return nil, nil
	}
	shake := &report.TLSHandshake{
		Address:                    j.Address,
		Port:                       j.Port,
		Completed:                  j.Completed,
		NotCompleted:               orEmpty(j.NotCompleted),
		Version:                    orEmpty(j.Version),
		CipherSuiteName:            orEmpty(j.CipherSuiteName),
		ALPN:                       orEmpty(j.ALPN),
		ServerName:                 orEmpty(j.ServerName),
		ClientCertificateRequested: j.ClientCertificateRequested != nil && *j.ClientCertificateRequested,
		LeafFingerprintSHA256:      orEmpty(j.LeafFingerprintSHA256),
		ChainComplete:              j.ChainComplete != nil && *j.ChainComplete,
		MatchesFirstAddress:        flag(j.MatchesFirstAddress),
		NameCovered:                flag(j.NameCovered),
	}
	if j.CipherSuite != nil {
		shake.CipherSuite = *j.CipherSuite
	}
	if j.Chain == nil {
		return shake, nil
	}
	var problems []error
	shake.Chain = make([]report.Certificate, 0, len(j.Chain))
	for i, c := range j.Chain {
		at := fmt.Sprintf("%s.tls_handshake.chain[%d]", where, i)
		notBefore, err := time.Parse(time.RFC3339, c.NotBefore)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s.not_before is not a time: %q", at, c.NotBefore))
		}
		notAfter, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s.not_after is not a time: %q", at, c.NotAfter))
		}
		shake.Chain = append(shake.Chain, report.Certificate{
			Subject:           c.Subject,
			Issuer:            c.Issuer,
			DNSNames:          copied(c.DNSNames),
			NotBefore:         notBefore,
			NotAfter:          notAfter,
			FingerprintSHA256: c.FingerprintSHA256,
			IsCA:              c.IsCA,
		})
	}
	return shake, problems
}

func trustStoreFrom(j *jsonTrustStore) *report.TrustStore {
	if j == nil {
		return nil
	}
	store := &report.TrustStore{
		Runtime:              j.Runtime,
		Instance:             j.Instance,
		Variant:              j.Variant,
		Architecture:         j.Architecture,
		StorePath:            j.StorePath,
		StoreForm:            report.StoreForm(j.StoreForm),
		Backend:              j.Backend,
		TrustAnchorCount:     j.TrustAnchorCount,
		TrustsPresentedChain: flag(j.TrustsPresentedChain),
		NotAssessed:          orEmpty(j.NotAssessed),
		SelectedBy:           copied(j.SelectedBy),
		TrustFailure:         report.TrustFailure(orEmpty(j.TrustFailure)),
	}
	if j.DefersTo != nil {
		store.DefersTo = &report.StoreRef{Runtime: j.DefersTo.Runtime, Instance: j.DefersTo.Instance}
	}
	if j.Fix != nil {
		store.Fix = &report.Fix{
			Command:           j.Fix.Command,
			Placeholders:      copied(j.Fix.Placeholders),
			RequiresElevation: j.Fix.RequiresElevation,
			Elevation:         orEmpty(j.Fix.Elevation),
			Caveat:            orEmpty(j.Fix.Caveat),
		}
	}
	return store
}

func signingAuthorityFrom(j *jsonSigningAuthority) *report.SigningAuthority {
	if j == nil {
		return nil
	}
	authority := &report.SigningAuthority{
		Issuer:          j.Issuer,
		LeafFingerprint: j.LeafFingerprintSHA256,
		HeldBy:          report.AnchorHolding(j.HeldBy),
		TrustingStores:  copied(j.TrustingStores),
		RefusingStores:  copied(j.RefusingStores),
		Caveat:          j.Caveat,
	}
	if j.Inspection != nil {
		authority.Inspection = &report.Inspection{
			Product: j.Inspection.Product, MatchedAttribute: j.Inspection.MatchedAttribute,
		}
	}
	return authority
}

func proxyStackFrom(j *jsonProxyStack) *report.ProxyStack {
	if j == nil {
		return nil
	}
	stack := &report.ProxyStack{
		Stack:      j.Stack,
		Read:       j.Read,
		Detail:     orEmpty(j.Detail),
		Bypass:     j.Bypass,
		BypassSet:  j.BypassSet,
		PACURL:     j.PACURL,
		AutoDetect: tristateOf(j.AutoDetect),
		Caveats:    copied(j.Caveats),
	}
	// NIL STAYS NIL, for the servers and the exception list alike: a place that
	// was not read and a place read and found empty are the two answers this
	// body exists to keep apart, and the document carries the difference as a
	// null against an empty array.
	if j.Servers != nil {
		stack.Servers = make([]report.ProxyServer, 0, len(j.Servers))
		for _, server := range j.Servers {
			stack.Servers = append(stack.Servers, proxyServerFrom(server))
		}
	}
	if j.Selected != nil {
		selected := proxyServerFrom(*j.Selected)
		stack.Selected = &selected
	}
	if j.BypassRules != nil {
		stack.BypassRules = make([]report.ProxyBypassRule, 0, len(j.BypassRules))
		for _, rule := range j.BypassRules {
			stack.BypassRules = append(stack.BypassRules, report.ProxyBypassRule{Rule: rule.Rule, Bypasses: rule.Bypasses})
		}
	}
	return stack
}

func proxyServerFrom(j jsonProxyServer) report.ProxyServer {
	return report.ProxyServer{
		Protocol: j.Protocol, Scheme: j.Scheme, Address: j.Address, CarriedCredentials: j.CarriedCredentials,
	}
}

func stackDivergenceFrom(j *jsonStackDivergence) *report.StackDivergence {
	if j == nil {
		return nil
	}
	return &report.StackDivergence{Class: j.Class, Stacks: copied(j.Stacks)}
}

func pacScriptFrom(j *jsonPACScript) *report.PACScript {
	if j == nil {
		return nil
	}
	script := &report.PACScript{
		URL:     j.URL,
		NamedBy: copied(j.NamedBy),
		Fetched: j.Fetched,
		Detail:  orEmpty(j.Detail),
		Outcome: j.Outcome,
		Answer:  j.Answer,
		Caveats: copied(j.Caveats),
	}
	// Nil stays nil for the directives and the names asked, for the reason
	// proxyStackFrom gives: nothing evaluated is a different answer from an
	// evaluation that named nothing.
	if j.Directives != nil {
		script.Directives = make([]report.PACDirective, 0, len(j.Directives))
		for _, directive := range j.Directives {
			script.Directives = append(script.Directives, pacDirectiveFrom(directive))
		}
	}
	if j.Selected != nil {
		selected := pacDirectiveFrom(*j.Selected)
		script.Selected = &selected
	}
	if j.Asked != nil {
		script.Asked = copied(j.Asked)
	}
	return script
}

func pacDirectiveFrom(j jsonPACDirective) report.PACDirective {
	return report.PACDirective{Kind: j.Kind, Endpoint: j.Endpoint, Recognised: j.Recognised}
}

func proxyChallengeFrom(j *jsonProxyChallenge) *report.ProxyChallenge {
	if j == nil {
		return nil
	}
	challenge := &report.ProxyChallenge{
		Endpoint:           j.Endpoint,
		NamedBy:            copied(j.NamedBy),
		Asked:              j.Asked,
		Detail:             orEmpty(j.Detail),
		Query:              j.Query,
		Status:             j.Status,
		CarriedCredentials: j.CarriedCredentials,
		Caveats:            copied(j.Caveats),
		Schemes:            make([]report.ProxyAuthScheme, 0, len(j.Schemes)),
	}
	for _, scheme := range j.Schemes {
		challenge.Schemes = append(challenge.Schemes, report.ProxyAuthScheme{Scheme: scheme.Scheme, Realm: scheme.Realm})
	}
	return challenge
}

func notesFrom(notes []jsonNote) []report.Note {
	read := make([]report.Note, 0, len(notes))
	for _, note := range notes {
		read = append(read, report.Note{
			Kind:   report.NoteKind(note.Kind),
			Layer:  layer.ID(orEmpty(note.Layer)),
			Field:  orEmpty(note.Field),
			Reason: status.Reason(orEmpty(note.Reason)),
			Detail: note.Detail,
		})
	}
	return read
}

// orEmpty is the inverse of optional: a null is the empty string.
func orEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// flag copies a pointer to a boolean, so the report owns what it points at.
func flag(b *bool) *bool {
	if b == nil {
		return nil
	}
	copiedValue := *b
	return &copiedValue
}

// tristateOf is the inverse of tristate.
func tristateOf(b *bool) report.Tristate {
	switch {
	case b == nil:
		return report.NotDetermined
	case *b:
		return report.DeterminedTrue
	default:
		return report.DeterminedFalse
	}
}

// copied is a list the report owns, never null: every list this document
// writes as an array is one an empty answer is written as [] for, and the
// fields that keep a null apart from an empty list are converted beside their
// own comment instead.
func copied(values []string) []string {
	return append([]string{}, values...)
}
