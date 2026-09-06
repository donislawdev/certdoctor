package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// The declared shape of the machine readable report.
//
// WHY THIS EXISTS AS DATA RATHER THAN AS A COMMENT. The regression surface has
// carried the line "--json validates against its declared schema" since before
// there was any JSON, with nothing behind it, because there was no schema to
// validate against. This is that schema. It is walked at test time against a
// real document, so the sentence stops being prose.
//
// WHY IT IS WRITTEN OUT BY HAND rather than derived from the struct tags in
// json.go. A schema generated from the structs would agree with the structs
// however wrong both were, which is the shape of a test that checks nothing.
// Two independent declarations mean a rename has to be made twice, and the day
// it is made once is the day this fails.
//
// WHAT IT DOES NOT CHECK, said here rather than discovered later: it knows
// nothing about the meaning of a value. A status outside the vocabulary, an
// exit code outside the table, a duration that is negative - all of those are
// well formed and all of them are caught somewhere else, by the core's own
// validation. This checks the shape a consumer parses against, and nothing
// more.
var schema = object(map[string]node{
	"schema_version": text(),
	"tool": object(map[string]node{
		"name":    text(),
		"version": text(),
	}),
	"run": object(map[string]node{
		"started_at":      text(),
		"duration_ms":     number(),
		"target":          text(),
		"privilege_level": text(),
		"platform": object(map[string]node{
			"os":   text(),
			"arch": text(),
			// Null means nothing established it. See the note carried in the
			// same report.
			"container": nullable(boolean()),
		}),
		"redacted":        boolean(),
		"budget_exceeded": boolean(),
	}),
	"verdict": object(map[string]node{
		"status":    text(),
		"sentence":  text(),
		"exit_code": number(),
	}),
	"layers": array(object(map[string]node{
		"id":     text(),
		"name":   text(),
		"status": text(),
		"reason": nullable(text()),
		"detail": nullable(text()),
		// Null means this layer never looked, an array means it did. The
		// difference is a claim about the machine, so it is in the contract
		// rather than left to a reader's charity.
		//
		// WHAT THIS DELIBERATELY DOES NOT ENCODE: that the body key has to match
		// the kind. That is the meaning of a value, and the paragraph at the top
		// of this file says this checks shape and nothing else. The union rule
		// itself is enforced twice on the other side - by the orchestrator when
		// a layer hands a finding over, and by the report validator before
		// anything is printed. The day a second kind exists, this declaration
		// grows a second nullable body next to the first, and that is a visible
		// edit rather than a silent gap.
		"findings": nullable(array(object(map[string]node{
			"kind":    text(),
			"summary": text(),
			"source":  text(),
			"environment_variable": nullable(object(map[string]node{
				"name": text(),
				// Null when the variable is not set. An empty string means it is
				// set to nothing, which switches proxying off in some tools.
				"value":               nullable(text()),
				"set":                 boolean(),
				"carried_credentials": boolean(),
			})),
			// The second body, and the paragraph above predicted this edit
			// exactly: the declaration grows a nullable body next to the first
			// rather than a gap appearing quietly.
			"name_resolution": nullable(object(map[string]node{
				"name": text(),
				"view": text(),
				// Null for the system view on all three: the operating system
				// resolves a name and reports neither which resolver replied, nor
				// which record type it asked for, nor what code came back.
				"resolver":      nullable(text()),
				"query_type":    nullable(text()),
				"response_code": nullable(text()),
				// Null unless this row is the system view of a run that had both
				// lenses: the class of the one comparison D13 asks for - ADR37.
				"divergence": nullable(text()),
				// Null whenever there WAS an answer, and one of the closed reasons
				// when there was not - ADR30. It sits beside response_code rather
				// than inside it because silence is a transport fact and a response
				// code is a DNS fact, and a consumer must not have to guess which
				// values came off the wire.
				"no_answer":   nullable(text()),
				"addresses":   array(text()),
				"duration_ms": number(),
			})),
			// The third body. Every field is present on every row of this kind:
			// an address, a port, an outcome from a closed list and a duration
			// are established for each attempt, including the ones that never
			// left this machine - where the duration is zero and the core
			// refuses anything else.
			"tcp_connect": nullable(object(map[string]node{
				"address":     text(),
				"port":        number(),
				"outcome":     text(),
				"duration_ms": number(),
			})),
			// The fourth body, and the first one carrying a structure rather than
			// a flat record. Almost every field is nullable and the pattern is a
			// single rule rather than a dozen judgements: null means nothing
			// established it. Address, port and completed are settled even for an
			// attempt that failed; everything else was negotiated, and a
			// negotiated value beside a handshake that never happened would be a
			// measurement of something that did not occur.
			"tls_handshake": nullable(object(map[string]node{
				"address":   text(),
				"port":      number(),
				"completed": boolean(),
				// Null when the handshake completed. It is a field of its own so
				// that a consumer branching on why does not have to read our
				// English - the thing this program refuses to do to anybody
				// else's output.
				"not_completed": nullable(text()),
				"version":       nullable(text()),
				// The number is the fact and the name is our rendering of it -
				// inviolable rule 19. Declared as a number and a string rather
				// than as one field, because that is the difference.
				"cipher_suite":                 nullable(number()),
				"cipher_suite_name":            nullable(text()),
				"server_name":                  nullable(text()),
				"alpn":                         nullable(text()),
				"client_certificate_requested": nullable(boolean()),
				"leaf_fingerprint_sha256":      nullable(text()),
				// Null on a row that carries no chain: a row with nothing to
				// describe cannot report whether it was complete.
				"chain_complete": nullable(boolean()),
				// Null on the row that carries the chain and set on every other
				// completed one - ADR45. The two are the same fact from opposite
				// ends, and the core refuses a row carrying both.
				"matches_first_address": nullable(boolean()),
				// THE FIRST NESTED ARRAY IN THIS DOCUMENT, and the case docs/18
				// named when it argued for a typed body instead of a flat pair of
				// name and value. A chain squeezed into that shape would be one
				// row per certificate field with the relationship glued into the
				// key, and this declaration would stop saying anything.
				//
				// Null rather than empty on the rows that do not carry it: an
				// empty array would claim the server presented nothing.
				"chain": nullable(array(object(map[string]node{
					// A string that MAY BE EMPTY - ADR47. RFC 5280 requires an
					// empty subject when the identity is in a critical
					// subjectAltName, so this declares the type while the
					// contract in the core declares the meaning.
					"subject": text(),
					"issuer":  text(),
					// Never null. The certificate was read either way, so an
					// empty array is a statement about it rather than about us.
					"dns_names": array(text()),
					// Reported, never judged. Whether expired means anything
					// depends on a clock this program does not own.
					"not_before": text(),
					"not_after":  text(),
					// Never null and never masked: it is the evidence inviolable
					// rule 21 requires beside any claim about interception.
					"fingerprint_sha256": text(),
					"is_ca":              boolean(),
				}))),
			})),
			// THE UNIT IS THE STORE, NOT THE RUNTIME - ADR48. A consumer
			// grouping these by "runtime" gets a list, and that is the contract:
			// measured, six Java stores and two curl binaries on one machine.
			"trust_store": nullable(object(map[string]node{
				"runtime":  text(),
				"instance": text(),
				// Empty for a runtime with no variants, and for one with them it
				// is what keeps a fix off the wrong installation.
				"variant":      text(),
				"architecture": text(),
				// Empty exactly when store_form says the store is not a file.
				"store_path": text(),
				"store_form": text(),
				// Empty where the runtime does not choose a TLS implementation.
				// Where it does, this is what decides WHICH store applies.
				"backend":            text(),
				"trust_anchor_count": number(),
				// Null is a THIRD STATE, not a false. "Does not trust the chain"
				// and "could not read the store" send a person to two different
				// places, and not_assessed is null exactly when this is not.
				"trusts_presented_chain": nullable(boolean()),
				"not_assessed":           nullable(text()),
				// Never null. An empty array says nothing selects this instance
				// by default, which is an answer rather than an absence.
				"selected_by": array(text()),
				// Null unless a store refused. Branch on THIS rather than on the
				// sentence beside it: only unknown_authority is a failure that
				// adding a certificate repairs.
				"trust_failure": nullable(text()),
				// The one object in this document describing something a person
				// EXECUTES. Null is the ordinary answer and means there is
				// nothing honest to say, never that nobody looked.
				"fix": nullable(object(map[string]node{
					"command": text(),
					// Never null. Empty says the command is ready to paste;
					// anything in it names a part the person must replace.
					"placeholders":       array(text()),
					"requires_elevation": boolean(),
					// Set exactly when requires_elevation is true - docs/20 rule
					// 5 wants the reason known before the command runs.
					"elevation": nullable(text()),
					"caveat":    nullable(text()),
				})),
			})),
			// The sixth body, and at most one row per run carries it: who
			// signed the leaf, and how widely the stores on this machine hold
			// that signer.
			"signing_authority": nullable(object(map[string]node{
				// A borrowed name, so it goes through redaction. It is evidence
				// and never a test - nothing in this program branches on the
				// text of it, because recognising interception by an issuer's
				// name would miss every appliance nobody has heard of.
				"issuer": text(),
				// Never redacted, for the same reason the chain's fingerprints
				// are not: it is what lets somebody check this claim with their
				// own tools.
				"leaf_fingerprint_sha256": text(),
				// One of all_stores, some_stores, no_stores. IT IS A COUNT AND
				// NOT A CONCLUSION - some_stores says the signer is here and did
				// not arrive with every runtime, which is what TLS inspection
				// looks like and equally what a company's own certificate
				// authority looks like. Measured, both produce this exact body.
				"held_by": text(),
				// Neither is ever null and an empty array is an answer. Only a
				// refusal for an unknown authority appears in the second: a
				// store refusing on dates holds the signer perfectly well.
				"trusting_stores": array(text()),
				"refusing_stores": array(text()),
				// What held_by does NOT settle, present on every row rather
				// than only on the awkward one. This is the heuristic named as
				// a heuristic that inviolable rule 21 requires, and it is here
				// rather than only in the terminal because a consumer of this
				// document is the reader most likely to raise an alarm from a
				// single value.
				"caveat": text(),
				// The ONLY field in this document an alert may branch on for
				// interception, and null is the ordinary answer - meaning "not
				// named", never "not inspection". Declared as an object rather
				// than a name so that later evidence can join it without
				// changing the type of anything already published.
				"inspection": nullable(object(map[string]node{
					"product":           text(),
					"matched_attribute": text(),
				})),
			})),
			// The seventh body: one PLACE this machine keeps proxy settings in.
			// The unit is the place and not the program, because several
			// programs read one place and one program reads two - a document
			// organised by program would repeat itself and still miss the case
			// this layer exists for.
			"proxy_stack": nullable(object(map[string]node{
				"stack": text(),
				"read":  boolean(),
				// Null when there is nothing to add. A false read WITHOUT one is
				// refused by the core: a place that would not answer has to say
				// why, or the row is a defect of ours wearing a fact's clothes.
				"detail": nullable(text()),
				// Null means this place was not read; an empty array means it was
				// read and names no proxy - ADR20, and here that is the one
				// distinction the whole layer exists to keep.
				"servers": nullable(array(object(map[string]node{
					// Empty when the entry is the default for every protocol
					// without one of its own, which is a real state and not a
					// gap.
					"protocol": text(),
					// Empty when the entry did not say. It is NOT the protocol
					// above: an https request through a proxy spoken to over
					// http is the ordinary CONNECT case.
					"scheme":  text(),
					"address": text(),
					// Never the credential itself - ADR89. The fact that one was
					// carried is half the answer to a 407 and the half that can
					// be said out loud.
					"carried_credentials": boolean(),
				}))),
				// Which entry applies to THIS target, or null when none does.
				// A consumer branching on the proxy in use reads this rather
				// than guessing from the list.
				"selected": nullable(object(map[string]node{
					"protocol":            text(),
					"scheme":              text(),
					"address":             text(),
					"carried_credentials": boolean(),
				})),
				// The exception list as this place holds it, and bypass_set is
				// what keeps "no list" apart from "a list excusing nothing".
				// Under --redact the text is withheld outright rather than
				// masked: its entries are wildcards and abbreviated networks, so
				// a masking rule would leave most of them untouched while the
				// document says it is redacted.
				"bypass":     text(),
				"bypass_set": boolean(),
				// Null when there is no list. ONE LIST, SEVERAL ANSWERS: the
				// same NO_PROXY is read differently by different runtimes, so a
				// single boolean here would be true of one program on the
				// machine and false of another.
				"bypass_rules": nullable(array(object(map[string]node{
					"rule":     text(),
					"bypasses": boolean(),
				}))),
				// Empty when this place names no automatic configuration script.
				// NAMING ONE IS NOT PROOF ANYTHING USES IT - measured, OBS111 -
				// and the caveat travels in the array below rather than being
				// left to the reader.
				"pac_url": text(),
				// NULL IS A THIRD ANSWER: this place has no such setting to
				// report. The WinHTTP structure has no auto-detect field at all
				// while the Internet Settings view has one that can be off, and
				// reporting both as false would claim a question was asked that
				// never was.
				"auto_detect": nullable(boolean()),
				// Never null. Our own sentences about what this row does not
				// settle; an empty array says there is nothing to add.
				"caveats": array(text()),
			})),
			// The eighth body, and at most one row per run carries it: how the
			// places above differ from each other.
			//
			// THE KEY CARRIES ITS SUBJECT ON PURPOSE. proxy.Divergence and
			// report.Divergence are two closed lists and both hold one_sided,
			// both rightly - the shape of the question is the same and the
			// subject is not. A key called "divergence" would put two
			// vocabularies behind one name, and name_resolution above already
			// holds the other one.
			"stack_divergence": nullable(object(map[string]node{
				"class": text(),
				// Never fewer than two, which the core refuses: a class is a
				// sentence about a comparison, and a comparison needs two
				// parties.
				"stacks": array(text()),
			})),
		}))),
	})),
	"notes": array(object(map[string]node{
		"kind":   text(),
		"layer":  nullable(text()),
		"field":  nullable(text()),
		"reason": nullable(text()),
		"detail": text(),
	})),
})

// kind is the JSON type a node accepts.
type kind uint8

const (
	kindObject kind = iota
	kindArray
	kindString
	kindNumber
	kindBool
)

func (k kind) String() string {
	switch k {
	case kindObject:
		return "an object"
	case kindArray:
		return "an array"
	case kindString:
		return "a string"
	case kindNumber:
		return "a number"
	default:
		return "a boolean"
	}
}

// node is one declared position in the document.
//
// Every declared field is required. That is stricter than most schemas and it
// is the right default here: this program controls both ends, so a field that
// is sometimes absent is a field somebody forgot rather than a field that is
// optional. Optionality is expressed as a null value, which keeps the key in
// place and the consumer's parsing simple.
type node struct {
	kind     kind
	nullable bool
	fields   map[string]node
	item     *node
}

func object(fields map[string]node) node { return node{kind: kindObject, fields: fields} }
func array(item node) node               { return node{kind: kindArray, item: &item} }
func text() node                         { return node{kind: kindString} }
func number() node                       { return node{kind: kindNumber} }
func boolean() node                      { return node{kind: kindBool} }

func nullable(n node) node {
	n.nullable = true
	return n
}

// ValidateDocument checks bytes produced by this package against the declared
// schema and returns every problem it finds rather than the first.
//
// The caller is a test and, for the entry point, a last check before the
// document leaves the process. A document that does not match its own declared
// schema is an internal failure and must not be printed: whoever receives it
// would parse it against the contract we published and get a different answer
// than we did.
//
// IT PARSES THE DOCUMENT A SECOND TIME AND THAT COSTS MEMORY, WHICH IS NAMED
// HERE SO IT CAN BE ADDED UP RATHER THAN DISCOVERED. Unmarshalling into `any`
// builds a full tree of map[string]any and []any, several times the size of the
// bytes it came from; alive at the same time are those bytes, the encoder's
// buffer, and the report.Report they were built from. Call it four times the
// document.
//
// IT IS A DELIBERATE COST RATHER THAN AN OVERSIGHT: this is the last gate before
// a contract leaves the process, and checking it against a tree the caller
// handed us would be checking our own idea of the document rather than the
// document. At today's size - a report of a few tens of kilobytes - the whole
// multiple is noise. It is written down because the thing that would make it
// matter is a report driven very large by somebody else's configuration, and
// that pressure now has a bound at its source: resolve.MaxNameservers.
func ValidateDocument(document []byte) error {
	var decoded any
	if err := json.Unmarshal(document, &decoded); err != nil {
		return fmt.Errorf("the document is not valid JSON: %w", err)
	}
	problems := schema.check("", decoded)
	sort.Slice(problems, func(i, j int) bool { return problems[i].Error() < problems[j].Error() })
	return errors.Join(problems...)
}

func (n node) check(path string, value any) []error {
	where := path
	if where == "" {
		where = "the document"
	}

	if value == nil {
		if n.nullable {
			return nil
		}
		return []error{fmt.Errorf("%s is null and the schema does not allow that", where)}
	}

	switch n.kind {
	case kindObject:
		return n.checkObject(path, where, value)
	case kindArray:
		return n.checkArray(path, where, value)
	case kindString:
		return expect[string](where, value, n.kind)
	case kindNumber:
		return expect[float64](where, value, n.kind)
	default:
		return expect[bool](where, value, n.kind)
	}
}

func (n node) checkObject(path, where string, value any) []error {
	fields, ok := value.(map[string]any)
	if !ok {
		return mismatch(where, value, n.kind)
	}

	var problems []error
	for name, declared := range n.fields {
		present, found := fields[name]
		if !found {
			problems = append(problems, fmt.Errorf("%s has no %q, which the schema declares", where, name))
			continue
		}
		problems = append(problems, declared.check(join(path, name), present)...)
	}
	for name := range fields {
		if _, declared := n.fields[name]; !declared {
			problems = append(problems, fmt.Errorf(
				"%s carries %q, which the schema does not declare - a field nobody declared is a field nobody versioned", where, name))
		}
	}
	return problems
}

func (n node) checkArray(path, where string, value any) []error {
	items, ok := value.([]any)
	if !ok {
		return mismatch(where, value, n.kind)
	}
	var problems []error
	for i, item := range items {
		problems = append(problems, n.item.check(fmt.Sprintf("%s[%d]", path, i), item)...)
	}
	return problems
}

func expect[T any](where string, value any, want kind) []error {
	if _, ok := value.(T); ok {
		return nil
	}
	return mismatch(where, value, want)
}

func mismatch(where string, value any, want kind) []error {
	return []error{fmt.Errorf("%s is %T, the schema declares %s", where, value, want)}
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
