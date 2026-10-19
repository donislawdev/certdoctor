package render

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
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
//
// 1.6 IS THE ORDINARY KIND OF MOVE AND THE FIRST ONE TO ADD A WHOLE BODY. L4
// arrives with tls_handshake: a fourth member of the union, a nested array of
// certificates inside it, and nothing removed or renamed anywhere. That is a
// minor by the rule at the top of this comment, read literally.
//
// WHAT A CONSUMER HAS TO KNOW, since a version number alone does not say it.
// The chain is on ONE row per run - ADR45 - and null on the others, which carry
// matches_first_address instead. A reader that expects a chain beside every
// handshake will find nulls and must not read them as "no certificates". The
// two fields are the same fact from opposite ends, and the reason for the shape
// is measured rather than aesthetic: every address of example.com and of
// cloudflare.com presented a byte-identical leaf, so four chains would be four
// times the page for none of the information.
//
// 1.6 ALSO CARRIES dns_names, AND THAT WAS FOLDED IN RATHER THAN COUNTED AS A
// SEVENTH - a decision with a condition, not a shortcut. ADR47 arrived while 1.6
// was still uncommitted, so no document numbered 1.6 has ever existed outside one
// working tree and no consumer could have been handed one without this field. A
// 1.7 would therefore be a version describing a document nobody ever received.
// The rule that says count up protects CONSUMERS, and here there are none.
//
// THE CONDITION EXPIRES THE MOMENT THIS IS COMMITTED: the argument is available
// exactly once, before the version leaves the tree. Anything added afterwards
// raises the minor, whatever anybody thinks about who is reading.
//
// 1.7 IS THE FIRST VERSION THE EXPIRED CONDITION APPLIES TO, and it went up
// without an argument because there is no longer one available. 1.6 left this
// tree in 72ee373, so a consumer holding it exists as far as this rule is
// concerned. 1.7 adds trust_store: a fifth member of the union, one row per
// STORE rather than per runtime - ADR48 - with no removals and no changed
// meanings, which is a MINOR by rule 2 of the contract.
//
// 1.8 ADDS TWO FIELDS TO trust_store AND BOTH ARRIVE WITH THE CODE THAT FILLS
// THEM IN - ADR30, which refuses a field declared ahead of its producer.
// trust_failure says which way a store refused, because only one of the ways is
// repaired by importing anything; fix is the command that would repair it. No
// removals and no changed meanings, so a MINOR by rule 2.
//
// A CONSUMER MUST NOT READ A NULL fix AS "NOBODY BOTHERED". It means there is
// nothing honest to say, which is every row of a green matrix and every row of a
// red one whose redness is the server's doing - measured on the bench 2026-08-19.
//
// 1.9 ADDS signing_authority: a sixth member of the union, at most one per run,
// saying who signed the leaf and how widely the stores here hold that signer -
// ADR53. No removals and no changed meanings, so a MINOR by rule 2.
//
// THE FIELD A CONSUMER WILL WANT TO MISREAD IS held_by, SO IT IS SPELLED OUT
// HERE. It is a COUNT of stores, never a conclusion about anybody's network.
// some_stores says the signer is present on this machine and did not arrive with
// every runtime - which is what TLS inspection looks like and equally what an
// organisation's own certificate authority looks like. Measured on the bench
// 2026-08-19: a middlebox and an honest internal server produced identical
// values in every field of this body. A consumer turning some_stores into an
// alert titled "interception" is making a claim this document does not make.
//
// 1.10 ADDS signing_authority.inspection: a nullable object naming the TLS
// inspection product whose name appears in the issuer, or null - P6b-K2. No
// removals and no changed meanings, so a MINOR by rule 2.
//
// THIS IS THE FIELD THE PARAGRAPH ABOVE WAS WAITING FOR, and it is the ONLY
// place in this document where an accusation may be read. held_by stays exactly
// what it was: a count. inspection is not derived from it and does not change
// it - a named product appears beside all_stores just as readily as beside
// some_stores, because how widely a machine holds a signer says nothing about
// who that signer is. A consumer wanting to alert on interception branches on
// this being non-null and on nothing else.
//
// IT IS AN OBJECT RATHER THAN A STRING, AND THAT IS A DECISION ABOUT GROWTH.
// This is the finding most likely to gain evidence later - what matched, how
// strongly it is sourced, whether more than one entry matched. Adding a member
// to an object is a MINOR; changing a declared string into an object is not,
// and would break every consumer that had read it. The same shape fix carries,
// for the same reason.
//
// A NULL HERE MEANS "NOT NAMED", NEVER "NOT INSPECTION" - the caveat beside it
// says so in words, and O11 is why the structural test never depended on this
// list in the first place.
//
// 1.11 ADDS AN EIGHTH VALUE TO THE CLOSED reason VOCABULARY: undetermined -
// ADR80, closing OBS90. No field is added or removed and no meaning changes, so
// a MINOR by rule 2 - but a consumer that branches exhaustively on reason now
// has eight cases, which is the whole point of the version being here.
//
// WHAT CHANGES FOR A CONSUMER THAT ALREADY SHIPPED. A run that used to answer
// reason: "access_denied" for L5 now answers reason: "undetermined" whenever
// every store came back unassessed and none of them timed out. Measured
// 2026-09-03 in an alpine container with git and no /etc/gitconfig, which is
// most Linux machines: the old word sent a reader to check file permissions for
// a machine on which nothing had been refused. access_denied is still declared
// and nothing produces it today; the reason that is deliberate is written where
// the word lives, in internal/core/status/reason.go.
// 1.12 ADDS TWO BODIES AT ONCE - proxy_stack and stack_divergence - which is
// L2 arriving. No removals and no changed meanings, so a MINOR by rule 2.
//
// TWO BODIES RATHER THAN ONE IS THE DECISION WORTH KNOWING ABOUT. A class of
// divergence is a sentence about a COMPARISON, so it belongs to no single place
// a machine keeps proxy settings in. L1 could hang its class on the system view
// because two views make an obvious second party; a set of stacks has no such
// party, and hanging it on one row would mean picking one - after which the
// class would disappear with that row. As a kind of its own, its ABSENCE says
// "fewer than two places could be read", which is exactly the rule ADR65 wrote.
//
// THE KEY THAT CARRIES ITS SUBJECT, AND WHY. This document now holds TWO closed
// vocabularies that both contain one_sided, and both are right: name_resolution
// .divergence compares SETS OF ADDRESSES for one name, stack_divergence.class
// compares PLACES a machine keeps proxy settings in. A consumer branching on
// either must read the key it came under and never the value alone.
//
// 1.13 ADDS THE pac_script BODY AND A NINTH reason: limit_exceeded - ADR91,
// which is the slice that fetched and ran a script. A MINOR by rule 2.
//
// THE ROW IS ABOUT THE SCRIPT AND NOT ABOUT THE PLACE THAT NAMED IT, which is
// the same argument as the two bodies above, one level along: two Windows stacks
// routinely hold one AutoConfigURL, so a row per place would fetch one file
// twice, run it twice, and print two answers that a file calling Math.random is
// entitled to make differ. A consumer reading named_by gets both namers on the
// one row instead.
//
// 1.14 ADDS THE proxy_challenge BODY AND A TENTH reason: credentials_required -
// ADR92, which is the slice that asks a proxy whether it wants a login. A MINOR
// by rule 2, and it closes the vocabulary ADR80 named: all ten now have a
// producer except access_denied, whose deliberate absence still lives in
// internal/core/status/reason.go.
//
// THE ROW IS PER ENDPOINT, and only a 407 settles anything. Measured on the
// bench before the code existed: a CONNECT to a port outside SSL_ports comes
// back 403 from a proxy that wants no credentials at all, and an allowed CONNECT
// came back 503 when the origin was unreachable. Anything but 407 leaves the
// verdict untouched and earns a caveat.
//
// 1.15 ADDS ONE MEMBER TO pac_script: asked. A MINOR by rule 2 - no removals, no
// changed meanings, and a consumer that ignores it reads 1.14 documents and 1.15
// documents identically.
//
// IT ARRIVES BECAUSE THE RESOLVER BEHIND A PAC FILE DID. Until this version
// dnsResolve, isResolvable and isInNet had nothing behind them - ADR91 part 1
// left them that way on purpose, because the allowed set is a list of PLACES and
// a resolver is on it, so every query somebody else's file provokes is permitted
// by construction and no guard sees the QUESTIONS. This field is the answer to
// that: the names are printed, so the channel is evidenced rather than invisible.
// Wiring the resolver was made conditional on the field existing.
//
// WHAT A CONSUMER THAT ALREADY SHIPPED SHOULD KNOW. Rows that used to carry a
// caveat saying a script called isInNet with nothing behind it will stop
// carrying it on machines with a resolver, and such a script can now settle a
// verdict where before it never could. A new caveat takes its place when a file
// asks about more distinct names than one evaluation may resolve.
//
// 1.16 ADDS ONE MEMBER TO tls_handshake: name_covered - ADR106, which closed
// OBS162. A MINOR by rule 2 - no removals and no changed meanings.
//
// WHAT CHANGES FOR A CONSUMER THAT ALREADY SHIPPED. Nothing used to ask whether
// the certificate was issued for the name in the URL, so wrong.host.badssl.com
// read "Everything assessed passed". L4 now fails on a name the leaf does not
// cover, so a run that used to end with code 0 or 5 against such a server ends
// with 4 - the right answer, and a different one.
//
// 2.0 IS THE FIRST MAJOR, AND IT IS ONE FOR A REMOVAL - ADR108, decided by the
// owner. layers carries six entries, L0 to L5, where it carried eight. L6 and
// L7 stood in every document as UNKNOWN "not implemented", so no run against a
// healthy target could end with code 0. The rule at the top of this comment
// reserves the major for exactly this: a consumer counting eight entries, or
// filtering on "L6", now reads a different shape rather than one more value.
// Nothing is released, so it costs nothing today. A note of kind
// not_implemented says that diagnosis from inside a container is not built.
const SchemaVersion = "2.0"

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
	TLSHandshake        *jsonTLSHandshake        `json:"tls_handshake"`
	TrustStore          *jsonTrustStore          `json:"trust_store"`
	SigningAuthority    *jsonSigningAuthority    `json:"signing_authority"`
	ProxyStack          *jsonProxyStack          `json:"proxy_stack"`
	StackDivergence     *jsonStackDivergence     `json:"stack_divergence"`
	PACScript           *jsonPACScript           `json:"pac_script"`
	ProxyChallenge      *jsonProxyChallenge      `json:"proxy_challenge"`
}

// jsonProxyStack is the seventh body: one PLACE this machine keeps proxy
// settings in, and what it says about this target.
type jsonProxyStack struct {
	Stack string `json:"stack"`
	Read  bool   `json:"read"`
	// Null when there is nothing to add. A place that would not answer must
	// carry one, which the core refuses to let through otherwise.
	Detail *string `json:"detail"`
	// Null means this place was not read; an empty array means it was read and
	// names no proxy. Those two are the pair this whole layer exists to keep
	// apart, so the difference is in the document rather than left to charity.
	Servers []jsonProxyServer `json:"servers"`
	// Which entry applies to this target, or null when none does.
	Selected *jsonProxyServer `json:"selected"`
	// The list as the place holds it. Withheld under --redact rather than
	// masked - its entries are wildcards and abbreviated networks, and a rule
	// that recognised them as machines does not exist.
	Bypass    string `json:"bypass"`
	BypassSet bool   `json:"bypass_set"`
	// Null when there is no list to read.
	BypassRules []jsonProxyBypassRule `json:"bypass_rules"`
	// Empty when this place names no automatic configuration script. Naming one
	// is a fact of configuration and never proof that anything uses it.
	PACURL string `json:"pac_url"`
	// NULL IS A THIRD ANSWER: this place does not have that setting at all.
	AutoDetect *bool `json:"auto_detect"`
	// Never null. Our sentences about what this row does not settle.
	Caveats []string `json:"caveats"`
}

// jsonPACScript is the ninth body: ONE automatic configuration script this run
// resolved, and what it says about this target.
//
// THE UNIT IS THE SCRIPT RATHER THAN THE PLACE THAT NAMED IT. Two Windows
// stacks routinely hold one AutoConfigURL, so a row per place would fetch it
// twice and print two answers a file using Math.random is entitled to make
// differ - and a script the user named on the command line would have no row at
// all, because nobody keeps proxy configuration there.
type jsonPACScript struct {
	URL string `json:"url"`
	// Never empty: a stack name, or the token for the command line. Several
	// namers of one script are one row with both names, never two rows.
	NamedBy []string `json:"named_by"`
	Fetched bool     `json:"fetched"`
	// Null when there is nothing to add. A script that was not fetched must
	// carry one, which the core refuses to let through otherwise.
	Detail *string `json:"detail"`
	// Empty when nothing was evaluated. The closed list of outcomes lives in
	// internal/core/pac beside the evaluator that produces them.
	Outcome string `json:"outcome"`
	// The answer verbatim, so a consumer can quote the file rather than our
	// reading of it. WITHHELD under --redact rather than masked: it is somebody
	// else's sentence holding a bare host:port, which no masking rule
	// recognises as a machine.
	Answer string `json:"answer"`
	// Null when nothing was evaluated; empty for every outcome but an answer.
	Directives []jsonPACDirective `json:"directives"`
	// The first entry a client would follow, or null when the answer named none
	// this program recognises.
	Selected *jsonPACDirective `json:"selected"`
	// Every distinct host this script sent to a resolver while it decided, in
	// the order it first asked about each. Null when the script never ran, empty
	// when it ran and asked about nothing. MASKED under --redact rather than
	// withheld: these are bare host names, so the pseudonym map handles them and
	// a reader keeps the count and any repetition.
	Asked []string `json:"asked"`
	// Never null. Our sentences about what this row does not settle.
	Caveats []string `json:"caveats"`
}

// jsonProxyChallenge is the tenth body: ONE proxy endpoint this run asked
// whether it wants credentials, or declined to ask.
//
// THE UNIT IS THE ENDPOINT RATHER THAN THE PLACE THAT NAMED IT, the same
// argument jsonPACScript makes about scripts, one level along: two Windows
// stacks and a script routinely arrive at one host:port, and a row per namer
// would open that connection three times and print three answers a proxy under
// load is entitled to make differ.
//
// NO CREDENTIALS ARE IN HERE AND THERE IS NOWHERE TO PUT ANY. Inviolable rule
// 17 says they never reach this document whatever --redact says, and the
// question this row records is what happens to a machine that offers none.
type jsonProxyChallenge struct {
	// The address as it was dialled, which is the address that went into the
	// allowed set. Masked under --redact through the same pseudonym map as every
	// other address in this document.
	Endpoint string `json:"endpoint"`
	// Never empty: stack names, and the token for an automatic configuration
	// script. Several namers of one endpoint are one row with all their names.
	NamedBy []string `json:"named_by"`
	Asked   bool     `json:"asked"`
	// Null when there is nothing to add. An endpoint that was not asked must
	// carry one, which the core refuses to let through otherwise.
	Detail *string `json:"detail"`
	// Empty when nothing was asked. WHICH QUESTION WAS PUT DECIDES WHAT THE
	// ANSWER MEANS - probe S15 measured a CONNECT to a non-SSL port being
	// refused by a proxy that wants no credentials at all, so a consumer that
	// cannot see the shape cannot tell that refusal from a real one.
	Query string `json:"query"`
	// Zero when nothing was asked. THE CODE AND NOT THE PROXY'S SENTENCE -
	// inviolable rule 19.
	Status int `json:"status"`
	// Empty when the proxy offered none.
	Schemes []jsonProxyAuthScheme `json:"schemes"`
	// That the configuration naming this endpoint held a credential, which was
	// cut off where it was read and NOT sent here. It is what stops this row
	// accusing a machine that has one.
	CarriedCredentials bool `json:"carried_credentials"`
	// Never null. Our sentences about what this row does not settle.
	Caveats []string `json:"caveats"`
}

// jsonProxyAuthScheme is one way a proxy offered to be told who is asking.
//
// THE TWO FIELDS ARE TREATED DIFFERENTLY UNDER --redact AND THAT IS WHY THEY
// ARE TWO. A scheme name is a token from the IANA registry, so it is an
// identifier and is printed; a realm is free text an administrator typed into
// somebody else's proxy, so it is WITHHELD rather than masked - the third field
// in this document so treated, after bypass and answer, and for the same reason.
type jsonProxyAuthScheme struct {
	Scheme string `json:"scheme"`
	Realm  string `json:"realm"`
}

type jsonPACDirective struct {
	// The keyword as the file spelled it, upper cased.
	Kind string `json:"kind"`
	// Empty for DIRECT, which names no endpoint.
	Endpoint string `json:"endpoint"`
	// An unrecognised keyword is carried rather than dropped - inviolable rule
	// 15. Dropping one would let this document say a client goes direct when
	// the file named something certdoctor failed to read.
	Recognised bool `json:"recognised"`
}

type jsonProxyServer struct {
	// Empty when the entry is the default for every protocol without one of its
	// own, which is a state rather than a gap.
	Protocol string `json:"protocol"`
	// Empty when the entry did not say. Not the same question as Protocol.
	Scheme  string `json:"scheme"`
	Address string `json:"address"`
	// Never the credential - only that one was there and was dropped.
	CarriedCredentials bool `json:"carried_credentials"`
}

type jsonProxyBypassRule struct {
	Rule     string `json:"rule"`
	Bypasses bool   `json:"bypasses"`
}

// jsonStackDivergence is the eighth body, and at most one row per run carries
// it.
//
// THE KEY CARRIES ITS SUBJECT. Two closed lists in this program both hold
// one_sided and both do so rightly, so the one about places is named for places
// - name_resolution above already holds the one about addresses.
type jsonStackDivergence struct {
	Class string `json:"class"`
	// Never fewer than two: a class is a sentence about a comparison.
	Stacks []string `json:"stacks"`
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

// jsonTLSHandshake is the fourth body: one row per address, the chain on one of
// them.
//
// ALMOST EVERYTHING HERE IS NULLABLE AND THE PATTERN IS ONE RULE, not a dozen
// decisions. A field is null when nothing established it. Address, port and
// completed are settled even for an attempt that failed, so they are always
// present; everything else was NEGOTIATED, and a version beside a handshake that
// never happened would be a measurement of something that did not occur.
//
// THE CHAIN IS NULL ON EVERY ROW BUT ONE - ADR45 - and that null does not mean
// "this server sent no certificates". It means this row is not the one carrying
// them, and matches_first_address is the field that says whether it presented
// the same leaf. A false there is the only signal this program has for a
// middlebox sitting on one path and not another, which is why it is a finding
// rather than a footnote.
type jsonTLSHandshake struct {
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Completed bool   `json:"completed"`
	// Null when the handshake completed, and the short English reason when it
	// did not. It is a field rather than only a sentence in the summary because a
	// consumer branching on why would otherwise have to parse our prose - the
	// thing this program refuses to do to anybody else's output.
	NotCompleted *string `json:"not_completed"`
	Version      *string `json:"version"`
	// CipherSuite is the IANA number that came off the wire and CipherSuiteName
	// is our rendering of it. BRANCH ON THE NUMBER - inviolable rule 19 in its
	// clearest case. The name is produced by the standard library rather than by
	// a table of ours, so it tracks somebody else's registry instead of claiming
	// to.
	CipherSuite     *uint16 `json:"cipher_suite"`
	CipherSuiteName *string `json:"cipher_suite_name"`
	// ServerName is what WE sent in SNI - ours, not theirs. It says which name
	// the chain below was chosen for, and on a virtual host that is the whole
	// difference between one certificate and another.
	ServerName *string `json:"server_name"`
	// ALPN is null when no protocol was agreed, which is a different fact from a
	// handshake that did not happen - the two are told apart by completed.
	ALPN                       *string `json:"alpn"`
	ClientCertificateRequested *bool   `json:"client_certificate_requested"`
	LeafFingerprintSHA256      *string `json:"leaf_fingerprint_sha256"`
	// ChainComplete is null on a row that carries no chain, because a row with
	// nothing to describe cannot report whether it was complete. It is a
	// STRUCTURAL verdict read from the presented bytes alone and consults no
	// trust store - ADR46, and the line on which the whole L4/L5 split stands.
	ChainComplete       *bool `json:"chain_complete"`
	MatchesFirstAddress *bool `json:"matches_first_address"`
	// NameCovered says whether THIS row's leaf covers the name the run asked
	// for, by subjectAltName - ADR106. Null where no certificate arrived. False
	// also when the name is only in the common name, which RFC 9525 section 2
	// forbids identifying a server by: the layer says WARN rather than FAIL for
	// that case, so branch on the layer's status to tell the two apart.
	NameCovered *bool `json:"name_covered"`
	// Null rather than an empty array on the rows that do not carry it. An empty
	// array would say "this server presented nothing", which is a claim about
	// somebody else's machine; null says this row is not where the chain lives.
	Chain []jsonCertificate `json:"chain"`
}

// jsonCertificate is one certificate exactly as the server presented it.
//
// NOTHING HERE SAYS WHETHER IT IS TRUSTED, and the absence is the contract
// rather than a gap - ADR46. Trust is one answer per runtime and belongs to L5.
// A trusted field here would quietly claim this machine has a single trust
// store, which is the claim the whole product exists to disprove.
type jsonCertificate struct {
	// Subject MAY BE THE EMPTY STRING and that is legal - ADR47. RFC 5280 section
	// 4.1.2.6 requires it when the identity lives only in a critical
	// subjectAltName, so a consumer must read dns_names rather than assume this
	// is always filled in.
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	// DNSNames is what a modern client actually matches on. RFC 6125 section
	// 6.4.4: a client MUST NOT match on the common name when a DNS-ID is
	// present. BRANCH ON THIS, not on the subject.
	//
	// Never null. An empty array says the certificate presents no DNS name,
	// which is a fact read off it rather than a question nobody asked.
	DNSNames []string `json:"dns_names"`
	// RFC3339 rather than the Nano the run's own timestamp uses. Certificate
	// validity is issued to the second and a string of trailing zeroes would
	// suggest a precision nobody stated.
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	// FingerprintSHA256 is the evidence inviolable rule 21 requires beside any
	// claim about interception. IT IS NEVER MASKED, under any flag: it is the
	// answer somebody came here for and it names no person, host or network.
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	IsCA              bool   `json:"is_ca"`
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

	document := documentFor(r)
	// BYTES THAT ARE NOT TEXT ARE SPELLED OUT BEFORE THE ENCODER CAN SWALLOW
	// THEM. encoding/json substitutes U+FFFD for every one of them and returns no
	// error, so a store path or a certificate subject carrying a stray byte came
	// out of --json as a value nobody has - while the terminal, from the same
	// run, printed what was really there. One run, two documents, and the machine
	// readable one was the one inventing.
	//
	// IT WALKS THE DOCUMENT RATHER THAN NAMING FIELDS, and that is the whole
	// reason it is worth its reflection. There are eighty-eight string fields
	// across seventeen structures here; a rule applied field by field is a rule
	// that will be missed by the eighty-ninth, and missing it is SILENT - the
	// value simply comes out wrong. Walking makes a new field covered by
	// existing, and forgetting impossible rather than unlikely.
	decodeSafely(reflect.ValueOf(&document).Elem())

	// HTML escaping is left on. Certificate subjects arrive from the network
	// and this renderer is not the place to decide what is safe to drop into a
	// page - turning it off here would buy slightly prettier output and hand a
	// footgun to whoever embeds the result somewhere else.
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// decodeSafely applies decodable to every string reachable from v.
//
// IT ONLY EVER WALKS THIS PACKAGE'S OWN DOCUMENT TYPES, which is what makes the
// shape below complete rather than optimistic: strings, pointers to them, slices
// of them, and structures containing them. There are no maps, no interfaces
// carrying arbitrary values and no channels in a jsonReport, and a kind arriving
// here that is none of the above is left exactly as it was - the safe direction,
// since the alternative would be a walker quietly rewriting something it does not
// understand.
func decodeSafely(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		// CanSet is false for an unexported field. There are none in this
		// document today; asking is what keeps that from becoming a panic if one
		// ever appears.
		if v.CanSet() {
			if fixed := decodable(v.String()); fixed != v.String() {
				v.SetString(fixed)
			}
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			decodeSafely(v.Elem())
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			decodeSafely(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			decodeSafely(v.Field(i))
		}
	}
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
			TLSHandshake:        tlsHandshakeOf(finding),
			TrustStore:          trustStoreOf(finding),
			SigningAuthority:    signingAuthorityOf(finding),
			ProxyStack:          proxyStackOf(finding),
			PACScript:           pacScriptOf(finding),
			ProxyChallenge:      proxyChallengeOf(finding),
			StackDivergence:     stackDivergenceOf(finding),
		})
	}
	return &found
}

// proxyStackOf encodes the proxy configuration body.
//
// NIL AND EMPTY ARE CARRIED ACROSS RATHER THAN NORMALISED, for the servers and
// for the exception list readings alike. A place that was not read names nothing
// and a place that was read may name nothing, and a conversion producing an
// empty array for both would erase the one distinction this layer is for.
//
// CAVEATS ARE NEVER NULL. An empty array says there is nothing to add, which is
// an answer; a null would read as "nobody considered it".
func proxyStackOf(finding report.Finding) *jsonProxyStack {
	if finding.ProxyStack == nil {
		return nil
	}
	stack := *finding.ProxyStack
	return &jsonProxyStack{
		Stack:       stack.Stack,
		Read:        stack.Read,
		Detail:      optional(stack.Detail),
		Servers:     proxyServersOf(stack.Servers),
		Selected:    proxyServerOrNil(stack.Selected),
		Bypass:      stack.Bypass,
		BypassSet:   stack.BypassSet,
		BypassRules: proxyBypassRulesOf(stack.BypassRules),
		PACURL:      stack.PACURL,
		AutoDetect:  tristate(stack.AutoDetect),
		// COPIED AND NEVER ALIASED, and never null: an empty array says there is
		// nothing to add, which is an answer, while a null would read as nobody
		// having considered it.
		Caveats: append([]string{}, stack.Caveats...),
	}
}

// pacScriptOf carries a script row across.
//
// NIL STAYS NIL FOR THE DIRECTIVES, and here the pair is "nothing was
// evaluated" against "it was evaluated and named no entry" - ADR20 one row
// further along than the servers below. CAVEATS ARE NEVER NULL, for the reason
// proxyStackOf gives.
func pacScriptOf(finding report.Finding) *jsonPACScript {
	if finding.PACScript == nil {
		return nil
	}
	script := *finding.PACScript
	return &jsonPACScript{
		URL:        script.URL,
		NamedBy:    append([]string{}, script.NamedBy...),
		Fetched:    script.Fetched,
		Detail:     optional(script.Detail),
		Outcome:    script.Outcome,
		Answer:     script.Answer,
		Directives: pacDirectivesOf(script.Directives),
		Selected:   pacDirectiveOrNil(script.Selected),
		Asked:      askedNamesOf(script.Asked),
		Caveats:    append([]string{}, script.Caveats...),
	}
}

// askedNamesOf carries the resolver questions across, KEEPING NULL APART FROM
// EMPTY - ADR20. A script that never ran asked nothing because nobody looked; a
// script that ran and asked nothing is a measurement, and an array is how this
// document says one was taken.
func askedNamesOf(names []string) []string {
	if names == nil {
		return nil
	}
	return append([]string{}, names...)
}

// proxyChallengeOf carries a challenge row across.
//
// CAVEATS AND SCHEMES ARE NEVER NULL, for the reason proxyStackOf gives about
// caveats: an empty array says "there is nothing to add", which is an answer,
// and a null would say the question was never asked.
func proxyChallengeOf(finding report.Finding) *jsonProxyChallenge {
	if finding.ProxyChallenge == nil {
		return nil
	}
	challenge := *finding.ProxyChallenge
	return &jsonProxyChallenge{
		Endpoint:           challenge.Endpoint,
		NamedBy:            append([]string{}, challenge.NamedBy...),
		Asked:              challenge.Asked,
		Detail:             optional(challenge.Detail),
		Query:              challenge.Query,
		Status:             challenge.Status,
		Schemes:            proxyAuthSchemesOf(challenge.Schemes),
		CarriedCredentials: challenge.CarriedCredentials,
		Caveats:            append([]string{}, challenge.Caveats...),
	}
}

func proxyAuthSchemesOf(schemes []report.ProxyAuthScheme) []jsonProxyAuthScheme {
	out := make([]jsonProxyAuthScheme, 0, len(schemes))
	for _, scheme := range schemes {
		out = append(out, jsonProxyAuthScheme{Scheme: scheme.Scheme, Realm: scheme.Realm})
	}
	return out
}

func pacDirectivesOf(directives []report.PACDirective) []jsonPACDirective {
	if directives == nil {
		return nil
	}
	out := make([]jsonPACDirective, 0, len(directives))
	for _, directive := range directives {
		out = append(out, pacDirectiveOf(directive))
	}
	return out
}

// pacDirectiveOrNil takes the pointer through a local, for the reason
// proxyServerOrNil gives: a pointer into a value that lives elsewhere is a
// pointer this document does not own.
func pacDirectiveOrNil(directive *report.PACDirective) *jsonPACDirective {
	if directive == nil {
		return nil
	}
	converted := pacDirectiveOf(*directive)
	return &converted
}

func pacDirectiveOf(directive report.PACDirective) jsonPACDirective {
	return jsonPACDirective{
		Kind:       directive.Kind,
		Endpoint:   directive.Endpoint,
		Recognised: directive.Recognised,
	}
}

func proxyServersOf(servers []report.ProxyServer) []jsonProxyServer {
	if servers == nil {
		return nil
	}
	out := make([]jsonProxyServer, 0, len(servers))
	for _, server := range servers {
		out = append(out, proxyServerOf(server))
	}
	return out
}

// proxyServerOrNil takes the pointer through a local, for the reason the
// handshake body gives: a pointer into a value that lives elsewhere is a pointer
// this document does not own.
func proxyServerOrNil(server *report.ProxyServer) *jsonProxyServer {
	if server == nil {
		return nil
	}
	encoded := proxyServerOf(*server)
	return &encoded
}

func proxyServerOf(server report.ProxyServer) jsonProxyServer {
	return jsonProxyServer{
		Protocol:           server.Protocol,
		Scheme:             server.Scheme,
		Address:            server.Address,
		CarriedCredentials: server.CarriedCredentials,
	}
}

func proxyBypassRulesOf(rules []report.ProxyBypassRule) []jsonProxyBypassRule {
	if rules == nil {
		return nil
	}
	out := make([]jsonProxyBypassRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, jsonProxyBypassRule{Rule: rule.Rule, Bypasses: rule.Bypasses})
	}
	return out
}

// stackDivergenceOf encodes the comparison body.
func stackDivergenceOf(finding report.Finding) *jsonStackDivergence {
	if finding.StackDivergence == nil {
		return nil
	}
	compared := *finding.StackDivergence
	return &jsonStackDivergence{Class: compared.Class, Stacks: append([]string{}, compared.Stacks...)}
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

// tlsHandshakeOf encodes the handshake body.
//
// THE SHAPE IS ONE RULE APPLIED THROUGHOUT: a field is null when nothing
// established it. An attempt that never completed negotiated nothing, so every
// negotiated field is null and only the address, the port, the flag saying so
// and the reason survive. Filling any of them in would be a measurement of
// something that did not happen - the same rule that keeps a duration off a
// connection which never left this machine.
//
// The chain is carried across rather than aliased, so the document holds its own
// copy of what a layer handed over. The pointers are taken through locals for
// the reason the two bodies above give: a pointer into a loop variable is a
// pointer every row shares.
func tlsHandshakeOf(finding report.Finding) *jsonTLSHandshake {
	if finding.TLSHandshake == nil {
		return nil
	}
	shake := *finding.TLSHandshake
	body := jsonTLSHandshake{
		Address:      shake.Address,
		Port:         shake.Port,
		Completed:    shake.Completed,
		NotCompleted: optional(shake.NotCompleted),
	}
	if shake.MatchesFirstAddress != nil {
		matches := *shake.MatchesFirstAddress
		body.MatchesFirstAddress = &matches
	}
	if shake.NameCovered != nil {
		covered := *shake.NameCovered
		body.NameCovered = &covered
	}
	if !shake.Completed {
		// NOTHING WAS NEGOTIATED, SO NOTHING IS FILLED IN. The core refuses a row
		// that says otherwise, and this is the same refusal expressed as a
		// document: the reader gets nulls rather than zero values that read as
		// measurements.
		return &body
	}

	body.Version = optional(shake.Version)
	body.ServerName = optional(shake.ServerName)
	body.ALPN = optional(shake.ALPN)
	body.LeafFingerprintSHA256 = optional(shake.LeafFingerprintSHA256)
	suite := shake.CipherSuite
	body.CipherSuite = &suite
	body.CipherSuiteName = optional(shake.CipherSuiteName)
	requested := shake.ClientCertificateRequested
	body.ClientCertificateRequested = &requested

	if shake.Chain == nil {
		// This row is not the one carrying the chain, so it has nothing to say
		// about whether that chain was complete either - ADR45.
		return &body
	}
	complete := shake.ChainComplete
	body.ChainComplete = &complete
	body.Chain = make([]jsonCertificate, 0, len(shake.Chain))
	for _, certificate := range shake.Chain {
		body.Chain = append(body.Chain, jsonCertificate{
			Subject:           certificate.Subject,
			Issuer:            certificate.Issuer,
			NotBefore:         certificate.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:          certificate.NotAfter.UTC().Format(time.RFC3339),
			FingerprintSHA256: certificate.FingerprintSHA256,
			// Never nil, so a certificate presenting no name renders [] rather
			// than null - the same distinction findings themselves carry.
			DNSNames: append([]string{}, certificate.DNSNames...),
			IsCA:     certificate.IsCA,
		})
	}
	return &body
}

// jsonTrustStore is the fifth body: one row per STORE, never per runtime.
//
// A consumer grouping by "runtime" gets a LIST, and that is the contract rather
// than an inconvenience - ADR48. Measured 2026-08-18: six Java stores and two
// curl binaries on one machine, and git reading a different store than the curl
// shipped beside it.
type jsonTrustStore struct {
	Runtime      string `json:"runtime"`
	Instance     string `json:"instance"`
	Variant      string `json:"variant"`
	Architecture string `json:"architecture"`

	StorePath string `json:"store_path"`
	StoreForm string `json:"store_form"`
	Backend   string `json:"backend"`
	// TrustAnchorCount is evidence and is never redacted, the same call the
	// fingerprint got in the body above.
	TrustAnchorCount int `json:"trust_anchor_count"`

	// TrustsPresentedChain is null when the store could not be assessed, and
	// NotAssessed carries the reason. THE NULL IS A THIRD STATE, not a false:
	// "does not trust" sends a person to an administrator and "could not be
	// read" sends them to a file permission.
	TrustsPresentedChain *bool   `json:"trusts_presented_chain"`
	NotAssessed          *string `json:"not_assessed"`

	// SelectedBy is never null. An empty array says nothing on this machine
	// selects this instance by default, which is true of five of the six Java
	// stores measured here - and it is an answer, not an absence.
	SelectedBy []string `json:"selected_by"`

	// TrustFailure says WHICH WAY a store refused, and is null unless one did.
	// Branch on it rather than on the sentence beside it: only unknown_authority
	// is a failure adding a certificate repairs.
	TrustFailure *string `json:"trust_failure"`
	// Fix is the command that would make this store accept this chain, and null
	// is the ordinary answer. A consumer must not read null as "we did not
	// bother" - it means there is nothing honest to say, which on a green matrix
	// is every row.
	Fix *jsonFix `json:"fix"`
}

// jsonFix is the only object in this document that describes something a person
// EXECUTES, and it is shaped so the uncomfortable half cannot be dropped.
type jsonFix struct {
	// Command carries real paths from this machine - docs/20 rule 6.
	Command string `json:"command"`
	// Placeholders is never null. An empty array means the command is ready to
	// paste; anything in it names a part the person must replace, spelled as it
	// appears in the command. It is a field rather than prose so that a consumer
	// can tell a ready command from a draft without reading English.
	Placeholders []string `json:"placeholders"`
	// RequiresElevation is answered always, and Elevation says why when it is
	// true - docs/20 rule 5 wants that known BEFORE the command runs.
	RequiresElevation bool    `json:"requires_elevation"`
	Elevation         *string `json:"elevation"`
	// Caveat is a limit worth knowing that does not stop the command working,
	// and is null when there is none.
	Caveat *string `json:"caveat"`
}

func trustStoreOf(finding report.Finding) *jsonTrustStore {
	if finding.TrustStore == nil {
		return nil
	}
	store := *finding.TrustStore
	body := jsonTrustStore{
		Runtime:              store.Runtime,
		Instance:             store.Instance,
		Variant:              store.Variant,
		Architecture:         store.Architecture,
		StorePath:            store.StorePath,
		StoreForm:            store.StoreForm.String(),
		Backend:              store.Backend,
		TrustAnchorCount:     store.TrustAnchorCount,
		TrustsPresentedChain: store.TrustsPresentedChain,
		SelectedBy:           store.SelectedBy,
	}
	if store.NotAssessed != "" {
		reason := store.NotAssessed
		body.NotAssessed = &reason
	}
	// An empty list is an answer and a null is not, so a store nothing selects
	// still gets an array - the same distinction dns_names carries in the body
	// above.
	if body.SelectedBy == nil {
		body.SelectedBy = []string{}
	}
	if store.TrustFailure != "" {
		failure := store.TrustFailure.String()
		body.TrustFailure = &failure
	}
	body.Fix = fixOf(store.Fix)
	return &body
}

// jsonSigningAuthority is the sixth body: who signed the leaf, and how widely
// the stores on this machine hold that signer. AT MOST ONE PER RUN.
//
// IT IS THE ONE BODY WHOSE VALUE IS A MEASUREMENT PEOPLE WILL WANT TO READ AS AN
// ACCUSATION, so the naming works against that on purpose. Nothing here says
// "intercepted". held_by counts stores, the issuer and the fingerprint are facts
// off the wire, and the summary beside them names both readings.
type jsonSigningAuthority struct {
	// Issuer is the distinguished name of whoever signed the leaf, and it goes
	// through redaction like every other borrowed name.
	Issuer string `json:"issuer"`
	// LeafFingerprintSHA256 is never redacted - it is the evidence inviolable
	// rule 21 requires beside any claim of this sort, and it names nobody.
	LeafFingerprintSHA256 string `json:"leaf_fingerprint_sha256"`
	// HeldBy is one of all_stores, some_stores, no_stores. BRANCH ON THIS rather
	// than on the summary, and read it as the count it is.
	HeldBy string `json:"held_by"`
	// TrustingStores and RefusingStores are never null, and an empty array is an
	// answer - the same shape selected_by and dns_names carry. Only a refusal
	// for an unknown authority appears in the second list: a store that refused
	// because something had expired holds the signer perfectly well and is
	// saying something about a clock instead.
	TrustingStores []string `json:"trusting_stores"`
	RefusingStores []string `json:"refusing_stores"`
	// Caveat is what held_by does NOT settle, and it is present on every row
	// rather than only on the awkward one. IT IS THE HEURISTIC NAMED AS A
	// HEURISTIC that inviolable rule 21 asks for, carried here so that a
	// consumer who never reads the terminal still receives it.
	Caveat string `json:"caveat"`
	// Inspection names a TLS inspection product, or is null. NULL IS THE
	// ORDINARY ANSWER and it means "not named", never "not inspection".
	//
	// BRANCH ON THIS AND ON NOTHING ELSE if you want to alert on interception.
	// Every other field in this body has the same value for a middlebox and for
	// an organisation's own certificate authority - measured, 2026-08-19.
	Inspection *jsonInspection `json:"inspection"`
}

// jsonInspection is the only place in this document where a name may be read as
// an accusation, and it is filled in only from a list carried in this program
// with a source beside every entry.
type jsonInspection struct {
	// Product is the name as this program spells it. IT IS OUR PROSE, not a
	// string off the wire, so it is not redacted and it will not vary with what
	// somebody's certificate happens to say.
	Product string `json:"product"`
	// MatchedAttribute is which part of the issuer's distinguished name carried
	// the name - "CN" or "O". It is evidence: it tells a reader where to look to
	// check this. The value itself is already in issuer and is not repeated.
	MatchedAttribute string `json:"matched_attribute"`
}

func signingAuthorityOf(finding report.Finding) *jsonSigningAuthority {
	if finding.SigningAuthority == nil {
		return nil
	}
	authority := *finding.SigningAuthority
	body := jsonSigningAuthority{
		Issuer:                authority.Issuer,
		LeafFingerprintSHA256: authority.LeafFingerprint,
		HeldBy:                authority.HeldBy.String(),
		TrustingStores:        authority.TrustingStores,
		RefusingStores:        authority.RefusingStores,
		Caveat:                authority.Caveat,
	}
	// The core's contract already refuses a nil list here, so these two lines
	// are belt to that brace: a null in this document would say "nobody looked"
	// where the truth is "nobody is on this side".
	if body.TrustingStores == nil {
		body.TrustingStores = []string{}
	}
	if body.RefusingStores == nil {
		body.RefusingStores = []string{}
	}
	if authority.Inspection != nil {
		body.Inspection = &jsonInspection{
			Product:          authority.Inspection.Product,
			MatchedAttribute: authority.Inspection.MatchedAttribute,
		}
	}
	return &body
}

// fixOf carries a remediation across, and null is the ordinary answer.
func fixOf(fix *report.Fix) *jsonFix {
	if fix == nil {
		return nil
	}
	body := jsonFix{
		Command:           fix.Command,
		Placeholders:      fix.Placeholders,
		RequiresElevation: fix.RequiresElevation,
	}
	// The same distinction selected_by carries: an empty list says there is
	// nothing to fill in, and a null would say nobody worked it out.
	if body.Placeholders == nil {
		body.Placeholders = []string{}
	}
	if fix.Elevation != "" {
		why := fix.Elevation
		body.Elevation = &why
	}
	if fix.Caveat != "" {
		caveat := fix.Caveat
		body.Caveat = &caveat
	}
	return &body
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
