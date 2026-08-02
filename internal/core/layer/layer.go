// Package layer names the eight diagnostic layers certdoctor walks, L0 to L7.
//
// The identifiers are a public contract. They go out in --json, they head the
// sections of the terminal report, and they end up quoted in other people's
// tickets. Renaming one is a breaking change and removing one is worse: a
// pipeline filtering on "L4" would quietly match nothing and report that as
// having found no problem.
//
// Why a registry and not eight bare constants. Every entry has to carry a
// display name and a one-line summary, and the registry test refuses a row that
// is missing either. That is the mistake this shape exists to catch - the layer
// added in a hurry with an identifier and nothing else, rendering as a blank
// heading that looks like a bug in the terminal rather than a gap in the code.
//
// The order of All is the order the report presents. It is declared once here
// rather than sorted at each call site, so no two renderers can disagree about
// it and no map iteration can shuffle it between runs.
package layer

// ID is a layer identifier. Its zero value is deliberately invalid, so that a
// forgotten assignment fails a check instead of silently becoming L0.
type ID string

const (
	// Context is the machine itself.
	Context ID = "L0"
	// Resolution is what the name resolves to.
	Resolution ID = "L1"
	// Proxy is which proxy will actually be used, and by which tool.
	Proxy ID = "L2"
	// TCP is whether each resolved address accepts a connection.
	TCP ID = "L3"
	// TLS is the handshake and the chain the server presented.
	TLS ID = "L4"
	// TrustMatrix is which runtimes on this machine trust that chain. It is the
	// part no other tool does.
	TrustMatrix ID = "L5"
	// Containers is the same questions asked from inside a container.
	Containers ID = "L6"
	// Report is assembling everything above into one artefact.
	Report ID = "L7"
)

// entry is one row of the registry. Every field is mandatory and the registry
// test refuses a half-filled row.
type entry struct {
	id ID
	// name heads the layer's section in the terminal report and in md/html.
	name string
	// summary is the one-line English text saying what this layer covers. It
	// lives here rather than at the call site so that the same layer cannot be
	// described three different ways in three renderers.
	summary string
}

// registry is the single declaration of what the eight layers are, in report
// order.
var registry = []entry{
	{Context, "Context", "the machine itself - operating system, container, VPN, the clock, and the environment variables that decide trust and proxying"},
	{Resolution, "Name resolution", "what the name resolves to, seen both the way this system sees it and the way certdoctor sees it"},
	{Proxy, "Proxy", "which proxy will actually be used for this URL, and by which tool"},
	{TCP, "TCP", "whether each resolved address accepts a connection, and how it refuses when it does not"},
	{TLS, "TLS", "the handshake and the chain the server presented, including whether it was re-signed on the way here"},
	{TrustMatrix, "Trust matrix", "which runtimes on this machine trust that chain, one row per installed instance"},
	{Containers, "Containers", "the same questions asked from inside a container, and the difference against the host"},
	{Report, "Report", "assembling the verdict, the layers and the remediation commands into one artefact"},
}

// All lists every layer exactly once, in report order. Anything that needs to
// enumerate layers reads this rather than repeating the list, so a new layer
// cannot be added in one place and forgotten in another.
var All = func() []ID {
	ids := make([]ID, 0, len(registry))
	for _, e := range registry {
		ids = append(ids, e.id)
	}
	return ids
}()

func lookup(id ID) (entry, bool) {
	for _, e := range registry {
		if e.id == id {
			return e, true
		}
	}
	return entry{}, false
}

// Valid reports whether id is one of the declared layers. Use it on anything
// that crossed a boundary - a decoded report, a flag value - never on our own
// constants.
func (id ID) Valid() bool {
	_, ok := lookup(id)
	return ok
}

// Name returns the display name of id, or the empty string for a layer outside
// the registry. Callers render the empty string as nothing rather than as an
// invented name.
func (id ID) Name() string {
	e, _ := lookup(id)
	return e.name
}

// Summary returns the one-line English text for id, or the empty string for a
// layer outside the registry.
func (id ID) Summary() string {
	e, _ := lookup(id)
	return e.summary
}

// Position returns where id sits in report order, or -1 for a layer outside the
// registry.
//
// It exists so that a report assembled out of order can be put back in order
// without anybody sorting on the identifier string. That would work today and
// break at L10.
func (id ID) Position() int {
	for i, e := range registry {
		if e.id == id {
			return i
		}
	}
	return -1
}

// String makes ID printable without a conversion at every call site.
func (id ID) String() string { return string(id) }
