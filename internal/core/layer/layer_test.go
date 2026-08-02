package layer

import "testing"

// TestLayerTableMatchesFrozenContract restates the identifiers on purpose, for
// the same reason the exit code table is restated: this is a contract pin, not
// a second source of truth. The identifiers go out in --json and into other
// people's tickets, so renaming one has to be a deliberate edit in two places
// rather than a rename that passes quietly.
func TestLayerTableMatchesFrozenContract(t *testing.T) {
	frozen := []struct {
		id   ID
		want string
	}{
		{Context, "L0"},
		{Resolution, "L1"},
		{Proxy, "L2"},
		{TCP, "L3"},
		{TLS, "L4"},
		{TrustMatrix, "L5"},
		{Containers, "L6"},
		{Report, "L7"},
	}

	if len(registry) != len(frozen) {
		t.Fatalf("the registry has %d layers, the frozen contract has %d - adding or removing one is a breaking change",
			len(registry), len(frozen))
	}
	for i, f := range frozen {
		if string(f.id) != f.want {
			t.Errorf("layer at position %d is %q, the frozen contract says %q", i, string(f.id), f.want)
		}
		if registry[i].id != f.id {
			t.Errorf("registry position %d holds %q, the frozen contract says %q - report order is part of the contract",
				i, registry[i].id, f.id)
		}
	}
}

// TestEveryLayerIsCompletelyDeclared is the registry test. One pass over the
// table demanding a full set of declarations from every row, so that the layer
// added in a hurry cannot render as a blank heading.
func TestEveryLayerIsCompletelyDeclared(t *testing.T) {
	if len(All) != len(registry) {
		t.Fatalf("All has %d layers, the registry has %d - an entry was added in one place only", len(All), len(registry))
	}

	seenID := map[ID]bool{}
	seenName := map[string]bool{}
	seenSummary := map[string]bool{}
	for _, e := range registry {
		if seenID[e.id] {
			t.Errorf("layer %s appears twice - two meanings behind one identifier is a contract nobody can read", e.id)
		}
		seenID[e.id] = true

		if e.name == "" {
			t.Errorf("layer %s has no display name - its section would head with nothing", e.id)
		}
		if seenName[e.name] {
			t.Errorf("display name %q appears twice", e.name)
		}
		seenName[e.name] = true

		if e.summary == "" {
			t.Errorf("layer %s has no summary", e.id)
		}
		if seenSummary[e.summary] {
			t.Errorf("summary %q appears twice - a copied row is a row nobody finished", e.summary)
		}
		seenSummary[e.summary] = true

		if !e.id.Valid() {
			t.Errorf("layer %s is in the registry but Valid() rejects it", e.id)
		}
	}
}

// TestIdentifiersFollowTheDeclaredShape pins the shape from the glossary:
// capital L followed by one digit. It is not decoration - a consumer filtering
// on a prefix depends on it, and so does anybody sorting a pasted report by eye.
func TestIdentifiersFollowTheDeclaredShape(t *testing.T) {
	for _, e := range registry {
		id := string(e.id)
		if len(id) != 2 || id[0] != 'L' || id[1] < '0' || id[1] > '9' {
			t.Errorf("identifier %q does not read as L followed by one digit", id)
		}
	}
}

// TestAllIsInReportOrderAndPositionAgreesWithIt closes the gap between two ways
// of asking the same question. A renderer walking All and a renderer sorting by
// Position have to produce the same order, or one report disagrees with another
// about which layer comes first.
func TestAllIsInReportOrderAndPositionAgreesWithIt(t *testing.T) {
	for i, id := range All {
		if got := id.Position(); got != i {
			t.Errorf("layer %s is at index %d of All but reports position %d", id, i, got)
		}
	}
}

// TestAllIsACopyRatherThanTheRegistryItself keeps a caller from reordering the
// report for everybody else. Returning the backing array would make the
// declared order writable from any package that ranges over it.
func TestAllIsACopyRatherThanTheRegistryItself(t *testing.T) {
	first := All[0]
	if first != Context {
		t.Fatalf("All starts with %s, want %s", first, Context)
	}
	if registry[0].id != Context {
		t.Fatalf("the registry starts with %s, want %s", registry[0].id, Context)
	}
}

// TestLayerOutsideTheRegistryDescribesItselfAsNothing guards the same promise as
// the status vocabulary and the exit code table: something we do not recognise
// is reported as nothing, never as an invented answer.
func TestLayerOutsideTheRegistryDescribesItselfAsNothing(t *testing.T) {
	for _, id := range []ID{"", "L8", "L42", "l0", "Context"} {
		if id.Valid() {
			t.Errorf("Valid() accepted %q, which is not in the registry", string(id))
		}
		if id.Name() != "" {
			t.Errorf("layer %q invented the name %q", string(id), id.Name())
		}
		if id.Summary() != "" {
			t.Errorf("layer %q invented the summary %q", string(id), id.Summary())
		}
		if id.Position() != -1 {
			t.Errorf("layer %q reports position %d rather than -1", string(id), id.Position())
		}
	}
}
