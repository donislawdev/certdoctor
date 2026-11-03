//go:build acceptance

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// trustRow is what the acceptance checks read of one trust row of a report -
// the fields they ask about and nothing else, so a change to any other field
// of the contract leaves them alone.
//
// ONE DECODER FOR EVERY CHECK. Three of them were written, one per runtime,
// each reading a different handful of the same object.
type trustRow struct {
	Runtime     string   `json:"runtime"`
	Instance    string   `json:"instance"`
	SelectedBy  []string `json:"selected_by"`
	NotAssessed *string  `json:"not_assessed"`
	Trusts      *bool    `json:"trusts_presented_chain"`
	Fix         *struct {
		Command string `json:"command"`
	} `json:"fix"`
}

// String names the row the way the report does, so a failure points at it.
func (r trustRow) String() string { return strings.TrimSpace(r.Runtime + " " + r.Instance) }

// reason is why the row was not assessed, empty for a row with a verdict.
func (r trustRow) reason() string {
	if r.NotAssessed == nil {
		return ""
	}
	return *r.NotAssessed
}

// trustRowsIn is every trust row in a report.
func trustRowsIn(t *testing.T, stdout string) []trustRow {
	t.Helper()
	var document struct {
		Layers []struct {
			Findings []struct {
				TrustStore *trustRow `json:"trust_store"`
			} `json:"findings"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	var rows []trustRow
	for _, section := range document.Layers {
		for _, finding := range section.Findings {
			if finding.TrustStore != nil {
				rows = append(rows, *finding.TrustStore)
			}
		}
	}
	return rows
}

// rowsOf is the trust rows of one runtime in a report.
func rowsOf(t *testing.T, stdout, runtime string) []trustRow {
	t.Helper()
	var rows []trustRow
	for _, row := range trustRowsIn(t, stdout) {
		if row.Runtime == runtime {
			rows = append(rows, row)
		}
	}
	return rows
}
