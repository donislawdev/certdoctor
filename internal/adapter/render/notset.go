package render

import "github.com/donislawdev/certdoctor/internal/core/report"

// notSetLabel names the paragraph that lists the variables nobody set - ADR137.
//
// THE THREE PAGES FOR PEOPLE SHARE IT, so a reader moving from the console to a
// pasted report meets the same words for the same fact.
const notSetLabel = "not set"

// splitNotSet takes the variables that are simply absent out of a layer's
// findings, and keeps every other finding in its order.
//
// WHY THEY ARE TAKEN OUT AT ALL. L0 asks about twenty-five variables and most
// machines set few of them - measured on the development machine on 2026-11-12:
// one set, and twenty-four rows each saying "is not set", so the row that
// mattered was one line among twenty-five. Printed as one paragraph of names,
// the set variables stand alone and every absent one still appears.
//
// ONLY A FINDING THAT SAYS NOTHING BUT ITS NAME GOES INTO THE PARAGRAPH: an
// absent variable, known from the default, whose sentence is exactly the one L0
// writes for that. Anything else - a variable set to nothing, a sentence that
// says more - keeps its own row, because the paragraph prints names and would
// silently drop whatever else was said.
//
// The machine readable document is not touched. It keeps one entry per
// variable, which is what a program reading it counts on.
func splitNotSet(findings []report.Finding) (rows []report.Finding, notSet []string) {
	for _, finding := range findings {
		if saysOnlyNotSet(finding) {
			notSet = append(notSet, finding.EnvironmentVariable.Name)
			continue
		}
		rows = append(rows, finding)
	}
	return rows, notSet
}

// saysOnlyNotSet is the condition above, kept apart so each of its parts can be
// read on its own line.
func saysOnlyNotSet(finding report.Finding) bool {
	variable := finding.EnvironmentVariable
	return variable != nil && !variable.Set &&
		finding.Source == report.SourceDefault &&
		finding.Summary == report.NotSetSummary(variable.Name)
}
