package main

import (
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// categoryTitles are the headings of the list of tools, one per category.
// TestEveryCategoryHasATitle holds the two lists together.
var categoryTitles = map[spec.Category]string{
	spec.Tokens: "TOKENS",
}

// toolListText is what "certdoctor tool" prints: every tool, by category, read
// from the list - a tool added there is listed here without a line written.
func toolListText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s tool - small tools for what stands around a connection\n", toolName)
	b.WriteString("\nUSAGE\n")
	fmt.Fprintf(&b, "  %s tool <name> [options]\n", toolName)
	fmt.Fprintf(&b, "  %s tool <name> --help      what a tool takes and how\n", toolName)
	width := 0
	for _, t := range spec.All {
		width = max(width, len(t.ID))
	}
	for _, c := range spec.Categories {
		fmt.Fprintf(&b, "\n%s\n", categoryTitles[c])
		for _, t := range spec.All {
			if t.Category != c {
				continue
			}
			fmt.Fprintf(&b, "  %-*s  %s\n", width, t.ID, t.Title)
			writeIndented(&b, t.Summary, 4+width)
		}
	}
	b.WriteString("\nA tool reads only what it is given, connects to nothing and changes nothing.\n")
	return b.String()
}

// toolHelpText is what "certdoctor tool <name> --help" prints.
func toolHelpText(t spec.Tool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s tool %s - %s\n\n", toolName, t.ID, t.Title)
	writeIndented(&b, t.Summary, 2)
	first := t.Inputs[0].Name
	b.WriteString("\nUSAGE\n")
	fmt.Fprintf(&b, "  %s tool %s                  paste the %s, then press Enter\n", toolName, t.ID, first)
	fmt.Fprintf(&b, "  %s tool %s < %s.txt\n", toolName, t.ID, first)
	fmt.Fprintf(&b, "  %s tool %s --file %s.txt\n", toolName, t.ID, first)
	fmt.Fprintf(&b, "\n  The %s is never taken as an argument: an argument stays in your shell's history\n", first)
	b.WriteString("  and in the list of running programs.\n")
	b.WriteString("\nOPTIONS\n")
	for _, line := range toolSwitches(t) {
		fmt.Fprintf(&b, "  %-18s  %s\n", line[0], line[1])
	}
	b.WriteString("\nEXIT CODES\n")
	b.WriteString("  0  the input was read and shown, whatever the checks say\n")
	b.WriteString("  2  the command line could not be understood\n")
	b.WriteString("  3  the input could not be used - not what the tool reads, too large, or unreadable\n")
	return b.String()
}

// writeIndented writes a sentence wrapped to the page, every line indent
// columns in.
func writeIndented(b *strings.Builder, sentence string, indent int) {
	for _, line := range render.Wrap(sentence, indent) {
		fmt.Fprintf(b, "%s%s\n", strings.Repeat(" ", indent), line)
	}
}

// toolSwitches are a tool's switches with what each does, the file switches
// read from its inputs.
func toolSwitches(t spec.Tool) [][2]string {
	var lines [][2]string
	for i, in := range t.Inputs {
		lines = append(lines, [2]string{"--" + inputSwitch(i, in) + " <path>", "read the " + in.Name + " from this file"})
	}
	return append(lines,
		[2]string{"--request <path>", "read every input from a request document, - for standard input"},
		[2]string{"--json", "write the document for programs instead of the page for people"},
		[2]string{"--format <name>", "terminal (the default) or json"},
		[2]string{"--no-color", "no colour, as NO_COLOR asks too"},
		[2]string{"--help", "this text"},
	)
}
