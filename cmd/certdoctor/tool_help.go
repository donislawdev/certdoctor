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
	spec.Certificates: "CERTIFICATES",
	spec.Proxy:        "PROXY",
	spec.Tokens:       "TOKENS",
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
	b.WriteString("\nUSAGE\n")
	if len(t.Inputs) > 1 {
		writeUsageOfSeveral(&b, t)
	} else {
		writeUsageOfOne(&b, t)
	}
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

// writeUsageOfOne is the usage of a tool taking one input: pasted when it is a
// line, piped in, or named with --file.
func writeUsageOfOne(b *strings.Builder, t spec.Tool) {
	in := t.Inputs[0]
	if in.Shape == spec.Line {
		fmt.Fprintf(b, "  %s tool %s                  paste the %s, then press Enter\n", toolName, t.ID, in.Name)
	}
	fmt.Fprintf(b, "  %s tool %s < %s\n", toolName, t.ID, in.File)
	fmt.Fprintf(b, "  %s tool %s --file %s\n", toolName, t.ID, in.File)
	// An input's name is a noun, singular or plural: the token, the certificates.
	verb := "is"
	if strings.HasSuffix(in.Name, "s") {
		verb = "are"
	}
	fmt.Fprintf(b, "\n  The %s %s never taken as an argument: an argument stays in your shell's history\n",
		in.Name, verb)
	b.WriteString("  and in the list of running programs.\n")
}

// writeUsageOfSeveral is the usage of a tool taking several inputs (ADR147
// point 3): each pasted when the terminal asks for it, or piped in one line
// each, or each named with its file switch.
func writeUsageOfSeveral(b *strings.Builder, t spec.Tool) {
	names := make([]string, len(t.Inputs))
	switches := make([]string, len(t.Inputs))
	for i, in := range t.Inputs {
		names[i] = "the " + in.Name
		switches[i] = "--" + t.FileSwitch(i) + " " + in.File
	}
	command := fmt.Sprintf("%s tool %s", toolName, t.ID)
	if severalLines(t) {
		fmt.Fprintf(b, "  %-*s  paste %s, each followed by Enter\n", len(command)+12, command, joinAnd(names))
		fmt.Fprintf(b, "  %-*s  one line each: %s\n", len(command)+12, command+" < input.txt",
			strings.Join(names, ", then "))
	}
	fmt.Fprintf(b, "  %s %s\n", command, strings.Join(switches, " "))
	fmt.Fprintf(b, "\n  %s are never taken as arguments: an argument stays in your shell's history\n",
		strings.ToUpper(joinAnd(names)[:1])+joinAnd(names)[1:])
	b.WriteString("  and in the list of running programs.\n")
}

// joinAnd joins nouns with commas and a last "and".
func joinAnd(nouns []string) string {
	last := len(nouns) - 1
	if last == 0 {
		return nouns[0]
	}
	return strings.Join(nouns[:last], ", ") + " and " + nouns[last]
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
		lines = append(lines, [2]string{"--" + t.FileSwitch(i) + " <path>", "read the " + in.Name + " from this file"})
	}
	return append(lines,
		[2]string{"--request <path>", "read every input from a request document, - for standard input"},
		[2]string{"--json", "write the document for programs instead of the page for people"},
		[2]string{"--format <name>", "terminal (the default) or json"},
		[2]string{"--no-color", "no colour, as NO_COLOR asks too"},
		[2]string{"--help", "this text"},
	)
}
