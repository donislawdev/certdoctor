package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

// helpGroups is the order the groups appear in. Declared rather than derived
// from the switch list so that adding a switch cannot silently reorder the page
// somebody reads every time they forget a flag name.
var helpGroups = []struct {
	name  string
	title string
}{
	{"input", "WHAT TO EXAMINE"},
	{"output", "OUTPUT"},
	{"containers", "CONTAINERS"},
	{"channels", "CHANNELS"},
	{"budget", "BUDGET"},
	{"meta", "META"},
}

// helpText renders --help.
//
// Everything in it is derived: the switches from their declarations, the exit
// codes from the frozen registry, the status names from the vocabulary. Nothing
// here restates a list that lives somewhere else, because a help page that
// restates a table is a help page that will one day describe a different tool
// than the one it ships with.
func helpText() string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s - work out why this machine, or this container, cannot reach a URL\n", toolName)
	b.WriteString("\nUSAGE\n")
	fmt.Fprintf(&b, "  %s <url> [options]\n\n", toolName)
	b.WriteString("  The URL is required and needs an explicit http:// or https:// scheme.\n")
	b.WriteString("  Without one there is no way to tell a host name from a port number.\n")

	writeSwitches(&b)
	writeExitCodes(&b)
	writeEnvironment(&b)
	writeNotBuilt(&b)

	b.WriteString("\nLICENSE\n")
	fmt.Fprintf(&b, "  GPL-3.0. Run %s --license for the full text.\n", toolName)
	b.WriteString("  Reports you generate belong to you and are not derivative works of this program.\n")
	return b.String()
}

func writeSwitches(b *strings.Builder) {
	width := 0
	for _, s := range switches {
		width = max(width, len(switchSpelling(s)))
	}
	for _, group := range helpGroups {
		fmt.Fprintf(b, "\n%s\n", group.title)
		for _, s := range switches {
			if s.group != group.name {
				continue
			}
			fmt.Fprintf(b, "  %-*s  %s\n", width, switchSpelling(s), s.summary)
		}
	}
}

// switchSpelling is how one switch is written on the page: every accepted
// spelling, then its placeholder.
func switchSpelling(s switchDecl) string {
	spellings := []string{"--" + s.name}
	for _, alias := range s.aliases {
		spellings = append(spellings, "-"+alias)
	}
	line := strings.Join(spellings, ", ")
	if s.arg != "" {
		line += " " + s.arg
	}
	return line
}

// writeExitCodes prints the frozen table, read from the registry rather than
// retyped. A help page and a pipeline disagreeing about what 5 means is the
// exact failure the single registry exists to prevent.
func writeExitCodes(b *strings.Builder) {
	b.WriteString("\nEXIT CODES\n")
	width := 0
	for _, code := range exitcode.All {
		width = max(width, len(code.Name()))
	}
	for _, code := range exitcode.All {
		fmt.Fprintf(b, "  %3d  %-*s  %s\n", code.Int(), width, code.Name(), code.Meaning())
	}
}

func writeEnvironment(b *strings.Builder) {
	b.WriteString("\nENVIRONMENT\n")
	b.WriteString("  NO_COLOR  set to any non-empty value to turn colour off.\n")
	fmt.Fprintf(b, "            It is the only variable that changes what %s does, and it changes\n", toolName)
	b.WriteString("            only how the report looks. Proxy and trust store variables are read\n")
	b.WriteString("            as things to diagnose, never as configuration for this tool.\n")
}

// writeNotBuilt says out loud which accepted options do nothing yet.
//
// An option that is accepted and quietly does nothing leaves a person waiting
// for an effect that is not coming. This section disappears one line at a time.
func writeNotBuilt(b *strings.Builder) {
	b.WriteString("\nNOT BUILT YET\n")
	b.WriteString("  No diagnostic layer is implemented. Every layer reports that it could not\n")
	fmt.Fprintf(b, "  be assessed, the run ends with %d %s, and nothing about this machine is\n",
		exitcode.Inconclusive.Int(), exitcode.Inconclusive.Name())
	b.WriteString("  claimed. The options below are accepted and refused with a reason:\n")
	for _, f := range formats {
		if !f.built {
			fmt.Fprintf(b, "    --format %-9s %s\n", f.name, f.why)
		}
	}
	b.WriteString("    --in, --image, --compare  container diagnosis is not built yet\n")
	b.WriteString("    --redact                  accepted, and there is nothing to mask yet\n")
}

// versionText renders --version.
//
// It reports every version that could change an answer, not only the tool's.
// The reason is forensic: when the same input produces a different verdict in
// six months, a CI log holding this block is the only trace of what moved. The
// shape is one stable key per line so a script can read it without a second
// output mode being invented for the purpose.
func versionText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", toolName, toolVersion)
	fmt.Fprintf(&b, "report schema: %s\n", render.SchemaVersion)
	fmt.Fprintf(&b, "go: %s\n", runtime.Version())
	fmt.Fprintf(&b, "platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return b.String()
}
