// Command sitefacts writes what the project website says about the program,
// as one JSON document on standard output.
//
// It is a build tool and never ships. The website under web/ shows every
// switch, exit code, layer, status and variable of the program, and it reads
// them from web/data/facts/certdoctor.json instead of saying them again by
// hand, so a page cannot name a switch the program no longer has. This writes
// that file, and its test fails when the file says something the program no
// longer says.
//
// IT OPENS NO FILE AND WRITES NONE. The document leaves on a pipe, as the bill
// of materials does from cmd/sbom, so the list of files allowed to write did
// not grow for a tool that is not the product.
//
// Usage, from the repository root, after a change the test points at:
//
//	go run ./cmd/sitefacts > web/data/facts/certdoctor.json
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	certdoctor "github.com/donislawdev/certdoctor"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/machine"
	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/core/switches"
)

func main() {
	if err := write(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "sitefacts: %v\n", err)
		os.Exit(1)
	}
}

// facts is the document. Its keys are what the website's templates read.
type facts struct {
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Statuses  []string    `json:"statuses"`
	Variables []string    `json:"variables"`
	Groups    []group     `json:"groups"`
	ExitCodes []exitCode  `json:"exitCodes"`
	Layers    []layerFact `json:"layers"`
}

type group struct {
	Name string `json:"name"`
	// Built is false for a group whose note in --help says it is not built.
	// The website leaves such a group out, because it shows what the program
	// does.
	Built    bool         `json:"built"`
	Switches []switchFact `json:"switches"`
}

type switchFact struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
	Arg     string   `json:"arg"`
	Summary string   `json:"summary"`
}

type exitCode struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Meaning string `json:"meaning"`
}

type layerFact struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
}

// write puts the document on w, indented, with the help's placeholders such
// as <url> kept as they are typed, because the file is read in a diff as often
// as by Hugo.
func write(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(collect())
}

func collect() facts {
	f := facts{
		Name:      certdoctor.Name,
		Version:   certdoctor.Version,
		Variables: machine.Variables(),
	}
	for _, s := range status.All {
		f.Statuses = append(f.Statuses, s.String())
	}
	for _, g := range switches.Groups {
		f.Groups = append(f.Groups, group{Name: g.Name, Built: g.Note == "", Switches: switchesOf(g.Name)})
	}
	for _, c := range exitcode.All {
		f.ExitCodes = append(f.ExitCodes, exitCode{c.Int(), c.Name(), c.Meaning()})
	}
	for _, id := range layer.All {
		f.Layers = append(f.Layers, layerFact{id.String(), id.Name(), id.Summary()})
	}
	return f
}

// switchesOf is every switch of one group, in the order the help prints them.
func switchesOf(name string) []switchFact {
	out := []switchFact{}
	for _, s := range switches.All {
		if s.Group == name {
			out = append(out, switchFact{s.Name, append([]string{}, s.Aliases...), s.Arg, s.Summary})
		}
	}
	return out
}
