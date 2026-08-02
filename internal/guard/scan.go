package guard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Finding is one violation of a structural rule. It carries a position an editor
// can jump to, because a guard that reports only "something is wrong" costs more
// to act on than it saves.
type Finding struct {
	// File is relative to the module root and uses forward slashes, so a finding
	// reads the same on Windows and in a Linux CI log.
	File   string
	Line   int
	Detail string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Detail)
}

// sourceFile is one parsed Go file together with the position information needed
// to turn a node back into a line number.
type sourceFile struct {
	rel    string
	isTest bool
	fset   *token.FileSet
	file   *ast.File
}

// tree is every Go file that belongs to this module.
type tree struct {
	root       string
	modulePath string
	files      []sourceFile
}

// skippedDirs are the directory names never walked.
//
// testdata holds the deliberately broken fixtures these guards are tested
// against. Scanning it live would make every guard fail on its own canaries.
//
// internal_tools is skipped twice over - by name here and by the nested-module
// rule below - and that repetition is deliberate. It is outside version control,
// so it exists on the owner's machine and not in a fresh clone. A guard that
// walked it would be red locally and green in CI, which teaches that a red guard
// is local noise. The nested-module rule alone would miss a stray .go file
// dropped there without a go.mod of its own.
var skippedDirs = map[string]bool{
	".git":           true,
	"testdata":       true,
	"internal_tools": true,
	"vendor":         true,
}

// loadModule parses every Go file belonging to this module.
//
// Every failure is returned rather than skipped. A scanner that quietly steps
// over a file it could not open reports "clean" about a file it never saw, which
// is forbidden silence dressed up as a pass.
func loadModule() (tree, error) {
	root, modulePath, err := findModuleRoot()
	if err != nil {
		return tree{}, err
	}

	fset := token.NewFileSet()
	var files []sourceFile

	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %s: %w", path, err)
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			// A directory carrying its own go.mod is a different module. Its
			// rules are its own and its files are not ours to police.
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		parsed, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", path, parseErr)
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return fmt.Errorf("locating %s relative to the module root: %w", path, relErr)
		}
		files = append(files, sourceFile{
			rel:    filepath.ToSlash(rel),
			isTest: strings.HasSuffix(d.Name(), "_test.go"),
			fset:   fset,
			file:   parsed,
		})
		return nil
	})
	if walkErr != nil {
		return tree{}, walkErr
	}

	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	return tree{root: root, modulePath: modulePath, files: files}, nil
}

// findModuleRoot walks up from the working directory to the directory holding
// go.mod and reads the module path out of it. The path is read rather than
// hardcoded so that renaming the module cannot leave a guard silently matching
// nothing.
func findModuleRoot() (root, modulePath string, err error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	for {
		candidate := filepath.Join(dir, "go.mod")
		if content, readErr := os.ReadFile(candidate); readErr == nil {
			path, parseErr := modulePathFrom(string(content))
			if parseErr != nil {
				return "", "", fmt.Errorf("reading %s: %w", candidate, parseErr)
			}
			return dir, path, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", fmt.Errorf("no go.mod found above the working directory")
		}
		dir = parent
	}
}

func modulePathFrom(goMod string) (string, error) {
	for _, line := range strings.Split(goMod, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			path := strings.TrimSpace(rest)
			if path == "" {
				return "", fmt.Errorf("the module directive has no path")
			}
			return path, nil
		}
	}
	return "", fmt.Errorf("no module directive")
}

// declaredImport is one import path together with the line it sits on.
type declaredImport struct {
	path string
	line int
}

// importsOf returns the import paths declared by a file.
//
// This reads what the file DECLARES, not what the build actually links. The two
// differ: a reference the linker drops leaves the declaration in place. The
// declaration is the one that matters for erosion, because that is how the layer
// rule breaks - one innocent looking import at a time, each unused on the day it
// was added.
func importsOf(sf sourceFile) []declaredImport {
	out := make([]declaredImport, 0, len(sf.file.Imports))
	for _, spec := range sf.file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			// An import path the parser accepted but strconv cannot unquote
			// should not exist. Report the raw text rather than dropping it.
			path = spec.Path.Value
		}
		out = append(out, declaredImport{path: path, line: sf.fset.Position(spec.Pos()).Line})
	}
	return out
}

// literalValue turns a Go string or rune literal back into the value it denotes,
// so that the hex form, the octal form, the \u form and a raw byte written
// straight into the source are all seen as one thing. A literal that will not
// unquote is returned as written, which errs towards reporting rather than
// towards silence.
func literalValue(lit *ast.BasicLit) string {
	if value, err := strconv.Unquote(lit.Value); err == nil {
		return value
	}
	return lit.Value
}

func sortFindings(findings []Finding) []Finding {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Detail < findings[j].Detail
	})
	return findings
}
