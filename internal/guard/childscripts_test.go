package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// THE SCRIPTS THIS PROGRAM HANDS TO ANOTHER (2026-11-11, beside
// notelemetry_test.go). L5 asks node and python what they trust by running a
// script of ours in them - node -e and python -I -S -B -c, ADR111 and ADR112.
// The script is a constant in our source, and every guard in Go reads it as a
// string: a line of it that fetched a page would open a connection from a
// process this program started, past every import guard and every allowlist,
// in a language none of them reads.
//
// So every script handed to an interpreter is registered here, and its text is
// held to a list of what may not be in it: the modules and calls of those two
// languages that open a connection or start a program, and the ones that run
// code nobody can read - eval, exec, a computed import. A string that looks
// like a script and is not registered is reported, so a new one cannot arrive
// unread.
//
// It is a list of words, not a parser, said plainly. What it refuses is what
// would be written by somebody not hiding it - the case it exists for - and a
// script assembled from pieces at run time, or a module reached through
// getattr, is beyond it. Both scripts use getattr on their own, so that word
// cannot be refused.

// scriptLanguage is the interpreter a script is handed to.
type scriptLanguage string

const (
	nodeScript   scriptLanguage = "node"
	pythonScript scriptLanguage = "python"
)

// childScripts are the constants handed to an interpreter, as file|constant.
var childScripts = map[string]scriptLanguage{
	"internal/adapter/probe/node/answer.go|script":   nodeScript,
	"internal/adapter/probe/python/answer.go|script": pythonScript,
}

// looksLikeScript are the marks of a script in a string: a require of a module
// in node, and an import statement on a line of its own in python.
var looksLikeScript = map[scriptLanguage]*regexp.Regexp{
	nodeScript:   regexp.MustCompile(`require\s*\(\s*['"]`),
	pythonScript: regexp.MustCompile(`(?m)^\s*(import\s+[A-Za-z_][\w.]*(\s*,\s*[\w.]+)*\s*$|from\s+[\w.]+\s+import\s+\w)`),
}

// refusedInScript are what a script may not hold, by language, each with why.
var refusedInScript = map[scriptLanguage][]struct {
	pattern *regexp.Regexp
	why     string
}{
	nodeScript: {
		{regexp.MustCompile(`require\s*\(\s*['"](node:)?(net|http|https|http2|dgram|dns|child_process|cluster|worker_threads|inspector|vm|module)['"]`),
			"a module of node's that opens a connection, starts a program or runs code"},
		{regexp.MustCompile(`require\s*\(\s*[^'"\s]`), "a module named by something other than a literal"},
		{regexp.MustCompile(`\bimport\s*\(|(?m)^\s*import\s`), "an import, which loads a module this list never reads"},
		{regexp.MustCompile(`\b(fetch|eval|Function)\s*\(|\b(WebSocket|XMLHttpRequest|EventSource)\b`),
			"a request of its own, or code built from a string"},
		{regexp.MustCompile(`\.(connect|request)\s*\(|process\.(binding|dlopen)`), "a connection, or native code loaded by hand"},
	},
	pythonScript: {
		{regexp.MustCompile(`\b(urlopen|create_connection|PoolManager|ProxyManager|connection_from_url)\b`),
			"a call that opens a connection"},
		{regexp.MustCompile(`\.(connect|request)\s*\(`), "a connection or a request of its own"},
		{regexp.MustCompile(`\b(eval|exec|compile|__import__)\s*\(|\bimportlib\b`), "code nobody can read - built from a string or imported by a computed name"},
		{regexp.MustCompile(`\bos\.(system|popen|exec\w*|spawn\w*|fork\w*|startfile)\b`), "another program started"},
	},
}

// refusedPythonModules are the modules a python script may not import - any
// part of a dotted name, and any name imported from a module. urllib3 is not
// urllib: the python script reads its version and the flags of a context it
// makes, and opens nothing with it.
var refusedPythonModules = map[string]bool{
	"socket": true, "http": true, "urllib": true, "requests": true, "ftplib": true, "smtplib": true,
	"poplib": true, "imaplib": true, "nntplib": true, "telnetlib": true, "xmlrpc": true, "socketserver": true,
	"asyncio": true, "subprocess": true, "multiprocessing": true, "webbrowser": true, "ctypes": true,
	// pip's own: network holds its session and downloader, index its finder of packages on an index.
	"network": true, "index": true,
}

var pythonImport = regexp.MustCompile(`(?m)^\s*(?:import\s+([\w., ]+?)|from\s+([\w.]+)\s+import\s+([\w., ]+?))\s*(?:#.*)?$`)

// scriptProblems are what a script of a language holds that it may not.
func scriptProblems(language scriptLanguage, text string) []string {
	var problems []string
	for _, rule := range refusedInScript[language] {
		if hit := rule.pattern.FindString(text); hit != "" {
			problems = append(problems, fmt.Sprintf("%q - %s", hit, rule.why))
		}
	}
	if language != pythonScript {
		return problems
	}
	for _, m := range pythonImport.FindAllStringSubmatch(text, -1) {
		names := strings.Split(m[1]+","+m[2]+","+m[3], ",")
		for _, name := range names {
			for _, part := range strings.Split(strings.Fields(name + " x")[0], ".") {
				if refusedPythonModules[part] {
					problems = append(problems, fmt.Sprintf("%q - a module that opens a connection or starts a program", strings.TrimSpace(m[0])))
				}
			}
		}
	}
	return problems
}

// scriptsIn are the string literals of a file that look like a script, and
// for each the registered constant it is the value of, if any.
func scriptsIn(sf sourceFile) (registered map[string]string, unregistered []ast.Node) {
	registered = map[string]string{}
	owned := map[ast.Node]string{}
	for _, decl := range sf.file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if _, known := childScripts[sf.rel+"|"+id.Name]; known && i < len(vs.Values) {
					if lit, isLit := vs.Values[i].(*ast.BasicLit); isLit {
						owned[lit], registered[id.Name] = id.Name, literalValue(lit)
					}
				}
			}
		}
	}
	ast.Inspect(sf.file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || owned[lit] != "" {
			return true
		}
		for _, mark := range looksLikeScript {
			if mark.MatchString(literalValue(lit)) {
				unregistered = append(unregistered, lit)
				break
			}
		}
		return true
	})
	return registered, unregistered
}

// checkChildScripts reports what a registered script may not hold, and every
// string that looks like a script and is not registered.
func checkChildScripts(files []sourceFile) []Violation {
	var violations []Violation
	for _, sf := range files {
		registered, unregistered := scriptsIn(sf)
		for _, lit := range unregistered {
			violations = append(violations, Violation{sf.rel, sf.fset.Position(lit.Pos()).Line, fmt.Sprintf(
				"%s holds a string that reads like a script for node or python and is not on childScripts in "+
					"childscripts_test.go - a script handed to another program runs past every guard in Go, so "+
					"each one is registered and read", sf.rel)})
		}
		for name, text := range registered {
			for _, problem := range scriptProblems(childScripts[sf.rel+"|"+name], text) {
				violations = append(violations, Violation{sf.rel, 0, fmt.Sprintf("%s: the script %s holds %s",
					sf.rel, name, problem)})
			}
		}
	}
	return sortViolations(violations)
}

// TestNoScriptHandedToAnotherProgramReachesOut is the guard on the tree, and it
// holds the registry to what is there: an entry whose constant is gone is
// reported, because it would register whatever arrives under that name next.
func TestNoScriptHandedToAnotherProgramReachesOut(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkChildScripts(shippedFiles(t, tr)), "a script handed to another program")
	var missing []string
	for key := range childScripts {
		rel, name, _ := strings.Cut(key, "|")
		sf, ok := fileOf(tr, rel)
		if !ok {
			missing = append(missing, key+" - the file is not in the tree")
			continue
		}
		if registered, _ := scriptsIn(sf); registered[name] == "" {
			missing = append(missing, key+" - the file declares no such constant as a literal")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("childScripts names %s", m)
	}
}

// The canary: each refused shape in each language, and the scripts' own
// shapes left alone.
func TestTheScriptScanReadsWhatItMustRead(t *testing.T) {
	for _, c := range []struct {
		language scriptLanguage
		text     string
		refused  bool
	}{
		{nodeScript, "require('https').get('https://x')", true},
		{nodeScript, "require(\"node:net\").connect(443)", true},
		{nodeScript, "require('tls').connect(443, 'x')", true},
		{nodeScript, "const m = 'child_' + 'process'; require(m)", true},
		{nodeScript, "fetch('https://x')", true},
		{nodeScript, "import('https')", true},
		{nodeScript, "eval(code)", true},
		{nodeScript, "const tls = require('tls');\nif (typeof tls.getCACertificates === 'function') {}\nprocess.stdout.write('x')", false},
		{pythonScript, "import urllib.request\nurllib.request.urlopen('https://x')", true},
		{pythonScript, "import socket, json", true},
		{pythonScript, "from http import client", true},
		{pythonScript, "from pip._vendor import requests", true},
		{pythonScript, "from pip._internal.network.session import PipSession", true},
		{pythonScript, "import subprocess", true},
		{pythonScript, "os.system('curl x')", true},
		{pythonScript, "exec(code)", true},
		{pythonScript, "c.connect(('x', 443))", true},
		{pythonScript, "import base64, json, os, ssl, sys\nfrom pip._vendor import urllib3\nfrom pip._vendor.urllib3.util.ssl_ import create_urllib3_context\nx = sys.executable\ny = getattr(urllib3, '__version__', None)", false},
	} {
		if got := scriptProblems(c.language, c.text); (len(got) > 0) != c.refused {
			t.Errorf("%s script %q: refused %v, and had to be %v (%v)", c.language, c.text, len(got) > 0, c.refused, got)
		}
	}
	unregistered := sourceFrom(t, "internal/adapter/probe/planted.go", "package p\n\nconst s = `import socket`\n\nvar t = \"require('x')\"\n")
	if got := checkChildScripts([]sourceFile{unregistered}); len(got) != 2 {
		t.Errorf("two unregistered scripts gave %d violation(s): %v", len(got), got)
	}
}
