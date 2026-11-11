package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
	"strconv"
	"strings"
	"testing"
)

// WAYS OUT THAT NO IMPORT SHOWS (2026-11-11, asked for by the owner: nobody, in
// a pull request or in another chat, adds telemetry or a connection nobody
// expects). The shape comes from TestingFilesGenerator, whose
// notelemetry_test.go guards a program that connects to nothing. This one
// guards a program that connects for a living, so the question is narrower:
// not whether a connection exists, but whether one can begin where the other
// guards do not look.
//
// What already stands is not repeated here. reach_test.go names the six files
// that may import a network package and the one file that may widen the set of
// places a run may reach, exec_test.go and spawns_test.go the programs this one
// may start, libraries_test.go where a library may be loaded from. Every one of
// them asks WHO. This file asks about the routes those questions leave open:
//
//   - a shortcut that skips dial.Permission, inside the six files as much as
//     outside them,
//   - a socket, a DNS query or a procedure of a library reached below the net
//     package, where no import guard sees it,
//   - a chain built or verified so that it fetches from the addresses a
//     certificate names (ADR101),
//   - an HTTP client or transport whose zero value goes where nobody chose,
//   - the allowed set widened with something written into the program,
//   - the toolkit of the window fetching an address, or handing one out.
//
// Addresses written into the code are addresses_test.go, the scripts handed to
// node and python childscripts_test.go, and what the binaries link of somebody
// else's networking linkednetwork_test.go.
//
// It reads the files a shipped binary is built from, asked of the compiler for
// every program and every build that ships, and every .go file of those
// packages whatever its build tags - a file built for macOS alone is read on
// Windows too.
//
// What it cannot see, said plainly: a value handed on through an interface or a
// function value, a name put together at run time, C code, and what a program
// this one starts does on its own. It is no proof that nothing leaves the
// machine - that needs a traffic monitor (docs/14 section 3). It is a lock on
// the surface: a new way out cannot arrive by accident, and one added on
// purpose has to be written into a registry here, with the reason.

// shippedFiles are this module's files that a shipped binary is built from.
func shippedFiles(t *testing.T, tr tree) []sourceFile {
	t.Helper()
	dirs := map[string]bool{}
	for _, program := range noticedPrograms {
		for _, target := range program.targets {
			for _, p := range listPackages(t, tr.root, program, target) {
				if p.Module != nil && p.Module.Main {
					dirs[strings.TrimPrefix(strings.TrimPrefix(p.ImportPath, tr.modulePath), "/")] = true
				}
			}
		}
	}
	for _, program := range []string{"cmd/certdoctor", "cmd/certdoctor-gui"} {
		if !dirs[program] {
			t.Fatalf("the compiler named no package %s among what ships, so this is not the real set", program)
		}
	}
	var files []sourceFile
	for _, sf := range tr.files {
		if !sf.isTest && dirs[path.Dir(sf.rel)] {
			files = append(files, sf)
		}
	}
	// Below this the set is not the real one, and a registry checked against
	// a short list would call every entry stale.
	if len(files) < 150 {
		t.Fatalf("only %d shipped file(s) found, which is too few to be the real set", len(files))
	}
	return files
}

// The reasons, one for each kind of way out, so every entry says which it is.
const (
	skipsPermission = "opens a connection without asking dial.Permission, which each of the six files on dialAllowlist asks before it dials"
	listens         = "waits for a connection from elsewhere, and this program accepts none"
	resolvesAside   = "asks the system resolver a question outside L1, whose two views are the only DNS questions this program puts"
	followsProxyEnv = "picks a proxy from this process's environment, so the connection goes where a variable says - the defect pac/fetch.go sets Proxy to nil against"
	belowNet        = "opens or uses a socket below the net package, where no import guard sees it"
	systemPool      = "is the system pool, which on Windows builds a chain through CertGetCertificateChain without the flags that keep it off the network (ADR101)"
	anyScheme       = "turns text into an address of any scheme, and the toolkit fetches an http or https one with http.Get when it is read"
	toolkitFetches  = "makes the toolkit fetch an address itself with http.Get, and nothing of ours stands in front of it"
	toolkitOpens    = "hands an address to the system browser on a press - the window's links do that in one place, waiting.go"
	byOrdinal       = "finds a procedure by its number, which nobody here can read"
	schemeHandler   = "puts a handler of the toolkit's behind a scheme of addresses"
)

// socketCalls are the calls below the net package that open, use or name the
// peer of a socket, or ask a resolver - for each of the three packages that
// carry them.
var socketCalls = []string{
	"Socket", "Connect", "Bind", "Listen", "Accept", "Accept4", "Sendto", "Sendmsg", "SendmsgN",
	"Recvfrom", "Recvmsg", "ConnectEx", "AcceptEx", "TransmitFile",
	"WSAStartup", "WSASocket", "WSAConnect", "WSASend", "WSASendTo", "WSARecv", "WSARecvFrom", "WSAIoctl",
	"GetAddrInfoW", "GetHostByName", "GetServByName", "DnsQuery",
}

// refusedNames are the names shipped code may not reach for, spelled with the
// path of their package, each with what it does that this program does not.
var refusedNames = func() map[string]string {
	names := map[string]string{
		"crypto/tls.Dial": skipsPermission, "crypto/tls.DialWithDialer": skipsPermission, "crypto/tls.Dialer": skipsPermission,
		"net/http.Get": skipsPermission, "net/http.Head": skipsPermission, "net/http.Post": skipsPermission,
		"net/http.PostForm": skipsPermission, "net/http.DefaultClient": skipsPermission,
		"net/http.DefaultTransport": followsProxyEnv, "net/http.ProxyFromEnvironment": followsProxyEnv,
		"crypto/tls.Listen": listens, "crypto/tls.NewListener": listens, "net/http.Server": listens,
		"net/http.ListenAndServe": listens, "net/http.ListenAndServeTLS": listens,
		"net/http.Serve": listens, "net/http.ServeTLS": listens,
		"net.DefaultResolver":                              resolvesAside,
		"crypto/x509.SystemCertPool":                       systemPool,
		"golang.org/x/sys/windows.GetProcAddressByOrdinal": byOrdinal,
		"fyne.io/fyne/v2.LoadResourceFromURLString":        toolkitFetches,
		"fyne.io/fyne/v2/canvas.NewImageFromURI":           toolkitFetches,
		"fyne.io/fyne/v2/widget.NewRichTextFromMarkdown":   toolkitFetches,
		"fyne.io/fyne/v2/widget.ImageSegment":              toolkitFetches,
		"fyne.io/fyne/v2/storage.ParseURI":                 anyScheme,
		"fyne.io/fyne/v2/storage.NewURI":                   anyScheme,
		"fyne.io/fyne/v2/storage/repository.ParseURI":      anyScheme,
		"fyne.io/fyne/v2/storage/repository.Register":      schemeHandler,
		"fyne.io/fyne/v2/widget.NewHyperlink":              toolkitOpens,
		"fyne.io/fyne/v2/widget.NewHyperlinkWithStyle":     toolkitOpens,
		"fyne.io/fyne/v2/widget.Hyperlink":                 toolkitOpens,
		"fyne.io/fyne/v2/widget.HyperlinkSegment":          toolkitOpens,
	}
	for _, call := range []string{"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix"} {
		names["net."+call] = skipsPermission
	}
	for _, call := range []string{"Listen", "ListenPacket", "ListenTCP", "ListenUDP", "ListenIP", "ListenUnix",
		"ListenUnixgram", "ListenMulticastUDP"} {
		names["net."+call] = listens
	}
	for _, call := range []string{"LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX", "LookupNS",
		"LookupPort", "LookupSRV", "LookupTXT", "ResolveIPAddr", "ResolveTCPAddr", "ResolveUDPAddr"} {
		names["net."+call] = resolvesAside
	}
	for _, pkg := range []string{"syscall", "golang.org/x/sys/windows", "golang.org/x/sys/unix"} {
		for _, call := range socketCalls {
			names[pkg+"."+call] = belowNet
		}
	}
	return names
}()

// refusedMethods are methods of the toolkit's values that fetch an address or
// hand one out. Read by name, in the files that import the toolkit, because
// the value they are called on has no package to spell.
var refusedMethods = map[string]string{
	"OpenURL":        toolkitOpens,
	"ParseMarkdown":  toolkitFetches,
	"AppendMarkdown": toolkitFetches,
}

// methodsAllowed are the files allowed ONE use of a refused method each, and why.
var methodsAllowed = map[string]map[string]string{
	"cmd/certdoctor-gui/waiting.go": {"OpenURL": "the GitHub and Donate links, handed to the browser on a press " +
		"beside the toolkit's loop - see openBeside (ADR122)"},
}

// chainBuilders build a certificate chain in Windows, and chainOffline are the
// flags without which they fetch from the network: CACHE_ONLY_URL_RETRIEVAL,
// DISABLE_AUTH_ROOT_AUTO_UPDATE and DISABLE_AIA, documented on the
// CertGetCertificateChain page (ADR101). The flags are the sixth argument.
var chainBuilders = map[string]bool{
	"syscall.CertGetCertificateChain":                  true,
	"golang.org/x/sys/windows.CertGetCertificateChain": true,
}

const chainOffline = 0x00000004 | 0x00000100 | 0x00002000

// procedureLookups are the methods that find a procedure in a loaded library
// by the name they are handed, and procedureAddresses the functions that do,
// with where the name is among their arguments.
var procedureLookups = map[string]bool{"NewProc": true, "FindProc": true, "MustFindProc": true}

var procedureAddresses = map[string]int{
	"syscall.GetProcAddress":                  1,
	"golang.org/x/sys/windows.GetProcAddress": 1,
}

// proceduresAllowed are the procedures each file may find by name, and why.
//
// libraries_test.go holds WHERE a library is loaded from. A library is not one
// operation, though: winhttp.dll is loaded to read this machine's proxy
// settings, and the same file holds WinHttpGetProxyForUrl and
// WinHttpDetectAutoProxyConfigUrl, which fetch a script and search the network
// for one (WPAD, outside this program - D16). iphlpapi.dll is loaded to read
// the resolvers, and holds IcmpSendEcho and SendARP, which send packets. So the
// procedures are named one by one, and a name nobody wrote here is refused.
var proceduresAllowed = map[string]map[string]string{
	"internal/adapter/dns/nameservers_windows.go": {
		"GetSystemDirectoryW": "where the system directory is, so iphlpapi.dll is loaded from there by path",
		"GetNetworkParams":    "the resolvers this machine is set to use, read from its own configuration",
	},
	"internal/adapter/proxyconf/proxyconf_windows.go": {
		"WinHttpGetIEProxyConfigForCurrentUser": "the person's proxy settings as Windows keeps them, read and not followed",
		"WinHttpGetDefaultProxyConfiguration":   "the machine's WinHTTP proxy, read from its configuration",
		"GlobalFree":                            "frees the strings WinHTTP handed back",
		"GetSystemDirectoryW":                   "where the system directory is, so winhttp.dll is loaded from there by path",
	},
	"internal/adapter/render/capability_windows.go": {
		"GetConsoleOutputCP": "the code page of the console the report is written to",
	},
}

// fieldRule is what a literal of a type has to say about one of its fields.
type fieldRule struct {
	field string
	want  string // "set" - present and not nil, "nil" - present and nil, "absent"
}

// requiredFields are the types whose zero value reaches where nobody chose,
// with what a literal of them has to say. A literal is the only way to make
// one here: a declared zero value or new() hides every field from this guard.
var requiredFields = map[string][]fieldRule{
	// Without Roots, Verify takes the system pool - on Windows a chain built
	// with nothing keeping it off the network (ADR101).
	"crypto/x509.VerifyOptions": {{"Roots", "set"}},
	// Without Transport, a client takes http.DefaultTransport.
	"net/http.Client": {{"Transport", "set"}},
	// DialContext is where dial.Permission stands. Proxy left out is nil as
	// well, but said out loud it is the line the mutation register aims at,
	// and the TLS dialers would skip DialContext altogether.
	"net/http.Transport": {{"DialContext", "set"}, {"Proxy", "nil"}, {"Dial", "absent"},
		{"DialTLS", "absent"}, {"DialTLSContext", "absent"}},
}

// TestNothingShippedReachesOutByAWayNobodyNamed is the guard on the tree.
func TestNothingShippedReachesOutByAWayNobodyNamed(t *testing.T) {
	tr := mustLoadModule(t)
	files := shippedFiles(t, tr)
	requireNoViolations(t, checkWaysOut(files, packageValues(tr.files)), "a way out of this program nobody named")
	t.Logf("%d shipped file(s) read, across every build tag rather than this system's", len(files))
}

// TestEveryWayOutExceptionStillNamesLiveCode - an entry naming code that is
// gone forgives whatever arrives in its place next.
func TestEveryWayOutExceptionStillNamesLiveCode(t *testing.T) {
	tr := mustLoadModule(t)
	for rel, names := range proceduresAllowed {
		sf, ok := fileOf(tr, rel)
		if !ok {
			t.Errorf("proceduresAllowed names %s, which is not in the tree", rel)
			continue
		}
		found := map[string]bool{}
		for _, p := range procedureFindings(sf) {
			found[p.name] = true
		}
		for name := range names {
			if !found[name] {
				t.Errorf("proceduresAllowed lets %s find %s, and it finds no such procedure - delete the line", rel, name)
			}
		}
	}
	for rel, methods := range methodsAllowed {
		sf, ok := fileOf(tr, rel)
		if !ok {
			t.Errorf("methodsAllowed names %s, which is not in the tree", rel)
			continue
		}
		uses := methodUses(sf)
		for method := range methods {
			if len(uses[method]) == 0 {
				t.Errorf("methodsAllowed lets %s use %s, and it does not - delete the line", rel, method)
			}
		}
	}
}

// checkWaysOut reports every way out in files that no registry here forgives.
// names are the package level values of each directory, for the widening check.
func checkWaysOut(files []sourceFile, names map[string]map[string]ast.Expr) []Violation {
	var violations []Violation
	for _, sf := range files {
		paths, _ := importPaths(sf.file)
		violations = append(violations, dotImportedWaysOut(sf)...)
		violations = append(violations, refusedReferences(sf, paths)...)
		violations = append(violations, chainFlagViolations(sf, paths)...)
		violations = append(violations, procedureViolations(sf)...)
		violations = append(violations, requiredFieldViolations(sf, paths)...)
		violations = append(violations, fixedWidenings(sf, paths, names[path.Dir(sf.rel)])...)
		violations = append(violations, refusedMethodViolations(sf)...)
	}
	return sortViolations(violations)
}

// violationAt is one violation of this file's rules at a node of sf.
func violationAt(sf sourceFile, n ast.Node, format string, args ...any) Violation {
	return Violation{sf.rel, sf.fset.Position(n.Pos()).Line, fmt.Sprintf(format, args...) +
		" - if it is wanted, that is a new decision, written into notelemetry_test.go with the reason"}
}

// dotImportedWaysOut are the imports with a dot of a package something here is
// read from - a dot hides which package a bare name belongs to.
func dotImportedWaysOut(sf sourceFile) []Violation {
	var violations []Violation
	for _, spec := range sf.file.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil || spec.Name == nil || spec.Name.Name != "." {
			continue
		}
		if networkPackage(p) || refusedPackage(p) {
			violations = append(violations, violationAt(sf, spec,
				"%s imports %s with a dot, which hides which of its names a call reaches for", sf.rel, p))
		}
	}
	return violations
}

// refusedPackage reports whether a name in refusedNames comes from p.
func refusedPackage(p string) bool {
	for name := range refusedNames {
		if name[:strings.LastIndex(name, ".")] == p {
			return true
		}
	}
	return false
}

// refusedReferences are the uses of a name in refusedNames, called or not -
// http.DefaultClient and tls.Dialer are reached for without a call of their own.
func refusedReferences(sf sourceFile, paths map[string]string) []Violation {
	var violations []Violation
	ast.Inspect(sf.file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := spelled(sel, paths)
		if reason, refused := refusedNames[name]; refused {
			violations = append(violations, violationAt(sf, sel, "%s reaches for %s, which %s", sf.rel, name, reason))
		}
		return true
	})
	return violations
}

// chainFlagViolations are the chains built with flags that are not a constant
// of the file carrying all three of chainOffline.
func chainFlagViolations(sf sourceFile, paths map[string]string) []Violation {
	var violations []Violation
	ast.Inspect(sf.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !chainBuilders[spelled(call.Fun, paths)] {
			return true
		}
		value, read := uint64(0), false
		if len(call.Args) > 5 {
			if flags, isName := call.Args[5].(*ast.Ident); isName {
				value, read = constantOf(sf.file, flags.Name)
			}
		}
		if !read || value&chainOffline != chainOffline {
			violations = append(violations, violationAt(sf, call, "%s builds a chain with flags that are not a "+
				"constant carrying CACHE_ONLY_URL_RETRIEVAL, DISABLE_AUTH_ROOT_AUTO_UPDATE and DISABLE_AIA, "+
				"so the chain may be fetched from the addresses its certificates name (ADR101)", sf.rel))
		}
		return true
	})
	return violations
}

// constantOf is the value of a constant declared in f, when it is written as
// whole numbers joined by |, which is how a set of flags is written.
func constantOf(f *ast.File, name string) (uint64, bool) {
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if id.Name == name && i < len(vs.Values) {
					return flagValue(vs.Values[i])
				}
			}
		}
	}
	return 0, false
}

// flagValue reads a whole number, or numbers joined by |.
func flagValue(e ast.Expr) (uint64, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		v, err := strconv.ParseUint(x.Value, 0, 64)
		return v, err == nil && x.Kind == token.INT
	case *ast.ParenExpr:
		return flagValue(x.X)
	case *ast.BinaryExpr:
		left, okLeft := flagValue(x.X)
		right, okRight := flagValue(x.Y)
		return left | right, okLeft && okRight && x.Op == token.OR
	}
	return 0, false
}

// procedureFinding is one procedure a file finds in a library: the name when
// it is a literal, and where.
type procedureFinding struct {
	name    string
	literal bool
	node    ast.Node
}

// procedureFindings are the procedures sf finds by name, in a file that
// imports a package able to load a library.
func procedureFindings(sf sourceFile) []procedureFinding {
	paths, _ := importPaths(sf.file)
	if !importsAny(paths, "syscall", "golang.org/x/sys/windows") {
		return nil
	}
	var found []procedureFinding
	ast.Inspect(sf.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		at, finds := procedureAddresses[spelled(call.Fun, paths)]
		if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel && procedureLookups[sel.Sel.Name] && spelled(sel, paths) == "" {
			at, finds = 0, true
		}
		if !finds || len(call.Args) <= at {
			return true
		}
		f := procedureFinding{node: call}
		if lit, isLit := call.Args[at].(*ast.BasicLit); isLit && lit.Kind == token.STRING {
			f.name, f.literal = literalValue(lit), true
		}
		found = append(found, f)
		return true
	})
	return found
}

// procedureViolations are the procedures found that proceduresAllowed does not
// name for the file, and every one whose name this guard cannot read.
func procedureViolations(sf sourceFile) []Violation {
	var violations []Violation
	for _, f := range procedureFindings(sf) {
		switch {
		case !f.literal:
			violations = append(violations, violationAt(sf, f.node,
				"%s finds a procedure in a library by a name that is not a literal, which nobody here can read", sf.rel))
		case proceduresAllowed[sf.rel][f.name] == "":
			violations = append(violations, violationAt(sf, f.node,
				"%s finds %s in a library, which proceduresAllowed does not name for it - a library loaded to read "+
					"a setting carries procedures that send packets beside it", sf.rel, f.name))
		}
	}
	return violations
}

// importsAny reports whether a file imports one of the packages.
func importsAny(paths map[string]string, packages ...string) bool {
	for _, p := range paths {
		for _, want := range packages {
			if p == want {
				return true
			}
		}
	}
	return false
}

// requiredFieldViolations are the values of a type in requiredFields that this
// guard cannot read the fields of, and the literals that say the wrong thing.
func requiredFieldViolations(sf sourceFile, paths map[string]string) []Violation {
	var violations []Violation
	ast.Inspect(sf.file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if rules, ok := requiredFields[spelled(x.Type, paths)]; ok {
				violations = append(violations, literalFieldViolations(sf, x, spelled(x.Type, paths), rules)...)
			}
		case *ast.ValueSpec:
			if _, ok := requiredFields[spelled(x.Type, paths)]; ok && len(x.Values) == 0 {
				violations = append(violations, violationAt(sf, x, "%s declares a %s with no literal, so its "+
					"fields are the zero value and this guard cannot read them", sf.rel, spelled(x.Type, paths)))
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
				if _, refused := requiredFields[spelled(x.Args[0], paths)]; refused {
					violations = append(violations, violationAt(sf, x, "%s makes a %s with new, so its fields are "+
						"the zero value and this guard cannot read them", sf.rel, spelled(x.Args[0], paths)))
				}
			}
		}
		return true
	})
	return violations
}

// literalFieldViolations are what a literal of a type in requiredFields says
// wrong, against each of its rules.
func literalFieldViolations(sf sourceFile, lit *ast.CompositeLit, typ string, rules []fieldRule) []Violation {
	values := map[string]ast.Expr{}
	for _, elt := range lit.Elts {
		kv, keyed := elt.(*ast.KeyValueExpr)
		if !keyed {
			return []Violation{violationAt(sf, lit, "%s writes a %s without field names, which this guard cannot read", sf.rel, typ)}
		}
		if key, ok := kv.Key.(*ast.Ident); ok {
			values[key.Name] = kv.Value
		}
	}
	var violations []Violation
	for _, rule := range rules {
		value, present := values[rule.field]
		isNil := present && isName(value, "nil")
		wrong := (rule.want == "set" && (!present || isNil)) || (rule.want == "nil" && !isNil) ||
			(rule.want == "absent" && present)
		if wrong {
			violations = append(violations, violationAt(sf, lit, "%s writes a %s whose %s is not %s, so the value "+
				"reaches where nobody here chose", sf.rel, typ, rule.field, map[string]string{
				"set": "given", "nil": "said to be nil", "absent": "left out"}[rule.want]))
		}
	}
	return violations
}

// fixedWidenings are the widenings of the allowed set with something written
// into the program rather than derived from the person's question.
//
// checkWidening in reach_test.go holds WHO widens the set - cli.go and nothing
// else. It does not hold WITH WHAT, and that was the cheapest way to add an
// update check this tree had: the transport of pac/fetch.go already dials, and
// one targets.Allow("api.github.com", ...) in cli.go would have let it, past
// every guard. Inviolable rule 16 permits only what the question derives.
func fixedWidenings(sf sourceFile, paths map[string]string, values map[string]ast.Expr) []Violation {
	if !importsAny(paths, allowedPackage) {
		return nil
	}
	var violations []Violation
	for _, decl := range sf.file.Decls {
		fn, _ := decl.(*ast.FuncDecl)
		scope := runScope{fn: fn, paths: paths, values: values}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Allow" || spelled(sel, paths) != "" {
				return true
			}
			if !scope.derived(call.Args[0], map[string]bool{}) {
				violations = append(violations, violationAt(sf, call, "%s widens the allowed set with something "+
					"written into the program rather than derived from the person's question - inviolable rule 16", sf.rel))
			}
			return true
		})
	}
	return violations
}

// runScope is where the names of one function are read: the function, the
// file's imports, and the values its package declares at package level.
type runScope struct {
	fn     *ast.FuncDecl
	paths  map[string]string
	values map[string]ast.Expr // nil for a package level variable declared without a value
}

// predeclared are the names Go declares itself, none of them a value of a run.
var predeclared = map[string]bool{
	"true": true, "false": true, "nil": true, "iota": true, "string": true, "byte": true, "rune": true,
	"int": true, "uint16": true, "len": true, "min": true, "max": true,
}

// pureCalls are the functions of other packages that compute a value from
// their arguments and from nothing else.
var pureCalls = map[string]bool{
	"net.JoinHostPort": true, "fmt.Sprint": true, "fmt.Sprintf": true, "strings.Join": true,
	"strings.ToLower": true, "strings.TrimSpace": true, "strconv.Itoa": true,
}

// derived reports whether e carries a value of the run - a parameter, a range,
// a call into this program or a method, which can read the machine - rather
// than only literals, constants and what is computed from them.
//
// It follows a local name to every binding of it in the function, so a
// literal does not pass by being put into a variable first. What it does not
// follow: a literal handed in through a parameter of a helper, and one
// returned by a function of this program - both read as derived.
func (sc runScope) derived(e ast.Expr, seen map[string]bool) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return false
	case *ast.Ident:
		return sc.local(x.Name, seen)
	case *ast.SelectorExpr:
		return spelled(x, sc.paths) == "" && sc.derived(x.X, seen)
	case *ast.ParenExpr:
		return sc.derived(x.X, seen)
	case *ast.UnaryExpr:
		return sc.derived(x.X, seen)
	case *ast.IndexExpr:
		return sc.derived(x.X, seen) || sc.derived(x.Index, seen)
	case *ast.BinaryExpr:
		return sc.derived(x.X, seen) || sc.derived(x.Y, seen)
	case *ast.KeyValueExpr:
		return sc.derived(x.Value, seen)
	case *ast.CompositeLit:
		for _, elt := range x.Elts {
			if sc.derived(elt, seen) {
				return true
			}
		}
		return false
	case *ast.CallExpr:
		if callee := spelled(x.Fun, sc.paths); !pureCalls[callee] && !predeclared[callee] {
			return true
		}
		for _, arg := range x.Args {
			if sc.derived(arg, seen) {
				return true
			}
		}
		return false
	}
	return true
}

// local reports whether a name is a value of the run.
func (sc runScope) local(name string, seen map[string]bool) bool {
	if predeclared[name] || sc.paths[name] != "" || seen[name] {
		return false
	}
	seen[name] = true
	defer delete(seen, name)
	if value, declared := sc.values[name]; declared {
		return value == nil || sc.derived(value, seen)
	}
	values, opaque := sc.bindings(name)
	if opaque || len(values) == 0 {
		return true
	}
	for _, v := range values {
		if sc.derived(v, seen) {
			return true
		}
	}
	return false
}

// bindings are the values a name is given in the function, and whether one of
// its bindings is a parameter, whose value comes from wherever it is called.
func (sc runScope) bindings(name string) (values []ast.Expr, opaque bool) {
	if sc.fn == nil || sc.fn.Body == nil {
		return nil, true
	}
	opaque = len(fieldBindings(sc.fn.Type, name)) > 0
	ast.Inspect(sc.fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				if isName(lhs, name) {
					values = append(values, s.Rhs[min(i, len(s.Rhs)-1)])
				}
			}
		case *ast.ValueSpec:
			for i, id := range s.Names {
				if id.Name == name && len(s.Values) > 0 {
					values = append(values, s.Values[min(i, len(s.Values)-1)])
				}
			}
		case *ast.RangeStmt:
			if isName(s.Key, name) || isName(s.Value, name) {
				values = append(values, s.X)
			}
		case *ast.FuncLit:
			opaque = opaque || len(fieldBindings(s.Type, name)) > 0
		}
		return true
	})
	return values, opaque
}

// packageValues are the values each directory declares at package level,
// constants and variables, with nil for a variable declared without one.
func packageValues(files []sourceFile) map[string]map[string]ast.Expr {
	values := map[string]map[string]ast.Expr{}
	for _, sf := range files {
		if sf.isTest {
			continue
		}
		dir := path.Dir(sf.rel)
		if values[dir] == nil {
			values[dir] = map[string]ast.Expr{}
		}
		for _, decl := range sf.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					values[dir][id.Name] = nil
					if len(vs.Values) > 0 {
						values[dir][id.Name] = vs.Values[min(i, len(vs.Values)-1)]
					}
				}
			}
		}
	}
	return values
}

// methodUses are the uses of each refused method in a file that imports the
// toolkit.
func methodUses(sf sourceFile) map[string][]ast.Node {
	paths, _ := importPaths(sf.file)
	toolkit := false
	for _, p := range paths {
		toolkit = toolkit || strings.HasPrefix(p, "fyne.io/")
	}
	uses := map[string][]ast.Node{}
	if !toolkit {
		return uses
	}
	ast.Inspect(sf.file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && refusedMethods[sel.Sel.Name] != "" && spelled(sel, paths) == "" {
			uses[sel.Sel.Name] = append(uses[sel.Sel.Name], sel)
		}
		return true
	})
	return uses
}

// refusedMethodViolations are the uses of a refused method past the one its
// file is allowed.
func refusedMethodViolations(sf sourceFile) []Violation {
	var violations []Violation
	for method, uses := range methodUses(sf) {
		if methodsAllowed[sf.rel][method] != "" {
			uses = uses[1:]
		}
		for _, use := range uses {
			violations = append(violations, violationAt(sf, use, "%s calls the toolkit's %s, which %s",
				sf.rel, method, refusedMethods[method]))
		}
	}
	return violations
}
