package guard

import (
	"strings"
	"testing"
)

// The canaries of notelemetry_test.go. A guard that has only ever read clean
// code has been shown to run, not to look - and on this tree every check there
// reads code that passes. Every shape is its own case rather than one standing
// for its kind, because the sister project measured its own scan reading one
// spelling of three.

// plantedFile is where a canary pretends to live unless it says otherwise.
const plantedFile = "internal/adapter/dns/planted.go"

const (
	importsNet       = "package p\n\nimport \"net\"\n\n"
	importsHTTP      = "package p\n\nimport \"net/http\"\n\n"
	importsX509      = "package p\n\nimport \"crypto/x509\"\n\n"
	importsSyscall   = "package p\n\nimport \"syscall\"\n\n"
	importsWindows   = "package p\n\nimport \"golang.org/x/sys/windows\"\n\n"
	importsAllowed   = "package main\n\nimport (\n\t\"net\"\n\n\t\"github.com/donislawdev/certdoctor/internal/core/allowed\"\n)\n\n"
	importsToolkit   = "package main\n\nimport \"fyne.io/fyne/v2\"\n\n"
	importsWidget    = "package main\n\nimport \"fyne.io/fyne/v2/widget\"\n\n"
	wideningFile     = "cmd/certdoctor/planted.go"
	windowFile       = "cmd/certdoctor-gui/planted.go"
	linksFile        = "cmd/certdoctor-gui/waiting.go"
	proxySettingFile = "internal/adapter/proxyconf/proxyconf_windows.go"
)

// wayOutCase is one planted file and what the scanner has to say about it.
type wayOutCase struct {
	label, rel, src string
	want            string // a part of the one violation it has to raise, or "" for none at all
}

var waysOutItMustRefuse = []wayOutCase{
	{"a dial that skips the permission", plantedFile, importsNet + "func f(a string) { _, _ = net.Dial(\"tcp\", a) }\n", "net.Dial, which"},
	{"the same under another import name", plantedFile, "package p\n\nimport n \"net\"\n\nfunc f(a string) { _, _ = n.DialTimeout(\"tcp\", a, 0) }\n", "net.DialTimeout, which"},
	{"a TLS dial of its own", plantedFile, "package p\n\nimport \"crypto/tls\"\n\nfunc f(a string) { _, _ = tls.Dial(\"tcp\", a, nil) }\n", "crypto/tls.Dial, which"},
	{"a TLS dialer", plantedFile, "package p\n\nimport \"crypto/tls\"\n\nvar d = &tls.Dialer{}\n", "crypto/tls.Dialer, which"},
	{"the default client", plantedFile, importsHTTP + "func f() { _, _ = http.DefaultClient.Do(nil) }\n", "net/http.DefaultClient, which"},
	{"a GET of the package", plantedFile, importsHTTP + "func f(u string) { _, _ = http.Get(u) }\n", "net/http.Get, which"},
	{"the proxy of the environment", plantedFile, importsHTTP + "var p = http.ProxyFromEnvironment\n", "net/http.ProxyFromEnvironment, which"},
	{"a listener", plantedFile, importsNet + "func f() { _, _ = net.Listen(\"tcp\", \":0\") }\n", "net.Listen, which"},
	{"a lookup beside L1", plantedFile, importsNet + "func f(h string) { _, _ = net.LookupHost(h) }\n", "net.LookupHost, which"},
	{"the default resolver", plantedFile, importsNet + "var r = net.DefaultResolver\n", "net.DefaultResolver, which"},
	{"a name resolved on the way to an address", plantedFile, importsNet + "func f(h string) { _, _ = net.ResolveUDPAddr(\"udp\", h) }\n", "net.ResolveUDPAddr, which"},
	{"a network package behind a dot", plantedFile, "package p\n\nimport . \"net\"\n\nfunc f() { _, _ = Dial(\"tcp\", \"x\") }\n", "with a dot"},
	{"a socket from syscall", plantedFile, importsSyscall + "func f() { _, _ = syscall.Socket(2, 1, 0) }\n", "syscall.Socket, which"},
	{"a connect under another import name", plantedFile, "package p\n\nimport w \"golang.org/x/sys/windows\"\n\nvar c = w.WSAConnect\n", "golang.org/x/sys/windows.WSAConnect, which"},
	{"a DNS query below net", plantedFile, importsWindows + "var q = windows.DnsQuery\n", "golang.org/x/sys/windows.DnsQuery, which"},
	{"a chain built with flags handed in", plantedFile, importsSyscall + "func f(flags uint32) { _ = syscall.CertGetCertificateChain(0, nil, nil, 0, nil, flags, 0, nil) }\n", "builds a chain"},
	{"a chain built without DISABLE_AIA", plantedFile, importsSyscall + "const noNetwork = 0x00000004 | 0x00000100\n\nfunc f() { _ = syscall.CertGetCertificateChain(0, nil, nil, 0, nil, noNetwork, 0, nil) }\n", "builds a chain"},
	{"a chain built with flags written in place", plantedFile, importsSyscall + "func f() { _ = syscall.CertGetCertificateChain(0, nil, nil, 0, nil, 0x2104, 0, nil) }\n", "builds a chain"},
	{"a chain built through the other package", plantedFile, importsWindows + "func f(flags uint32) { _ = windows.CertGetCertificateChain(0, nil, nil, 0, nil, flags, 0, nil) }\n", "builds a chain"},
	{"a socket by its number", plantedFile, importsSyscall + "func f() { _, _, _ = syscall.Syscall(syscall.SYS_SOCKET, 2, 1, 0) }\n", "by its number with syscall.Syscall,"},
	{"ioctl by a number written in place", plantedFile, importsSyscall + "func f(fd, p uintptr) { _, _, _ = syscall.RawSyscall(16, fd, 0x5401, p) }\n", "by its number with syscall.RawSyscall,"},
	{"a raw call taken as a value", plantedFile, importsSyscall + "var call = syscall.Syscall6\n", "by its number with syscall.Syscall6,"},
	{"a raw call of the other package", plantedFile, "package p\n\nimport u \"golang.org/x/sys/unix\"\n\nfunc f() { _, _, _ = u.Syscall(41, 2, 1, 0) }\n", "by its number with golang.org/x/sys/unix.Syscall,"},
	{"a procedure nobody named, in a file allowed others", proxySettingFile, importsSyscall + "var p = syscall.NewLazyDLL(\"x\").NewProc(\"WinHttpGetProxyForUrl\")\n", "finds WinHttpGetProxyForUrl"},
	{"a procedure by a name nobody can read", proxySettingFile, importsSyscall + "func f(lib *syscall.LazyDLL, name string) { _ = lib.NewProc(name) }\n", "not a literal"},
	{"a procedure found by address", plantedFile, importsSyscall + "func f(h syscall.Handle) { _, _ = syscall.GetProcAddress(h, \"IcmpSendEcho\") }\n", "finds IcmpSendEcho"},
	{"a procedure found by number", plantedFile, importsWindows + "func f(h windows.Handle) { _, _ = windows.GetProcAddressByOrdinal(h, 5) }\n", "GetProcAddressByOrdinal, which"},
	{"the system pool", plantedFile, importsX509 + "func f() { _, _ = x509.SystemCertPool() }\n", "crypto/x509.SystemCertPool, which"},
	{"verify options without roots", plantedFile, importsX509 + "func f(c *x509.Certificate) { _, _ = c.Verify(x509.VerifyOptions{}) }\n", "whose Roots is not given"},
	{"verify options with roots of nil", plantedFile, importsX509 + "var o = x509.VerifyOptions{Roots: nil}\n", "whose Roots is not given"},
	{"verify options declared empty", plantedFile, importsX509 + "func f() { var o x509.VerifyOptions\n\t_ = o\n}\n", "with no literal"},
	{"verify options made with new", plantedFile, importsX509 + "var o = new(x509.VerifyOptions)\n", "with new"},
	{"a client written without field names", plantedFile, importsHTTP + "var c = http.Client{nil, nil, nil, 0}\n", "without field names"},
	{"a client without a transport", plantedFile, importsHTTP + "var c = &http.Client{}\n", "whose Transport is not given"},
	{"a transport that follows the environment", plantedFile, importsHTTP + "func f(d any) { _ = &http.Transport{DialContext: d} }\n", "whose Proxy is not said to be nil"},
	{"a transport dialling TLS past DialContext", plantedFile, importsHTTP + "func f(d any) { _ = &http.Transport{DialContext: d, Proxy: nil, DialTLSContext: d} }\n", "whose DialTLSContext is not left out"},
	{"the set widened with a literal", wideningFile, importsAllowed + "func f(t *allowed.Targets) { _ = t.Allow(\"api.github.com\", allowed.ReasonTarget) }\n", "widens the allowed set"},
	{"the set widened with a constant", wideningFile, importsAllowed + "const updates = \"api.github.com\"\n\nfunc f(t *allowed.Targets) { _ = t.Allow(updates, allowed.ReasonTarget) }\n", "widens the allowed set"},
	{"the set widened with a package variable", wideningFile, importsAllowed + "var updates = \"api.github.com\"\n\nfunc f(t *allowed.Targets) { _ = t.Allow(updates, allowed.ReasonTarget) }\n", "widens the allowed set"},
	{"the set widened through a local name", wideningFile, importsAllowed + "func f(t *allowed.Targets) {\n\thost := \"api.github.com\"\n\t_ = t.Allow(host, allowed.ReasonTarget)\n}\n", "widens the allowed set"},
	{"the set widened through a constant of the function", wideningFile, importsAllowed + "func f(t *allowed.Targets) {\n\tconst host = \"api.github.com\"\n\t_ = t.Allow(host, allowed.ReasonTarget)\n}\n", "widens the allowed set"},
	{"the set widened with a literal and a port", wideningFile, importsAllowed + "func f(t *allowed.Targets) { _ = t.Allow(net.JoinHostPort(\"api.github.com\", \"443\"), allowed.ReasonTarget) }\n", "widens the allowed set"},
	{"the set widened over a written list", wideningFile, importsAllowed + "func f(t *allowed.Targets) {\n\tfor _, h := range []string{\"api.github.com\"} {\n\t\t_ = t.Allow(h, allowed.ReasonTarget)\n\t}\n}\n", "widens the allowed set"},
	{"the toolkit fetching an address", windowFile, importsToolkit + "func f(u string) { _, _ = fyne.LoadResourceFromURLString(u) }\n", "fyne.io/fyne/v2.LoadResourceFromURLString, which"},
	{"an address of any scheme for the toolkit", windowFile, "package main\n\nimport \"fyne.io/fyne/v2/storage\"\n\nfunc f(s string) { _, _ = storage.ParseURI(s) }\n", "storage.ParseURI, which"},
	{"text the toolkit reads as Markdown", windowFile, importsWidget + "func f(md string) { _ = widget.NewRichTextFromMarkdown(md) }\n", "NewRichTextFromMarkdown, which"},
	{"Markdown read into a value", windowFile, importsWidget + "func f(t *widget.RichText, md string) { t.ParseMarkdown(md) }\n", "toolkit's ParseMarkdown"},
	{"a link the toolkit opens", windowFile, importsWidget + "func f() { _ = widget.NewHyperlink(\"x\", nil) }\n", "NewHyperlink, which"},
	{"a page handed to the browser elsewhere", windowFile, importsToolkit + "func f() { _ = fyne.CurrentApp().OpenURL(nil) }\n", "toolkit's OpenURL"},
	{"a page handed to the browser twice in its place", linksFile, importsToolkit + "var a, b = fyne.CurrentApp().OpenURL, fyne.CurrentApp().OpenURL\n", "toolkit's OpenURL"},
	{"a handler behind a scheme", windowFile, "package main\n\nimport \"fyne.io/fyne/v2/storage/repository\"\n\nfunc f() { repository.Register(\"https\", nil) }\n", "repository.Register, which"},
	{"a third handler in the file allowed two", offlineFile, importsRepository + "func f() {\n\trepository.Register(\"http\", offline{})\n\trepository.Register(\"https\", offline{})\n\trepository.Register(\"ftp\", other{})\n}\n", "repository.Register, which"},
}

const (
	offlineFile       = "cmd/certdoctor-gui/offline.go"
	importsRepository = "package main\n\nimport \"fyne.io/fyne/v2/storage/repository\"\n\n"
)

var waysOutItMustLeave = []wayOutCase{
	{"a dial after the permission", plantedFile, importsNet + "func f(may func(string) error, a string) {\n\tif may(a) != nil {\n\t\treturn\n\t}\n\tvar d net.Dialer\n\t_, _ = d.Dial(\"tcp\", a)\n}\n", ""},
	{"addresses as values", plantedFile, "package p\n\nimport (\n\t\"net/netip\"\n\t\"net/url\"\n)\n\nfunc f(s string) { _, _ = url.Parse(s)\n\t_, _ = netip.ParseAddr(s) }\n", ""},
	{"a method called Listen on a type of ours", plantedFile, importsNet + "type t struct{}\n\nfunc (t) Listen() {}\n\nfunc f(x t) { x.Listen() }\n", ""},
	{"ioctl by its name", plantedFile, importsSyscall + "func f(fd, req, p uintptr) { _, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, req, p) }\n", ""},
	{"verify options with roots", plantedFile, importsX509 + "func f(c *x509.Certificate, p *x509.CertPool) { _, _ = c.Verify(x509.VerifyOptions{Roots: p}) }\n", ""},
	{"the transport of the script fetch", plantedFile, importsHTTP + "func f(d any) *http.Transport {\n\treturn &http.Transport{Proxy: nil, DialContext: d, DisableKeepAlives: true}\n}\n\nvar c = &http.Client{Transport: f(nil)}\n", ""},
	{"a chain built with the three flags", plantedFile, importsSyscall + "const noNetwork = 0x00000004 | 0x00000100 | 0x00002000\n\nfunc f() { _ = syscall.CertGetCertificateChain(0, nil, nil, 0, nil, noNetwork, 0, nil) }\n", ""},
	{"the procedures a file is allowed", proxySettingFile, importsSyscall + "var p = syscall.NewLazyDLL(\"x\").NewProc(\"WinHttpGetIEProxyConfigForCurrentUser\")\n", ""},
	{"the set widened the ways cli.go widens it", wideningFile, importsAllowed +
		"type found struct{ Known []string }\n\n" +
		"func f(t *allowed.Targets, host string, resolvers found, port string) {\n" +
		"\t_ = t.Allow(host, allowed.ReasonTarget)\n" +
		"\tfor _, r := range resolvers.Known {\n\t\taddress, err := target(r)\n\t\tif err != nil {\n\t\t\tcontinue\n\t\t}\n\t\t_ = t.Allow(address, allowed.ReasonResolver)\n\t}\n" +
		"\tif raw := target2(port); raw != \"\" {\n\t\t_ = t.Allow(raw, allowed.ReasonResolver)\n\t}\n" +
		"\tfor _, fallback := range fallbacks() {\n\t\t_ = t.Allow(fallback, allowed.ReasonResolver)\n\t}\n" +
		"\t_ = t.Allow(net.JoinHostPort(host, \"53\"), allowed.ReasonResolver)\n" +
		"\tauthorise := func(endpoints []string) {\n\t\tfor _, e := range endpoints {\n\t\t\t_ = t.Allow(e, allowed.ReasonProxy)\n\t\t}\n\t}\n\t_ = authorise\n}\n", ""},
	{"the one page handed to the browser in its place", linksFile, importsToolkit + "var open = fyne.CurrentApp().OpenURL\n", ""},
	{"the two handlers the window puts behind the web", offlineFile, importsRepository + "func f() {\n\trepository.Register(\"http\", offline{})\n\trepository.Register(\"https\", offline{})\n}\n", ""},
	{"a folder of the person's own as an address", windowFile, "package main\n\nimport \"fyne.io/fyne/v2/storage\"\n\nfunc f(p string) { _ = storage.NewFileURI(p) }\n", ""},
}

// wayOutViolations is what checkWaysOut says of one planted file.
func wayOutViolations(t *testing.T, c wayOutCase) []Violation {
	t.Helper()
	files := []sourceFile{sourceFrom(t, c.rel, c.src)}
	return checkWaysOut(files, packageValues(files))
}

func TestTheWayOutScannerRefusesWhatItMustRefuse(t *testing.T) {
	for _, c := range waysOutItMustRefuse {
		got := wayOutViolations(t, c)
		if len(got) != 1 || !strings.Contains(got[0].Detail, c.want) {
			t.Errorf("%s: wanted one violation saying %q, got %d: %v", c.label, c.want, len(got), got)
		}
	}
}

// And it does not get there by refusing everything, or the cases above prove
// nothing: the shapes this tree uses, each written the way it is written.
func TestTheWayOutScannerLeavesWhatItMustLeave(t *testing.T) {
	for _, c := range waysOutItMustLeave {
		if got := wayOutViolations(t, c); len(got) != 0 {
			t.Errorf("%s: wanted nothing, got %v", c.label, got)
		}
	}
}

// The rule of reach_test.go, by prefix since 2026-11-11, read case by case.
func TestTheNetworkPackageRuleReadsEveryShape(t *testing.T) {
	for p, want := range map[string]bool{
		"net": true, "net/http": true, "net/textproto": true, "net/rpc/jsonrpc": true, "net/smtp": true,
		"crypto/tls": true, "log/syslog": true, "golang.org/x/net/http2": true, "golang.org/x/net/proxy": true,
		"golang.org/x/net": true, "net/url": false, "net/netip": false, "golang.org/x/net/html": false,
		"crypto/x509": false, "os": false, "netip": false, "github.com/netx/net": false,
	} {
		if got := networkPackage(p); got != want {
			t.Errorf("networkPackage(%q) is %v, and has to be %v", p, got, want)
		}
	}
}
