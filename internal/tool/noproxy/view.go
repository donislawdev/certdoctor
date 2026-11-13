package noproxy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// shownHost is the host as an address writes it, an IPv6 address in brackets.
func (a asked) shownHost() string {
	if h := a.address.target.Host; strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return a.address.target.Host
}

// programs counts the programs by their answer: every release of the program
// going directly, every release through the proxy, or the answer depending on
// the release.
func (a asked) programs() (direct, proxied, mixed int) {
	var order []string
	seen := map[string][2]bool{}
	for _, x := range a.answers {
		key := x.rule.ProgramKey()
		if _, ok := seen[key]; !ok {
			order = append(order, key)
		}
		s := seen[key]
		s[boolIndex(x.decision.Direct)] = true
		seen[key] = s
	}
	for _, key := range order {
		switch s := seen[key]; {
		case s[0] && s[1]:
			mixed++
		case s[1]:
			direct++
		default:
			proxied++
		}
	}
	return direct, proxied, mixed
}

func boolIndex(b bool) int {
	if b {
		return 1
	}
	return 0
}

// agreement is the one judgement: whether the programs give one answer. A list
// read differently by two programs on one machine is what this tool is for, so
// that is a warning, and one answer from all of them passes whichever it is.
func (a asked) agreement() spec.Check {
	direct, proxied, mixed := a.programs()
	host := a.shownHost()
	switch {
	case proxied == 0 && mixed == 0:
		return spec.Check{ID: "agreement", Status: status.Pass,
			Summary: fmt.Sprintf("Every program that reads NO_PROXY goes to %s directly, without the proxy.", host)}
	case direct == 0 && mixed == 0:
		return spec.Check{ID: "agreement", Status: status.Pass,
			Summary: fmt.Sprintf("Every program that reads NO_PROXY goes to %s through the proxy.", host)}
	}
	// The first phrase says "of the 7" and carries the verb, the ones after it
	// lean on it: "3 of the 7 go to it directly, 3 through the proxy and for 1
	// it depends on the release".
	total := direct + proxied + mixed
	var parts []string
	add := func(n int, lead, follow string) {
		switch {
		case n == 0:
		case len(parts) == 0:
			parts = append(parts, fmt.Sprintf("%d of the %d %s", n, total, lead))
		default:
			parts = append(parts, fmt.Sprintf("%d %s", n, follow))
		}
	}
	add(direct, verb(direct)+" to it directly", "directly")
	add(proxied, verb(proxied)+" to it through the proxy", "through the proxy")
	switch {
	case mixed == 0:
	case len(parts) == 0:
		parts = append(parts, fmt.Sprintf("for %d of the %d it depends on the release", mixed, total))
	default:
		parts = append(parts, fmt.Sprintf("for %d it depends on the release", mixed))
	}
	return spec.Check{ID: "agreement", Status: status.Warn,
		Summary: fmt.Sprintf("The programs disagree about %s: %s.", host, joinAnd(parts))}
}

// verb agrees "go" with a count of programs.
func verb(n int) string {
	if n == 1 {
		return "goes"
	}
	return "go"
}

// joinAnd joins two or three phrases with commas and a last "and".
func joinAnd(parts []string) string {
	last := len(parts) - 1
	if last == 0 {
		return parts[0]
	}
	return strings.Join(parts[:last], ", ") + " and " + parts[last]
}

// view is what a person is shown: the address as read, the programs going
// directly, the programs going through the proxy, and the two things the
// answers do not say on their own.
func (a asked) view() []spec.Block {
	blocks := []spec.Block{a.addressBlock()}
	for _, group := range []struct {
		direct bool
		title  string
	}{{true, "Directly, without the proxy"}, {false, "Through the proxy"}} {
		var rows []spec.Field
		for _, x := range a.answers {
			if x.decision.Direct == group.direct {
				rows = append(rows, a.row(x))
			}
		}
		if len(rows) > 0 {
			blocks = append(blocks, spec.Block{Kind: spec.Fields, Title: group.title, Fields: rows})
		}
	}
	return append(blocks,
		spec.Block{Kind: spec.Text, Title: "When this applies", Body: "These are the answers of programs that " +
			"take their proxy from the environment. A program given no proxy goes directly whatever the list " +
			"says, and Node.js takes no proxy from the environment unless NODE_USE_ENV_PROXY=1 is set or it is " +
			"started with --use-env-proxy."},
		spec.Block{Kind: spec.Text, Title: "Java", Body: javaSentence},
	)
}

// javaSentence is what a person who expected Java among the programs is told.
//
// SOURCE: OpenJDK, src/java.base/share/classes/sun/net/spi/DefaultProxySelector.java,
// which takes the proxy from the http, https, ftp and socks properties and the
// exceptions from http.nonProxyHosts and ftp.nonProxyHosts - reading no
// environment variable - and src/java.base/unix/native/libnet/DefaultProxySelector.c,
// which with java.net.useSystemProxies=true asks GConf or GIO, the desktop's
// settings. Read on master 2026-11-13.
// https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/net/spi/DefaultProxySelector.java
const javaSentence = "Java does not read NO_PROXY. A JVM takes its proxy from the http.proxyHost and " +
	"https.proxyHost properties and its exceptions from http.nonProxyHosts - or, with " +
	"java.net.useSystemProxies=true, from the system's own proxy settings."

// addressBlock is the address as the programs are asked about it.
func (a asked) addressBlock() spec.Block {
	t := a.address.target
	port := spec.Field{Label: "Port", Value: strconv.Itoa(a.address.port)}
	if a.address.port == 0 {
		port = spec.Field{Label: "Port", Value: defaultPort(t.Scheme),
			Note: "the " + t.Scheme + " default - the address names none"}
	}
	return spec.Block{Kind: spec.Fields, Title: "Address", Fields: []spec.Field{
		{Label: "Scheme", Value: t.Scheme},
		{Label: "Host", Value: t.Host},
		port,
	}}
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}

// row is one reading's answer as a person reads it: the program, what decided,
// and the releases it holds for.
func (a asked) row(x answer) spec.Field {
	note := x.rule.Versions()
	if c := x.rule.Condition(); c != "" {
		note += ", only with " + c
	}
	return spec.Field{Label: x.rule.Program(), Value: a.because(x.decision), Note: note}
}

// because says what an answer rests on, short enough to stand in a column.
func (a asked) because(d proxy.Decision) string {
	switch d.Basis {
	case proxy.BasisEntry:
		return `entry "` + d.Entry + `"`
	case proxy.BasisWholeValue:
		return "the whole list is *"
	case proxy.BasisLocal:
		// The one program with such places sends both localhost and the
		// loopback addresses directly (proxy.BasisLocal).
		if _, err := netip.ParseAddr(a.address.target.Host); err == nil {
			return "a loopback address is never proxied"
		}
		return "localhost is never proxied"
	}
	return "no entry applies"
}
