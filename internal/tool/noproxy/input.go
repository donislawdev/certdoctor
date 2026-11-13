package noproxy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// THIS FILE READS THE TWO INPUTS, and refuses what the programs would read in
// different ways before any of them is asked. A list is the bytes of a variable
// and is taken as they are. An address passes through each program's own URL
// parser before NO_PROXY is consulted, and those parsers do not agree on every
// spelling of a host or a port - so a spelling they disagree on is refused here,
// with the spelling they all read the same way, rather than answered as if one
// of them were every program.
//
// A REFUSAL NAMES A POSITION AND NEVER QUOTES THE INPUT, as every tool's does.

// refuse is a refusal of an input, said after its name.
func refuse(input, format string, args ...any) error {
	return &spec.Refusal{Reason: "the " + input + " " + fmt.Sprintf(format, args...)}
}

// line is an input without the one line ending a file or a pipe leaves after
// it - it is the end of the line, not a part of the value.
func line(raw []byte) string {
	s := string(raw)
	if rest, ok := strings.CutSuffix(s, "\n"); ok {
		return strings.TrimSuffix(rest, "\r")
	}
	return s
}

// readList is the list as the programs would be handed it, and what was taken
// off it first.
//
// THE LIST IS TAKEN BYTE FOR BYTE, blanks around it included: curl reads "*" as
// "never use a proxy" and " *" as a host nobody has. The one thing taken off is
// the variable's name in front of it, which is how the list comes out of env and
// set - a name no program could hold as an entry, so taking it off answers the
// question that was meant.
func readList(raw []byte) (string, []string, error) {
	list := line(raw)
	var notes []string
	const name = "no_proxy="
	if len(list) >= len(name) && strings.EqualFold(list[:len(name)], name) {
		notes = append(notes, fmt.Sprintf("Took off %q in front of the list.", list[:len(name)]))
		list = list[len(name):]
	}
	for i := 0; i < len(list); i++ {
		at := utf8.RuneCountInString(list[:i]) + 1
		switch c := list[i]; {
		case c == '\n' || c == '\r':
			return "", nil, refuse("list", "breaks onto a new line at character %d - NO_PROXY is one line, its "+
				"entries separated by commas", at)
		case c >= utf8.RuneSelf:
			return "", nil, refuse("list", "has a character outside ASCII at character %d. Each program turns an "+
				"international name into ASCII its own way, so write the name as a program sends it, the "+
				"xn-- form", at)
		case (c < ' ' && c != '\t') || c == 0x7f:
			return "", nil, refuse("list", "has a control character at character %d", at)
		}
	}
	return list, notes, nil
}

// address is the place the programs are asked about, as read.
type address struct {
	target proxy.Target
	// port is the port the address named, zero when it named none.
	port int
}

// readAddress is the address as the programs would see it, and what was taken
// off it or assumed.
//
// ONLY THE SCHEME, THE HOST AND THE PORT ARE READ: they are all a program hands
// its NO_PROXY reading. A path, a query and a fragment are set aside and said
// to be, and an address without a scheme is read as https://, the scheme most
// programs are asked for, and said to be too.
func readAddress(raw []byte) (address, []string, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return address{}, nil, refuse("address", "is empty - give a URL such as https://example.com, or a host name")
	}
	if err := printable(text); err != nil {
		return address{}, nil, err
	}
	var notes []string
	scheme, rest, found := strings.Cut(text, "://")
	if found {
		var err error
		if scheme, err = httpScheme(scheme); err != nil {
			return address{}, nil, err
		}
	} else {
		scheme, rest = "https", text
		notes = append(notes, "The address names no scheme, so it is read as an https:// address.")
	}
	authority, after := cutAuthority(rest)
	if after != "" && after != "/" {
		notes = append(notes, "Only the scheme, host and port of the address are read - NO_PROXY is decided "+
			"by them alone - so what came after them was set aside.")
	}
	if strings.Contains(authority, "@") {
		return address{}, nil, refuse("address", "has a user name before @. NO_PROXY is decided by the host, so "+
			"give the address without it")
	}
	host, portText, err := splitHostPort(authority)
	if err != nil {
		return address{}, nil, err
	}
	port, err := readPort(portText)
	if err != nil {
		return address{}, nil, err
	}
	return address{target: proxy.Target{Scheme: scheme, Host: host, Port: portText}, port: port}, notes, nil
}

// printable refuses what no program's URL parser takes as it is: a character
// outside ASCII, which each one converts its own way, and a space or a control
// character inside the address.
func printable(text string) error {
	for i := 0; i < len(text); i++ {
		at := utf8.RuneCountInString(text[:i]) + 1
		switch c := text[i]; {
		case c >= utf8.RuneSelf:
			return refuse("address", "has a character outside ASCII at character %d. Each program turns an "+
				"international name into ASCII its own way, so write the name as a program sends it, the "+
				"xn-- form", at)
		case c <= ' ' || c == 0x7f:
			return refuse("address", "has a space or a control character at character %d", at)
		}
	}
	return nil
}

// httpScheme is the scheme in lower case, or a refusal of one that is not
// http or https - the two a program sends through an HTTP proxy.
func httpScheme(scheme string) (string, error) {
	switch s := strings.ToLower(scheme); s {
	case "http", "https":
		return s, nil
	}
	return "", refuse("address", "has a scheme other than http:// and https://, and NO_PROXY is read for "+
		"those two")
}

// cutAuthority is the part of an address before its path, query or fragment,
// and what follows it. A backslash is not one of the three: browsers read it as
// a slash and the other parsers as a character, so it is left in the host to be
// refused there.
func cutAuthority(rest string) (authority, after string) {
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		return rest[:i], rest[i:]
	}
	return rest, ""
}

// splitHostPort is the host and the port text of an authority.
func splitHostPort(authority string) (host, port string, err error) {
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", "", refuse("address", "opens an IPv6 address with [ and does not close it with ]")
		}
		after := authority[end+1:]
		if after != "" && after[0] != ':' {
			return "", "", refuse("address", "has something other than a port after the ] of its IPv6 address")
		}
		host, err = readIPv6(authority[1:end])
		return host, strings.TrimPrefix(after, ":"), err
	}
	switch strings.Count(authority, ":") {
	case 0:
		host = authority
	case 1:
		host, port, _ = strings.Cut(authority, ":")
		if port == "" {
			return "", "", refuse("address", "ends its host with a colon and no port after it")
		}
	default:
		return "", "", refuse("address", "has more than one colon. An IPv6 address is written in brackets, with "+
			"its port after them")
	}
	return host, port, readName(host)
}

// readIPv6 is the address between the brackets, refused unless every program
// reads it the same way: as the shortest form, which is what the browsers'
// parser - and fetch in Node.js with it - writes it back as, while Go and
// Python compare the text as it was typed.
//
// AN IPv4 ADDRESS WRITTEN AS IPv6 IS REFUSED TOO: Go writes it back in its
// dotted form and that parser in hexadecimal, so no one spelling is the one
// they all compare.
func readIPv6(text string) (string, error) {
	addr, err := netip.ParseAddr(text)
	switch {
	case err != nil || !addr.Is6():
		return "", refuse("address", "has brackets around something that is not an IPv6 address")
	case addr.Zone() != "":
		return "", refuse("address", "names an IPv6 zone after %%. The programs do not agree on keeping it, so "+
			"give the address without it")
	case addr.Is4In6():
		return "", refuse("address", "is an IPv4 address written as IPv6, which the programs write back in "+
			"different ways - give the IPv4 address itself, %s", addr.Unmap())
	case !strings.EqualFold(addr.String(), text):
		return "", refuse("address", "has its IPv6 address in a long form. The programs shorten it before "+
			"comparing it, and not all of them - write it as [%s]", addr)
	}
	return text, nil
}

// readName refuses a host that is not a name or an IPv4 address every program
// reads the same way.
//
// A NAME ENDING IN A NUMBER IS AN IPv4 ADDRESS TO SOME OF THEM. The browsers'
// parser, and fetch in Node.js with it, reads "10.1" as 10.0.0.1, "0x7f.1" as
// 127.0.0.1 and "010.0.0.1" as 8.0.0.1, while Go and Python compare the text -
// so an address ending in a number has to be four decimal numbers, written the
// way they all write it back.
func readName(host string) error {
	if host == "" {
		return refuse("address", "names no host - give one such as https://example.com")
	}
	for i := 0; i < len(host); i++ {
		if c := host[i]; !(isLetterOrDigit(c) || c == '.' || c == '-' || c == '_') {
			return refuse("address", "has a character no host name has in its host - a host name is letters, "+
				"digits, dots, hyphens and underscores")
		}
	}
	if !endsInNumber(host) {
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() && addr.String() == host {
		return nil
	}
	return refuse("address", "has a host that ends in a number but is not an IPv4 address written as four "+
		"numbers from 0 to 255. Node.js reads 10.1 as 10.0.0.1 and Go and Python read it as a name, so write "+
		"the address as four numbers, 10.0.0.1")
}

// endsInNumber is the URL Standard's "ends in a number checker": the last
// label - after one empty label a trailing dot leaves - is decimal digits, or
// hexadecimal digits after 0x.
//
// SOURCE: WHATWG URL Standard, section 3.5 "Host parsing", ends in a number
// checker, read 2026-11-13. https://url.spec.whatwg.org/#ends-in-a-number-checker
func endsInNumber(host string) bool {
	labels := strings.Split(host, ".")
	if labels[len(labels)-1] == "" && len(labels) > 1 {
		labels = labels[:len(labels)-1]
	}
	last := labels[len(labels)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	hex, ok := strings.CutPrefix(strings.ToLower(last), "0x")
	return ok && strings.Trim(hex, "0123456789abcdef") == ""
}

// readPort is the port an address named, zero for none, refused unless it is
// a number every program reads the same way: 1 to 65535, without a leading
// zero, which the browsers' parser drops and Go and Python keep in the text.
func readPort(text string) (int, error) {
	if text == "" {
		return 0, nil
	}
	if strings.Trim(text, "0123456789") != "" {
		return 0, refuse("address", "has a port that is not a number")
	}
	if len(text) > 1 && text[0] == '0' {
		return 0, refuse("address", "writes its port with a leading zero, which some programs drop and others "+
			"keep - write it without")
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 || n > 65535 {
		return 0, refuse("address", "asks for a port outside 1 to 65535")
	}
	return n, nil
}

func isLetterOrDigit(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
