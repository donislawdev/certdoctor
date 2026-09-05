package proxy

import "strings"

// Server is one proxy that a configuration names.
//
// IT KEEPS THREE THINGS APART THAT ONE STRING RUNS TOGETHER, and a reader of the
// report needs all three: which protocol the entry is FOR, which scheme the
// proxy itself is reached BY, and where it lives. "http=http://p:8080" answers
// all three and "p" answers only the last.
type Server struct {
	// Protocol is the protocol this entry applies to, lower case, or empty when
	// the entry is the default for every protocol that has no entry of its own.
	Protocol string
	// Scheme is how the proxy itself is reached, lower case, or empty when the
	// entry did not say. It is NOT the same as Protocol: an https request can
	// legitimately go through a proxy spoken to over http, which is the ordinary
	// case for CONNECT.
	Scheme string
	// Address is host or host:port, as written, with the case of a name left
	// alone so that the report shows what the machine holds.
	//
	// USERINFO IS NEVER IN HERE - see CarriedCredentials below.
	Address string
	// CarriedCredentials records that the entry named a user and a password and
	// that this package dropped them. The name is the one report.Finding already
	// uses for the same fact, because the glossary allows one name per concept.
	//
	// THE FACT IS HALF THE ANSWER TO "WHY DO I GET A 407" and it is the half
	// that can be said without saying the secret. Vendors document the shape:
	// Microsoft, HttpClient.DefaultProxy, read 2026-09-06 - the proxy URL "may
	// optionally include a username and password for proxy authentication".
	//
	// WHY THE SPLIT HAPPENS HERE AND NOT ON THE ASSEMBLY PATH, WHICH IS WHERE
	// ADR18 PUTS MASKING. report.EnvironmentVariable keeps the raw value and
	// lets the orchestrator mask it, and that is right for a value whose only
	// destiny is a report line. Address is not that: it is the field a later
	// slice turns into a connection target and into an entry in the allowed set,
	// so a secret left in it does not stay on the reporting path. Inviolable
	// rule 17 says credentials never reach the report or the log whatever
	// --redact says, and the cheapest way to keep a promise like that is to make
	// it structural - the value is not dropped by a rule somewhere downstream,
	// it never enters the struct.
	CarriedCredentials bool
}

// IsDefault reports whether this entry applies to any protocol without one of
// its own.
func (s Server) IsDefault() bool { return s.Protocol == "" }

// ParseServerList reads the proxy server list in the form both Windows stacks
// hold it.
//
// SOURCE: Microsoft, WINHTTP_PROXY_INFO, read 2026-09-05 - "The proxy server
// list contains one or more of the following strings separated by semicolons or
// whitespace", with the form ([<scheme>=][<scheme>"://"]<server>[":"<port>]).
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_proxy_info
//
// SOURCE for the default entry, same day: Microsoft, "ProxyCfg.exe proxy
// configuration tool" - "To list a proxy for a specific protocol, the string
// must follow the format, <protocol>=..."; "If a proxy name is listed by itself,
// you can use it as the default proxy for any protocols that do not have a
// specified proxy", with the worked example that "http=http_proxy other_proxy"
// uses http_proxy for HTTP while HTTPS uses other_proxy.
// https://learn.microsoft.com/en-us/windows/win32/winhttp/proxycfg-exe--a-proxy-configuration-tool
//
// AN ENTRY THAT NAMES NOTHING IS DROPPED AND AN ENTRY THAT NAMES SOMETHING
// UNREADABLE IS KEPT. "http=" has no address, so there is nothing to report and
// nothing to connect to. Anything else comes back as written: this package
// reports what a machine holds, and deciding that a string is not a real proxy
// is a verdict rather than a reading.
func ParseServerList(list string) []Server {
	entries := splitList(list, "; \t\r\n")
	out := make([]Server, 0, len(entries))
	for _, entry := range entries {
		s, ok := parseServer(entry)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

// parseServer pulls one entry apart. The entry arrives already trimmed, because
// splitList drops surrounding space off every field it hands back and whitespace
// is one of this list's separators anyway.
//
// THE PROTOCOL IS TAKEN OFF BEFORE THE SCHEME, and the order is forced by the
// grammar rather than chosen: "http=http://p" holds both, and an "=" can only
// belong to the first because the second is introduced by "://".
//
// AN "=" AFTER THE "://" IS NOT A PROTOCOL, which is why the comparison below is
// positional rather than a bare "is there an equals sign". A proxy written with
// a query - "http://p.corp/?a=b" - would otherwise be read as a protocol named
// "http://p.corp/?a" serving a proxy called "b".
//
// USERINFO IS CUT OFF AND ONLY THE FACT OF IT SURVIVES - inviolable rule 17 and
// Server.CarriedCredentials. It is cut here rather than in the environment
// parser alone, even though the Windows grammar above has no place for it,
// because one rule in two places is the shape OBS50 has measured five times in
// this tree. The order matters and is not free: a path is cut FIRST, so that
// "http://p:8080/a@b" is the server p:8080 rather than a server called "b".
func parseServer(entry string) (Server, bool) {
	var s Server
	rest := entry
	if eq := strings.Index(rest, "="); eq >= 0 && eq < indexOrLast(rest, "://") {
		s.Protocol = lower(rest[:eq])
		rest = rest[eq+1:]
	}
	if i := strings.Index(rest, "://"); i >= 0 {
		s.Scheme = lower(rest[:i])
		rest = rest[i+len("://"):]
	}
	// A path or query has no meaning in this grammar; the list names servers.
	if cut := strings.IndexAny(rest, "/?#"); cut >= 0 {
		rest = rest[:cut]
	}
	// The LAST "@" separates userinfo from the host, because a host name cannot
	// contain one and an unencoded password can. An empty userinfo carries no
	// credential, so "@p:8080" is a badly written address and not a secret.
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		s.CarriedCredentials = at > 0
		rest = rest[at+1:]
	}
	s.Address = rest
	if s.Address == "" {
		return Server{}, false
	}
	return s, true
}

// indexOrLast gives the position of sep, or a position past the end of s when
// it is absent - so that "is the = before the ://" is one comparison rather than
// two nested conditions.
func indexOrLast(s, sep string) int {
	if i := strings.Index(s, sep); i >= 0 {
		return i
	}
	return len(s) + 1
}

// ServerFor picks the entry that applies to one protocol.
//
// THE PROTOCOL-SPECIFIC ENTRY WINS AND THE DEFAULT IS THE FALLBACK, which is the
// vendor's worked example read literally: with "http=http_proxy other_proxy" an
// HTTP request uses http_proxy and an HTTPS request uses other_proxy.
//
// THE FIRST MATCH WINS RATHER THAN THE LAST. Nothing in the source says what a
// list holding one protocol twice means, so this takes the reading that costs
// nothing to explain in a report - the first thing the machine says about a
// protocol is the answer - instead of inventing a precedence nobody documented.
//
// ASKING WITH NO PROTOCOL NEEDS NO BRANCH OF ITS OWN, and the first draft had
// one. A default entry IS an entry whose Protocol is empty, so an empty question
// finds it in the loop below without being sent past it. The guard that used to
// stand here could not change an answer, which makes it a line no mutation entry
// could ever redden - the same shape that came out of bypassWinHTTP one file
// over.
func ServerFor(servers []Server, protocol string) (Server, bool) {
	protocol = lower(protocol)
	for _, s := range servers {
		if s.Protocol == protocol {
			return s, true
		}
	}
	for _, s := range servers {
		if s.IsDefault() {
			return s, true
		}
	}
	return Server{}, false
}
