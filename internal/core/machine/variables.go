package machine

import "strings"

// variables is every environment variable L0 reads, in report order.
//
// EACH ONE CARRIES ITS SOURCE, AND THAT IS RULE 18, NOT DECORATION. Every line
// below is a claim about somebody else's tool, and this project's most expensive
// mistake would be to state one of them in the same voice as something measured.
// A source is three things and no fourth - the document by NAME as well as by
// link, the date it was read, and the claim written in our own words. Nobody
// else's prose is copied: some of these documents are licensed incompatibly with
// ours, and a fact is not copyrightable while a sentence is. ADR21 and ADR22.
//
// THE ORDER IS THE REPORT ORDER and it is declared once here, so no renderer
// sorts it and no map iteration shuffles it between runs.
//
// The list is twenty-one entries and it is APPROVED - D11. A variable is not
// added here because it seems useful; it is added by a decision, and two that
// turned up while these sources were being read were left out for exactly that
// reason.
var variables = []string{
	// curl, manual page, section "Environment", read 2026-08-04:
	// https://curl.se/docs/manpage.html
	//
	// Both spellings are listed BECAUSE THEY ARE NOT THE SAME VARIABLE, and
	// this is the single most misleading thing L0 could get wrong. curl accepts
	// these in either case and prefers the lower case one, EXCEPT for the http
	// proxy, which it honours in lower case only. The reason is the CGI
	// convention of turning an incoming request header into an environment
	// variable prefixed HTTP_, which would let a remote request hand a server
	// side script its own proxy - Everything curl, "http_proxy in lower case
	// only", read 2026-08-04:
	// https://github.com/curl/everything-curl/blob/master/usingcurl/proxies/env.md
	//
	// On systems whose environment is case insensitive, Windows among them, the
	// two spellings are ONE variable and both come back set. That is not a
	// duplicate row to be folded away: it is the divergence this tool exists to
	// show, and a report that merged them would be true and misleading at once.
	"HTTP_PROXY",
	"http_proxy",
	"HTTPS_PROXY",
	"https_proxy",
	// ALL_PROXY applies when no protocol specific proxy is set - same document
	// and section, read 2026-08-04.
	"ALL_PROXY",
	"all_proxy",
	// NO_PROXY holds a comma separated list of hosts that bypass the proxy, a
	// lone asterisk meaning all of them. It overrides a proxy given on the
	// command line rather than the other way round - same document and section,
	// read 2026-08-04.
	"NO_PROXY",
	"no_proxy",

	// OpenSSL, openssl-env(7), read 2026-08-04:
	// https://github.com/openssl/openssl/blob/master/doc/man7/openssl-env.pod
	//
	// These name the default file and the default directory of CA certificates.
	// The directory form takes more than one path, separated by colons, or by
	// semicolons on Windows - so finding a separator in the value does not mean
	// the path is malformed.
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",

	// curl, manual page, section "Environment", read 2026-08-04:
	// https://curl.se/docs/manpage.html
	//
	// CURL_CA_BUNDLE supplies the value of --cacert - AND IS IGNORED WHEN THE
	// TLS BACKEND IS SCHANNEL. The manual page says so in two independent
	// places, at --cacert and in the environment section. It matters here
	// because a remediation command built around this variable does nothing at
	// all on a Windows curl using the system store, and the person who ran it
	// waits for an effect that is never coming.
	"CURL_CA_BUNDLE",
	// CURL_SSL_BACKEND picks the TLS backend when curl was built with support
	// for more than one, by case insensitive name - the manual page lists
	// gnutls, mbedtls, openssl, rustls, schannel and wolfssl - and a name that
	// is not built in leaves curl on its default. Same document and section,
	// read 2026-08-04.
	//
	// IT IS ON THIS LIST BECAUSE IT DECIDES WHETHER THE VARIABLE ABOVE MEANS
	// ANYTHING. Setting this to schannel is what makes CURL_CA_BUNDLE inert. A
	// report showing the bundle as set without showing this would be stating a
	// fact and implying an effect that may not exist.
	"CURL_SSL_BACKEND",

	// requests, Advanced Usage, read 2026-08-04:
	// https://github.com/psf/requests/blob/main/docs/user/advanced.rst
	//
	// REQUESTS_CA_BUNDLE overrides the bundle requests trusts, AND FALLS BACK TO
	// CURL_CA_BUNDLE when it is unset. So the curl variable above can be
	// deciding what Python trusts on a machine where nobody set a Python
	// variable at all - which is why both are read rather than one.
	"REQUESTS_CA_BUNDLE",

	// Node.js, doc/api/cli.md, read 2026-08-04:
	// https://github.com/nodejs/node/blob/main/doc/api/cli.md
	//
	// NODE_EXTRA_CA_CERTS adds certificates to the well known roots. THE WHOLE
	// LOT IS DROPPED - the extra certificates AND the well known roots - as soon
	// as the code passes an explicit ca option to a TLS or HTTPS client or
	// server. So this variable being set is not the same as it taking effect,
	// and L0 reports the setting without claiming the effect.
	"NODE_EXTRA_CA_CERTS",
	// NODE_TLS_REJECT_UNAUTHORIZED set to the string 0 turns certificate
	// validation off for TLS, and so for HTTPS - same document, read 2026-08-04.
	//
	// THE VALUE HERE IS THE ENTIRE FINDING AND IT HAS BEEN DELETED ONCE ALREADY.
	// A masking rule asking whether the NAME contained a credential word said
	// yes, because "unauthorized" contains "auth", and what it removed was the
	// 0. The name is now read in segments and is handed to the masking rules
	// beside the value rather than glued to it - D8 and ADR19.
	"NODE_TLS_REJECT_UNAUTHORIZED",
	// NODE_USE_ENV_PROXY set to 1 makes Node read HTTP_PROXY, HTTPS_PROXY and
	// NO_PROXY at startup and route its requests accordingly. Added in v24.0.0
	// and v22.21.0 - same document, read 2026-08-04.
	//
	// IT IS ON THIS LIST FOR THE SAME REASON AS CURL_SSL_BACKEND: it decides
	// whether three variables already reported above reach this runtime at all.
	// Without it, "HTTPS_PROXY is set" is a true row that says nothing about
	// whether the Node process everyone is complaining about ever saw it.
	//
	// Node marks this one as under active development, so the behaviour may
	// move. That is a reason to report the setting and claim nothing about the
	// effect, which is what this layer does with all of them.
	"NODE_USE_ENV_PROXY",

	// JVM Tool Interface specification, section "JAVA_TOOL_OPTIONS", read
	// 2026-08-04:
	// https://docs.oracle.com/en/java/javase/25/docs/specs/jvmti.html
	//
	// JAVA_TOOL_OPTIONS exists so that options reach a JVM whose command line
	// cannot be edited, which is most of them in a container or behind a script.
	// It is split into options on white space, with quoting - so it is a
	// COMPOUND value, and a trust store password can sit inside it beside the
	// store path. That is why the whole value goes through the masking rules
	// rather than being reported as one opaque string.
	"JAVA_TOOL_OPTIONS",

	// git, Documentation/config/http.adoc, read 2026-08-04:
	// https://github.com/git/git/blob/master/Documentation/config/http.adoc
	//
	// GIT_SSL_CAINFO overrides http.sslCAInfo, the file of certificates git
	// verifies a peer with, and GIT_SSL_CAPATH overrides http.sslCAPath, the
	// directory form of the same thing.
	//
	// THE TRAP THAT MAKES THESE WORTH READING AT ALL. When the schannel backend
	// was selected through http.sslBackend, git tells cURL NOT to use that
	// bundle by default, because it would displace the Windows certificate
	// store; http.schannelUseSSLCAInfo is what turns that back on. So on
	// Windows this variable can be set, correct, and doing nothing - the same
	// shape of trap as CURL_CA_BUNDLE above, reached by a different route.
	//
	// Read for the fact only. This document is GPL-2.0-only, which does not
	// combine with the GPL-3.0 we publish under, so not one phrase of it is
	// reproduced here - ADR21.
	"GIT_SSL_CAINFO",
	"GIT_SSL_CAPATH",

	// pip, Configuration, section "Environment Variables", read 2026-08-04:
	// https://github.com/pypa/pip/blob/main/docs/html/topics/configuration.md
	//
	// pip turns any long command line option into an environment variable named
	// PIP_ plus the option in upper case, so PIP_CERT is the --cert option: the
	// path to a PEM encoded CA bundle that replaces the default. Checked against
	// the option's own declaration in pip's source rather than inferred from the
	// naming rule alone:
	// https://github.com/pypa/pip/blob/main/src/pip/_internal/cli/cmdoptions.py
	//
	// Worth knowing when reading the value: pip states that a variable set to an
	// empty string is NOT read as false. Empty and unset are different answers
	// here too.
	"PIP_CERT",

	// AWS Command Line Interface User Guide, environment variables, read
	// 2026-08-04:
	// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
	//
	// AWS_CA_BUNDLE names the certificate bundle used to validate HTTPS
	// certificates. It beats the ca_bundle profile setting and is itself beaten
	// by --ca-bundle on the command line.
	//
	// Read for the fact only - this guide carries no open licence, so nothing is
	// quoted from it.
	"AWS_CA_BUNDLE",

	// Kubernetes, "Accessing the Kubernetes API from a Pod", read 2026-08-04:
	// https://github.com/kubernetes/website/blob/main/content/en/docs/tasks/run-application/access-api-from-pod.md
	//
	// A container in a Pod builds the API server address out of
	// KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT_HTTPS. The variable
	// follows the kubelet's general rule of publishing SVCNAME_SERVICE_HOST for
	// each active Service, and the API server is published as a Service named
	// kubernetes in the default namespace - Kubernetes, "Service", section
	// "Discovering services", read 2026-08-04:
	// https://github.com/kubernetes/website/blob/main/content/en/docs/concepts/services-networking/service.md
	//
	// IT IS A HINT AND NOT A VERDICT. Saying "this is a container" belongs to
	// L6, and L0 only says which variables were found - D11.
	"KUBERNETES_SERVICE_HOST",

	// systemd, Container Interface, section "Environment Variables", read
	// 2026-08-04:
	// https://github.com/systemd/systemd/blob/main/docs/CONTAINER_INTERFACE.md
	//
	// A container manager is asked to set container to a short lower case string
	// naming its implementation, so that software inside can tell it is in one.
	//
	// THE LIMIT IS PART OF THE FACT: the interface asks for it to be set for the
	// container's PID 1. A process further down the tree need not have inherited
	// it, so the variable being absent says nothing, while the variable being
	// present says something. That asymmetry is exactly why this is a hint for
	// L6 rather than an answer - D11.
	"container",
}

// ProxyVariables returns the declared variables that carry a PROXY ADDRESS, in
// the order L0 reports them.
//
// IT IS DERIVED AND NOT LISTED, AND THE FIRST DRAFT LISTED THEM. Writing the
// eight names again put the same literals in the file twice, and the mutation
// register works on TEXT rather than on intent: two existing entries aiming at
// "`t`"http_proxy`",`n" immediately reported TRAFIEN 2 and stopped proving
// anything. That is OBS50 committed while its own paragraph was being written -
// the shape is not "one RULE in two places", it is "one STRING in two places",
// and the second is easier to reach by accident. Fixed at the source rather than
// by widening the anchors, which is what OBS50 itself prescribes.
//
// THE RULE: a name ending in _PROXY with exactly one underscore in it. That
// catches both spellings of all four addresses and would catch FTP_PROXY on the
// day somebody adds it, which is the behaviour we want from a derived list.
//
// WHAT IT DELIBERATELY LEAVES OUT, and both exclusions fall out of the rule
// rather than being special cases. NODE_USE_ENV_PROXY ends in _PROXY and has
// three underscores: it is a SWITCH saying whether Node reads the others at all,
// which is a fact about a runtime rather than an address. JAVA_TOOL_OPTIONS does
// not end in _PROXY at all, and is out for the opposite reason - it may CARRY
// proxy properties inside its value, so it is read by a parser rather than by
// name, and listing it here would invite somebody to treat its whole value as a
// proxy URL.
func ProxyVariables() []string {
	out := make([]string, 0, len(variables))
	for _, name := range variables {
		if carriesProxyAddress(name) {
			out = append(out, name)
		}
	}
	return out
}

// carriesProxyAddress is the rule ProxyVariables applies. It is separate so that
// a test can put a name to it and so that the exclusion above has somewhere to
// be stated once.
func carriesProxyAddress(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasSuffix(upper, "_PROXY") && strings.Count(upper, "_") == 1
}
