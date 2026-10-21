// Package trust is L5: what each runtime on this machine makes of the chain the
// server presented.
//
// THE UNIT IS THE STORE, NEVER THE RUNTIME - ADR48. Measured on the owner's
// machine 2026-08-18: six Java trust stores, two curl binaries on PATH, and git
// reading a different store than the curl shipped in the same install. A layer
// answering "does java trust this" with one value would be making the
// single-store claim this whole product exists to disprove.
//
// WHERE THE L4/L5 LINE RUNS - ADR46. L4 says what the server SENT and touches no
// store at all. This layer says what a store MAKES of it. Neither answer
// substitutes for the other, and the measured reason is on the bench: an
// intercepted chain and an honest server missing its intermediate produce the
// SAME structural verdict, and only a trust store tells them apart.
package trust

import "github.com/donislawdev/certdoctor/internal/core/report"

// Source says where a claim about somebody else's runtime came from.
//
// THIS TYPE IS INVIOLABLE RULE 18 MADE MACHINE-CHECKABLE. The rule says every
// claim about another runtime carries its source beside it, and that a claim
// with no source is a JUDGEMENT rather than a fact. A rule enforced by good
// intentions is the one this project said it would break first and most
// expensively, so a descriptor without a source does not compile past its test.
type Source string

const (
	// Measured - somebody ran it on a real machine and wrote down what happened.
	// The strongest evidence here, and still a claim about ONE machine.
	Measured Source = "measured"
	// Documentation - the vendor says so, with a link.
	Documentation Source = "documentation"
	// Judgement - neither. It is allowed, and it has to SAY so: docs/20 is blunt
	// that a judgement must never be quoted as a fact.
	Judgement Source = "judgement"
)

var sourceMeanings = map[Source]string{
	Measured:      "run on a real machine, with the result written down",
	Documentation: "stated by the vendor, with a link",
	Judgement:     "neither measured nor documented, and must not be quoted as fact",
}

// Valid reports whether the source is one this program declared.
func (s Source) Valid() bool {
	_, ok := sourceMeanings[s]
	return ok
}

// Meaning returns the declared meaning.
func (s Source) Meaning() string { return sourceMeanings[s] }

// String makes Source printable without a conversion at every call site.
func (s Source) String() string { return string(s) }

// Descriptor is what this program claims about one family of runtime, before it
// has looked at this machine.
//
// Evidence is OUR OWN SENTENCE, and a link where there is one - never somebody
// else's prose copied in, which ADR21 forbids for a reason that outlives the
// link: a quotation goes stale silently, while a sentence we wrote is a claim
// somebody here is answerable for.
type Descriptor struct {
	// ID is the identity used in the report and in docs/20.
	ID string
	// Runtime is the family name a person reads in the matrix.
	Runtime string
	// TrustSource says, in one line, where this family keeps its anchors.
	TrustSource string
	// Source and Evidence are the rule 18 pair, and neither may be empty.
	Source   Source
	Evidence string
	// FixSource and FixEvidence are the SECOND rule 18 pair, and they are second
	// rather than shared because they carry a different claim.
	//
	// TrustSource says where a runtime KEEPS its anchors, which is a fact about
	// reading. This pair says what makes a runtime ACCEPT a new one, which is a
	// fact about writing - and it is the one a person acts on. docs/15 has the
	// registry carrying both under one source; measuring them showed they come
	// from different documents, and one evidence sentence covering two claims is
	// how the weaker of the two travels on the strength of the stronger.
	FixSource   Source
	FixEvidence string
}

// descriptors is the registry.
//
// IT NAMES ONLY THE PROBES THAT EXIST, and that is a decision rather than an
// omission. docs/20 describes thirteen, and declaring all thirteen while three
// are implemented would produce a registry whose entries mean nothing on this
// machine - the same "declared and never filled in" shape ADR16 refuses for
// schema fields and ADR30 refuses for schema versions. An entry arrives with the
// code that answers it.
var descriptors = []Descriptor{
	{
		// FIRST, because it is the store several other rows defer to - curl on
		// Schannel says in so many words that this row answers for it.
		ID:      report.RuntimeSystemStore,
		Runtime: report.RuntimeSystemStore,
		TrustSource: "the platform's own store - on Windows the logical Root store of this account and of the machine, " +
			"asked through crypt32 with every network retrieval switched off",
		Source: Measured,
		Evidence: "Measured on the owner's machine 2026-09-23: the logical Root store holds 91 certificates for both " +
			"CurrentUser and LocalMachine, because it CONTAINS AuthRoot and Enterprise - so adding the stores up counts " +
			"twice. With the three flags that switch off retrieval, a root in Microsoft's root program that this machine " +
			"has not downloaded yet - www.buypass.no - fails as a partial chain, exactly like an inspection authority nobody " +
			"installed. Measured 2026-10-13: the local copy of the program's list in the registry, 562 entries, tells " +
			"the two apart without the network. Measured 2026-10-14 on generated chains: a missing issuer reports " +
			"PARTIAL_CHAIN alone, a root the server sent reports UNTRUSTED_ROOT, both engines answer alike, and an AIA " +
			"address in a certificate is not fetched.",
		FixSource: Documentation,
		FixEvidence: "certutil, Windows Commands reference, read 2026-10-14 at " +
			"https://learn.microsoft.com/windows-server/administration/windows-commands/certutil - -addstore adds a " +
			"certificate to the named store, and -user aims it at this account's store instead of the machine's. " +
			"Measured beside it the same day: certutil -user -addstore read a PEM file and added the certificate, " +
			"tried on this account's Personal store so that nothing was trusted, then removed. And the dialog the " +
			"caveat promises was measured by the owner: aimed at this account's Root store, the command opened " +
			"Windows' security warning, it was declined, and nothing was added.",
	},
	{
		ID:      "git",
		Runtime: "git",
		TrustSource: "http.sslBackend decides: schannel uses the Windows store, openssl the file GIT_SSL_CAINFO or " +
			"http.sslCAInfo names - and on Linux a git naming no backend reads that file too, and may read " +
			"/etc/ssl/certs beside it, and the distribution's own git naming nothing takes the answer of the platform " +
			"store's row",
		Source: Measured,
		Evidence: "Measured on the owner's machine 2026-08-18: git 2.55.0.windows.3 reports http.sslbackend=openssl and " +
			"http.sslcainfo pointing at its own bundle, both from the SYSTEM level - so adding a CA to the Windows " +
			"store fixes a browser and does not fix git clone. That bundle held 229042 bytes then and 185311 on " +
			"2026-09-02 under git 2.55.0.windows.5: it is somebody else's file and it moves, which is why the probe " +
			"reads it rather than remembering it. Read from the config files rather than by running git, which is why " +
			"this probe needs no process at all. Measured again 2026-09-02, and that measurement moved what proves an " +
			"installation: the CONFIGURATION is optional - git 2.54.0 in a Debian based image has none at any level - " +
			"so a binary on PATH is the proof, and a configuration only says which store that binary reads. Both " +
			"git.exe on PATH here answered git config --list --show-origin --system with the same file, one directory " +
			"above the cmd folder and two above the mingw64 one. Measured 2026-10-20 with probe S26 in a Debian 13 " +
			"image (git 2.47.3 on libcurl over GnuTLS) and an Alpine 3.24 one (git 2.54.0 on libcurl over OpenSSL), " +
			"with no backend named: GIT_SSL_CAINFO, GIT_SSL_CAPATH and http.sslCAInfo were followed and curl's own " +
			"variables were not, an empty GIT_SSL_NO_VERIFY and http.sslVerify=false switched verification off, and " +
			"a root kept only as a hashed link in /etc/ssl/certs was trusted while the named file lacked it. Read " +
			"beside it in http.c and parse.c of git 2.54.0 at https://github.com/git/git/tree/v2.54.0 - the " +
			"environment is read after the configuration and wins, each variable acts by being set at all, and a key " +
			"standing alone is true. Which configuration git reads is read in config.c and path.c of the same tag " +
			"and in compat/mingw.c of Git for Windows 2.55.0.windows.5, and measured the same day by S26 round 3, " +
			"thirty steps in both images, each as the source predicts: ~/.gitconfig is read after the XDG file and " +
			"wins over it, GIT_CONFIG_GLOBAL replaces both, GIT_CONFIG_SYSTEM and GIT_CONFIG_NOSYSTEM name and skip " +
			"the system file, GIT_CONFIG_COUNT pairs win over every file, an include applies where it stands, a " +
			"section for one URL beats the general key, and a syntax error stops git before it connects. Not " +
			"followed, and the row says so: an [includeIf] or a URL section that sets one of the four keys, because " +
			"which repository or address it applies to is not this probe's question, GIT_CONFIG_PARAMETERS, and on " +
			"Windows a home directory that HOMEDRIVE and HOMEPATH put somewhere other than USERPROFILE, because " +
			"telling which one git takes means looking at what may be a network share. " +
			"Measured 2026-10-20 with probe S26 and with this program's own binary in Debian 13, Alpine 3.24 and RHEL 9.7 images: with nothing named, a root appended to the first bundle on Go's list - the file the system-store row judges - was trusted by curl from the package and by git from the Debian and Alpine ones, and the command printed for that row fixed them too. So a binary the distribution's own package installed, on a distribution whose recipe for libcurl names that file, takes the answer of the system-store row, and each condition that does not hold is said on its own - the recipes are cited beside the table in internal/adapter/probe/deferral.go.",
		FixSource: Documentation,
		FixEvidence: "git-config, Documentation/config/http.adoc, read 2026-08-19 at " +
			"https://git-scm.com/docs/git-config - http.sslCAInfo is \"File containing the certificates to verify the " +
			"peer with when fetching or pushing over HTTPS\". So the file IS the anchor set, and a certificate appended " +
			"to it is read by the same code that read the rest. Measured beside it: this program parsed that same file " +
			"and verified a real chain against the 150 anchors in it.",
	},
	{
		ID:          "java",
		Runtime:     "java",
		TrustSource: "lib/security/cacerts inside each installation, one store per install and never one per runtime",
		Source:      Measured,
		Evidence: "Measured on the owner machine 2026-08-18: SIX stores - four OpenJDK installs plus a JRE 8 in both " +
			"bitnesses - and TWO directories named latest with no store inside at all, which is why an install is proved " +
			"by a store that opens rather than by a directory that exists. JAVA_HOME named one of the six. The stores are " +
			"PKCS12 in the JDKs and JKS in the JRE, so they are read through keytool -list -rfc, which returns PEM in one " +
			"call - 113 blocks, 563 ms - rather than through two parsers.",
		FixSource: Documentation,
		FixEvidence: "keytool, JDK tool specification, read 2026-08-19 at " +
			"https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html - -importcert \"read the certificate " +
			"or certificate chain (...) from -file file, and store it in the keystore entry identified by -alias\", and " +
			"\"The initial password of the cacerts keystore file is changeit\". Measured beside it: changeit opened " +
			"every one of the six stores on this machine, so the password in the command is the one that worked rather " +
			"than the one the document names.",
	},
	{
		ID:      "curl",
		Runtime: "curl",
		TrustSource: "decided by the TLS backend: a Schannel build judges by this account's Windows store and takes the " +
			"answer of system-store CurrentUser, OpenSSL builds read the file CURL_CA_BUNDLE or SSL_CERT_FILE names - " +
			"and on Linux may read /etc/ssl/certs beside it, and the distribution's own build naming nothing takes " +
			"the answer of the platform store's row",
		Source: Measured,
		Evidence: "Measured on the owner machine 2026-08-18: TWO curl.exe on PATH, the system one and the one shipped " +
			"inside the Git installation, and BOTH are Schannel - the second was expected to be OpenSSL and is not. " +
			"Schannel IGNORES CURL_CA_BUNDLE, measured earlier by pointing it at a path that does not exist and still " +
			"getting a 200, so a fix generated without reading the backend is a command that does nothing. " +
			"Measured 2026-10-20 with probe S25, both builds, curl 8.21.0: a root held in this account's Root store " +
			"and not in the machine's was trusted, so Schannel judges with the CurrentUser engine, and a leaf naming no " +
			"revocation address failed with CRYPT_E_NO_REVOCATION_CHECK. Read beside it in curl 8.21.0, " +
			"lib/vtls/schannel.c and src/tool_operate.c at https://github.com/curl/curl/tree/curl-8_21_0 - with no " +
			"--cacert Schannel validates by itself with SCH_CRED_REVOCATION_CHECK_CHAIN, and on Schannel the tool " +
			"ignores CURL_CA_BUNDLE, SSL_CERT_FILE, SSL_CERT_DIR and curl-ca-bundle.crt. Measured 2026-10-20 with " +
			"probe S26, curl 7.76.1 to 8.21.0 in Debian, Ubuntu, Alpine and RHEL images: CURL_CA_BUNDLE, " +
			"SSL_CERT_FILE and SSL_CERT_DIR are each followed, an empty value counts as unset, CURL_CA_BUNDLE " +
			"silences SSL_CERT_DIR, and the Debian, Ubuntu and Alpine packages trusted a root kept only as a hashed " +
			"link in /etc/ssl/certs while the named file lacked it - RHEL and the curlimages build did not. Read " +
			"beside it in src/tool_operate.c, src/tool_findfile.c, lib/getenv.c and lib/vtls/vtls_config.c of " +
			"8.21.0 and src/tool_operate.c of 7.76.1. Not looked at: the configuration file in the home directory " +
			"of an account known only to a directory service, which a release build without cgo cannot ask for. " +
			"Measured 2026-10-20 with probe S26 and with this program's own binary in Debian 13, Alpine 3.24 and RHEL 9.7 images: with nothing named, a root appended to the first bundle on Go's list - the file the system-store row judges - was trusted by curl from the package and by git from the Debian and Alpine ones, and the command printed for that row fixed them too. So a binary the distribution's own package installed, on a distribution whose recipe for libcurl names that file, takes the answer of the system-store row, and each condition that does not hold is said on its own - the recipes are cited beside the table in internal/adapter/probe/deferral.go.",
		FixSource: Documentation,
		FixEvidence: "curl manual page, section Environment and the --cacert entry, read 2026-08-04 at " +
			"https://curl.se/docs/manpage.html - CURL_CA_BUNDLE supplies the value of --cacert, which names the file " +
			"of CA certificates, AND IS IGNORED ON SCHANNEL. Hence the shape of the fix here: a certificate is added " +
			"to the bundle a file-reading build already uses, and a Schannel build gets no command at all because the " +
			"one it would get is the measured trap. Measured 2026-08-19 on the bench: curl 8.21.0 on OpenSSL 3.5.7 " +
			"reading a 179359-byte bundle refused a private root, which is the row this fix is written for.",
	},
	{
		ID:      report.RuntimeNode,
		Runtime: report.RuntimeNode,
		TrustSource: "the list compiled into each node binary - Mozilla's, as of that release - widened by the file " +
			"NODE_EXTRA_CA_CERTS names and, when NODE_USE_SYSTEM_CA=1 or --use-system-ca asks for it, by the " +
			"platform's store as Node itself reads it; read by asking that binary, and only a self-signed certificate " +
			"on the list ends a chain",
		Source: Measured,
		Evidence: "Measured 2026-10-20 with probe S27 in eight places - the owner's machine with node v26.9.0, the " +
			"node:26, node:26-alpine and node:22-alpine images, and Node from the Debian 13, Ubuntu 26.04, Alpine 3.24 " +
			"and Fedora 44 packages - with a request over loopback as the signal. On the official builds " +
			"tls.getCACertificates('default') was what Node trusted at every step, except under --use-openssl-ca, " +
			"where it came back empty while Node trusted OpenSSL's store. Every distribution's build carried " +
			"NODE_OPENSSL_CERT_STORE among its defines in process.config and trusted OpenSSL's store, which its list " +
			"misstated both ways, and Debian's v20.19.2 has no getCACertificates. An intermediate alone in the list did " +
			"not make a leaf it signed trusted in any of the eight. Read beside it in src/node_options.cc and " +
			"doc/api/cli.md of v26.x at https://github.com/nodejs/node/tree/v26.x - NODE_OPTIONS is split on spaces " +
			"with double quotes, NODE_USE_SYSTEM_CA counts only as 1, and an explicit flag wins over it, which node " +
			"v26.9.0 confirmed the same day. The list is read from the binary with a constant script, under an " +
			"environment without NODE_OPTIONS and the variables that make Node write files - ADR111.",
		FixSource: Documentation,
		FixEvidence: "Node.js doc/api/cli.md of v26.x, read 2026-10-20 at " +
			"https://github.com/nodejs/node/blob/v26.x/doc/api/cli.md - NODE_EXTRA_CA_CERTS names a PEM file whose " +
			"certificates extend the well known roots, read once when the process starts and ignored under setuid or " +
			"file capabilities, and NODE_USE_SYSTEM_CA=1 adds the platform's store, since v24.6.0 and v22.19.0. So a " +
			"command acts on node processes started after it, never on one already running. Measured beside it with " +
			"probe S27: a root in the file NODE_EXTRA_CA_CERTS named was trusted by every official build, and on " +
			"Linux, under NODE_USE_SYSTEM_CA=1, a root in the file the system list read was trusted too. Adding one " +
			"to the Windows store was not measured, because that needs the owner at the machine.",
	},
	{
		ID:      report.RuntimePython,
		Runtime: report.RuntimePython,
		TrustSource: "what each interpreter's ssl module trusts by default, as the interpreter lists it - the file " +
			"OpenSSL reads by default or the one SSL_CERT_FILE names, and on Windows the CA and ROOT stores beside it - " +
			"plus the certificates in OpenSSL's hashed directory, which the list leaves out; read by asking that " +
			"interpreter, and since 3.13 every certificate on the list ends a chain, before it only a self-signed one",
		Source: Measured,
		Evidence: "Measured 2026-10-21 with probe S28 on the owner's machine, seven interpreters from 3.10 to 3.15, and " +
			"in nine images - python:3.15-slim, 3.14-slim, 3.12-slim and 3.15-alpine, and Python from the Debian 13, " +
			"Ubuntu 26.04, Alpine 3.24, Fedora 44 and RHEL 9.8 packages - with a request over loopback as the signal. " +
			"The default context's verify_flags were 0x88020 from 3.13 on and 0x8000 before: an intermediate alone in " +
			"SSL_CERT_FILE made a leaf trusted on every 3.13 and newer and on nothing older, and a chain whose " +
			"intermediate lacked an authority key identifier, or carried basicConstraints not marked critical, was " +
			"refused by every 3.13 and newer and trusted by everything older and by Go. get_ca_certs listed the file " +
			"and the Windows stores and never the hashed directory: on Fedora it listed nothing, while Python trusted " +
			"the directory. SSL_CERT_FILE replaced the default file on Linux and added to the stores on Windows. Read " +
			"beside it in Lib/ssl.py of CPython 3.15.0 - create_default_context, load_default_certs and the stores " +
			"CA and ROOT - and in crypto/x509/by_dir.c of OpenSSL's openssl-3.5 branch, which reads SSL_CERT_DIR in " +
			"place of the default directory and opens only files named by a subject hash. The interpreter is started " +
			"with -I -S -B, so it runs nothing from site-packages, the user's directory or PYTHONSTARTUP and writes no " +
			"bytecode, and without SSLKEYLOGFILE and OPENSSL_CONF - ADR112; that it still lists the same certificates " +
			"was measured the same day in all nine images and with all seven interpreters.",
		FixSource: Documentation,
		FixEvidence: "certutil, Windows Commands reference, read 2026-10-14 at " +
			"https://learn.microsoft.com/windows-server/administration/windows-commands/certutil - -addstore adds a " +
			"certificate to the named store and -user aims it at this account's store, the ROOT store Lib/ssl.py " +
			"enumerates for this account. On Linux the certificate is appended to the file Python reads, which " +
			"OpenSSL loads whole each time a context is made - measured with probe S28: a root appended to the " +
			"distribution's bundle was trusted by the standard library in every image whose Python reads that " +
			"bundle. Adding one to the Windows store was not measured, because that needs the owner at the machine.",
	},
}

// All returns every declared descriptor, in declaration order.
func All() []Descriptor {
	out := make([]Descriptor, len(descriptors))
	copy(out, descriptors)
	return out
}

// Breach names what is wrong with a descriptor, or returns the empty string for
// one that is well formed. It continues a sentence naming the descriptor.
func (d Descriptor) Breach() string {
	switch {
	case d.ID == "":
		return "carries no id, and a row in the matrix has to be attributable"
	case d.Runtime == "":
		return "carries no runtime name, and the matrix is read by people"
	case d.TrustSource == "":
		return "does not say where this runtime keeps its anchors, which is the one thing a descriptor is for"
	case !d.Source.Valid():
		return "carries a source outside the registry, and inviolable rule 18 turns on that word"
	case d.Evidence == "":
		return "carries a source and no evidence, which is the shape rule 18 exists to refuse"
	case !d.FixSource.Valid():
		return "carries a fix source outside the registry, and a command somebody RUNS is the last claim that may go unsourced"
	case d.FixEvidence == "":
		return "says nothing about where its remediation command comes from, and that command is the one thing here a person executes"
	}
	return ""
}
