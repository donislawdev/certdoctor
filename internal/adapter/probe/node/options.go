package node

import (
	"errors"
	"strings"
)

// Environment is what this probe reads of the environment. It is read at the
// entry point and handed in, like git's and curl's, so this package reads no
// environment of its own.
type Environment struct {
	// Options is NODE_OPTIONS. The node process is started without it, and the
	// three CA flags in it are read here the way Node reads them and handed over
	// as arguments - ADR111 part 2.
	Options string
	// UseSystemCA is NODE_USE_SYSTEM_CA. Node reads it itself from the
	// environment it inherits, so it is read here only to name what turned the
	// system list on.
	UseSystemCA string
	// ExtraCACerts is NODE_EXTRA_CA_CERTS, and CertFileSet and CertDirSet say
	// SSL_CERT_FILE and SSL_CERT_DIR are set. A node that trusts OpenSSL's
	// default store trusts something other than that store's default file when
	// any of them is - ADR111 part 6, condition 4.
	ExtraCACerts            string
	CertFileSet, CertDirSet bool
	// Platform is the operating system this program runs on, as runtime.GOOS
	// names it - only on Linux does a distribution's package say which file
	// OpenSSL's default store is.
	Platform string
}

// EnvironmentFrom reads the variables.
//
// UNSET AND EMPTY ARE ONE ANSWER FOR THE THREE NODE READS: it parses an empty
// NODE_OPTIONS into nothing and compares NODE_USE_SYSTEM_CA with "1" -
// HandleEnvOptions in src/node_options.cc of v26.x - and adds nothing for an
// empty NODE_EXTRA_CA_CERTS - NewRootCertStore in src/crypto/crypto_context.cc
// of v26.x, both read 2026-10-20 at https://github.com/nodejs/node/tree/v26.x/src
//
// NOT FOR THE TWO OPENSSL READS: a variable set to nothing still replaces the
// default, and then names no file at all - by_file_ctrl and dir_ctrl in
// crypto/x509 of OpenSSL's openssl-3.5 branch, read 2026-10-20 at
// https://github.com/openssl/openssl/tree/openssl-3.5/crypto/x509
func EnvironmentFrom(lookup func(string) (string, bool), platform string) Environment {
	value := func(name string) string {
		v, _ := lookup(name)
		return v
	}
	_, certFile := lookup("SSL_CERT_FILE")
	_, certDir := lookup("SSL_CERT_DIR")
	return Environment{Options: value("NODE_OPTIONS"), UseSystemCA: value("NODE_USE_SYSTEM_CA"),
		ExtraCACerts: value("NODE_EXTRA_CA_CERTS"), CertFileSet: certFile, CertDirSet: certDir, Platform: platform}
}

// withheld are the variables the node process starts without - ADR111 part 2,
// decided by the owner 2026-10-20. Each one, from Node.js doc/api/cli.md of
// v26.x, read 2026-10-20 at https://github.com/nodejs/node/blob/v26.x/doc/api/cli.md
//   - NODE_OPTIONS holds options read before the command line, and --require
//     and --import among them load a module into the process - somebody else's
//     code inside the one this program started, against inviolable rule 16.
//   - NODE_V8_COVERAGE makes Node write coverage files into a directory,
//     NODE_REDIRECT_WARNINGS writes warnings into a file it creates, and
//     NODE_COMPILE_CACHE keeps a module cache in a directory - inviolable rule
//     14, which no child of this program may break on its behalf.
//   - OPENSSL_CONF names the OpenSSL configuration Node loads when it starts,
//     and that file can name a provider module, which is native code loaded
//     into the process - the class NODE_OPTIONS is withheld for. Decided by the
//     owner 2026-10-20, OBS188. Measured with node v26.9.0 that day: a
//     nodejs_conf section naming a module that does not exist stopped node with
//     exit code 134, while an openssl_conf section alone was not read. Without
//     the variable Node reads the default file the build names, which the
//     environment cannot redirect. An EMPTY value would stop that file too, but
//     it would hand the child a variable, and a child here only loses them.
var withheld = []string{"NODE_OPTIONS", "NODE_V8_COVERAGE", "NODE_REDIRECT_WARNINGS", "NODE_COMPILE_CACHE", "OPENSSL_CONF"}

// The three switches of Node's CA list, spelled as src/node_options.cc of
// v26.x declares them.
const (
	flagSystem  = "use-system-ca"
	flagOpenSSL = "use-openssl-ca"
	flagBundled = "use-bundled-ca"
)

var caFlags = []string{flagSystem, flagOpenSSL, flagBundled}

var (
	errEscapeAtTheEnd = errors.New("NODE_OPTIONS ends with a backslash inside a quoted string")
	errUnterminated   = errors.New("NODE_OPTIONS ends inside a quoted string")
)

// splitOptions splits NODE_OPTIONS into arguments exactly as Node does -
// ParseNodeOptionsEnvVar in src/node_options.cc of v26.x, read 2026-10-20 at
// https://github.com/nodejs/node/blob/v26.x/src/node_options.cc
//
// A SPACE AND NOTHING ELSE SEPARATES, a double quote anywhere toggles a quoted
// string, and a backslash escapes the next byte only inside one - outside, it
// is an ordinary byte of the argument. Measured with node v26.9.0 the same day:
// a tab joined two options into one Node then refused, and a backslash ending
// an unquoted option stayed part of it. The two errors are the two inputs on
// which Node does not start at all. It works on bytes, as Node does, so a name
// spelled in UTF-8 passes through whole.
func splitOptions(options string) ([]string, error) {
	var args []string
	var current []byte
	inString, startNew := false, true
	for index := 0; index < len(options); index++ {
		c := options[index]
		switch {
		case c == '\\' && inString:
			if index+1 == len(options) {
				return nil, errEscapeAtTheEnd
			}
			index++
			c = options[index]
		case c == ' ' && !inString:
			startNew = true
			continue
		case c == '"':
			inString = !inString
			continue
		}
		if startNew {
			if current != nil {
				args = append(args, string(current))
			}
			current, startNew = []byte{}, false
		}
		current = append(current, c)
	}
	if inString {
		return nil, errUnterminated
	}
	if current != nil {
		args = append(args, string(current))
	}
	return args, nil
}

// mentions is every CA flag the arguments mention, in their order, each
// spelled back as node's own argument - what node is started with.
//
// THE RULES, each measured with node v26.9.0 on 2026-10-20 and the first stated
// in cli.md: a word may be separated by an underscore as well as a dash, so
// --use_system_ca is --use-system-ca. --no- in front turns a flag off. A value
// after "=" is ignored - --use-system-ca=false turned the system list ON. The
// name is case sensitive - --USE-SYSTEM-CA stopped node.
//
// EVERY MENTION, NOT THE STATE THEY LEAVE, because the order decides more than
// each flag's own value - OBS190, see openSSLStore. Each one is spelled from
// this file's constants, so nothing of the variable's own text reaches node.
//
// ONE SHAPE IS NOT READ, NAMED: a flag written as the value of the option
// before it, like --title --use-system-ca, which Node takes as the title. Which
// options take a value is Node's whole option table, and this reads three
// names.
func mentions(args []string) []string {
	var said []string
	for _, arg := range args {
		name, isOption := strings.CutPrefix(arg, "--")
		if !isOption {
			continue
		}
		name, _, _ = strings.Cut(name, "=")
		name = strings.ReplaceAll(name, "_", "-")
		name, negated := strings.CutPrefix(name, "no-")
		for _, flag := range caFlags {
			switch {
			case name != flag:
			case negated:
				said = append(said, "--no-"+flag)
			default:
				said = append(said, "--"+flag)
			}
		}
	}
	return said
}

// flagsIn is the final state of every CA flag mentioned - the last mention
// wins, measured the same day - and a flag never mentioned is absent rather
// than false: absent leaves Node to its default and to NODE_USE_SYSTEM_CA,
// while false overrides that variable, as --no-use-system-ca beat it.
func flagsIn(said []string) map[string]bool {
	flags := map[string]bool{}
	for _, mention := range said {
		flag, negated := strings.CutPrefix(strings.TrimPrefix(mention, "--"), "no-")
		flags[flag] = !negated
	}
	return flags
}

// openSSLStore says this node trusts OpenSSL's default store rather than its
// own lists. built is whether the build made that store its default - the
// NODE_OPENSSL_CERT_STORE the script reads.
//
// A --no- DOES NOT TAKE THE STORE BACK - OBS190. --use-openssl-ca implies the
// store and --use-bundled-ca implies the list, and the implications of a
// negated option are looked up under its --no- name, where none is declared -
// Implies and ImpliesNot in src/node_options.cc and OptionsParser::Parse in
// src/node_options-inl.h of v26.x, read 2026-10-20 at
// https://github.com/nodejs/node/tree/v26.x/src - so the last of the two turned
// on decides. Measured with node v26.9.0 the same day: started with
// --use-openssl-ca --no-use-openssl-ca, node listed its bundled roots and
// trusted the root SSL_CERT_FILE named, which no list held.
func openSSLStore(said []string, built bool) bool {
	store := built
	for _, mention := range said {
		switch mention {
		case "--" + flagOpenSSL:
			store = true
		case "--" + flagBundled:
			store = false
		}
	}
	return store
}
