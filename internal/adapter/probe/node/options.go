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
}

// EnvironmentFrom reads the two variables. Unset and empty are one answer for
// both: Node parses an empty NODE_OPTIONS into nothing, and compares
// NODE_USE_SYSTEM_CA with "1" - HandleEnvOptions in src/node_options.cc of
// v26.x, read 2026-10-20 at
// https://github.com/nodejs/node/blob/v26.x/src/node_options.cc
func EnvironmentFrom(getenv func(string) string) Environment {
	return Environment{Options: getenv("NODE_OPTIONS"), UseSystemCA: getenv("NODE_USE_SYSTEM_CA")}
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

// caFlags is the order the flags are handed to node in. Each is a separate
// boolean, so the order changes nothing Node decides.
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

// flagsIn is the final state of every CA flag the arguments mention, and a
// flag they do not mention is absent rather than false - absent leaves Node to
// its default and to NODE_USE_SYSTEM_CA, while false overrides that variable.
//
// THE RULES, each measured with node v26.9.0 on 2026-10-20 and the first stated
// in cli.md: a word may be separated by an underscore as well as a dash, so
// --use_system_ca is --use-system-ca. --no- in front turns a flag off, and the
// last mention wins. A value after "=" is ignored - --use-system-ca=false turned
// the system list ON. The name is case sensitive - --USE-SYSTEM-CA stopped node.
//
// ONE SHAPE IS NOT READ, NAMED: a flag written as the value of the option
// before it, like --title --use-system-ca, which Node takes as the title. Which
// options take a value is Node's whole option table, and this reads three
// names.
func flagsIn(args []string) map[string]bool {
	flags := map[string]bool{}
	for _, arg := range args {
		name, isOption := strings.CutPrefix(arg, "--")
		if !isOption {
			continue
		}
		name, _, _ = strings.Cut(name, "=")
		name = strings.ReplaceAll(name, "_", "-")
		name, negated := strings.CutPrefix(name, "no-")
		for _, flag := range caFlags {
			if name == flag {
				flags[flag] = !negated
			}
		}
	}
	return flags
}

// arguments spells the final state back as node's own arguments, one per flag
// mentioned. A flag that was turned off is passed turned off, so a
// NODE_USE_SYSTEM_CA=1 that Node itself would have overridden stays overridden -
// measured the same day: --no-use-system-ca beat the variable.
func arguments(flags map[string]bool) []string {
	var args []string
	for _, flag := range caFlags {
		on, mentioned := flags[flag]
		switch {
		case !mentioned:
		case on:
			args = append(args, "--"+flag)
		default:
			args = append(args, "--no-"+flag)
		}
	}
	return args
}
