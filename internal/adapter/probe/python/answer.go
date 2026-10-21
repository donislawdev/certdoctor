package python

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
)

// script is what an interpreter is asked to run, and it is a CONSTANT - nothing
// from the target, the machine or the command line reaches it, the rule ADR49
// sets for every argument a probe passes. It makes no connection and writes
// nothing but its answer: the version, the flags the default context verifies
// with, the directory OpenSSL looks in, and every certificate the default context
// holds, in the order it lists them.
//
// THE LIST IS create_default_context's, because that is what a program asking
// for nothing in particular gets - urllib, http.client and every library that
// does not build a context of its own. Lib/ssl.py of CPython 3.15.0, read
// 2026-10-21: the context loads the default certificates, and on Windows the CA
// and ROOT stores beside them. get_ca_certs leaves out the hashed directory,
// which OpenSSL reads only when it looks for an issuer - measured by S28, Fedora
// listed nothing - so the directory is named here and read by the probe.
//
// THE DIRECTORY COMES FROM THE ENVIRONMENT FIRST, as OpenSSL takes it: a set
// SSL_CERT_DIR replaces the default directory, even when empty - dir_ctrl in
// crypto/x509/by_dir.c of OpenSSL's openssl-3.5 branch, read 2026-10-21 at
// https://github.com/openssl/openssl/blob/openssl-3.5/crypto/x509/by_dir.c -
// while get_default_verify_paths keeps the variable only when it names one
// directory that exists. So the variable itself is sent.
//
// THE INTERPRETER ALSO SAYS WHICH FILE IT IS, because an app execution alias
// names only the package that answers it - ADR112 - and sys.executable is the
// interpreter's own word for where it was started from.
//
// AND WHICH OpenSSL IT IS BUILT WITH, as numbers, because the strict rules differ
// between OpenSSL 1.1.1 and 3 - ADR112 part 3.
const script = `import base64, json, os, ssl, sys
c = ssl.create_default_context()
p = ssl.get_default_verify_paths()
sys.stdout.write(json.dumps({
    'version': '%d.%d.%d' % tuple(sys.version_info[:3]),
    'executable': sys.executable,
    'openssl': list(ssl.OPENSSL_VERSION_INFO),
    'flags': int(c.verify_flags),
    'cafile': p.cafile,
    'dir_env': os.environ.get(p.openssl_capath_env),
    'dir_default': p.openssl_capath,
    'der': [base64.b64encode(d).decode('ascii') for d in c.get_ca_certs(binary_form=True)],
}))
`

// arguments start the interpreter so that it runs nothing but the script -
// ADR112 part 6. -I leaves out PYTHONPATH, PYTHONSTARTUP and the user's own
// site-packages, -S leaves out site and with it every .pth file and
// sitecustomize, which would run somebody else's code in the process this
// program started, and -B writes no bytecode, inviolable rule 14 - Python's
// command line documentation, read 2026-10-21 at
// https://docs.python.org/3/using/cmdline.html . Measured with probe S28 the
// same day: under -I -S -B every interpreter listed the certificates it lists
// when started plainly, in all nine images and with all seven interpreters on
// the owner's machine.
var arguments = []string{"-I", "-S", "-B", "-c", script}

// answer is what the script prints.
type answer struct {
	Version string `json:"version"`
	// Executable is sys.executable - empty, or None and so empty here, when
	// Python cannot tell where it was started from: the sys module's
	// documentation, read 2026-10-21 at
	// https://docs.python.org/3/library/sys.html#sys.executable
	Executable string `json:"executable"`
	// OpenSSL is ssl.OPENSSL_VERSION_INFO, five integers about the library -
	// the ssl module's documentation, read 2026-10-21 at
	// https://docs.python.org/3/library/ssl.html - which Modules/_ssl.c of
	// CPython's 3.15 branch, read the same day, parses out of
	// OpenSSL_version_num(), the major first. LibreSSL defines that number as
	// 0x20000000 (src/lib/libcrypto/opensslv.h of libressl/openbsd, read the same
	// day), so it reads as major 2 here.
	OpenSSL []int `json:"openssl"`
	// Flags is a pointer so that an answer without it is told from a context
	// with no flags at all.
	Flags *int64 `json:"flags"`
	// CAFile is the file OpenSSL loaded, and nil when it loaded none -
	// get_default_verify_paths names it only when it is a file.
	CAFile *string `json:"cafile"`
	// DirEnv is SSL_CERT_DIR as the interpreter saw it, nil when unset.
	DirEnv     *string `json:"dir_env"`
	DirDefault string  `json:"dir_default"`
	// DER arrives as base64, which encoding/json turns into bytes.
	DER [][]byte `json:"der"`
}

// ask runs the script and returns its answer, or the sentence a row says when
// there is none.
func ask(ctx context.Context, run probe.Runner, interpreter string) (answer, string) {
	out, err := run(ctx, interpreter, arguments...)
	switch {
	case err != nil:
		return answer{}, fmt.Sprintf("python could not be asked for its certificate list: %v", err)
	case out.Truncated:
		return answer{}, "python answered with more than this program keeps, so the list it sent is incomplete"
	case out.ExitCode != 0:
		// The exit code alone is the answer, never the message - rule 19. A
		// Python 2, or one built without ssl, ends here.
		return answer{}, fmt.Sprintf("python exited with %d when asked for its certificate list", out.ExitCode)
	}
	var a answer
	if err := json.Unmarshal([]byte(out.Stdout), &a); err != nil {
		return answer{}, fmt.Sprintf("python's answer was not the JSON this program asked for: %v", err)
	}
	if a.Version == "" || a.Flags == nil {
		return answer{}, "python's answer was not the JSON this program asked for: the version or the verification flags are missing"
	}
	return a, ""
}

// flags are the flags the default context verifies with - ssl.VERIFY_X509_STRICT
// and ssl.VERIFY_X509_PARTIAL_CHAIN are OpenSSL's own values.
func (a answer) flags() probe.OpenSSLFlags { return probe.OpenSSLFlags(*a.Flags) }

// openSSL3 says the interpreter is built with OpenSSL 3, the only one whose
// strict rules this program applies.
func (a answer) openSSL3() bool { return len(a.OpenSSL) > 0 && a.OpenSSL[0] == 3 }

// bundle is the list and the directory's certificates as one PEM bundle, each
// certificate once - the directory of a distribution holds the very certificates
// its file does, and the verifier counts every block it reads.
func (a answer) bundle(directory []byte) []byte {
	var b strings.Builder
	seen := map[string]bool{}
	add := func(der []byte) {
		if seen[string(der)] {
			return
		}
		seen[string(der)] = true
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	for _, der := range a.DER {
		add(der)
	}
	for rest := directory; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			add(block.Bytes)
		}
	}
	return []byte(b.String())
}
