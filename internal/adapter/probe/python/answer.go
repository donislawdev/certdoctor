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
//
// AND WHAT ITS pip READS, in the same process - ADR112 part 5 - asked of pip's
// own code, so the order of its configuration files and PIP_ variables is pip's
// and not a copy of it. The script puts the site-packages directories on
// sys.path itself, which -S left out, and imports from them nothing but pip.
// pip's parser is built the way pip builds it, with no --help of its own -
// src/pip/_internal/cli/base_command.py of pip 26.2.2 and 23.0.1, read
// 2026-10-27 - holding only the five options asked about, under the section of
// pip install; it skips a configured key with no option in it, as pip does for
// every command. Nothing it prints reaches the answer, because a configuration
// pip cannot read makes its parser print to stdout and exit.
//
// THE PROXY IS ASKED ABOUT, NEVER SENT. A proxy, or --no-proxy-env, turns off
// trust_env and with it REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE - pip 26.2.2's
// _build_session in src/pip/_internal/cli/index_command.py and requests 2.34.2's
// merge_environment_settings in sessions.py, read 2026-10-27 in the copies on the
// owner's machine - and a proxy's address can carry a password, so the script
// says only whether one is set.
//
// TRUSTSTORE SAYS ITSELF WHICH FILE IT LOADS, off Windows and macOS, by being
// handed something that records what it is told to load: the function pip calls
// before every connection, _configure_context in truststore 0.10.4's _openssl.py,
// loads OpenSSL's defaults when the default file exists or the default directory
// holds a hashed name, and the first of its candidate files otherwise. None in
// the list stands for the defaults.
//
// AND URLLIB3'S FLAGS, for a pip that does not use truststore: urllib3 makes the
// context then, and urllib3 2 sets PARTIAL_CHAIN and STRICT on Python 3.13 and
// later - create_urllib3_context in urllib3 2.7.0's util/ssl_.py, read the same
// day - so the flags are what that function returns, not a rule kept here.
const script = `import base64, json, os, ssl, sys
c = ssl.create_default_context()
p = ssl.get_default_verify_paths()
answer = {
    'version': '%d.%d.%d' % tuple(sys.version_info[:3]),
    'executable': sys.executable,
    'openssl': list(ssl.OPENSSL_VERSION_INFO),
    'flags': int(c.verify_flags),
    'cafile': p.cafile,
    'dir_env': os.environ.get(p.openssl_capath_env),
    'dir_default': p.openssl_capath,
    'der': [base64.b64encode(d).decode('ascii') for d in c.get_ca_certs(binary_form=True)],
}
def about_pip():
    import contextlib, io, site
    facts, step = {}, 'pip'
    try:
        sys.path.extend(site.getsitepackages())
        try:
            import pip
        except ModuleNotFoundError as e:
            if e.name == 'pip':
                return None
            raise
        facts['version'] = pip.__version__
        step = 'certifi'
        from pip._vendor import certifi
        facts['certifi'] = certifi.where()
        step = 'settings'
        from pip._internal.cli import cmdoptions
        from pip._internal.cli.parser import ConfigOptionParser
        parser = ConfigOptionParser(name='install', isolated=False, add_help_option=False)
        for option in ('cert', 'proxy', 'no_proxy_env', 'use_new_feature', 'use_deprecated_feature'):
            if hasattr(cmdoptions, option):
                parser.add_option(getattr(cmdoptions, option)())
        with contextlib.redirect_stdout(io.StringIO()):
            o = parser.parse_args([])[0]
        facts['cert'] = o.cert or None
        facts['deprecated'] = sorted(getattr(o, 'deprecated_features_enabled', None) or [])
        facts['features'] = sorted(getattr(o, 'features_enabled', None) or [])
        facts['proxy'] = bool(o.proxy)
        facts['no_proxy_env'] = bool(getattr(o, 'no_proxy_env', False))
        facts['requests_ca_bundle'] = os.environ.get('REQUESTS_CA_BUNDLE')
        facts['curl_ca_bundle'] = os.environ.get('CURL_CA_BUNDLE')
        facts['pip_cert'] = os.environ.get('PIP_CERT')
        step = 'urllib3'
        from pip._vendor.urllib3.util.ssl_ import create_urllib3_context
        facts['legacy_flags'] = int(create_urllib3_context().verify_flags)
        step = 'truststore'
        try:
            from pip._vendor import truststore
            facts['truststore'] = True
        except ImportError:
            facts['truststore'] = False
        if facts['truststore'] and sys.platform not in ('win32', 'darwin'):
            from pip._vendor.truststore import _openssl
            class Told:
                def __init__(self):
                    self.loads = []
                def set_default_verify_paths(self):
                    self.loads.append(None)
                def load_verify_locations(self, cafile=None, capath=None, cadata=None):
                    self.loads.append(cafile)
            told = Told()
            with _openssl._configure_context(told):
                pass
            facts['truststore_loads'] = told.loads
    except BaseException as e:
        facts['failed'] = step + ': ' + type(e).__name__
    return facts
answer['pip'] = about_pip()
sys.stdout.write(json.dumps(answer))
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
	// Pip is what the interpreter's pip reads, and nil when it has none.
	Pip *pipAnswer `json:"pip"`
}

// pipAnswer is what the script learned of pip, from pip's own code.
type pipAnswer struct {
	// Failed names the step that raised and the type of what it raised, and is
	// empty when every step answered. The message is left out: it is somebody
	// else's text, and a path in it is the only thing it could add.
	Failed  string `json:"failed"`
	Version string `json:"version"`
	// Certifi is certifi.where() as pip imports it - its own copy, or the file a
	// distribution points it at.
	Certifi string `json:"certifi"`
	// Cert is pip's cert option, from PIP_CERT or its configuration files, nil
	// when unset. PipCert is PIP_CERT itself, which says where it came from.
	Cert    *string `json:"cert"`
	PipCert *string `json:"pip_cert"`
	// Deprecated and Features are --use-deprecated and --use-feature.
	Deprecated []string `json:"deprecated"`
	Features   []string `json:"features"`
	// Proxy and NoProxyEnv are whether pip was given a proxy, or told not to
	// read one from the environment - either turns trust_env off.
	Proxy      bool `json:"proxy"`
	NoProxyEnv bool `json:"no_proxy_env"`
	// The two variables requests reads, nil when unset.
	RequestsCABundle *string `json:"requests_ca_bundle"`
	CurlCABundle     *string `json:"curl_ca_bundle"`
	// LegacyFlags are the flags of the context urllib3 makes for a pip that does
	// not use truststore.
	LegacyFlags *int64 `json:"legacy_flags"`
	// Truststore says pip can import truststore, which it needs to use it.
	Truststore bool `json:"truststore"`
	// TruststoreLoads is what truststore loads off Windows and macOS - a nil
	// entry for OpenSSL's defaults, or a file - and nil where it was not asked.
	TruststoreLoads []*string `json:"truststore_loads"`
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

// bundle is the list and the certificates of each PEM given - the directory's,
// and for pip the files it reads beside it - as one PEM bundle, each certificate
// once: the directory of a distribution holds the very certificates its file
// does, and the verifier counts every block it reads.
func (a answer) bundle(more ...[]byte) []byte {
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
	for _, certificates := range more {
		for rest := certificates; ; {
			var block *pem.Block
			if block, rest = pem.Decode(rest); block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				add(block.Bytes)
			}
		}
	}
	return []byte(b.String())
}
