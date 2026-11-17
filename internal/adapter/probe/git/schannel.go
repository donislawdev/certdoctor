package git

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// GIT ON SCHANNEL READS A FILE ONLY WHEN TOLD TO, AND THEN NOTHING ELSE - OBS183.
//
// SOURCE, inviolable rule 18, read 2026-11-17: http.c of Git for Windows at
// https://github.com/git-for-windows/git/blob/v2.56.0.windows.4/http.c hands
// libcurl no CA file on schannel unless http.schannelUseSSLCAInfo is true, and
// then the one GIT_SSL_CAINFO or http.sslCAInfo names. lib/vtls/schannel_verify.c
// of curl at https://github.com/curl/curl/blob/curl-8_23_0/lib/vtls/schannel_verify.c
// then builds a chain engine whose ONLY roots are the certificates of that file
// (hExclusiveRoot), and from Windows 8 any of them may end a chain
// (CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG).
//
// MEASURED the same day with probe S35, git 2.56.0.windows.4 on libcurl 8.23.0:
// with the key true and a file holding one private root, every chain under that
// root was trusted and github.com was refused, so the Windows store does not
// count at all. An intermediate alone, a leaf alone and a self-signed leaf alone
// in the file each ended their chain, GIT_SSL_CAINFO won over the key,
// http.sslCAPath was ignored, and with the key unset, or true with no file
// named, the Windows store decided. So the file is judged as the other backends'
// files are, every entry an anchor, and a directory beside it changes nothing.
//
// A MISSING INTERMEDIATE IS JUDGED WITHOUT AIA, as the system-store row judges
// it. S35 measured Windows fetching an intermediate from the address its leaf
// names and trusting the chain, while this program never fetches one (rule 16) -
// the same gap OBS167 records for a browser.

// schannelRow writes the row of a git that names schannel.
func schannelRow(store report.TrustStore, source file.Source, settings Settings, env Environment, chain [][]byte,
	now time.Time) report.TrustStore {
	if env.Platform != "windows" {
		// http.c stops on a backend its libcurl was not built with, and curl
		// builds Schannel on Windows alone - OBS184 measured that refusal.
		store.NotAssessed = fmt.Sprintf("http.sslBackend is schannel at the %s level, a backend libcurl has only on "+
			"Windows, so git stops before it connects", settings.BackendLevel)
		return store
	}
	// schannelKeyUnread has already sent away a value git cannot read.
	useFile, _ := boolean(settings.UseCAInfo)
	named, path := caFile(settings, env)
	if !useFile || named == "" {
		// THE ANSWER BELONGS TO ANOTHER PROBE AND SAYING SO IS THE HONEST ROW.
		// Reporting "trusted" here would mean this probe silently answered a
		// question about the Windows store, which is system-store's job. Claiming
		// failure would be worse.
		store.NotAssessed = "this install is configured to use the platform store, which the system-store probe answers"
		return store
	}
	bundle, read := openBundle(&store, source, named, path)
	if !read {
		return store
	}
	loaded, refused := schannelReads(bundle)
	if refused == "" && len(loaded) == 0 {
		refused = "holds no certificate git on Schannel reads - it reads PEM certificate blocks only, and stops at " +
			"a begin line with no line break after it"
	}
	if refused != "" {
		store.NotAssessed = fmt.Sprintf("the bundle named by %s %s", named, refused)
		return store
	}
	probe.Verify(&store, loaded, chain, now)
	if why := strictRevocation(settings); why != "" && store.TrustsPresentedChain != nil && *store.TrustsPresentedChain {
		probe.Undetermined(&store, why)
	}
	return store
}

// maxSchannelCAFile is MAX_CAFILE_SIZE in schannel_verify.c of curl 8.23.0. S35
// measured a file of exactly this many bytes used and one byte more refused.
const maxSchannelCAFile = 1 << 20

// The two markers curl looks for, spelled as schannel_verify.c spells them - the
// end marker begins with a line break.
const (
	schannelBegin = "-----BEGIN CERTIFICATE-----"
	schannelEnd   = "\n-----END CERTIFICATE-----"
)

// schannelReads is the bundle as libcurl on Schannel reads it: the certificate
// blocks it loads, as PEM, or why it stops every connection over this file.
//
// IT IS CURL'S SCAN, NOT A PEM PARSER - add_certs_data_to_store in
// schannel_verify.c of curl 8.23.0. A begin marker not followed by a line break
// ends the reading quietly and nothing after it is loaded. A begin marker with no
// end marker after it stops every connection, and so does a block Windows cannot
// read. S35 measured both, a file over the size limit refused the same way, and
// an empty file and a DER one loading nothing.
//
// A BLOCK GO CANNOT READ IS A QUESTION, NOT A REFUSAL. Windows reads some
// certificates Go refuses - a negative serial number, ADR128 - so whether
// Windows reads it was not established, and if it does not, git connects nowhere.
func schannelReads(bundle []byte) (loaded []byte, refused string) {
	if len(bundle) > maxSchannelCAFile {
		return nil, fmt.Sprintf("holds %d bytes, and git on Schannel stops every connection when its CA file is "+
			"larger than %d bytes", len(bundle), maxSchannelCAFile)
	}
	rest := bundle
	for {
		begin := bytes.Index(rest, []byte(schannelBegin))
		after := begin + len(schannelBegin)
		if begin < 0 || after >= len(rest) || (rest[after] != '\n' && rest[after] != '\r') {
			return loaded, ""
		}
		end := bytes.Index(rest[begin:], []byte(schannelEnd))
		if end < 0 {
			return nil, "has a BEGIN CERTIFICATE line with no END CERTIFICATE line after it, and git on Schannel " +
				"stops every connection over such a file"
		}
		block := rest[begin : begin+end+len(schannelEnd)]
		if err := certificateIn(block); err != nil {
			return nil, fmt.Sprintf("holds a certificate this program could not read (%v), and git on Schannel stops "+
				"every connection when Windows cannot read one either, so whether it can use this file was not "+
				"established", err)
		}
		loaded = append(append(loaded, block...), '\n')
		rest = rest[begin+len(block):]
	}
}

// certificateIn says why one block curl would hand Windows is not a certificate
// this program can read, or returns nil.
func certificateIn(block []byte) error {
	decoded, _ := pem.Decode(block)
	if decoded == nil {
		return errors.New("not a PEM block")
	}
	_, err := x509.ParseCertificate(decoded.Bytes)
	return err
}

// strictRevocation says why a chain the file trusts may still be refused over
// revocation, or returns the empty string when git does not insist on an answer.
//
// GIT FOR WINDOWS TOLERATES AN UNKNOWN REVOCATION STATUS UNLESS TOLD OTHERWISE.
// http.c of v2.56.0.windows.4 starts from CURLSSLOPT_REVOKE_BEST_EFFORT, as it
// has since v2.26.0.windows.1 (read 2026-11-17 at both tags), "best-effort"
// keeps that, false sets CURLSSLOPT_NO_REVOKE, and true sets nothing, so curl
// insists. MEASURED with S35: unset, best-effort and false trusted all five
// chains of S25, while true refused a leaf naming no revocation list, an
// intermediate naming none and a list nobody answers at - the column S25
// measured for curl --cacert. Whether a list answers is a question this program
// never asks (rule 16), so a trust under true cannot stand, and a refusal stands
// either way.
func strictRevocation(settings Settings) string {
	// best-effort is no boolean, so it falls out here with unset and false.
	if on, _ := boolean(settings.CheckRevoke); settings.CheckRevokeLevel == "" || !on {
		return ""
	}
	return fmt.Sprintf("http.schannelCheckRevoke is true at the %s level, so git also refuses a chain unless every "+
		"certificate below the root names a revocation list or responder that answers, and this program does not "+
		"ask one", settings.CheckRevokeLevel)
}

// schannelKeyUnread names a schannel key whose value git cannot read, or returns
// the empty string.
//
// http.c reads both keys whatever the backend, with git_config_bool, which stops
// git on a word it does not know - so such a value stops every https connection,
// not only one on schannel. "best-effort" is a word only Git for Windows knows,
// and it is the git this program finds on Windows.
func schannelKeyUnread(settings Settings, platform string) string {
	const unread = "%s is %q at the %s level, and git stops on a value it cannot read"
	if _, read := boolean(settings.UseCAInfo); settings.UseCAInfoLevel != "" && !read {
		return fmt.Sprintf(unread, keyNames[keyUseCAInfo], settings.UseCAInfo, settings.UseCAInfoLevel)
	}
	if settings.CheckRevokeLevel == "" || (platform == "windows" && settings.CheckRevoke == "best-effort") {
		return ""
	}
	if _, read := boolean(settings.CheckRevoke); !read {
		return fmt.Sprintf(unread, keyNames[keyCheckRevoke], settings.CheckRevoke, settings.CheckRevokeLevel)
	}
	return ""
}
