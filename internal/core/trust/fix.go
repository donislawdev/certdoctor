package trust

import (
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// This file is the only place in the program that builds a remediation command,
// and the remediation guard is what keeps it that way.
//
// WHY ONE PLACE, AND THE REASON IS MEASURED RATHER THAN TIDY. A fix is safe to
// offer only when THREE facts hold together, and each one alone looks sufficient:
//
//  1. the chain the server sent is structurally COMPLETE, or some other store on
//     this machine closed it anyway. Measured on the bench 2026-08-19: a server
//     withholding its intermediate turns every trust row on the machine red, and
//     the fault is the server's - a command there sends somebody to edit a store
//     that is perfectly fine. The second arm arrived with ADR55 for the case
//     that looks identical and is the opposite: a middlebox signing straight
//     from its own root, where another store having closed the chain is proof
//     that an anchor closing it exists.
//  2. this store refused because it holds no signer - never because something
//     expired. Importing a certificate does not move a clock.
//  3. the store is a FILE this program opened and can name. Measured 2026-08-02:
//     Schannel ignores CURL_CA_BUNDLE, so a file-shaped fix aimed at a platform
//     store is a command that does nothing while a person waits for it. The ONE
//     exception is the platform's own store asked directly - ADR103 - whose
//     command names that store by the platform's constant and no file at all.
//
// A second copy of this function would be a second place where two of the three
// could be checked, and the row it produced would look identical. That is the
// shape OBS50 has now taken four times in this tree.
//
// WHAT EVERY COMMAND HERE HAS IN COMMON: IT ADDS. None of them points a runtime
// at a different store. Redirecting a runtime to another file grants the trust
// somebody asked for and silently WITHDRAWS every other trust that runtime had,
// so one broken site is traded for all the working ones - and the person finds
// out days later, somewhere else. Adding to the store already in use cannot do
// that.

// Machine is the little this generator needs to know about where it is running.
//
// BOTH FIELDS ARE HANDED IN AND NEITHER IS READ HERE, the same rule the probes
// follow: an assessment has to be reproducible from its input, and a core that
// can ask the environment is a core whose output depends on where it ran.
type Machine struct {
	// OS is the platform identifier, because appending bytes to a file is
	// spelled differently on Windows than everywhere else.
	OS string
	// Home is this account's own directory, used for ONE question: is this store
	// shared with every other account. Empty is allowed and answers "assume it
	// is", which is the safe direction - see elevationFor.
	Home string
}

// The two things this program cannot know, spelled the same way in every
// command so that a reader meets one vocabulary rather than three.
const (
	// certificatePlaceholder is the CA to import. IT IS NOT ON THE WIRE and
	// never will be: a middlebox does not send its own root, measured on the
	// bench 2026-08-18. Inviolable rule 14 forbids this program writing it out
	// anywhere, so it stays a named gap rather than an invented path.
	certificatePlaceholder = "<certificate.pem>"
	// aliasPlaceholder is the name the certificate takes inside a Java keystore.
	// Every entry needs one and no name we chose would mean anything to the
	// person whose store it is.
	aliasPlaceholder = "<alias>"
)

// fixFor returns the command that would make this store accept this chain, or
// nil when there is nothing honest to say.
//
// NIL IS THE ORDINARY ANSWER. On the owner's machine every row of the matrix is
// green or unassessed, so a run against a public site produces nine rows and no
// commands - which is the correct output and not an empty feature.
func fixFor(store report.TrustStore, chainComplete, closedElsewhere bool, m Machine) (*report.Fix, string) {
	if !chainComplete && !closedElsewhere {
		// THE FAULT IS THE SERVER'S AND NO STORE CAN REPAIR IT. This is the gate
		// the contract cannot check, because whether the chain was complete is a
		// fact about L4 rather than about a store.
		//
		// THE SECOND ARM IS POSITIVE PROOF RATHER THAN A SECOND GUESS - ADR55.
		// closedElsewhere says another store ON THIS MACHINE built a path
		// through this very chain, so an anchor that closes it demonstrably
		// exists and the store that refused can be given it. Measured on the
		// bench 2026-08-19: a middlebox signing leaves straight from its own
		// root presents an incomplete chain for the OPPOSITE reason to a
		// misconfigured server, and adding the certificate is exactly the
		// repair. With only the first arm, the one case a command is for got no
		// command.
		//
		// IT CANNOT LET A COMMAND THROUGH ON no-intermediate.txt, and that is
		// what makes it safe: there no store closes the chain, so this stays
		// shut. The bench checks both directions.
		return nil, ""
	}
	if store.TrustFailure != report.UnknownAuthority {
		return nil, ""
	}
	if store.Runtime == report.RuntimeSystemStore {
		// ASKED BEFORE THE FILE GATE, AND ONLY FOR THIS RUNTIME. The file gate
		// stays shut for every other row on a platform store, which is the
		// measured trap it exists for - ADR103.
		return platformStoreFix(store, m)
	}
	if store.StoreForm != report.StoreFile || store.StorePath == "" {
		return nil, ""
	}

	elevated, why := elevationFor(store.StorePath, m)

	switch store.Runtime {
	case "java":
		// EVERY PIECE GOES THROUGH THE SAME QUOTING, THE PLACEHOLDERS INCLUDED.
		// A person substitutes their own path into <certificate.pem>, and a space
		// in it is ordinary - ADR59. The angle brackets are a redirection in both
		// shells this command can land in, so they need the quotes even before
		// anybody has substituted anything.
		keytool, keytoolOK := quoteFor(m.OS, keytoolBeside(store))
		storePath, pathOK := quoteFor(m.OS, store.StorePath)
		alias, aliasOK := quoteFor(m.OS, aliasPlaceholder)
		certificate, certificateOK := quoteFor(m.OS, certificatePlaceholder)
		if !keytoolOK || !pathOK || !aliasOK || !certificateOK {
			return nil, unwritablePath
		}
		return &report.Fix{
			Command: fmt.Sprintf(`%s -importcert -trustcacerts -keystore %s -storepass changeit -alias %s -file %s`,
				keytool, storePath, alias, certificate),
			Placeholders:      []string{aliasPlaceholder, certificatePlaceholder},
			RequiresElevation: elevated,
			Elevation:         why,
			// The password is the default one this store was just READ with, so
			// it is measured rather than assumed - and it is not a secret.
			Caveat: "installing a newer build of this runtime brings its own store and does not carry this certificate across",
		}, ""
	case "curl", "git":
		command, ok := appendPEM(store.StorePath, m.OS)
		if !ok {
			return nil, unwritablePath
		}
		return &report.Fix{
			Command:           command,
			Placeholders:      []string{certificatePlaceholder},
			RequiresElevation: elevated,
			Elevation:         why,
			Caveat: "whatever maintains this bundle - a package manager, or reinstalling the runtime - rewrites the file " +
				"and removes the certificate again, and this program does not know what maintains it here",
		}, ""
	}
	// A runtime with a probe and no template gets NO command rather than a
	// guessed one. The registry test refuses to let that state ship.
	return nil, ""
}

// platformStoreFix is the command that adds one root to the Windows store this
// row answered for - ADR103, decided by the owner 2026-10-14.
//
// IT ADDS AND NOTHING ELSE, like every command in this file. certutil -addstore
// puts one certificate into the named store and leaves the rest of it alone;
// the -f switch docs/20 once carried is left out, because overwriting an entry
// that is already there is not adding.
//
// SOURCE, inviolable rule 18: certutil, Windows Commands reference, read
// 2026-10-14 at https://learn.microsoft.com/windows-server/administration/windows-commands/certutil
// - "-addstore: Adds a certificate to the store", and "-user accesses a user
// store instead of a machine store". WHAT IS NOT MEASURED, said here rather than
// implied: whether -addstore reads a PEM file as it reads a DER one. Running it
// changes this machine's store, so it is the owner's check, by hand - and until
// it is made the descriptor says Documentation rather than Measured.
//
// A ROW THIS PROGRAM DID NOT WRITE GETS NO COMMAND. Only the two instances the
// probe produces are known, and only on Windows. Anything else is a store nobody
// here knows how to name, and a guessed name is the command that does nothing.
func platformStoreFix(store report.TrustStore, m Machine) (*report.Fix, string) {
	if store.StoreForm != report.StoreSystem || m.OS != "windows" {
		return nil, ""
	}
	certificate, ok := quoteFor(m.OS, certificatePlaceholder)
	if !ok {
		return nil, unwritablePath
	}
	switch store.Instance {
	case report.InstanceLocalMachine:
		return &report.Fix{
			Command:           "certutil -addstore Root " + certificate,
			Placeholders:      []string{certificatePlaceholder},
			RequiresElevation: true,
			Elevation:         "the LocalMachine store is read by every account and every service on this machine, so changing it needs administrator rights",
			Caveat: "programs that carry a store of their own - git and java among them - do not read this one, " +
				"so their rows need their own commands",
		}, ""
	case report.InstanceCurrentUser:
		return &report.Fix{
			Command:      "certutil -user -addstore Root " + certificate,
			Placeholders: []string{certificatePlaceholder},
			// THIS ACCOUNT'S OWN STORE, so no administrator is needed - and
			// Windows asks the person to confirm instead, which the caveat says
			// before it surprises anybody.
			RequiresElevation: false,
			Caveat: "Windows asks for confirmation in a dialog before it adds a root to this account's store, and services " +
				"running as other accounts do not read it - the LocalMachine command reaches them too",
		}, ""
	}
	return nil, ""
}

// appendPEM is the command that adds one certificate to a PEM bundle without
// disturbing what is already in it.
//
// THE WINDOWS FORM IS MEASURED, NOT REASONED - 2026-08-19, on this machine.
// "copy /b a+b a" appended byte for byte: 59 plus 59 came out 118, with no byte
// order mark, no end of file marker and no newline translation. The obvious
// alternative, a ">>" redirection, is written by whichever shell the person
// happens to be in - and Windows PowerShell 5.1 writes UTF-16, which turns a
// certificate bundle into a file no TLS library will read.
func appendPEM(storePath, platform string) (string, bool) {
	path, pathOK := quoteFor(platform, storePath)
	certificate, certificateOK := quoteFor(platform, certificatePlaceholder)
	if !pathOK || !certificateOK {
		return "", false
	}
	if platform == "windows" {
		return fmt.Sprintf(`cmd /c copy /b %s+%s %s`, path, certificate, path), true
	}
	return fmt.Sprintf(`cat %s >> %s`, certificate, path), true
}

// keytoolBeside names the keytool belonging to THIS installation rather than
// whichever one a typed command would find.
//
// ADR50 IS THE REASON. Letting PATH pick the tool is naming a favourite, and on
// this machine PATH names one Java install out of six - so a command built that
// way would look right and, on five rows out of six, run the wrong binary
// against the right file.
//
// THE SEPARATOR COMES FROM THE PATH ITSELF rather than from the platform. The
// store path is real, read off this machine, so it already carries whichever
// separator this machine uses - and taking it from there means this function has
// no opinion about the operating system at all.
//
// It relies on one property of the java probe: for that runtime the instance IS
// the installation root. That coupling is named here rather than left to be
// rediscovered, and the java probe has a test that pins it.
func keytoolBeside(store report.TrustStore) string {
	separator := "/"
	if strings.Contains(store.StorePath, `\`) {
		separator = `\`
	}
	return strings.Join([]string{strings.TrimRight(store.Instance, `/\`), "bin", "keytool"}, separator)
}

// elevationFor answers whether an ordinary account can edit this store, and says
// why in one sentence.
//
// THE UNKNOWN CASE ANSWERS "YES, ELEVATED" AND THAT DIRECTION IS THE DECISION.
// Being told a command may need administrator rights when it does not costs a
// moment. Being told it does not when it does costs a failed command, a
// permission error somebody has to interpret, and the suspicion that the tool
// was wrong about everything else too - docs/20 rule 5 exists for the second
// case.
//
// WHAT IT DOES NOT DO, SAID HERE RATHER THAN IMPLIED: it does not read the
// file's permissions. This program never asks the filesystem whether it could
// write somewhere, because the honest way to ask is to try. The question it
// answers instead - is this store inside this account's own files - is a
// different question with the same answer nearly always, and the sentence it
// produces says which question was asked.
func elevationFor(storePath string, m Machine) (bool, string) {
	if m.Home == "" {
		return true, "this program could not establish where this account's own files are, so it assumes the store is shared with every other account"
	}
	if within(storePath, m.Home, m.OS) {
		return false, ""
	}
	return true, "this store is outside this account's own files, so it belongs to every account on the machine"
}

// within reports whether a path lies inside a directory.
//
// IT COMPARES WHOLE SEGMENTS AND THAT IS THE POINT - the same measured trap the
// git and java probes carry a test for. "C:\Users\bobby" begins with
// "C:\Users\bob" as TEXT, so a prefix comparison would hand one account's files
// to another account's name and answer the elevation question backwards.
func within(path, directory, os string) bool {
	if os == "windows" {
		path, directory = strings.ToLower(path), strings.ToLower(directory)
	}
	path, directory = strings.ReplaceAll(path, `\`, "/"), strings.ReplaceAll(directory, `\`, "/")
	directory = strings.TrimRight(directory, "/")
	return path == directory || strings.HasPrefix(path, directory+"/")
}

// unwritablePath is the sentence a row carries when a command exists in
// principle and this program will not write it - ADR59. It is not the ordinary
// nil answer, which needs no explanation, so it says which of the two happened.
const unwritablePath = "no command is offered for it: the path holds a character that a shell would read as an " +
	"instruction rather than as part of a name, and a line this program cannot write safely is not written at all"

// windowsMetacharacters are the characters that quoting on Windows does NOT
// make literal, so a path carrying one gets no command at all - ADR59.
//
// EACH ONE IS MEASURED ON THIS MACHINE AND HAS AN OFFICIAL SOURCE, because the
// whole point of this list is that it is a claim about somebody else's shell -
// inviolable rule 18. Measured 2026-08-26:
//
//   - "%": cmd /c echo "a%USERNAME%b" printed "aTestttb". Documented at
//     https://learn.microsoft.com/windows-server/administration/windows-commands/cmd
//     (read 2026-08-26): "To substitute variable values in the command line or
//     scripts, enclose the variable name in percent signs".
//   - "$" and the backquote: this command begins with "cmd /c" and is pasted
//     into whatever shell the person is using, which on Windows is as likely to
//     be PowerShell. Measured: "z$(1+1)z" printed z2z. Documented at
//     https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_quoting_rules
//     (read 2026-08-26): a double-quoted string is an expandable string and the
//     backquote is the escape character.
//   - the double quote itself ends the quoting and cannot be escaped in a way
//     both shells agree on.
//
// WHAT IS DELIBERATELY NOT HERE, AND IT IS A DECISION RATHER THAN AN OVERSIGHT.
// "&", "|", "<", ">" and "^" ARE made literal by the quotes - measured, cmd /c
// echo "a&b|c^d<e>f" printed the lot unchanged - so refusing them would take the
// command away from paths that are perfectly ordinary. "!" is expanded only when
// delayed expansion has been turned on, which the same Microsoft page says is
// off by default, so it stays out too and stands named in ADR59 as the residual.
const windowsMetacharacters = "%\"$`"

// quoteFor writes one path so that a shell reads it as a single literal word,
// and answers false when this program cannot write it safely at all.
//
// THIS IS THE ONLY LINE THIS PROGRAM HANDS A PERSON TO RUN, and the path in it
// comes from somebody else's configuration - http.sslCAInfo out of a gitconfig,
// CURL_CA_BUNDLE out of the environment. The double quotes that used to stand
// here stop a space from becoming two arguments and stop nothing else: a POSIX
// shell still expands $(...) inside them.
//
// THE POSIX FORM IS THE APOSTROPHE, and the escape looks strange because the
// standard leaves no other way. IEEE Std 1003.1-2024, Shell Command Language
// section 2.2.2 (read 2026-08-26,
// https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html):
// "Enclosing characters in single-quotes shall preserve the literal value of
// each character within the single-quotes. A single-quote cannot occur within
// single-quotes." So an apostrophe is written by leaving the quoting, escaping
// one apostrophe, and going back in. Measured in WSL the same day, from a file
// rather than a one-liner: single quotes left $(...) and ${...} untouched.
//
// A CONTROL CHARACTER IS REFUSED ON BOTH PLATFORMS, and the reason is the report
// rather than the shell: a newline inside apostrophes is legal and would turn one
// printed line into two, which is a command nobody can paste.
func quoteFor(platform, s string) (string, bool) {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	if platform == "windows" {
		if strings.ContainsAny(s, windowsMetacharacters) {
			return "", false
		}
		return `"` + s + `"`, true
	}
	return `'` + strings.ReplaceAll(s, `'`, `'\''`) + `'`, true
}
