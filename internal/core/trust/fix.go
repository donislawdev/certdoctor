package trust

import (
	"fmt"
	"slices"
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
	// NodeExtraCACerts is the value of NODE_EXTRA_CA_CERTS, because the command
	// for a node row adds to the file it names rather than naming another -
	// nodeFix. Empty is unset.
	NodeExtraCACerts string
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
		// measured trap it exists for - ADR103. On Linux this store IS a file,
		// and the function asks for its path itself - ADR104.
		return platformStoreFix(store, m)
	}
	if store.Runtime == report.RuntimeNode {
		// ASKED BEFORE THE FILE GATE TOO - ADR111 part 7. Node's list lives in
		// the binary, so its commands name the variable Node reads, never a store.
		return nodeFix(store, m)
	}
	if store.Runtime == report.RuntimePython {
		// AND BEFORE IT FOR PYTHON - ADR112 part 4. On Windows its list is the
		// platform's stores, which have no path, and on Linux the probe names
		// the file only when Python reads one.
		return pythonFix(store, m)
	}
	if store.StoreForm != report.StoreFile || store.StorePath == "" {
		return nil, ""
	}

	elevated, why := elevationFor(store.StorePath, m)

	switch store.Runtime {
	case "java":
		return javaFix(store, m, elevated, why)
	case report.RuntimePip:
		return pipFix(store, m, elevated, why)
	case "curl", "git":
		command, withheld := appendPEM(store.StorePath, store.FileEnd, m.OS)
		if withheld != "" {
			return nil, withheld
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

// javaFix is keytool importing into the store this row read, with the keytool
// of that same installation - keytoolBeside says why.
func javaFix(store report.TrustStore, m Machine, elevated bool, why string) (*report.Fix, string) {
	// EVERY PIECE GOES THROUGH THE SAME QUOTING, THE PLACEHOLDERS INCLUDED. A
	// person substitutes their own path into <certificate.pem>, and a space in it
	// is ordinary - ADR59. The angle brackets are a redirection in both shells
	// this command can land in, so they need the quotes even before anybody has
	// substituted anything.
	keytool, keytoolOK := quoteFor(m.OS, keytoolBeside(store))
	storePath, pathOK := quoteFor(m.OS, store.StorePath)
	alias, aliasOK := quoteFor(m.OS, aliasPlaceholder)
	certificate, certificateOK := quoteFor(m.OS, certificatePlaceholder)
	if !keytoolOK || !pathOK || !aliasOK || !certificateOK {
		return nil, unwritablePath
	}
	caveat := "installing a newer build of this runtime brings its own store and does not carry this certificate across"
	if m.OS == "windows" {
		caveat += ", and " + powerShellCall
	}
	return &report.Fix{
		Command: fmt.Sprintf(`%s -importcert -trustcacerts -keystore %s -storepass changeit -alias %s -file %s`,
			keytool, storePath, alias, certificate),
		Placeholders:      []string{aliasPlaceholder, certificatePlaceholder},
		RequiresElevation: elevated,
		Elevation:         why,
		// The password is the default one this store was just READ with, so it
		// is measured rather than assumed - and it is not a secret.
		Caveat: caveat,
	}, ""
}

// powerShellCall says where the Windows keytool command can be pasted as it
// stands - ADR114 B14, decided by the owner.
//
// THE COMMAND BEGINS WITH A QUOTED PATH, which the Command Prompt runs and
// PowerShell reads as a string. "If you try to execute the quoted path,
// PowerShell displays the contents of the quoted string instead of running the
// script. The call operator allows you to execute the contents of the string" -
// about_Operators, Call operator, read 2026-10-27 at
// https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_operators
// Measured the same day with this command's shape, -list in place of
// -importcert so nothing was changed: cmd.exe ran keytool, the PowerShell parser
// of 7.6.8 and of 5.1 refused the line with two UnexpectedToken errors, and with
// "& " in front 7.6.8 ran keytool with every argument as written.
//
// A CAVEAT AND NOT A SECOND FORM. A form starting with "& " fails in the Command
// Prompt instead - measured the same day, "& was unexpected at this time" - and
// a form for each shell is a template change the owner did not take, since it
// needs probe S18 measured again in five shells.
const powerShellCall = "the line is for the Command Prompt (cmd.exe) - PowerShell runs it only with & and a space " +
	"put before it"

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
// store instead of a machine store". That the machine's Root store needs an
// elevated session and a user's Root store applies to that user context is at
// https://learn.microsoft.com/windows-server/identity/ad-cs/inspect-certificates-manage-certificate-stores
// read the same day.
//
// MEASURED 2026-10-14: certutil -user -addstore read a PEM file and added the
// certificate, found afterwards by its serial number and removed again. It was
// measured on this account's Personal store, which grants no trust, rather
// than on Root - reading the file happens before any store is chosen, which is
// a JUDGEMENT. The confirmation dialog the CurrentUser caveat promises has no
// document behind it, so it was measured by the owner the same day: the same
// command aimed at this account's Root store opened Windows' security warning,
// it was declined, and the store was read afterwards with nothing added.
//
// A ROW THIS PROGRAM DID NOT WRITE GETS NO COMMAND. Only the two instances the
// probe produces are known, and only on Windows - and on Linux only the file the
// probe names. Anything else is a store nobody here knows how to name, and a
// guessed name is the command that does nothing.
func platformStoreFix(store report.TrustStore, m Machine) (*report.Fix, string) {
	if store.StoreForm == report.StoreFile && m.OS == "linux" {
		return distributionBundleFix(store, m)
	}
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
		return thisAccountsRootFix(certificate, "Windows asks for confirmation in a dialog before it adds a root to "+
			"this account's store, and services running as other accounts do not read it - the LocalMachine command "+
			"reaches them too"), ""
	}
	return nil, ""
}

// thisAccountsRootFix adds one root to this account's Root store. Two rows are
// given it - the platform's own row for this account, and python reading the
// Windows stores - so the command is written once, and each row says its own
// caveat.
func thisAccountsRootFix(certificate, caveat string) *report.Fix {
	return &report.Fix{
		Command:      "certutil -user -addstore Root " + certificate,
		Placeholders: []string{certificatePlaceholder},
		// THIS ACCOUNT'S OWN STORE, so no administrator is needed - and Windows
		// asks the person to confirm instead, which every caveat says before it
		// surprises anybody.
		RequiresElevation: false,
		Caveat:            caveat,
	}
}

// pythonFix is the command for a python row - ADR112 part 4, decided by the owner
// 2026-10-21.
//
// ON WINDOWS IT IS THIS ACCOUNT'S Root STORE. Python's list there is what the CA
// and ROOT stores hold, gathered each time a program makes a default context -
// load_default_certs and _load_windows_store_certs in Lib/ssl.py of CPython
// 3.15.0, read 2026-10-21 - and the stores it enumerates are this account's and
// the machine's, so a root added for this account is on the list of every
// interpreter it starts. Pointing Python at a file instead was rejected in ADR112:
// SSL_CERT_FILE is read by every program on OpenSSL, not by Python alone.
//
// ON LINUX IT IS THE APPEND, to the one file Python reads. The probe names that
// file only when Python reported reading it, spelled as the platform store's row
// spells it when it is the same file, so the two rows hand a person one command.
// A Python reading only the platform's hashed directory gets none: a certificate
// counts there only under the hash of its subject, which this program does not
// compute - OBS186.
func pythonFix(store report.TrustStore, m Machine) (*report.Fix, string) {
	switch {
	case store.StoreForm == report.StoreSystem && m.OS == "windows":
		// The placeholder is our own constant and holds nothing quoting refuses.
		certificate, _ := quoteFor(m.OS, certificatePlaceholder)
		return thisAccountsRootFix(certificate, "Windows asks for confirmation in a dialog before it adds a root to "+
			"this account's store, and a Python program reads the stores again each time it makes a TLS context"), ""
	case store.StoreForm == report.StoreFile && store.StorePath != "":
		command, withheld := appendPEM(store.StorePath, store.FileEnd, m.OS)
		if withheld != "" {
			return nil, withheld
		}
		elevated, why := elevationFor(store.StorePath, m)
		return &report.Fix{
			Command:           command,
			Placeholders:      []string{certificatePlaceholder},
			RequiresElevation: elevated,
			Elevation:         why,
			Caveat:            sharedFileCaveat,
		}, ""
	}
	return nil, ""
}

// sharedFileCaveat is what an append to a file Python or pip reads leaves behind.
const sharedFileCaveat = "every program reading this file trusts the certificate too, and whatever maintains it - " +
	"update-ca-certificates or update-ca-trust, when it is the distribution's bundle - rewrites the file and drops a " +
	"certificate appended here"

// pipFix adds the certificate to the file this pip reads - ADR112 part 5,
// decided by the owner.
//
// THE FILE NAMED FOR VERIFICATION FIRST, AND THE PROBE HAS ALREADY PUT IT IN
// StorePath. Setting cert or REQUESTS_CA_BUNDLE to another file would take the
// trust the first one gives - docs/20 rule 7 - and REQUESTS_CA_BUNDLE hides cert
// without a word, which is why the command adds to what is named and never names
// something new. With nothing named, a pip on truststore reads the platform's
// file, and the probe put that file there instead. A row on the platform's store
// with no file never reaches this function - on Windows it defers to this
// account's store and takes that row's command.
//
// A PIP ON certifi ALONE WITH NOTHING NAMED GETS NO COMMAND, and says why. A file
// named with cert or REQUESTS_CA_BUNDLE takes certifi's place there instead of
// joining it - HTTPAdapter.cert_verify in requests 2.34.2, adapters.py, uses the
// named path in place of certifi's, read 2026-10-27 in the copy pip 26.2.2 carries
// - so the only command left would be one somebody has to fill with every root
// pip needs. That this replaces rather than adds is read and not measured, since
// the bench serves no publicly trusted chain.
func pipFix(store report.TrustStore, m Machine, elevated bool, why string) (*report.Fix, string) {
	if store.Variant != report.PipTruststore && !namesItsFile(store) {
		return nil, certifiAlone
	}
	command, withheld := appendPEM(store.StorePath, store.FileEnd, m.OS)
	if withheld != "" {
		return nil, withheld
	}
	return &report.Fix{
		Command:           command,
		Placeholders:      []string{certificatePlaceholder},
		RequiresElevation: elevated,
		Elevation:         why,
		Caveat:            sharedFileCaveat,
	}, ""
}

// namesItsFile says a pip row's file was named for verification rather than
// being certifi's - the probe adds the name that did it to SelectedBy.
func namesItsFile(store report.TrustStore) bool {
	return slices.ContainsFunc(store.SelectedBy, func(name string) bool {
		switch name {
		case report.PipRequestsCABundle, report.PipCurlCABundle, report.PipCertVariable, report.PipCertSetting:
			return true
		}
		return false
	})
}

// certifiAlone is the sentence a pip on certifi alone carries in place of a
// command - pipFix has the reason.
const certifiAlone = "no command is offered for it: this pip trusts the one file certifi names, and naming another " +
	"with cert or REQUESTS_CA_BUNDLE would replace that file rather than add to it - pip 24.2 and later, without " +
	"--use-deprecated=legacy-certs, read this machine's store as well"

// distributionBundleFix is the command for the Linux platform store - ADR104,
// decided by the owner 2026-10-15: the same append git and curl get, aimed at
// the bundle the distribution keeps.
//
// THE DISTRIBUTION'S OWN TOOL WAS MEASURED AND NOT CHOSEN, because it TAKES
// AWAY. Probe S24, 2026-10-15: update-ca-certificates and update-ca-trust
// rebuild the bundle from their source directory, and in all five images where
// the tool ran, a certificate appended to the bundle by hand was gone
// afterwards. A command that drops whatever somebody added before is not
// adding, whatever it adds. The same run measured the two traps the caveat
// names: the Debian and Ubuntu tool ignores a file not named *.crt, and one RHEL
// image ships update-ca-trust unable to start.
//
// THE PRICE IS THAT THIS APPEND DOES NOT SURVIVE THE NEXT REBUILD - measured the
// same way - and the caveat says so before anybody relies on it.
func distributionBundleFix(store report.TrustStore, m Machine) (*report.Fix, string) {
	if store.StorePath == "" {
		return nil, ""
	}
	command, withheld := appendPEM(store.StorePath, store.FileEnd, m.OS)
	if withheld != "" {
		return nil, withheld
	}
	elevated, why := elevationFor(store.StorePath, m)
	return &report.Fix{
		Command:           command,
		Placeholders:      []string{certificatePlaceholder},
		RequiresElevation: elevated,
		Elevation:         why,
		Caveat: "update-ca-certificates and update-ca-trust rebuild this file from the distribution's own directory " +
			"and drop a certificate appended here - a copy named *.crt in /usr/local/share/ca-certificates, or one in " +
			"/etc/pki/ca-trust/source/anchors, is what survives the rebuild, and programs that carry a store of their " +
			"own - java among them - do not read this file",
	}, ""
}

// nodeFix is the command for a node row - ADR111 part 7, decided by the owner
// 2026-10-20. Three commands, asked in this order: turning on NODE_USE_SYSTEM_CA
// where the platform's list would close the chain, adding to the file
// NODE_EXTRA_CA_CERTS names, and setting that variable where nothing is set.
//
// ALL THREE ADD. NODE_USE_SYSTEM_CA=1 puts the certificates the system trusts
// beside the list Node is built with, and NODE_EXTRA_CA_CERTS extends that list,
// and neither takes anything out of it - Node.js doc/api/cli.md of v26.x, read
// 2026-10-20 at https://github.com/nodejs/node/blob/v26.x/doc/api/cli.md. Where
// NODE_EXTRA_CA_CERTS already names a file the certificate goes INTO that file,
// because setting it again would point Node at another file and drop every
// certificate the first one gave it - the redirect this file refuses everywhere.
//
// THE PLATFORM'S LIST COMES FIRST, because on a machine whose root reaches every
// account through the system's own store - a company's policy is the common case
// - it needs no file at all, and the file a person would be sent to find is the
// one they do not have.
//
// NONE REACHES A node ALREADY RUNNING: Node reads both variables once, when it
// starts - the same document - and every caveat says so. setx writes the
// account's environment, read by windows opened afterwards and not by the one
// it ran in - setx, Windows Commands reference, read 2026-10-20 at
// https://learn.microsoft.com/windows-server/administration/windows-commands/setx
// - and export reaches the commands this shell runs afterwards, IEEE Std
// 1003.1-2024, export, at https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html
func nodeFix(store report.TrustStore, m Machine) (*report.Fix, string) {
	if store.StoreForm != report.StoreBuiltin {
		return nil, ""
	}
	if store.PlatformListCloses {
		return systemListFix(m), ""
	}
	if m.NodeExtraCACerts != "" {
		return nodeExtraFileFix(store, m)
	}
	// The placeholder is our own constant and holds nothing quoting refuses, so
	// there is no refusal to handle - a branch here could never run.
	certificate, _ := quoteFor(m.OS, certificatePlaceholder)
	const fullPath = "put the certificate file's full path in place of " + certificatePlaceholder
	if m.OS == "windows" {
		return &report.Fix{
			Command:      "setx NODE_EXTRA_CA_CERTS " + certificate,
			Placeholders: []string{certificatePlaceholder},
			Caveat: fullPath + " - setx keeps it for this account and only windows opened afterwards read it, " +
				"so a node already running, and this window, keep the old value",
		}, ""
	}
	return &report.Fix{
		Command:      "export NODE_EXTRA_CA_CERTS=" + certificate,
		Placeholders: []string{certificatePlaceholder},
		Caveat: fullPath + " - export reaches this shell and what it starts from now on, so the line belongs in " +
			"the shell's profile to stay, and a node already running keeps the old value",
	}, ""
}

// systemListFix turns on the list of certificates the system trusts, which the
// probe found would close the chain for this node.
//
// NOTHING IS LEFT TO FILL IN - the certificate is already where the system keeps
// it, which is the whole point of this command. Node compares the value with
// "1" and with nothing else - HandleEnvOptions in src/node_options.cc of v26.x,
// read 2026-10-20 at https://github.com/nodejs/node/blob/v26.x/src/node_options.cc
// - so the command spells exactly that.
//
// THE VARIABLE REACHES EVERY node, not just this row's, and the caveat says
// which of them read it.
func systemListFix(m Machine) *report.Fix {
	const reach = "every node started afterwards that reads the variable - v22.19.0 and v24.6.0 onwards, and no v23 - " +
		"adds the certificates this system trusts to its own list"
	if m.OS == "windows" {
		return &report.Fix{
			Command:      "setx NODE_USE_SYSTEM_CA 1",
			Placeholders: []string{},
			Caveat: reach + ", and setx keeps it for this account and only windows opened afterwards read it, so a node " +
				"already running, and this window, keep the old value",
		}
	}
	return &report.Fix{
		Command:      "export NODE_USE_SYSTEM_CA=1",
		Placeholders: []string{},
		Caveat: reach + ", and export reaches this shell and what it starts from now on, so the line belongs in the " +
			"shell's profile to stay, and a node already running keeps the old value",
	}
}

// nodeExtraFileFix adds the certificate to the file NODE_EXTRA_CA_CERTS names.
//
// ONLY A FILE THIS node READ IS ADDED TO. A name it read nothing from - a file
// that is missing, or holds no certificate - says nothing about where Node
// would look next, and setting the variable instead would drop the choice
// somebody made. A relative name is looked up from wherever node starts, so it
// names no one file either. Both say why on the row instead.
func nodeExtraFileFix(store report.TrustStore, m Machine) (*report.Fix, string) {
	switch {
	case !slices.Contains(store.SelectedBy, "NODE_EXTRA_CA_CERTS"):
		return nil, fmt.Sprintf("no command is offered for it: NODE_EXTRA_CA_CERTS names %s, from which this node "+
			"read no certificate, and setting the variable again would drop the file it names", m.NodeExtraCACerts)
	case !absoluteOn(m.OS, m.NodeExtraCACerts):
		return nil, fmt.Sprintf("no command is offered for it: NODE_EXTRA_CA_CERTS names %s, a relative path that "+
			"each node looks up from wherever it starts", m.NodeExtraCACerts)
	}
	command, withheld := appendPEM(m.NodeExtraCACerts, store.FileEnd, m.OS)
	if withheld != "" {
		return nil, withheld
	}
	elevated, why := elevationFor(m.NodeExtraCACerts, m)
	return &report.Fix{
		Command:           command,
		Placeholders:      []string{certificatePlaceholder},
		RequiresElevation: elevated,
		Elevation:         why,
		Caveat:            "node reads this file when it starts, so a node already running does not see the certificate",
	}, ""
}

// absoluteOn reports whether a path names one file wherever it is used from:
// a drive and a separator, or a UNC name, on Windows, and a leading slash
// elsewhere.
func absoluteOn(platform, path string) bool {
	if platform == "windows" {
		drive := len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
		return drive || strings.HasPrefix(path, `\\`)
	}
	return strings.HasPrefix(path, "/")
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
//
// THE FILE'S END IS ASKED HERE, SO NO CALLER CAN SKIP IT - ADR114 B13. Both forms
// join bytes and nothing else, so a file whose last line has no line break
// would come out with one line ending the old block and beginning the new, and
// the store would lose its last certificate along with the one added. The
// templates stay as they are - a form adding the line break itself would change
// every command for a rare file, and needs the five shells of probe S18
// measured again. The second answer is the sentence a withheld command leaves
// on the row, and is empty when there is a command.
func appendPEM(storePath string, end report.FileEnd, platform string) (string, string) {
	path, pathOK := quoteFor(platform, storePath)
	certificate, certificateOK := quoteFor(platform, certificatePlaceholder)
	switch {
	case !pathOK || !certificateOK:
		return "", unwritablePath
	case end == report.FileEndMidLine:
		return "", endsMidLine
	case end != report.FileEndLineBreak:
		return "", endUnseen
	}
	if platform == "windows" {
		return fmt.Sprintf(`cmd /c copy /b %s+%s %s`, path, certificate, path), ""
	}
	return fmt.Sprintf(`cat %s >> %s`, certificate, path), ""
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

// endsMidLine and endUnseen are the sentences for a file an append cannot be
// trusted with - ADR114 B13. The first is a fact about the file, and says what
// a person can do about it. The second says this program did not see the end,
// which is not the same as the file being wrong.
const (
	endsMidLine = "no command is offered for it: the file does not end with a line break, so a certificate appended " +
		"to it would continue its last line, and neither the certificate ending there nor the one appended would be " +
		"read - end the file with a line break and run this again"
	endUnseen = "no command is offered for it: a certificate appended to the file starts a line of its own only when " +
		"the file ends with a line break, and this program could not read the file to see whether it does"
)

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
