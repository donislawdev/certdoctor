package guard

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The README is where a person first reads what a release is, before anything
// was downloaded, and it names the same files and the same commands the release
// note does. It is checked rather than trusted because it drifted twice with
// nothing noticing: it promised a checksum file under a name no release
// carries, and asked for a Go version go.mod had already moved past.
const readmeFile = "README.md"

// archiveNaming are the lines of the build script that turn a target into an
// archive's name. archiveName follows them, and the script is asked for them,
// so renaming an archive there fails here instead of leaving the README and
// the release note naming files no release has.
var archiveNaming = []string{
	`darwin) echo "macos" ;;`,
	`base="certdoctor_${version}_$(label_of "$os")_${arch}"`,
	`base="certdoctor-gui_${version}_$(label_of "$os")_${arch}"`,
	`zip -q -r -X "$dist/${base}.zip" .`,
	`tar -czf "$dist/${base}.tar.gz" -C "$pack" .`,
}

// archiveName is the end of the name the build script gives one target's
// archive, everything after the version: Go's darwin is labelled macos, and
// Windows gets a zip.
func archiveName(target [2]string) string {
	label, extension := target[0], ".tar.gz"
	switch target[0] {
	case "darwin":
		label = "macos"
	case "windows":
		extension = ".zip"
	}
	return "_" + label + "_" + target[1] + extension
}

// releaseArchives is every archive a release ships, by the name build_release.sh
// gives it with version standing in for the version: the command line for each
// release target and the window for each window target (ADR125 (a)).
func releaseArchives(version string) []string {
	var names []string
	for _, target := range releaseTargets {
		names = append(names, "certdoctor_"+version+archiveName(target))
	}
	for _, target := range windowTargets {
		names = append(names, "certdoctor-gui_"+version+archiveName(target))
	}
	return names
}

// TestTheReadmeSaysWhatAReleaseShipsAndHowToCheckIt holds the README to the
// release: every archive the eight builds make, the checksum file the signing
// script writes and no other, the commands the release note gives, and the Go
// version go.mod asks for. The release note and the verifier are held to the
// same archive names, and the signing script's table of archives to them.
func TestTheReadmeSaysWhatAReleaseShipsAndHowToCheckIt(t *testing.T) {
	root := moduleRoot(t)
	goMod := readRel(t, root, "go.mod")
	modulePath, err := modulePathFrom(goMod)
	if err != nil {
		t.Fatal(err)
	}
	goVersion, err := goDirectiveFrom(goMod)
	if err != nil {
		t.Fatal(err)
	}
	repository := strings.TrimPrefix(modulePath, "github.com/")
	notes := readRel(t, root, releaseNotes)
	requireNoViolations(t, checkReadme(readRel(t, root, readmeFile), repository, goVersion),
		"what the README says about a release")
	requireNoViolations(t, checkAttestationCommands(releaseNotes, notes, repository), "the release note's commands")
	requireNoViolations(t, checkArchiveNames(map[string]string{
		buildScript:    readRel(t, root, buildScript),
		releaseNotes:   notes,
		signingScript:  readRel(t, root, signingScript),
		verifyWorkflow: readRel(t, root, verifyWorkflow),
	}), "the archive names")
}

// windowSource is the file that names the window's application ID, which Fyne
// keeps its preferences under.
const windowSource = "cmd/certdoctor-gui/run_cgo.go"

// TestTheReadmeSaysWhereTheWindowKeepsItsSetting holds the README's answer to
// "does it change anything on my machine" to the window's application ID. Fyne
// keeps the window's one setting in a folder named after it, the ID is a value
// that may still change before the first release (ADR127), and a README naming
// the folder of an ID the window no longer has sends a person to delete the
// wrong thing.
func TestTheReadmeSaysWhereTheWindowKeepsItsSetting(t *testing.T) {
	root := moduleRoot(t)
	m := appIDLine.FindStringSubmatch(readRel(t, root, windowSource))
	if m == nil {
		t.Fatalf("%s has no line const appID = \"...\", so the folder the README names was never compared with it", windowSource)
	}
	requireNoViolations(t, checkSettingsFolders(readRel(t, root, readmeFile), m[1]), "where the window keeps its setting")
}

func TestTheReadmeGuardCanFail(t *testing.T) {
	stale := "**With Go installed** (1.27.2 or newer):\nevery release carries `SHA256SUMS`.\n" +
		"certdoctor_<version>_windows_amd64.zip and certdoctor_<version>_linux_amd64.tar.gz\n"
	violations := checkReadme(stale, "a/b", "1.27.3")
	requireViolation(t, violations, "asks for Go 1.27.2, and go.mod asks for 1.27.3")
	requireViolation(t, violations, "names SHA256SUMS as the checksum file")
	requireViolation(t, violations, "never names certdoctor_<version>_macos_arm64.tar.gz")
	requireViolation(t, violations, "never names certdoctor-gui_<version>_windows_amd64.zip")
	requireViolation(t, violations, "never mentions gh attestation verify")
	requireViolation(t, checkReadme("nothing about Go here\n", "a/b", "1.27.3"), "never says which Go builds it")
	two := "gh attestation verify x -R a/b --predicate-type p\ngh attestation verify x -R a/bc\n"
	requireViolation(t, checkAttestationCommands("fixture", two, "a/b"), "asks gh about another repository than a/b")
	requireNoViolations(t, checkAttestationCommands("fixture", "gh attestation verify x -R a/b \\\n   --flag\n", "a/b"),
		"a command continued on the next line")
	for _, v := range checkReadme("the list is in verify-SHA256SUMS.txt. Then `verify-SHA256SUMS.txt`, again.\n", "a/b", "1.27.3") {
		if strings.Contains(v.Detail, "as the checksum file") {
			t.Errorf("a sentence ending after the file name was read as another file: %s", v)
		}
	}

	violations = checkArchiveNames(map[string]string{
		buildScript:    "darwin) echo \"osx\" ;;\n",
		releaseNotes:   "certdoctor_<version>_windows_amd64.zip\n",
		verifyWorkflow: "\"certdoctor_${version}_windows_amd64.zip\"\ncertdoctor-gui_${version}_linux_amd64.tar.gz\n",
		signingScript: "RELEASE = (\n" +
			"    (\"certdoctor\", \"_windows_amd64.zip\", \"card\"),\n" +
			"    (\"certdoctor\", \"_win_arm64.zip\", \"card\"),\n" +
			"    (\"certdoctor\", \"_linux_amd64.tar.gz\", \"card\"),\n" +
			"    (\"certdoctor\", \"_windows_amd64.zip\", \"card\"),\n" +
			"    (\"certdoctor-gui\", \"_macos_arm64.tar.gz\", None),\n" +
			")\n" +
			"    (\"certdoctor\", \"_linux_arm64.tar.gz\", None),\n",
	})
	requireViolation(t, violations, `has no line darwin) echo "macos" ;;`)
	requireViolation(t, violations, "never names certdoctor_<version>_linux_arm64.tar.gz")
	requireViolation(t, violations, "never names certdoctor-gui_<version>_macos_arm64.tar.gz")
	requireViolation(t, violations, "never asks for certdoctor-gui_${version}_linux_amd64.tar.gz")
	requireViolation(t, violations, "expects certdoctor _win_arm64.zip, and no target is called that")
	requireViolation(t, violations, `signs certdoctor _linux_amd64.tar.gz at "card", and an archive for linux is signed at None`)
	requireViolation(t, violations, `signs certdoctor-gui _macos_arm64.tar.gz at None, and an archive for darwin is signed at "mac"`)
	requireViolation(t, violations, "lists certdoctor _windows_amd64.zip twice")
	// A row after the table closes is not in the table.
	requireViolation(t, violations, "never lists certdoctor _linux_arm64.tar.gz")
	requireViolation(t, checkArchiveNames(map[string]string{signingScript: "nothing\n"}), "lists no archive")

	settings := checkSettingsFolders("`AppData\\Roaming\\fyne\\a.b`, `~/.config/fyne/a.b` and `~/Library/Preferences/fyne/a.c`\n", "a.b")
	if len(settings) != 1 {
		t.Fatalf("want one folder named wrongly, got %v", settings)
	}
	requireViolation(t, settings, "never names ~/Library/Preferences/fyne/a.b")
}

// appIDLine is the line of the window's source that names its application ID.
var appIDLine = regexp.MustCompile(`(?m)^const appID = "([^"]+)"\s*$`)

// windowSettings are the folders Fyne keeps the window's preferences in, read
// in the code of the Fyne the window is built with (internal/app/config_*.go of
// v2.8.2, 2026-11-11): AppData\Roaming in the user folder on Windows, the XDG
// configuration folder on Linux and Library/Preferences on macOS, each with
// fyne and the window's application ID under it.
func windowSettings(appID string) []string {
	return []string{`AppData\Roaming\fyne\` + appID, "~/.config/fyne/" + appID, "~/Library/Preferences/fyne/" + appID}
}

// checkSettingsFolders reports a README that does not name each folder the
// window keeps its setting in, under the ID the window has.
func checkSettingsFolders(readme, appID string) []Violation {
	var violations []Violation
	for _, folder := range windowSettings(appID) {
		if !strings.Contains(readme, folder) {
			violations = append(violations, Violation{readmeFile, 0, "never names " + folder + ", where the window keeps its setting"})
		}
	}
	return violations
}

// checksumFile is anything the README could call a checksum list.
var checksumFile = regexp.MustCompile(`[A-Za-z0-9._-]*SHA256SUMS[A-Za-z0-9._-]*`)

// goInstalled is the sentence telling a person which Go installs the program.
var goInstalled = regexp.MustCompile(`\*\*With Go installed\*\* \((\d+\.\d+(?:\.\d+)?) or newer\)`)

// checkReadme reports a README that no longer describes the release.
func checkReadme(body, repository, goVersion string) []Violation {
	var violations []Violation
	at := func(detail string) { violations = append(violations, Violation{readmeFile, 0, detail}) }
	// The release note's promises, asked of the README: the same commands, so a
	// person reading either one checks a download the same way.
	for _, v := range checkReleaseNote(body, repository) {
		at(v.Detail)
	}
	violations = append(violations, checkAttestationCommands(readmeFile, body, repository)...)
	for _, name := range releaseArchives("<version>") {
		if !strings.Contains(body, name) {
			at("never names " + name + ", an archive every release carries")
		}
	}
	for _, named := range checksumFile.FindAllString(body, -1) {
		if named = strings.TrimRight(named, "."); named != "verify-SHA256SUMS.txt" {
			at("names " + named + " as the checksum file, and a release carries verify-SHA256SUMS.txt")
		}
	}
	switch asked := goInstalled.FindStringSubmatch(body); {
	case asked == nil:
		at("never says which Go builds it")
	case asked[1] != goVersion:
		at("asks for Go " + asked[1] + ", and go.mod asks for " + goVersion)
	}
	return violations
}

// checkAttestationCommands reports a gh attestation verify command that asks
// another repository. Asked line by line, because there are two of them and a
// check that the repository is mentioned somewhere is satisfied by either.
func checkAttestationCommands(rel, body, repository string) []Violation {
	var violations []Violation
	for i, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "gh attestation verify") && !strings.Contains(line, "-R "+repository+" ") &&
			!strings.HasSuffix(strings.TrimRight(line, " \\\r"), "-R "+repository) {
			violations = append(violations, Violation{rel, i + 1, "asks gh about another repository than " + repository})
		}
	}
	return violations
}

// signingRow is one row of the signing script's RELEASE table: a program, the
// end of its archive's name after the version, and where that archive is
// signed, written as Python writes it.
var signingRow = regexp.MustCompile(`^\s+\("([a-z-]+)", "(_[a-z0-9]+_[a-z0-9]+\.(?:zip|tar\.gz))", (None|"[a-z]+")\),\s*$`)

// signingTable is the rows of the RELEASE table, and nothing after it closes.
func signingTable(script string) [][3]string {
	_, rest, found := strings.Cut("\n"+script, "\nRELEASE = (\n")
	if !found {
		return nil
	}
	block, _, _ := strings.Cut(rest, "\n)")
	var rows [][3]string
	for _, line := range strings.Split(block, "\n") {
		if m := signingRow.FindStringSubmatch(line); m != nil {
			rows = append(rows, [3]string{m[1], m[2], m[3]})
		}
	}
	return rows
}

// signedAt is where the archive for a system is signed, as the signing script
// writes it: Windows at the card, macOS on the Mac, and Linux nowhere - its
// archive is the build's own bytes, which the build's statement describes.
func signedAt(goos string) string {
	switch goos {
	case "windows":
		return `"card"`
	case "darwin":
		return `"mac"`
	}
	return "None"
}

// checkArchiveNames reports a build script that names archives another way, a
// release note or a verifier missing one, and a signing table that lists an
// archive no target makes, misses one, lists one twice, or signs one where its
// system is not signed. A table missing an archive would have the release
// refuse it at the card, or carry it unsigned.
func checkArchiveNames(files map[string]string) []Violation {
	var violations []Violation
	at := func(rel, detail string) { violations = append(violations, Violation{rel, 0, detail}) }
	if script, ok := files[buildScript]; ok {
		for _, line := range archiveNaming {
			if !strings.Contains(script, line) {
				at(buildScript, "has no line "+line+", which is how an archive gets the name the README gives it")
			}
		}
	}
	if note, ok := files[releaseNotes]; ok {
		for _, name := range releaseArchives("<version>") {
			if !strings.Contains(note, name) {
				at(releaseNotes, "never names "+name)
			}
		}
	}
	if verifier, ok := files[verifyWorkflow]; ok {
		for _, name := range releaseArchives("${version}") {
			if !strings.Contains(verifier, `"`+name+`"`) {
				at(verifyWorkflow, "never asks for "+name+", so a release page without it would answer for itself")
			}
		}
	}

	want := map[string]string{}
	var order []string
	for _, group := range []struct {
		program string
		targets [][2]string
	}{{"certdoctor", releaseTargets}, {"certdoctor-gui", windowTargets}} {
		for _, target := range group.targets {
			key := group.program + " " + archiveName(target)
			want[key] = target[0]
			order = append(order, key)
		}
	}
	rows := signingTable(files[signingScript])
	if len(rows) == 0 {
		at(signingScript, "lists no archive to sign, so the names above were never compared with it")
	}
	seen := map[string]bool{}
	for _, row := range rows {
		key := row[0] + " " + row[1]
		goos, known := want[key]
		switch {
		case seen[key]:
			at(signingScript, "lists "+key+" twice")
		case !known:
			at(signingScript, "expects "+key+", and no target is called that")
		case row[2] != signedAt(goos):
			at(signingScript, "signs "+key+" at "+row[2]+", and an archive for "+goos+" is signed at "+signedAt(goos))
		}
		seen[key] = true
	}
	for _, key := range order {
		if !seen[key] {
			at(signingScript, "never lists "+key+", so the release would refuse it at the card or carry it unsigned")
		}
	}
	return violations
}

// goDirectiveFrom is the version go.mod's go line asks for.
func goDirectiveFrom(goMod string) (string, error) {
	for _, line := range strings.Split(goMod, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "go "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("no go directive")
}
