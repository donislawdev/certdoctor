package guard

import (
	"fmt"
	"regexp"
	"strconv"
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

// TestTheReadmeSaysWhatAReleaseShipsAndHowToCheckIt holds the README to the
// release: every archive the five builds make, the checksum file the signing
// script writes and no other, the commands the release note gives, and the Go
// version go.mod asks for. The release note is held to the same archive names,
// and the signing script's own list of archives to them.
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
		buildScript:   readRel(t, root, buildScript),
		releaseNotes:  notes,
		signingScript: readRel(t, root, signingScript),
	}), "the archive names")
}

func TestTheReadmeGuardCanFail(t *testing.T) {
	stale := "**With Go installed** (1.27.2 or newer):\nevery release carries `SHA256SUMS`.\n" +
		"certdoctor_<version>_windows_amd64.zip and certdoctor_<version>_linux_amd64.tar.gz\n"
	violations := checkReadme(stale, "a/b", "1.27.3")
	requireViolation(t, violations, "asks for Go 1.27.2, and go.mod asks for 1.27.3")
	requireViolation(t, violations, "names SHA256SUMS as the checksum file")
	requireViolation(t, violations, "never names the _macos_arm64.tar.gz archive")
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
		buildScript:  "darwin) echo \"osx\" ;;\n",
		releaseNotes: "certdoctor_<version>_windows_amd64.zip\n",
		signingScript: "SIGNED_ARCHIVES = (\"_windows_amd64.zip\", \"_win_arm64.zip\")\n" +
			"MACOS_ARCHIVE = \"_macos_arm64.tar.gz\"\nARCHIVES = 6\n",
	})
	requireViolation(t, violations, `has no line darwin) echo "macos" ;;`)
	requireViolation(t, violations, "never names the _linux_arm64.tar.gz archive")
	requireViolation(t, violations, "expects _win_arm64.zip, and no target is called that")
	requireViolation(t, violations, "expects 6 archives, and the release builds 5")
	requireViolation(t, checkArchiveNames(map[string]string{signingScript: "nothing\n"}), "lists no archive")
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
	for _, target := range releaseTargets {
		if name := archiveName(target); !strings.Contains(body, name) {
			at("never names the " + name + " archive")
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

// signedArchive is one archive name the signing script expects, quoted on the
// line that declares it.
var signedArchive = regexp.MustCompile(`"(_[a-z0-9]+_[a-z0-9]+\.(?:zip|tar\.gz))"`)

// archiveCount is the number of archives the signing script waits for.
var archiveCount = regexp.MustCompile(`(?m)^ARCHIVES = (\d+)$`)

// checkArchiveNames reports a build script that names archives another way, a
// release note missing one, and a signing script expecting one no target makes.
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
	names := map[string]bool{}
	for _, target := range releaseTargets {
		names[archiveName(target)] = true
		if note, ok := files[releaseNotes]; ok && !strings.Contains(note, archiveName(target)) {
			at(releaseNotes, "never names the "+archiveName(target)+" archive")
		}
	}
	script := files[signingScript]
	expected := 0
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(line, "SIGNED_ARCHIVES = ") && !strings.HasPrefix(line, "MACOS_ARCHIVE = ") {
			continue
		}
		for _, m := range signedArchive.FindAllStringSubmatch(line, -1) {
			expected++
			if !names[m[1]] {
				at(signingScript, "expects "+m[1]+", and no target is called that")
			}
		}
	}
	if expected == 0 {
		at(signingScript, "lists no archive to sign, so the names above were never compared with it")
	}
	if m := archiveCount.FindStringSubmatch(script); m == nil {
		at(signingScript, "never says how many archives a release has")
	} else if n, _ := strconv.Atoi(m[1]); n != len(releaseTargets) {
		at(signingScript, fmt.Sprintf("expects %d archives, and the release builds %d", n, len(releaseTargets)))
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
