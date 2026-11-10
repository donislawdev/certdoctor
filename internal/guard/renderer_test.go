package guard

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The software renderer is two files of somebody else's that travel beside the
// window on Windows - ADR125 decisions 4 to 6. Nothing in a build knows whether
// they are there: the release puts them in the archive from a download it makes
// itself. So three places describe them, and each is read by something else:
// the pin, which the fetching script downloads by, the notices, which a person
// reads and the bill of materials is written from, and the window's own code,
// which asks for the files by name. A version raised in the pin alone would
// ship files whose licences nobody read again, and a name changed in one of the
// three would ship a folder the window does not look in.
const (
	rendererPin     = ".github/mesa-dist-win"
	rendererFetcher = ".github/scripts/fetch_software_renderer.sh"
	rendererProject = "pal1000/mesa-dist-win"
	rendererHeading = "Mesa 3D"
	windowNotices   = "THIRD-PARTY-NOTICES-GUI.md"
	windowRenderer  = "cmd/certdoctor-gui/software.go"
)

// A pinnedRenderer is what the pin names.
type pinnedRenderer struct {
	version string
	archive string
	sum     string
	files   []pinnedFile
}

// A pinnedFile is one file taken out of the archive.
type pinnedFile struct {
	inside string // the path inside the archive
	sum    string
	size   int64
}

// TestTheRendererThatShipsIsTheOneTheNoticesDescribe holds the pin to the
// notices and both to the names the window asks for.
func TestTheRendererThatShipsIsTheOneTheNoticesDescribe(t *testing.T) {
	root := moduleRoot(t)
	pin, violations := parseRendererPin(rendererPin, readRel(t, root, rendererPin))
	requireNoViolations(t, violations, "the pin of the software renderer")

	sections, problems := noticeSections(windowNotices, readRel(t, root, windowNotices))
	requireNoViolations(t, problems, "the notices file")
	folder, names, err := windowRendererNames(readRel(t, root, windowRenderer))
	if err != nil {
		t.Fatalf("%s: %v", windowRenderer, err)
	}
	requireNoViolations(t, checkRendererNotices(pin, sections[rendererHeading], folder), "the notices of the software renderer")
	requireNoViolations(t, checkRendererNames(pin, names), "the files the window asks for")

	// The one reader of the pin reads it, and nothing that runs at a release
	// carries a sum of its own - a second copy is the copy that drifts.
	fetcher := readRel(t, root, rendererFetcher)
	if !strings.Contains(fetcher, `pin="`+rendererPin+`"`) {
		t.Errorf("%s does not read %s, so it downloads by a version of its own", rendererFetcher, rendererPin)
	}
	for _, rel := range append(workflowFiles(t, root), rendererFetcher, buildScript, signingScript, macSigning) {
		body := readRel(t, root, rel)
		for _, sum := range append([]string{pin.sum}, sumsOf(pin.files)...) {
			if strings.Contains(body, sum) {
				t.Errorf("%s carries a sum of the software renderer itself, a second copy that can drift from %s", rel, rendererPin)
			}
		}
	}
}

func TestTheRendererGuardCanFail(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	good := "# a comment\nversion=1.2.3\narchive=mesa3d-1.2.3-release-msvc.7z\nsha256=" + sum + "\n" +
		"file=x64/first.dll " + other + " 10\nfile=x64/second.dll " + sum + " 20\n"
	pin, violations := parseRendererPin("fixture", good)
	requireNoViolations(t, violations, "a well formed pin")

	_, violations = parseRendererPin("fixture", "version=1.2.3\nversion=1.2.4\narchive=a.zip\nsha256="+strings.ToUpper(sum)+"\n"+
		"file=../x64/first.dll "+other+" 10\nfile=x64/second.dll "+sum+"\nfile=x64/second.dll "+sum+" 0\ncolour=red\n")
	requireViolation(t, violations, "names version twice")
	requireViolation(t, violations, "is not the name of a 7z archive")
	requireViolation(t, violations, "is not a lowercase sha256")
	requireViolation(t, violations, "is not a path inside the archive")
	requireViolation(t, violations, "has 2 fields where a file has three")
	requireViolation(t, violations, "is not a size")
	requireViolation(t, violations, "names colour")
	_, violations = parseRendererPin("fixture", "version=1.2.3\n")
	requireViolation(t, violations, "names no archive")
	requireViolation(t, violations, "names no file")

	section := "\nVersion `1.2.3`. MIT. Words.\n\n" +
		"- `opengl/first.dll`, 10 bytes, SHA-256 `" + other + "`\n" +
		"- `opengl/second.dll`, 20 bytes, SHA-256 `" + sum + "`\n\n" +
		"Out of `mesa3d-1.2.3-release-msvc.7z`, SHA-256 `" + sum + "`, at\n" +
		"<https://github.com/pal1000/mesa-dist-win/releases/tag/1.2.3>.\n"
	requireNoViolations(t, checkRendererNotices(pin, section, "opengl"), "a section that agrees with the pin")

	requireViolation(t, checkRendererNotices(pin, "", "opengl"), "have no section")
	requireViolation(t, checkRendererNotices(pin, strings.Replace(section, "`1.2.3`.", "`1.2.2`.", 1), "opengl"), "states 1.2.2")
	requireViolation(t, checkRendererNotices(pin, strings.Replace(section, "10 bytes", "11 bytes", 1), "opengl"), "does not list opengl/first.dll")
	requireViolation(t, checkRendererNotices(pin, section+"- `opengl/third.dll`, 5 bytes, SHA-256 `"+sum+"`\n", "opengl"), "lists 3 file(s)")
	requireViolation(t, checkRendererNotices(pin, section, "software"), "does not list software/first.dll")
	requireViolation(t, checkRendererNotices(pin, strings.Replace(section, "release-msvc.7z`, SHA-256 `"+sum, "release-msvc.7z`, SHA-256 `"+other, 1), "opengl"),
		"does not name the archive")
	requireViolation(t, checkRendererNotices(pin, strings.Replace(section, "/tag/1.2.3>", "/tag/1.2.2>", 1), "opengl"), "does not point at the release")

	requireNoViolations(t, checkRendererNames(pin, []string{"first.dll", "second.dll"}), "names that agree with the pin")
	requireViolation(t, checkRendererNames(pin, []string{"second.dll", "first.dll"}), "loads second.dll as file 1")
	requireViolation(t, checkRendererNames(pin, []string{"first.dll"}), "asks for 1 file(s)")

	if _, _, err := windowRendererNames("const (\n\tsoftwareDir = \"opengl\"\n)\n"); err == nil {
		t.Error("a file that names no renderer was read as one that does")
	}
	folder, names, err := windowRendererNames("const (\n\tsoftwareDir      = \"opengl\"\n\tsoftwareRenderer = \"a.dll\"\n\tsoftwareLoader   = \"b.dll\"\n)\n")
	if err != nil || folder != "opengl" || len(names) != 2 || names[0] != "a.dll" || names[1] != "b.dll" {
		t.Errorf("the window's names were read as %q %q (%v)", folder, names, err)
	}
}

var (
	rendererVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)
	rendererArchive = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.7z$`)
	rendererInside  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)
)

// parseRendererPin reads the pin the way the fetching script does, and refuses
// what that script refuses: a key given twice, a value of the wrong shape, a
// line that is neither.
func parseRendererPin(rel, body string) (pinnedRenderer, []Violation) {
	var pin pinnedRenderer
	var problems []Violation
	seen := map[string]bool{}
	single := map[string]*string{"version": &pin.version, "archive": &pin.archive, "sha256": &pin.sum}
	for i, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			problems = append(problems, Violation{rel, i + 1, fmt.Sprintf("%q is neither a comment nor key=value", line)})
			continue
		}
		if key == "file" {
			file, problem := parsePinnedFile(value)
			if problem != "" {
				problems = append(problems, Violation{rel, i + 1, problem})
				continue
			}
			pin.files = append(pin.files, file)
			continue
		}
		target, known := single[key]
		if !known {
			problems = append(problems, Violation{rel, i + 1, "names " + key + ", which is not something a pin says"})
			continue
		}
		if seen[key] {
			problems = append(problems, Violation{rel, i + 1, "names " + key + " twice, so the line a reviewer read may not be the line that is used"})
			continue
		}
		seen[key], *target = true, value
	}
	for _, key := range []string{"version", "archive", "sha256"} {
		if !seen[key] {
			problems = append(problems, Violation{rel, 0, "names no " + key})
		}
	}
	if seen["version"] && !rendererVersion.MatchString(pin.version) {
		problems = append(problems, Violation{rel, 0, fmt.Sprintf("%q is not a version", pin.version)})
	}
	if seen["archive"] && !rendererArchive.MatchString(pin.archive) {
		problems = append(problems, Violation{rel, 0, fmt.Sprintf("%q is not the name of a 7z archive", pin.archive)})
	}
	if seen["sha256"] && !sha256Hex.MatchString(pin.sum) {
		problems = append(problems, Violation{rel, 0, "the sum of the archive is not a lowercase sha256"})
	}
	if len(pin.files) == 0 {
		problems = append(problems, Violation{rel, 0, "names no file to take out of the archive"})
	}
	return pin, problems
}

func parsePinnedFile(value string) (pinnedFile, string) {
	fields := strings.Fields(value)
	if len(fields) != 3 {
		return pinnedFile{}, fmt.Sprintf("%q has %d fields where a file has three: a path, a sha256 and a size", value, len(fields))
	}
	if !rendererInside.MatchString(fields[0]) {
		return pinnedFile{}, fmt.Sprintf("%q is not a path inside the archive", fields[0])
	}
	if !sha256Hex.MatchString(fields[1]) {
		return pinnedFile{}, fmt.Sprintf("the sum of %s is not a lowercase sha256", fields[0])
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size <= 0 {
		return pinnedFile{}, fmt.Sprintf("%q is not a size in bytes", fields[2])
	}
	return pinnedFile{inside: fields[0], sum: fields[1], size: size}, ""
}

func sumsOf(files []pinnedFile) []string {
	var sums []string
	for _, f := range files {
		sums = append(sums, f.sum)
	}
	return sums
}

// listedFile is one line of the list the section opens with. The bill of
// materials is written from these lines, so their shape is part of what is held.
var listedFile = regexp.MustCompile("(?m)^- `([^`]+)`, ([0-9]+) bytes, SHA-256 `([0-9a-f]{64})`$")

// checkRendererNotices asks the section for the version, for each file under
// the name it ships by, for no file more, and for where the files come from.
func checkRendererNotices(pin pinnedRenderer, section, folder string) []Violation {
	if section == "" {
		return []Violation{{windowNotices, 0, fmt.Sprintf(
			"the files of the software renderer have no section \"## %s\", and their licences ask to travel with them", rendererHeading)}}
	}
	var problems []Violation
	if stated := versionIn(section); stated != pin.version {
		problems = append(problems, Violation{windowNotices, 0, fmt.Sprintf(
			"the section %q states %s and the release downloads %s - read the licences of that version again, then change both",
			rendererHeading, stated, pin.version)})
	}
	listed := map[string]bool{}
	for _, m := range listedFile.FindAllStringSubmatch(section, -1) {
		listed[m[1]+" "+m[2]+" "+m[3]] = true
	}
	for _, f := range pin.files {
		shipped := folder + "/" + path.Base(f.inside)
		if !listed[fmt.Sprintf("%s %d %s", shipped, f.size, f.sum)] {
			problems = append(problems, Violation{windowNotices, 0, fmt.Sprintf(
				"the section %q does not list %s with the %d bytes and the sum the pin names", rendererHeading, shipped, f.size)})
		}
	}
	if len(listed) != len(pin.files) {
		problems = append(problems, Violation{windowNotices, 0, fmt.Sprintf(
			"the section %q lists %d file(s) and the release ships %d", rendererHeading, len(listed), len(pin.files))})
	}
	if !strings.Contains(section, "`"+pin.archive+"`, SHA-256 `"+pin.sum+"`") {
		problems = append(problems, Violation{windowNotices, 0, fmt.Sprintf(
			"the section %q does not name the archive %s with its sum", rendererHeading, pin.archive)})
	}
	if !strings.Contains(section, "<https://github.com/"+rendererProject+"/releases/tag/"+pin.version+">") {
		problems = append(problems, Violation{windowNotices, 0, fmt.Sprintf(
			"the section %q does not point at the release %s of %s", rendererHeading, pin.version, rendererProject)})
	}
	return problems
}

// checkRendererNames holds the files the window loads, in the order it loads
// them, to the files the pin takes out of the archive, in the order it names
// them. The order matters to the window - the second imports the first by name
// - and one order written in two places is one that cannot be told apart from
// two.
func checkRendererNames(pin pinnedRenderer, names []string) []Violation {
	if len(names) != len(pin.files) {
		return []Violation{{windowRenderer, 0, fmt.Sprintf(
			"the window asks for %d file(s) and the release ships %d", len(names), len(pin.files))}}
	}
	var problems []Violation
	for i, f := range pin.files {
		if want := path.Base(f.inside); names[i] != want {
			problems = append(problems, Violation{windowRenderer, 0, fmt.Sprintf(
				"the window loads %s as file %d where the pin names %s", names[i], i+1, want)})
			break
		}
	}
	return problems
}

var windowRendererConst = regexp.MustCompile(`(?m)^\s*(softwareDir|softwareRenderer|softwareLoader)\s*=\s*"([^"]+)"\s*$`)

// windowRendererNames reads the folder and the two file names out of the
// window's source, in the order softwareFiles returns them.
func windowRendererNames(src string) (string, []string, error) {
	found := map[string]string{}
	for _, m := range windowRendererConst.FindAllStringSubmatch(src, -1) {
		found[m[1]] = m[2]
	}
	for _, name := range []string{"softwareDir", "softwareRenderer", "softwareLoader"} {
		if found[name] == "" {
			return "", nil, fmt.Errorf("no constant %s, so the names the window asks for cannot be read", name)
		}
	}
	return found["softwareDir"], []string{found["softwareRenderer"], found["softwareLoader"]}, nil
}
