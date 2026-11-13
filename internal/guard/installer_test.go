package guard

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The Windows installer (ADR148): the template WiX builds it from, the script
// that fills and builds it, the signing step that builds it from the signed
// archive, the release job that installs it on a runner, and the verifier that
// checks the published one. What the installer DOES is asked by that job and,
// before it was written, on Windows Server 2025. These guards hold what
// neither of those sees coming: a line those measurements rest on, a value
// that must never change, one name written in several places, and one rule for
// a release candidate. They read the files as text and run nothing, so they
// run on every system, WiX or not.
const (
	installerTemplate = "packaging/msi/certdoctor-setup.wxs.in"
	installerScript   = ".github/scripts/build_msi.py"
	windowCatalogue   = "internal/gui/words/words.go"
	commandResources  = "cmd/certdoctor/winres.json"
	windowResources   = "cmd/certdoctor-gui/winres.json"
	siteConfig        = "web/hugo.toml"
)

// installerFile is the installer as the README and the release note name it,
// with <version> where the release puts its version.
const installerFile = "`certdoctor-setup_<version>_windows_amd64.msi`"

// installerUpgradeCode is the product's identity in Windows Installer, for
// good. Every machine that has the program finds the version it has through
// it, so a new one would leave the old install beside the new one on every one
// of them. Written here a second time on purpose: this is the copy that does
// not move when the script does.
const installerUpgradeCode = "8078E22A-32AA-4080-B031-CA470D5D3EB7"

// asViolations turns the details a check of this file finds into violations of
// the file it reads first, for the helpers every guard here reports through.
func asViolations(file string, details []string) []Violation {
	out := make([]Violation, 0, len(details))
	for _, d := range details {
		out = append(out, Violation{File: file, Detail: d})
	}
	return out
}

const wixNamespace = "http://wixtoolset.org/schemas/v4/wxs"

// wxsElement is one element of the installer source: its name, its namespace,
// its attributes and the element it sits in. Comments are not elements, so a
// word in the explanation of a line never counts as the line.
type wxsElement struct {
	name, space string
	attrs       map[string]string
	parent      int
}

func wxsElements(source string) ([]wxsElement, error) {
	dec := xml.NewDecoder(strings.NewReader(source))
	var found []wxsElement
	open := []int{-1}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return found, nil
		}
		if err != nil {
			return nil, err
		}
		switch el := tok.(type) {
		case xml.StartElement:
			attrs := map[string]string{}
			for _, a := range el.Attr {
				key := a.Name.Local
				if a.Name.Space != "" {
					key = a.Name.Space + ":" + a.Name.Local
				}
				attrs[key] = a.Value
			}
			found = append(found, wxsElement{el.Name.Local, el.Name.Space, attrs, open[len(open)-1]})
			open = append(open, len(found)-1)
		case xml.EndElement:
			open = open[:len(open)-1]
		}
	}
}

func elementsNamed(els []wxsElement, name string) []wxsElement {
	var out []wxsElement
	for _, e := range els {
		if e.name == name {
			out = append(out, e)
		}
	}
	return out
}

// wantAttrs adds a violation for every attribute of e that is not the value
// the measurement rests on.
func wantAttrs(v []string, what string, e wxsElement, want map[string]string, why string) []string {
	for _, attr := range sortedKeys(want) {
		if got := e.attrs[attr]; got != want[attr] {
			v = append(v, fmt.Sprintf("%s has %s=%q, want %q: %s", what, attr, got, want[attr], why))
		}
	}
	return v
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// checkInstallerShape is the template against the lines the measurement on
// Windows Server 2025 rests on. Each one changed would still build a working
// installer, which is why it needs a guard rather than a build: what breaks is
// an upgrade, an uninstall or another account's Start menu, on somebody
// else's machine.
func checkInstallerShape(source string) []string {
	els, err := wxsElements(source)
	if err != nil {
		return []string{"the template is not XML: " + err.Error()}
	}
	var v []string
	if len(els) < 10 {
		v = append(v, fmt.Sprintf("read %d element(s), so this is not reading the installer source", len(els)))
	}
	// No extension, no custom action, nothing that ends a program, no dialogs
	// but Windows Installer's own (ADR148 decision 4): a diagnosis in
	// progress is cut off by nothing, and the package holds only our files.
	for _, e := range els {
		if e.space != wixNamespace {
			v = append(v, fmt.Sprintf("<%s> is from %q, an extension of WiX - the installer carries none", e.name, e.space))
		}
		for key := range e.attrs {
			if strings.HasPrefix(key, "xmlns:") {
				v = append(v, fmt.Sprintf("<%s> brings in the namespace %s - the installer uses no extension", e.name, key))
			}
		}
		switch e.name {
		case "CustomAction", "CloseApplication", "InstallExecuteSequence", "UI", "UIRef", "Binary":
			v = append(v, fmt.Sprintf("the installer has a <%s>. It runs no action of its own, ends nothing that is "+
				"running, and its only dialogs are Windows Installer's", e.name))
		}
	}

	pkg := elementsNamed(els, "Package")
	if len(pkg) != 1 {
		return append(v, fmt.Sprintf("the template has %d <Package>, and it is one package", len(pkg)))
	}
	v = wantAttrs(v, "the package", pkg[0], map[string]string{
		"Name": "{{APP_NAME}}", "UpgradeCode": "{{UPGRADE_CODE}}", "Scope": "perMachine",
	}, "the name and the UpgradeCode come from build_msi.py, where a guard pins them, and the package installs "+
		"for the machine, so the command line is on PATH for a build agent and the window in every account's Start menu")

	upgrade := elementsNamed(els, "MajorUpgrade")
	if len(upgrade) != 1 {
		v = append(v, fmt.Sprintf("the template has %d <MajorUpgrade>, and the next release replaces this one", len(upgrade)))
	} else {
		v = wantAttrs(v, "the major upgrade", upgrade[0], map[string]string{
			"Schedule": "afterInstallExecute", "AllowSameVersionUpgrades": "yes",
		}, "the old version goes after the new files are in place, and a rebuild of one version replaces the first build")
	}

	// Measured: with the Restart Manager on, an upgrade while the command line
	// ran failed after thirty seconds and closed it anyway. The OLD package's
	// properties decide an upgrade, so this is in the package from the first.
	var manager []wxsElement
	for _, e := range elementsNamed(els, "Property") {
		if e.attrs["Id"] == "MSIRESTARTMANAGERCONTROL" {
			manager = append(manager, e)
		}
	}
	if len(manager) != 1 || manager[0].attrs["Value"] != "Disable" {
		v = append(v, fmt.Sprintf("the package sets MSIRESTARTMANAGERCONTROL %d time(s), and once, to Disable - "+
			"or an upgrade while certdoctor runs fails and ends the run", len(manager)))
	}

	env := elementsNamed(els, "Environment")
	if len(env) != 1 {
		v = append(v, fmt.Sprintf("the template has %d <Environment>, and it sets one PATH entry", len(env)))
	} else {
		v = wantAttrs(v, "the PATH entry", env[0], map[string]string{
			"Name": "PATH", "System": "yes", "Part": "last", "Value": "[INSTALLFOLDER]", "Permanent": "no", "Action": "set",
		}, "the folder goes on the machine's PATH after everything already there, and comes off again at uninstall")
	}

	shortcuts := elementsNamed(els, "Shortcut")
	if len(shortcuts) != 1 {
		v = append(v, fmt.Sprintf("the template has %d shortcut(s). The window has one, and the command line none", len(shortcuts)))
	} else {
		v = wantAttrs(v, "the shortcut", shortcuts[0], map[string]string{
			"Target": "[INSTALLFOLDER]{{WINDOW_EXE}}", "WorkingDirectory": "INSTALLFOLDER", "Name": "{{APP_NAME}}",
		}, "it starts the window, by the name build_msi.py gives it, in the folder it is installed in")
	}

	folder := -1
	for i, e := range els {
		if e.name == "Directory" && e.attrs["Id"] == "INSTALLFOLDER" {
			folder = i
		}
	}
	if folder < 0 || els[folder].parent < 0 || els[els[folder].parent].attrs["Id"] != "ProgramFiles64Folder" ||
		els[folder].attrs["Name"] != "{{APP_NAME}}" {
		v = append(v, "the install folder is not Program Files\\{{APP_NAME}} - the verifier unpacks the installer "+
			"and looks for its files there")
	}
	files := elementsNamed(els, "Files")
	if len(files) != 1 || files[0].attrs["Include"] != `$(PayloadDir)\**` {
		v = append(v, "the template does not take the window's archive whole with one <Files Include=\"$(PayloadDir)\\**\">")
	}
	return v
}

func TestTheInstallerIsTheShapeThatWasMeasured(t *testing.T) {
	root := moduleRoot(t)
	requireNoViolations(t, asViolations(installerTemplate, checkInstallerShape(readRel(t, root, installerTemplate))), "the installer template")
}

func TestTheInstallerShapeGuardCanFail(t *testing.T) {
	real := readRel(t, moduleRoot(t), installerTemplate)
	for _, c := range []struct{ old, new, want string }{
		{`<Property Id="MSIRESTARTMANAGERCONTROL" Value="Disable" />`, ``, "MSIRESTARTMANAGERCONTROL"},
		{`Scope="perMachine"`, `Scope="perUser"`, `Scope="perUser"`},
		{`Schedule="afterInstallExecute"`, `Schedule="afterInstallValidate"`, "the major upgrade has Schedule"},
		{`System="yes" Permanent="no"`, `System="yes" Permanent="yes"`, "the PATH entry has Permanent"},
		{`<MediaTemplate EmbedCab="yes" />`, `<MediaTemplate EmbedCab="yes" /><CustomAction Id="x" />`, "<CustomAction>"},
		{`Target="[INSTALLFOLDER]{{WINDOW_EXE}}"`, `Target="[INSTALLFOLDER]certdoctor.exe"`, "the shortcut has Target"},
		{`UpgradeCode="{{UPGRADE_CODE}}"`, `UpgradeCode="` + installerUpgradeCode + `"`, "the package has UpgradeCode"},
		{`<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">`,
			`<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util">`,
			"brings in the namespace"},
	} {
		if strings.Count(real, c.old) != 1 {
			t.Fatalf("the template holds %q %d time(s), so this canary would break nothing", c.old, strings.Count(real, c.old))
		}
		requireViolation(t, asViolations(installerTemplate, checkInstallerShape(strings.Replace(real, c.old, c.new, 1))), c.want)
	}
}

var (
	pythonConstant  = `(?m)^%s = "([^"]*)"$`
	catalogueName   = regexp.MustCompile(`(?m)^\s*AppName:\s+"([^"]*)",$`)
	catalogueRepo   = regexp.MustCompile(`(?m)^\s*RepositoryURL\s*=\s*"([^"]*)"$`)
	releaseWixPin   = regexp.MustCompile(`dotnet tool install --global wix --version (\S+)`)
	resourceVersion = []string{"RT_VERSION", "#1", "0000", "info", "0409"}
)

// pyConst is the value of NAME = "..." at the top of a Python script, or "".
func pyConst(script, name string) string {
	m := regexp.MustCompile(fmt.Sprintf(pythonConstant, regexp.QuoteMeta(name))).FindStringSubmatch(script)
	if m == nil {
		return ""
	}
	return m[1]
}

// resourceString is one string of a winres.json's version block, or "".
func resourceString(body, key string) string {
	var node any
	if json.Unmarshal([]byte(body), &node) != nil {
		return ""
	}
	for _, step := range resourceVersion {
		m, ok := node.(map[string]any)
		if !ok {
			return ""
		}
		node = m[step]
	}
	m, ok := node.(map[string]any)
	if !ok {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// checkInstallerNames holds every place that writes one of the installer's
// names to the one place it lives. files maps a path to its text.
func checkInstallerNames(files map[string]string) []string {
	var v []string
	script := files[installerScript]
	same := func(what, got, want string) {
		if got != want {
			v = append(v, fmt.Sprintf("%s is %q, and it has to be %q", what, got, want))
		}
	}
	same("UPGRADE_CODE in "+installerScript, pyConst(script, "UPGRADE_CODE"), installerUpgradeCode)
	same("NAME in "+installerScript, pyConst(script, "NAME"), "certdoctor-setup_{version}_windows_amd64.msi")
	same("INSTALLER in "+signingScript, pyConst(files[signingScript], "INSTALLER"), "certdoctor-setup_%s_windows_amd64.msi")
	if !strings.Contains(files[verifyWorkflow], "certdoctor-setup_${version}_windows_amd64.msi") {
		v = append(v, verifyWorkflow+" does not ask for certdoctor-setup_${version}_windows_amd64.msi by name")
	}

	// The product's name (ADR148 decision 1): what Windows calls the program,
	// the window's title, the product name of both programs, the name macOS
	// shows for the window's bundle, and where the verifier and the release
	// job look for the installed files.
	app := pyConst(script, "APP_NAME")
	if app == "" {
		v = append(v, "APP_NAME is not read out of "+installerScript)
	}
	name := ""
	if m := catalogueName.FindStringSubmatch(files[windowCatalogue]); m != nil {
		name = m[1]
	}
	same("the window's AppName in "+windowCatalogue, name, app)
	for _, res := range []string{commandResources, windowResources} {
		same("ProductName in "+res, resourceString(files[res], "ProductName"), app)
		same("CompanyName in "+res, resourceString(files[res], "CompanyName"), pyConst(script, "PUBLISHER"))
	}
	for path, text := range map[string]string{
		releaseWorkflow: "$name = '" + app + "'",
		verifyWorkflow:  `PFiles64\` + app,
		buildScript:     `"$version" "` + app + `" "$binary"`,
	} {
		if !strings.Contains(files[path], text) {
			v = append(v, fmt.Sprintf("%s does not hold %q, so it names the product otherwise", path, text))
		}
	}
	// Where a person first reads the name, and where a person is told which
	// file to download: the README's title, the website's title, and the
	// installer in the README's download tables (which the download page reads)
	// and in the release note.
	for path, text := range map[string]string{
		readmeFile:   "# " + app + " ",
		siteConfig:   `title = "` + app + `"`,
		releaseNotes: installerFile,
	} {
		if !strings.Contains(files[path], text) {
			v = append(v, fmt.Sprintf("%s does not hold %q", path, text))
		}
	}
	if !strings.Contains(files[readmeFile], "| "+installerFile+" |") {
		v = append(v, readmeFile+" has no row for "+installerFile+", so the download page lists no installer")
	}

	repo := ""
	if m := catalogueRepo.FindStringSubmatch(files[windowCatalogue]); m != nil {
		repo = m[1]
	}
	same("REPOSITORY in "+installerScript, pyConst(script, "REPOSITORY"), repo)
	wix := ""
	if m := releaseWixPin.FindStringSubmatch(files[releaseWorkflow]); m != nil {
		wix = m[1]
	}
	same("the WiX "+releaseWorkflow+" installs", wix, pyConst(script, "WIX_VERSION"))
	return v
}

func installerFiles(t *testing.T) map[string]string {
	root := moduleRoot(t)
	files := map[string]string{}
	for _, rel := range []string{installerScript, signingScript, verifyWorkflow, releaseWorkflow, windowCatalogue,
		commandResources, windowResources, buildScript, readmeFile, siteConfig, releaseNotes} {
		files[rel] = readRel(t, root, rel)
	}
	return files
}

func TestTheInstallerIsNamedTheSameEverywhere(t *testing.T) {
	requireNoViolations(t, asViolations(installerScript, checkInstallerNames(installerFiles(t))), "the installer's names")
}

func TestTheInstallerNameGuardCanFail(t *testing.T) {
	for _, c := range []struct{ file, old, new, want string }{
		{installerScript, `UPGRADE_CODE = "` + installerUpgradeCode + `"`, `UPGRADE_CODE = "00000000-0000-0000-0000-000000000000"`, "UPGRADE_CODE in"},
		{windowCatalogue, `AppName:         "Cert Doctor",`, `AppName:         "certdoctor",`, "the window's AppName"},
		{windowResources, `"ProductName": "Cert Doctor"`, `"ProductName": "certdoctor"`, "ProductName in " + windowResources},
		{signingScript, `INSTALLER = "certdoctor-setup_%s_windows_amd64.msi"`, `INSTALLER = "certdoctor_%s_windows_amd64.msi"`, "INSTALLER in"},
		{releaseWorkflow, "--global wix --version 5.0.2", "--global wix --version 6.0.0", "the WiX"},
		{readmeFile, "# Cert Doctor ", "# certdoctor ", readmeFile + " does not hold"},
		{readmeFile, "| " + installerFile + " |", "| `certdoctor-setup_<version>_windows_amd64.exe` |", "has no row for"},
		{releaseNotes, installerFile, "`certdoctor_<version>_windows_amd64.msi`", releaseNotes + " does not hold"},
	} {
		files := installerFiles(t)
		if strings.Count(files[c.file], c.old) != 1 {
			t.Fatalf("%s holds %q %d time(s), so this canary would break nothing", c.file, c.old, strings.Count(files[c.file], c.old))
		}
		files[c.file] = strings.Replace(files[c.file], c.old, c.new, 1)
		requireViolation(t, asViolations(installerScript, checkInstallerNames(files)), c.want)
	}
}

// checkCandidateRule holds one rule for a release candidate in every place
// that asks: a hyphen in the version. Windows Installer reads only the three
// numbers, so a candidate's installer would take the release's own version,
// and the release would then not replace it.
func checkCandidateRule(files map[string]string) []string {
	var v []string
	for _, c := range []struct{ path, text, what string }{
		{installerScript, `if "-" in tag:`, "refuses a candidate's installer"},
		{signingScript, `return "-" in version`, "builds no installer for a candidate"},
		{releaseWorkflow, `$env:VERSION.Contains('-')`, "installs no installer for a candidate"},
		{releaseWorkflow, `*-*) flags+=(--prerelease) ;;`, "marks a candidate as a pre-release"},
	} {
		if !strings.Contains(files[c.path], c.text) {
			v = append(v, fmt.Sprintf("%s no longer %s by %q", c.path, c.what, c.text))
		}
	}
	verify := files[verifyWorkflow]
	start := strings.Index(verify, "installers=(*.msi)")
	end := -1
	if start >= 0 {
		end = strings.Index(verify[start:], "esac")
	}
	if start < 0 || end < 0 || !strings.Contains(verify[start:start+end], "*-*)") {
		v = append(v, verifyWorkflow+" does not count installers by the hyphen in the tag")
	}
	return v
}

func TestEveryPlaceAsksTheSameQuestionOfACandidate(t *testing.T) {
	requireNoViolations(t, asViolations(installerScript, checkCandidateRule(installerFiles(t))), "the candidate rule")
}

func TestTheCandidateGuardCanFail(t *testing.T) {
	for _, c := range []struct{ file, old, new, want string }{
		{signingScript, `return "-" in version`, `return "-rc" in version`, signingScript + " no longer builds"},
		{installerScript, `if "-" in tag:`, `if "-rc" in tag:`, installerScript + " no longer refuses"},
		{verifyWorkflow, "            *-*)\n              if [ \"${#installers[@]}\" != \"0\" ]",
			"            *-rc*)\n              if [ \"${#installers[@]}\" != \"0\" ]", "does not count installers"},
	} {
		files := installerFiles(t)
		if strings.Count(files[c.file], c.old) != 1 {
			t.Fatalf("%s holds %q %d time(s), so this canary would break nothing", c.file, c.old, strings.Count(files[c.file], c.old))
		}
		files[c.file] = strings.Replace(files[c.file], c.old, c.new, 1)
		requireViolation(t, asViolations(installerScript, checkCandidateRule(files)), c.want)
	}
}

// checkInstallerSigning holds the order the signing script builds the
// installer in: asked whether it can be built before the card signs anything,
// built after the programs are signed - an installer made before would carry
// unsigned copies - and before the checksums, which have to list it. It is
// signed with the product's name, built from the tree of the tag, and the
// draft is not complete without it. The release waits for the job that
// installs it on a runner.
func checkInstallerSigning(signing, release string) []string {
	var v []string
	_, main, found := strings.Cut(signing, "\ndef main(")
	if !found {
		return []string{signingScript + " has no main"}
	}
	steps := []string{"check_installer(tree, version)", "signing_thumbprint(windows_pin)", "sign_windows(work",
		"build_installer(tree, work", "write_checksums(work)"}
	at := -1
	for _, step := range steps {
		i := strings.Index(main, step)
		if i < 0 {
			v = append(v, fmt.Sprintf("main in %s never calls %s", signingScript, step))
			continue
		}
		if i < at {
			v = append(v, fmt.Sprintf("main in %s calls %s out of order: %s", signingScript, step, strings.Join(steps, ", then ")))
		}
		at = i
	}
	for _, text := range []string{`"/d", name`, `["git", "archive", "--format=tar", ref]`, `installer = INSTALLER % version`} {
		if !strings.Contains(signing, text) {
			v = append(v, fmt.Sprintf("%s no longer holds %s", signingScript, text))
		}
	}
	if !strings.Contains(release, "needs: [check, build, installer]") {
		v = append(v, releaseWorkflow+" opens the draft without waiting for the job that installs the installer")
	}
	return v
}

func TestTheSigningBuildsTheInstallerAfterTheCardAndBeforeTheSums(t *testing.T) {
	files := installerFiles(t)
	requireNoViolations(t, asViolations(signingScript, checkInstallerSigning(files[signingScript], files[releaseWorkflow])), "the installer's signing")
}

func TestTheInstallerSigningGuardCanFail(t *testing.T) {
	files := installerFiles(t)
	signing, release := files[signingScript], files[releaseWorkflow]
	early := "        print(\"\\n[7/%d] building and signing the Windows installer\" % steps)\n" +
		"        build_installer(tree, work, version, thumbprint, windows_pin, signtool, args.dry_run)\n"
	if strings.Count(signing, early) != 1 {
		t.Fatalf("%s does not hold the installer step this canary moves", signingScript)
	}
	moved := strings.Replace(signing, early, "", 1)
	moved = strings.Replace(moved, "        print(\"\\n[4/%d] the card\" % steps)\n", early+"        print(\"\\n[4/%d] the card\" % steps)\n", 1)
	requireViolation(t, asViolations(signingScript, checkInstallerSigning(moved, release)), "out of order")
	requireViolation(t, asViolations(signingScript, checkInstallerSigning(strings.Replace(signing, `"/d", name`, `"/v"`, 1), release)), `no longer holds "/d", name`)
	requireViolation(t, asViolations(signingScript, checkInstallerSigning(signing, strings.Replace(release, "needs: [check, build, installer]", "needs: [check, build]", 1))),
		"without waiting")
}
