package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The WinGet and Chocolatey packages (ADR149): the templates in packaging/ and
// the script that renders them for a published release. What the packages DO -
// install, upgrade and uninstall - is asked by the CI job that installs the
// Chocolatey packages and, before they were submitted, on Windows Server 2025.
// These guards hold what neither sees coming: the lines those measurements
// rest on, the identifiers that are public for good once a feed has them, and
// the values the renderer keeps a copy of. They read the files as text and run
// nothing.
const (
	packagesScript        = ".github/scripts/build_packages.py"
	wingetFullInstaller   = "packaging/winget/installer.full.yaml.in"
	wingetCLIInstaller    = "packaging/winget/installer.cli.yaml.in"
	chocoFullInstall      = "packaging/chocolatey/tools/chocolateyinstall.full.ps1.in"
	chocoFullUninstall    = "packaging/chocolatey/tools/chocolateyuninstall.full.ps1.in"
	chocoCLIInstall       = "packaging/chocolatey/tools/chocolateyinstall.cli.ps1.in"
	chocoCLIBeforeModify  = "packaging/chocolatey/tools/chocolateybeforemodify.cli.ps1.in"
	chocoNuspec           = "packaging/chocolatey/package.nuspec.in"
	wingetLocale          = "packaging/winget/locale.en-US.yaml.in"
	wingetVersion         = "packaging/winget/version.yaml.in"
	sbomLicences          = "cmd/sbom/licences.go"
	sbomDocument          = "cmd/sbom/spdx.go"
	packageIconInTheTree  = "assets/icon/certdoctor.png"
	packageIconInRenderer = `ICON = "` + packageIconInTheTree + `"`
)

// packageTemplates is every template the renderer reads. A template added to
// packaging/ and missing here is caught by TestEveryPackageTemplateIsGuarded.
var packageTemplates = []string{
	wingetFullInstaller, wingetCLIInstaller, wingetLocale, wingetVersion,
	chocoNuspec, chocoFullInstall, chocoFullUninstall, chocoCLIInstall, chocoCLIBeforeModify,
}

// packageIdentifiers are the four names the feeds know the packages by, public
// for good once a feed has published one (ADR149 decision 2). A new one would
// start a second package beside the first, and every install of the first
// would never hear of a new version.
var packageIdentifiers = []string{
	`Package("full", "DonislawDev.CertDoctor", "cert-doctor", MSI.APP_NAME,`,
	`Package("cli", "DonislawDev.CertDoctor.CLI", "cert-doctor-cli", MSI.APP_NAME + " CLI",`,
}

func packagingFiles(t *testing.T) map[string]string {
	root := moduleRoot(t)
	files := map[string]string{}
	for _, rel := range append([]string{packagesScript, installerScript, sbomLicences, sbomDocument}, packageTemplates...) {
		files[rel] = readRel(t, root, rel)
	}
	return files
}

// codeLines is a template or a script without its comment lines, so a word in
// the explanation of a line never counts as the line.
func codeLines(text string) string {
	var keep []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

// checkPackageShape is the templates against the lines the measurements rest
// on. Each one changed would still render a package a feed accepts, which is
// why it needs a guard: what breaks is an install, an upgrade or an uninstall
// on somebody else's machine.
func checkPackageShape(files map[string]string) []string {
	var v []string
	need := func(file, text, why string) {
		if !strings.Contains(codeLines(files[file]), text) {
			v = append(v, fmt.Sprintf("%s no longer holds %q: %s", file, text, why))
		}
	}

	// WinGet, the whole product: the installer FIRST, the archive second.
	full := codeLines(files[wingetFullInstaller])
	wix, zip := strings.Index(full, "InstallerType: wix"), strings.Index(full, "InstallerType: zip")
	if wix < 0 || zip < 0 || wix > zip {
		v = append(v, wingetFullInstaller+" does not list the Windows installer before the archive - a fresh "+
			"install would then take the archive, which puts nothing in the Start menu")
	}
	for _, text := range []string{"Scope: machine", "ElevationRequirement: elevatesSelf", "InstallerUrl: {{MSI_URL}}",
		"- UpgradeCode: '{{UPGRADE_CODE}}'"} {
		need(wingetFullInstaller, text, "the Windows installer entry is the shape that was measured, and WinGet "+
			"finds the installed program again by its UpgradeCode")
	}
	for _, file := range []string{wingetFullInstaller, wingetCLIInstaller} {
		need(file, "NestedInstallerType: portable", "the archive holds the program as it is")
		need(file, "ArchiveBinariesDependOnPath: true", "without it WinGet reaches the program through a link, and "+
			"the window started that way finds neither the command line nor its software renderer")
	}
	need(wingetCLIInstaller, "{{WINGET_INSTALLERS}}", "the command line comes for every architecture the release builds")

	// Chocolatey, the whole product: the release's installer, by checksum.
	for _, text := range []string{"Install-ChocolateyPackage", "-FileType 'msi'", "-Url64bit '{{MSI_URL}}'",
		"-Checksum64 '{{MSI_SHA256}}'", "-ChecksumType64 'sha256'", "-ValidExitCodes @(0, 3010, 1641)"} {
		need(chocoFullInstall, text, "the package installs the published installer, checked by its checksum, and "+
			"an upgrade that leaves a running copy for the next restart is a success")
	}
	// Found by the product's identity, never by a name a person reads.
	need(chocoFullUninstall, "RelatedProducts('{{UPGRADE_CODE}}')", "the uninstall finds the installer by its UpgradeCode")
	if strings.Contains(codeLines(files[chocoFullUninstall]), "Get-UninstallRegistryKey") {
		v = append(v, chocoFullUninstall+" looks the program up by its name in Programs and Features - another "+
			"program may carry that name, and the UpgradeCode is the product's identity")
	}
	// Chocolatey, the command line: the release's archive, by checksum.
	for _, text := range []string{"Install-ChocolateyZipPackage", "-Url64bit '{{URL_AMD64}}'",
		"-Checksum64 '{{SHA256_AMD64}}'", "-ChecksumType64 'sha256'"} {
		need(chocoCLIInstall, text, "the package installs the published archive, checked by its checksum")
	}

	// No package ends a program: a diagnosis in progress is cut off by nothing.
	ends := regexp.MustCompile(`(?i)\b(Stop-Process|taskkill|Stop-Service)\b|\.Kill\(`)
	for _, file := range []string{chocoFullInstall, chocoFullUninstall, chocoCLIInstall, chocoCLIBeforeModify} {
		if m := ends.FindString(codeLines(files[file])); m != "" {
			v = append(v, fmt.Sprintf("%s ends a program (%s) - no package does", file, m))
		}
	}
	return v
}

// versionNumber is a dotted version in a template. The version comes from the
// tag and the WinGet schema from the renderer, so a template holding one is a
// value the renderer no longer controls.
var versionNumber = regexp.MustCompile(`\b\d+\.\d+\.\d+\b`)

// checkPackageSources holds the templates to what Windows PowerShell 5.1 and
// the renderer need: ASCII, no version of their own, and every template
// guarded here.
func checkPackageSources(files map[string]string, onDisk []string) []string {
	var v []string
	for _, file := range packageTemplates {
		for i, line := range strings.Split(files[file], "\n") {
			if strings.IndexFunc(line, func(r rune) bool { return r > 127 }) >= 0 {
				v = append(v, fmt.Sprintf("%s line %d is not ASCII - Windows PowerShell 5.1 reads a script without "+
					"a byte order mark in the machine's code page", file, i+1))
			}
			if m := versionNumber.FindString(line); m != "" {
				v = append(v, fmt.Sprintf("%s line %d carries the version %s - versions come from the tag and the "+
					"renderer", file, i+1, m))
			}
		}
	}
	guarded := map[string]bool{}
	for _, file := range packageTemplates {
		guarded[file] = true
	}
	for _, file := range onDisk {
		if !guarded[file] {
			v = append(v, file+" is a package template no guard reads - add it to packageTemplates")
		}
	}
	return v
}

// checkPackageValues holds what the renderer takes from elsewhere to where it
// comes from: the installer's name, its UpgradeCode and the product's name from
// build_msi.py, read rather than copied, and the two copies it does keep - the
// licence and the copyright line - equal to the Go constants the program's own
// documents are made from. The four identifiers are pinned for good.
func checkPackageValues(files map[string]string) []string {
	var v []string
	script := files[packagesScript]
	for _, text := range []string{"MSI.NAME", "MSI.UPGRADE_CODE", "MSI.APP_NAME", "MSI.PUBLISHER", "MSI.REPOSITORY",
		"MSI.site()", "MSI.parse_version(tag)"} {
		if !strings.Contains(script, text) {
			v = append(v, fmt.Sprintf("%s no longer reads %s from %s, where the installer's own value lives",
				packagesScript, text, installerScript))
		}
	}
	for _, name := range []string{"NAME", "UPGRADE_CODE", "APP_NAME", "PUBLISHER", "REPOSITORY"} {
		if pyConst(script, name) != "" {
			v = append(v, fmt.Sprintf("%s keeps a copy of %s - it is read from %s, so the two cannot differ",
				packagesScript, name, installerScript))
		}
	}
	goConst := func(file, name string) string {
		m := regexp.MustCompile(`(?m)^const ` + regexp.QuoteMeta(name) + ` = "([^"]*)"$`).FindStringSubmatch(files[file])
		if m == nil {
			return ""
		}
		return m[1]
	}
	for _, c := range []struct{ py, file, goName string }{
		{"LICENCE", sbomLicences, "ourLicence"},
		{"COPYRIGHT", sbomDocument, "ourCopyright"},
	} {
		want, got := goConst(c.file, c.goName), pyConst(script, c.py)
		if want == "" || got != want {
			v = append(v, fmt.Sprintf("%s in %s is %q, and %s in %s is %q - the packages say what the program says",
				c.py, packagesScript, got, c.goName, c.file, want))
		}
	}
	for _, id := range packageIdentifiers {
		if !strings.Contains(script, id) {
			v = append(v, fmt.Sprintf("%s no longer holds %s - the feeds know the packages by these names for good",
				packagesScript, id))
		}
	}
	// A CDN pinned to the tag: Chocolatey's moderation refuses raw GitHub
	// addresses, and an icon on a branch keeps changing under an approved package.
	if !strings.Contains(script, `"https://cdn.jsdelivr.net/gh/%s@%s/%s" % (repo, tag, ICON)`) ||
		!strings.Contains(script, packageIconInRenderer) {
		v = append(v, packagesScript+" no longer points the Chocolatey icon at "+packageIconInTheTree+" on a CDN, "+
			"pinned to the tag")
	}
	return v
}

// templatesOnDisk is every template the renderer would read, found on disk, so
// a new one cannot go unguarded by being left off packageTemplates.
func templatesOnDisk(t *testing.T) []string {
	root := moduleRoot(t)
	var found []string
	for _, dir := range []string{"packaging/winget", "packaging/chocolatey", "packaging/chocolatey/tools"} {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".in") {
				found = append(found, dir+"/"+e.Name())
			}
		}
	}
	if len(found) < len(packageTemplates) {
		t.Fatalf("found %d template(s) on disk and %d are guarded, so this is not reading packaging/", len(found), len(packageTemplates))
	}
	return found
}

func TestThePackagesAreTheShapeThatWasMeasured(t *testing.T) {
	requireNoViolations(t, asViolations(packagesScript, checkPackageShape(packagingFiles(t))), "the packages' shape")
}

func TestThePackageShapeGuardCanFail(t *testing.T) {
	for _, c := range []struct{ file, old, new, want string }{
		{wingetFullInstaller, "ArchiveBinariesDependOnPath: true", "ArchiveBinariesDependOnPath: false", "ArchiveBinariesDependOnPath"},
		{wingetCLIInstaller, "ArchiveBinariesDependOnPath: true", "ArchiveBinariesDependOnPath: false", wingetCLIInstaller},
		{wingetFullInstaller, "  InstallerType: wix", "  InstallerType: msi", "before the archive"},
		{wingetFullInstaller, "  Scope: machine", "  Scope: user", "Scope: machine"},
		{chocoFullInstall, "-ValidExitCodes @(0, 3010, 1641)", "-ValidExitCodes @(0)", "ValidExitCodes"},
		{chocoFullInstall, "-Checksum64 '{{MSI_SHA256}}'", "-Checksum64 ''", "checked by its checksum"},
		{chocoFullUninstall, "$installer = New-Object", "[array]$key = Get-UninstallRegistryKey -SoftwareName 'Cert Doctor'\n$installer = New-Object", "by its name"},
		{chocoCLIInstall, "-Checksum64 '{{SHA256_AMD64}}'", "-Checksum64 ''", chocoCLIInstall},
		{chocoCLIBeforeModify, "$running = @()\ntry {", "Stop-Process -Name certdoctor\n$running = @()\ntry {", "ends a program"},
	} {
		files := packagingFiles(t)
		files[c.file] = strings.ReplaceAll(files[c.file], "\r\n", "\n")
		if strings.Count(files[c.file], c.old) != 1 {
			t.Fatalf("%s holds %q %d time(s), so this canary would break nothing", c.file, c.old, strings.Count(files[c.file], c.old))
		}
		files[c.file] = strings.Replace(files[c.file], c.old, c.new, 1)
		requireViolation(t, asViolations(packagesScript, checkPackageShape(files)), c.want)
	}
}

func TestThePackageSourcesAreASCIIAndCarryNoVersion(t *testing.T) {
	requireNoViolations(t, asViolations(packagesScript, checkPackageSources(packagingFiles(t), templatesOnDisk(t))),
		"the package templates")
}

func TestThePackageSourcesGuardCanFail(t *testing.T) {
	files := packagingFiles(t)
	files[chocoCLIInstall] += "\nWrite-Host 'Type certdoctor \xe2\x80\x94 done'\n"
	requireViolation(t, asViolations(packagesScript, checkPackageSources(files, nil)), "is not ASCII")

	files = packagingFiles(t)
	files[wingetVersion] += "\nManifestVersion: 1.28.0\n"
	requireViolation(t, asViolations(packagesScript, checkPackageSources(files, nil)), "carries the version 1.28.0")

	requireViolation(t, asViolations(packagesScript, checkPackageSources(packagingFiles(t),
		append(templatesOnDisk(t), "packaging/chocolatey/tools/chocolateyuninstall.cli.ps1.in"))), "no guard reads")
}

func TestThePackagesTakeTheirValuesFromWhereTheyLive(t *testing.T) {
	requireNoViolations(t, asViolations(packagesScript, checkPackageValues(packagingFiles(t))), "the packages' values")
}

func TestThePackageValuesGuardCanFail(t *testing.T) {
	for _, c := range []struct{ file, old, new, want string }{
		{packagesScript, `LICENCE = "GPL-3.0-only"`, `LICENCE = "GPL-3.0-or-later"`, "LICENCE in"},
		{packagesScript, `COPYRIGHT = "Copyright (C) 2026 DonislawDev"`, `COPYRIGHT = "Copyright (C) 2027 DonislawDev"`, "COPYRIGHT in"},
		{sbomDocument, `const ourCopyright = "Copyright (C) 2026 DonislawDev"`, `const ourCopyright = "Copyright (C) 2026 Someone"`, "ourCopyright in"},
		{packagesScript, `"DonislawDev.CertDoctor.CLI", "cert-doctor-cli",`, `"DonislawDev.CertDoctor.Cli", "cert-doctor-cli",`, "for good"},
		{packagesScript, `"DonislawDev.CertDoctor", "cert-doctor", MSI.APP_NAME,`, `"DonislawDev.CertDoctor", "certdoctor", MSI.APP_NAME,`, "for good"},
		{packagesScript, `"UPGRADE_CODE": "{%s}" % MSI.UPGRADE_CODE,`, `"UPGRADE_CODE": "{%s}" % UPGRADE_CODE,` + "\nUPGRADE_CODE = \"" + installerUpgradeCode + "\"", "keeps a copy of UPGRADE_CODE"},
		{packagesScript, "@%s/%s\" % (repo, tag, ICON)", "@main/%s\" % (repo, ICON)", "pinned to the tag"},
	} {
		files := packagingFiles(t)
		files[c.file] = strings.ReplaceAll(files[c.file], "\r\n", "\n")
		if strings.Count(files[c.file], c.old) != 1 {
			t.Fatalf("%s holds %q %d time(s), so this canary would break nothing", c.file, c.old, strings.Count(files[c.file], c.old))
		}
		files[c.file] = strings.Replace(files[c.file], c.old, c.new, 1)
		requireViolation(t, asViolations(packagesScript, checkPackageValues(files)), c.want)
	}
}
