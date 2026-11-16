# Install both Chocolatey packages, ask the machine what happened, remove them,
# and ask again (ADR149).
#
#   pwsh -File .github/scripts/check_chocolatey_packages.ps1 -Feed <folder with both .nupkg> -Version 0.2.0
#
# The packages download the release's own files - the Windows installer for
# cert-doctor and the command line's archive for cert-doctor-cli - and are
# checked against its checksums, so this asks the network for the published
# release named by -Version. Every check is asked of what Windows did, not of
# what a script says: the entry Windows Installer keeps under the product's
# UpgradeCode, the machine's PATH, the Start menu shortcut, the version the
# installed program prints, the shim Chocolatey made and the exit code that
# comes back through it.
#
# The same script runs in CI on a clean runner and, before a submission, on
# Windows Server 2025 over ssh - which is why it is ASCII and Windows
# PowerShell 5.1 as well as PowerShell 7.
#
# Exit codes:
#   0  every check passed
#   1  a check failed, and the line above the summary says which
#   2  the machine was not clean before - a package or the program was there
param(
    [Parameter(Mandatory = $true)][string] $Feed,
    [Parameter(Mandatory = $true)][string] $Version
)

$ErrorActionPreference = 'Continue'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$name = 'Cert Doctor'
$installDir = Join-Path $env:ProgramFiles $name
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) ($name + '.lnk')
$bin = Join-Path $env:ChocolateyInstall 'bin'
$lib = Join-Path $env:ChocolateyInstall 'lib'
$cliExe = Join-Path $lib 'cert-doctor-cli\tools\certdoctor\certdoctor.exe'
$shim = Join-Path $bin 'certdoctor.exe'

# The product's identity in Windows Installer, read from the script that
# builds the installer, where a guard pins it.
$found = Select-String -LiteralPath (Join-Path $root '.github\scripts\build_msi.py') -Pattern '^UPGRADE_CODE = "([0-9A-F-]+)"$'
if (-not $found) { Write-Host 'cannot read UPGRADE_CODE from build_msi.py'; exit 1 }
$upgradeCode = '{' + $found.Matches[0].Groups[1].Value + '}'

$script:failed = 0
function Check($ok, [string]$what) {
    if ($ok) { Write-Host "ok      $what" } else { Write-Host "FAILED  $what"; $script:failed++ }
}
function Products {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    return @($installer.RelatedProducts($upgradeCode))
}
function OursOnPath {
    return @(([Environment]::GetEnvironmentVariable('Path', 'Machine')).Split(';') | Where-Object { $_.TrimEnd('\') -eq $installDir })
}
function Packages {
    return ((& choco.exe list --limit-output) -join "`n")
}
function Run-Choco([string[]]$argv) {
    # The whole output is kept and shown: what Chocolatey said is the first
    # thing to read when a check after it fails.
    $out = (& choco.exe @argv --yes --no-progress 2>&1 | ForEach-Object { "$_" } | Out-String)
    $code = $LASTEXITCODE
    Write-Host $out
    Write-Host "choco $($argv -join ' ') -> $code"
    return @{ Code = $code; Out = $out }
}
function FirstLine([string]$exe, [string[]]$argv) {
    $lines = @(& $exe @argv 2>&1)
    return @{ Code = $LASTEXITCODE; Line = ([string]$lines[0]).Trim() }
}

# --- the machine is clean
$clean = ((Products).Count -eq 0) -and -not (Test-Path -LiteralPath $installDir) -and
    -not ((Packages) -match '(?m)^cert-doctor') -and -not (Test-Path -LiteralPath $shim)
if (-not $clean) {
    Write-Host 'the machine is not clean: Cert Doctor, one of its packages or the certdoctor shim is already here'
    exit 2
}

# --- cert-doctor: the Windows installer
$r = Run-Choco @('install', 'cert-doctor', '--source', $Feed)
Check ($r.Code -eq 0) 'cert-doctor installs'
Check ((Packages) -match "(?m)^cert-doctor\|$([regex]::Escape($Version))$") "Chocolatey lists cert-doctor $Version"
Check ((Products).Count -eq 1) "Windows Installer has one product of the UpgradeCode ($((Products).Count))"
$said = FirstLine (Join-Path $installDir 'certdoctor.exe') @('--version')
Check ($said.Code -eq 0 -and $said.Line -eq "certdoctor: $Version") "the installed command line says $Version ($($said.Line))"
Check ((OursOnPath).Count -eq 1) "the install folder is on the machine PATH once ($((OursOnPath).Count))"
Check (Test-Path -LiteralPath $shortcut) 'the Start menu has the shortcut for every account'
if (Test-Path -LiteralPath $shortcut) {
    $link = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut)
    Check ($link.TargetPath -eq (Join-Path $installDir 'certdoctor-gui.exe')) "it starts the window ($($link.TargetPath))"
}
Check (-not (Test-Path -LiteralPath $shim) -and -not (Test-Path -LiteralPath (Join-Path $bin 'certdoctor-gui.exe'))) 'Chocolatey made no shim for the installed programs'

$r = Run-Choco @('uninstall', 'cert-doctor')
Check ($r.Code -eq 0) 'cert-doctor uninstalls'
Check ((Products).Count -eq 0) 'Windows Installer has no product of the UpgradeCode'
Check (-not (Test-Path -LiteralPath $installDir)) 'the install folder is gone'
Check ((OursOnPath).Count -eq 0) 'nothing of ours on the machine PATH'
Check (-not (Test-Path -LiteralPath $shortcut)) 'no shortcut'
Check (-not ((Packages) -match '(?m)^cert-doctor\|')) 'Chocolatey no longer lists cert-doctor'

# --- cert-doctor removed outside Chocolatey, then uninstalled by it
$r = Run-Choco @('install', 'cert-doctor', '--source', $Feed)
Check ($r.Code -eq 0) 'cert-doctor installs again'
foreach ($product in Products) {
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/x', $product, '/qn', '/norestart') -PassThru -Wait
    Write-Host "msiexec /x $product -> $($p.ExitCode)"
}
Check ((Products).Count -eq 0) 'the program was removed outside Chocolatey'
$r = Run-Choco @('uninstall', 'cert-doctor')
Check ($r.Code -eq 0) 'the uninstall still succeeds'
Check ($r.Out -match 'is not installed any more') 'and says that the program was already gone'
Check (-not ((Packages) -match '(?m)^cert-doctor\|')) 'Chocolatey no longer lists cert-doctor'

# --- cert-doctor-cli: the command line's archive
$r = Run-Choco @('install', 'cert-doctor-cli', '--source', $Feed)
Check ($r.Code -eq 0) 'cert-doctor-cli installs'
Check ((Packages) -match "(?m)^cert-doctor-cli\|$([regex]::Escape($Version))$") "Chocolatey lists cert-doctor-cli $Version"
Check (Test-Path -LiteralPath $cliExe) 'the command line is in a folder of its own under the package'
$said = FirstLine $shim @('--version')
Check ($said.Code -eq 0 -and $said.Line -eq "certdoctor: $Version") "certdoctor through the shim says $Version ($($said.Line))"
$said = FirstLine $shim @()
Check ($said.Code -eq 2) "certdoctor without an address answers 2 through the shim ($($said.Code)), so a script reads the program's own exit code"
# The shim describes itself without starting anything: its target, and GUI
# 'False' - a console shim, which waits for the program.
$help = (& $shim --shimgen-help 2>&1 | ForEach-Object { "$_" } | Out-String)
Check ($help.Contains($cliExe) -and $help -match "GUI: 'False'") 'the shim starts the packaged command line and waits for it'
Check ((Products).Count -eq 0) 'the command line package installs no Windows Installer product'

$r = Run-Choco @('uninstall', 'cert-doctor-cli')
Check ($r.Code -eq 0) 'cert-doctor-cli uninstalls'
Check (-not (Test-Path -LiteralPath $shim)) 'the shim is gone'
Check (-not (Test-Path -LiteralPath (Join-Path $lib 'cert-doctor-cli'))) 'the package folder is gone'

# --- both at once: each leaves the other working
$r = Run-Choco @('install', 'cert-doctor', 'cert-doctor-cli', '--source', $Feed)
Check ($r.Code -eq 0) 'both install side by side'
$r = Run-Choco @('uninstall', 'cert-doctor-cli')
Check ($r.Code -eq 0) 'the command line package uninstalls beside the full one'
$said = FirstLine (Join-Path $installDir 'certdoctor.exe') @('--version')
Check ($said.Line -eq "certdoctor: $Version") "the installed command line still answers ($($said.Line))"
$r = Run-Choco @('install', 'cert-doctor-cli', '--source', $Feed)
$r = Run-Choco @('uninstall', 'cert-doctor')
Check ($r.Code -eq 0) 'the full package uninstalls beside the command line one'
$said = FirstLine $shim @('--version')
Check ($said.Line -eq "certdoctor: $Version") "the shim still answers ($($said.Line))"
$r = Run-Choco @('uninstall', 'cert-doctor-cli')
Check ($r.Code -eq 0 -and (Products).Count -eq 0 -and -not (Test-Path -LiteralPath $installDir) -and -not (Test-Path -LiteralPath $shim)) 'and nothing of either is left'

if ($script:failed -ne 0) {
    Write-Host "$($script:failed) check(s) of the Chocolatey packages failed"
    exit 1
}
Write-Host 'both Chocolatey packages install, answer, and leave nothing of their own behind'
exit 0
