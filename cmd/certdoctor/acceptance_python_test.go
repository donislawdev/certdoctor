//go:build acceptance

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestTheShippedBinaryStartsPythonWithoutPythonPath is ADR112 part 6 asked of
// the program as it ships, the half -I answers. A module named like one the
// probe's script imports, put in a directory PYTHONPATH names, is imported in its
// place - the twin below shows Python doing exactly that here - so the
// interpreter this program starts must not see the variable. Only the running
// binary can answer this: the arguments are the probe's and the runner is
// main's, and a wrong one in either passes every test in the probe's own package.
//
// Skipped where no Python is on PATH, because then there is nothing to start.
func TestTheShippedBinaryStartsPythonWithoutPythonPath(t *testing.T) {
	python := pythonOnPath(t)
	dir := t.TempDir()
	marker := filepath.ToSlash(filepath.Join(dir, "imported"))
	writeMarking(t, filepath.Join(dir, "base64.py"), marker)
	setting := "PYTHONPATH=" + dir

	// THE TWIN: Python imports the planted module when the variable reaches it.
	twin := exec.Command(python, "-c", "import base64")
	twin.Env = append(minimalEnvironment(), setting)
	runTheTwin(t, twin, marker)

	r := startProgram(t, invocation{env: []string{setting}}, aLoopbackTarget(t), "--json")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the planted module ran inside the python process this program started")
	}
	if len(trustRowsIn(t, r.stdout, "python")) == 0 {
		t.Fatalf("no python row in the report, so python was never asked and the marker proves nothing:\n%s", r.stdout)
	}
}

// TestTheShippedBinaryStartsPythonWithoutSite is the half -S answers. A
// sitecustomize module in an interpreter's own site-packages runs inside every
// process of that interpreter - the twin shows it - and the place is one a
// package installer writes to, so the interpreter this program starts must not
// import site at all. A virtual environment in a temporary directory stands in
// for an installation, and putting it first on PATH also asks the probe to tell
// it apart from the interpreter it was made from.
func TestTheShippedBinaryStartsPythonWithoutSite(t *testing.T) {
	python := pythonOnPath(t)
	venv := filepath.Join(t.TempDir(), "venv")
	if out, err := exec.Command(python, "-m", "venv", "--without-pip", venv).CombinedOutput(); err != nil {
		t.Skipf("no virtual environment could be made, so there is no site-packages to plant in: %v\n%s", err, out)
	}
	bin, name := "bin", "python"
	if runtime.GOOS == "windows" {
		bin, name = "Scripts", "python.exe"
	}
	interpreter := filepath.Join(venv, bin, name)
	out, err := exec.Command(interpreter, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])").Output()
	if err != nil {
		t.Fatalf("the environment did not name its site-packages: %v", err)
	}
	marker := filepath.ToSlash(filepath.Join(venv, "customized"))
	writeMarking(t, filepath.Join(strings.TrimSpace(string(out)), "sitecustomize.py"), marker)
	runTheTwin(t, exec.Command(interpreter, "-c", "0"), marker)

	path := "PATH=" + filepath.Join(venv, bin) + string(os.PathListSeparator) + os.Getenv("PATH")
	r := startProgram(t, invocation{env: []string{path}}, aLoopbackTarget(t), "--json")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("sitecustomize ran inside the python process this program started")
	}
	if !slicesContainsFold(pythonInstancesIn(t, r.stdout), interpreter) {
		t.Fatalf("no row for %s, so it was never asked and the marker proves nothing:\n%s", interpreter, r.stdout)
	}
}

// TestTheShippedBinaryAsksPipWhatItReads is ADR112 part 5 asked of the program
// as it ships: the script hands pip's own parser the question, and only a real
// pip answers it - a script that broke on one pip passes every test in the
// probe's package. REQUESTS_CA_BUNDLE has to reach the pip row, and a proxy in
// pip's own configuration has to take it away again from pip 24.2 on, because
// that pip turns trust_env off for a proxy - read in pip's tags on 2026-10-27
// and measured with probe S28: pip 23.0.1 still read the variable. Each row's own
// interpreter is asked which pip it carries, so the test expects what that pip
// does - CI's Ubuntu and macOS ship a pip older than 24.2.
//
// Skipped where the python on PATH has no pip, because then nothing is asked.
func TestTheShippedBinaryAsksPipWhatItReads(t *testing.T) {
	python := pythonOnPath(t)
	if out, err := exec.Command(python, "-I", "-m", "pip", "--version").CombinedOutput(); err != nil {
		t.Skipf("the python on PATH has no pip of its own, so no pip row is asked for: %v\n%s", err, out)
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "company.pem")
	config := filepath.Join(dir, "pip.conf")
	if err := os.WriteFile(bundle, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("[global]\nproxy = http://127.0.0.1:9\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	named := pipRowsIn(t, startProgram(t, invocation{env: []string{"REQUESTS_CA_BUNDLE=" + bundle}}, aLoopbackTarget(t),
		"--json").stdout)
	if len(named) == 0 {
		t.Fatal("no pip row in the report, so pip was never asked")
	}
	for _, row := range named {
		if !slices.Contains(row.SelectedBy, "REQUESTS_CA_BUNDLE") {
			t.Errorf("the pip row of %s does not say REQUESTS_CA_BUNDLE named its file: %v (%s)", row.Instance,
				row.SelectedBy, row.NotAssessed)
		}
	}

	proxied := pipRowsIn(t, startProgram(t, invocation{env: []string{"REQUESTS_CA_BUNDLE=" + bundle,
		"PIP_CONFIG_FILE=" + config}}, aLoopbackTarget(t), "--json").stdout)
	for _, row := range proxied {
		release, known := pipReleaseOf(row.Instance)
		if !known {
			t.Logf("the pip of %s did not say its version, so the proxy is not judged for it", row.Instance)
			continue
		}
		turnsOff := release[0] > 24 || release[0] == 24 && release[1] >= 2
		if read := slices.Contains(row.SelectedBy, "REQUESTS_CA_BUNDLE"); read == turnsOff {
			t.Errorf("the pip row of %s (pip %d.%d) says REQUESTS_CA_BUNDLE is read through a proxy: %v, and that "+
				"pip reads it there: %v", row.Instance, release[0], release[1], read, !turnsOff)
		}
	}
}

// pipReleaseOf is the first two numbers of the pip an interpreter carries, asked
// the way the probe asks it - without site, with site-packages put on the path.
func pipReleaseOf(interpreter string) ([2]int, bool) {
	out, err := exec.Command(interpreter, "-I", "-S", "-c",
		"import site, sys; sys.path.extend(site.getsitepackages()); import pip; print(pip.__version__)").Output()
	if err != nil {
		return [2]int{}, false
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), ".", 3)
	if len(parts) < 2 {
		return [2]int{}, false
	}
	var release [2]int
	for i := range release {
		digits := parts[i]
		if end := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
			digits = digits[:end]
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return [2]int{}, false
		}
		release[i] = n
	}
	return release, true
}

// pipRow is what TestTheShippedBinaryAsksPipWhatItReads reads of a pip row.
type pipRow struct {
	Runtime     string   `json:"runtime"`
	Instance    string   `json:"instance"`
	SelectedBy  []string `json:"selected_by"`
	NotAssessed string   `json:"not_assessed"`
}

// pipRowsIn is every pip row in a report.
func pipRowsIn(t *testing.T, stdout string) []pipRow {
	t.Helper()
	var document struct {
		Layers []struct {
			Findings []struct {
				TrustStore *pipRow `json:"trust_store"`
			} `json:"findings"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	var rows []pipRow
	for _, layer := range document.Layers {
		for _, finding := range layer.Findings {
			if finding.TrustStore != nil && finding.TrustStore.Runtime == "pip" {
				rows = append(rows, *finding.TrustStore)
			}
		}
	}
	return rows
}

// pythonOnPath is the interpreter a person typing python3, or else python, runs.
func pythonOnPath(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if python, err := exec.LookPath(name); err == nil {
			return python
		}
	}
	t.Skip("no python on PATH, so there is no interpreter to keep the code out of")
	return ""
}

// writeMarking writes a module that leaves a marker file when it runs.
func writeMarking(t *testing.T, module, marker string) {
	t.Helper()
	if err := os.WriteFile(module, []byte("open("+strconv.Quote(marker)+", 'w').write('ran')\n"), 0o600); err != nil {
		t.Fatalf("no module: %v", err)
	}
}

// runTheTwin starts Python the ordinary way and requires the marker, so the
// marker staying absent afterwards is this program's doing - and clears it.
func runTheTwin(t *testing.T, twin *exec.Cmd, marker string) {
	t.Helper()
	if out, err := twin.CombinedOutput(); err != nil {
		t.Fatalf("python would not start with the module: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Skipf("python did not run the module either, so this test would prove nothing: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatalf("the marker could not be cleared: %v", err)
	}
}

// pythonInstancesIn is the instance of every python row in a report.
func pythonInstancesIn(t *testing.T, stdout string) []string {
	t.Helper()
	var document struct {
		Layers []struct {
			Findings []struct {
				TrustStore *struct {
					Runtime  string `json:"runtime"`
					Instance string `json:"instance"`
				} `json:"trust_store"`
			} `json:"findings"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	var instances []string
	for _, layer := range document.Layers {
		for _, finding := range layer.Findings {
			if store := finding.TrustStore; store != nil && store.Runtime == "python" {
				instances = append(instances, store.Instance)
			}
		}
	}
	return instances
}

// slicesContainsFold says one of the paths is this one, folding case as Windows
// does.
func slicesContainsFold(paths []string, path string) bool {
	for _, p := range paths {
		if strings.EqualFold(filepath.Clean(p), filepath.Clean(path)) {
			return true
		}
	}
	return false
}
