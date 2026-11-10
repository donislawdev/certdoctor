//go:build cgo

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"fyne.io/fyne/v2/lang"

	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// carriedWords reads the toolkit's own word files out of the module this
// build links: the language as the file names it, then identifier to text, a
// plural form read as its "other" - the form the toolkit asks for, since it
// gives no count.
func carriedWords(t *testing.T) map[string]map[string]string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-json", "fyne.io/fyne/v2").Output()
	if err != nil {
		t.Fatalf("go list -m fyne.io/fyne/v2: %v", err)
	}
	var m struct{ Dir string }
	if err := json.Unmarshal(out, &m); err != nil || m.Dir == "" {
		t.Fatalf("go list named no directory for the toolkit (%v)", err)
	}
	dir := filepath.Join(m.Dir, "lang", "translations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the toolkit's words: %v", err)
	}
	carried := map[string]map[string]string{}
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.Name(), "base.")
		if !ok {
			continue
		}
		language, ok := strings.CutSuffix(name, ".json")
		if !ok {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatalf("%s is not the shape this test reads: %v", e.Name(), err)
		}
		texts := map[string]string{}
		for id, value := range raw {
			var text string
			if json.Unmarshal(value, &text) != nil {
				var forms struct{ Other string }
				if err := json.Unmarshal(value, &forms); err != nil || forms.Other == "" {
					t.Fatalf("%s: %s is neither a text nor a plural with an other form", e.Name(), id)
				}
				text = forms.Other
			}
			texts[id] = text
		}
		carried[language] = texts
	}
	if len(carried) == 0 {
		t.Fatalf("%s holds no word files - the toolkit moved them, and this test has nothing to compare", dir)
	}
	return carried
}

// TestTheToolkitLanguagesAreTheOnesItCarries holds the window's two lists to
// the module the build links: the languages English is given under, and the
// English given. A toolkit that brings a language the list lacks would speak
// it in the window, and a word it adds would stay in the system's language -
// both are an upgrade of the toolkit nobody reads the word files of.
func TestTheToolkitLanguagesAreTheOnesItCarries(t *testing.T) {
	carried := carriedWords(t)

	var want []string
	for language := range carried {
		if language != "en" {
			want = append(want, strings.ReplaceAll(language, "_", "-"))
		}
	}
	var given []string
	for _, l := range toolkitLanguages {
		given = append(given, string(l))
	}
	sort.Strings(want)
	sort.Strings(given)
	if strings.Join(given, " ") != strings.Join(want, " ") {
		t.Errorf("English is given under %v, and the toolkit carries words in %v", given, want)
	}

	ours := words.Toolkit()
	for id, text := range carried["en"] {
		if ours[id] != text {
			t.Errorf("the toolkit's English for %q is %q, and the window gives %q", id, text, ours[id])
		}
	}
	for id := range ours {
		if _, ok := carried["en"][id]; !ok {
			t.Errorf("the window gives English for %q, which the toolkit's English does not have", id)
		}
	}
	for language, texts := range carried {
		for id := range texts {
			if _, ok := ours[id]; !ok {
				t.Errorf("the toolkit says %q in %s, and the window gives no English for it", id, language)
			}
		}
	}
}

// TestTheToolkitSpeaksEnglishWhateverTheSystemSpeaks is OBS206 measured
// rather than read: after speakEnglish the menu of a box to type in, the
// dialog that names a new folder and the names of the days are English - on
// this system, whatever it is set to, and on Linux under every language the
// toolkit carries, which there it takes from the environment. A Polish
// Windows, where this was found, answers Wytnij for Cut without it.
func TestTheToolkitSpeaksEnglishWhateverTheSystemSpeaks(t *testing.T) {
	speaks := func(system string) {
		t.Helper()
		if err := speakEnglish(); err != nil {
			t.Fatalf("%s: giving the toolkit its words: %v", system, err)
		}
		for _, id := range []string{"Cut", "Copy", "Paste", "Select all", "New Folder", "Create Folder"} {
			if got := lang.L(id); got != id {
				t.Errorf("%s: the toolkit says %q for %q", system, got, id)
			}
		}
		for id, english := range map[string]string{"file.name": "Name", "monday": "Monday"} {
			if got := lang.X(id, english); got != english {
				t.Errorf("%s: the toolkit says %q for %q", system, got, english)
			}
		}
	}
	speaks("this system, " + string(lang.SystemLocale()))

	// Only on Linux do the languages come from the environment - Windows and
	// macOS ask the system - so only there can every one be tried.
	if runtime.GOOS != "linux" {
		return
	}
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")
	for _, l := range toolkitLanguages {
		t.Setenv("LANGUAGE", strings.ReplaceAll(string(l), "-", "_"))
		speaks("LANGUAGE=" + os.Getenv("LANGUAGE"))
	}
	// The shape of the Mac: the language the toolkit calls the system's is
	// not the one it picks. Here the first entry is one lang.SystemLocale
	// turns into English, and the toolkit picks Polish from the second - so
	// English given under the system's language alone would leave Wytnij.
	t.Setenv("LANGUAGE", "C:pl")
	speaks("LANGUAGE=C:pl, a system language that is not the one picked")
}
