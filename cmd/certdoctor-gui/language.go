//go:build cgo

package main

import (
	"encoding/json"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/lang"

	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// toolkitLanguages are the languages fyne v2.8.2 carries words of its own in,
// English apart - its files lang/translations/base.<language>.json, read in
// the module on 2026-11-10. language_test.go holds this list to the module
// the build links, so a toolkit that brings a new language stops the tests
// instead of speaking it in the window.
var toolkitLanguages = []fyne.Locale{
	"cs", "de", "el", "es", "fr", "ja", "pl", "pt", "pt-BR", "ru", "sv", "ta", "uk", "zh-Hans",
}

// speakEnglish gives the toolkit the window's English for its own words under
// every language it carries words in (OBS206). Called before the first window,
// so no word of the toolkit has been asked for yet.
//
// The toolkit picks the language of its words itself, from the languages the
// system lists, and v2.8.2 offers no call to choose one. Words given under a
// language replace the toolkit's own for that language, so with English under
// every one of them, whichever it picks says English.
//
// EVERY LANGUAGE AND NOT ONLY THE SYSTEM'S, which is what TestingFilesGenerator
// gives, measured there on a Polish Windows. On Windows the language the
// toolkit calls the system's and the list it picks from come from one call.
// On macOS they do not: lang.SystemLocale reads AppleLocale, the region
// format, and the list is AppleLanguages, the languages of the menus -
// measured 2026-11-10 on the Mac beside this machine as "en_US@rg=plzzzz"
// against (en-US, pl-PL). A Mac with Polish menus and an English region format
// would be given English under en-US and pick Polish.
//
// The price: each language given makes the toolkit ask the system for its
// languages again, which on macOS, for a program with no translations of its
// own, is a "defaults read" process each time - fifteen of them took 77 ms on
// that Mac, so the start pays about seventy milliseconds there, once.
func speakEnglish() error {
	data, err := json.Marshal(words.Toolkit())
	if err != nil {
		return err
	}
	for _, l := range toolkitLanguages {
		if err := lang.AddTranslationsForLocale(data, l); err != nil {
			return fmt.Errorf("%s: %w", l, err)
		}
	}
	return nil
}
