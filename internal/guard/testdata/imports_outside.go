// This file is a fixture, never compiled and never part of the build. It exists
// so the external dependency guard can be proved to fail rather than assumed to
// work.
package probe

import (
	"strings"

	"github.com/dop251/goja"
	"golang.org/x/text/language"
)

func borrow(source string) string {
	_ = goja.New()
	_ = language.English
	return strings.TrimSpace(source)
}
