// Package planted is a fixture, never compiled and never part of the build. It
// imports the status vocabulary, which the tools' layer may see, and the proxy
// readings, which one package of that layer may see through its own door.
package planted

import (
	_ "github.com/donislawdev/certdoctor/internal/core/proxy"
	_ "github.com/donislawdev/certdoctor/internal/core/status"
)
