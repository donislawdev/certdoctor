// This file is a fixture, never compiled and never part of the build. It stands
// in for a diagnostic layer that decided to mask its own evidence.
//
// ADR18 says masking runs on the assembly path and nowhere else, because a
// Redaction holds three maps and no lock, and the fan-out this program is
// heading for lives inside a layer. Two branches calling it produce
// "fatal error: concurrent map writes", which recover cannot catch.
package probe

import _ "github.com/donislawdev/certdoctor/internal/core/redact"
