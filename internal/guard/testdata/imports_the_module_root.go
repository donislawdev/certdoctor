// This file is a fixture, never compiled and never part of the build. It
// imports the module root package from somewhere that is not the entry point.
//
// The import path of that package is the module path itself, with no trailing
// slash, so a check written around the "module path plus slash" prefix would
// mistake it for a third party dependency and wave it through.
package status

import _ "github.com/donislawdev/certdoctor"
