// This file is a fixture with a planted violation. It is under testdata, so the
// module walk never reaches it and no guard is red because of it. It exists so
// the guard below can be seen to FAIL, which is the only way to know it can.
package planted

import "github.com/donislawdev/certdoctor/internal/core/report"

// Fix is a local type with the same name, planted so the scanner can be seen to
// read the NAME rather than the package it came from. A second remediation rule
// written in a package that declares its own type would otherwise walk straight
// past a guard that only recognised report.Fix.
type Fix struct {
	Command string
}

func qualified() *report.Fix {
	// The first shape: the real type, built somewhere that is not the one file
	// allowed to build it.
	return &report.Fix{Command: "keytool -importcert -keystore somewhere"}
}

func unqualified() Fix {
	// The second shape, because a composite literal with a bare type name is a
	// different node and a guard reading only the qualified one would have a
	// hole exactly here.
	return Fix{Command: "curl --cacert somewhere"}
}
