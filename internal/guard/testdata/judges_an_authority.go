// This file is a fixture with a planted violation. It is under testdata, so the
// module walk never reaches it and no guard is red because of it. It exists so
// the guard below can be seen to FAIL, which is the only way to know it can.
package planted

import "github.com/donislawdev/certdoctor/internal/core/report"

// SigningAuthority is a local type with the same name, planted so the scanner
// can be seen to read the NAME rather than the package it came from. A second
// place deciding how widely an anchor is held, written in a package that
// declared its own type, would otherwise walk straight past a guard that only
// recognised report.SigningAuthority.
type SigningAuthority struct {
	Issuer string
	HeldBy string
}

func qualified() *report.SigningAuthority {
	// The first shape: the real type, judged somewhere that is not the one file
	// allowed to judge it.
	return &report.SigningAuthority{Issuer: "CN=somebody", HeldBy: report.HeldBySomeStores}
}

func unqualified() SigningAuthority {
	// The second shape, because a composite literal with a bare type name is a
	// different node and a guard reading only the qualified one would have a
	// hole exactly here.
	return SigningAuthority{Issuer: "CN=somebody else", HeldBy: "some_stores"}
}

func names() *report.Inspection {
	// The third shape, added with P6b-K2. Attaching a product name is the step
	// that turns a count into a sentence about somebody's network, so it is the
	// same judgement arriving by a second door - and a scanner that knew only
	// the first type name would let it through while looking busy.
	return &report.Inspection{Product: "somebody's appliance", MatchedAttribute: "CN"}
}
