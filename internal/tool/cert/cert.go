// Package cert is the certificate decoder (ADR146): it shows what a
// certificate or a chain says and judges what can be judged from the
// certificates alone - their dates, their signatures and keys, the names a
// client matches, and whether the chain is complete and in order.
//
// IT CONNECTS TO NOTHING AND TRUSTS NOTHING. Whether this machine trusts the
// chain is the diagnosis's question, asked of each trust store in L5; here a
// signature is checked only to say which certificate issued which, by the
// rules L4 uses for a server's chain (internal/tool/certfacts). The addresses a
// certificate names - where its issuer, its OCSP responder and its CRL are -
// are shown and never opened (inviolable rule 16).
//
// THE INPUT IS HOSTILE. It comes from a ticket, a file or somebody else's
// server, so a refusal names what it found by kind and position, never by
// content, and a private key that came along is not read and not shown.
package cert

import (
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// Data is what the decoder found, for a script to read.
type Data struct {
	// Form is how the input was read: pem, base64 (one certificate), der
	// (one certificate) or x5c (a JSON array of base64 certificates).
	Form string `json:"form"`
	// Certificates are the certificates the library read, in input order.
	Certificates []Certificate `json:"certificates"`
	// Unreadable are the certificates it could not read.
	Unreadable []Unreadable `json:"unreadable"`
	Chain      Chain        `json:"chain"`
	// Skipped are the PEM blocks that are not certificates, private keys
	// among them.
	Skipped []Skipped `json:"skipped"`
}

// Unreadable is a certificate the library refused, with its words.
type Unreadable struct {
	Number int    `json:"number"`
	Reason string `json:"reason"`
}

// Skipped is a PEM block that was not read, by its number among the blocks
// and its type.
type Skipped struct {
	Block int    `json:"block"`
	Type  string `json:"type"`
}

// Decode reads raw as certificates and judges them at now. A refusal is a
// *spec.Refusal and means raw holds no certificate this can read.
func Decode(raw []byte, now time.Time) (spec.Outcome, error) {
	in, err := read(raw)
	if err != nil {
		return spec.Outcome{}, err
	}
	var readable []entry
	for _, e := range in.entries {
		if e.cert != nil {
			readable = append(readable, e)
		}
	}
	if len(readable) == 0 {
		return spec.Outcome{}, noneReadable(in.entries)
	}
	j := judged{in: in, read: readable, now: now, chain: chainOf(readable)}
	return spec.Outcome{Notes: in.notes, Checks: spec.SortChecks(j.checks(), checkOrder), Data: j.data(), View: j.view()}, nil
}

// noneReadable is the refusal for an input whose every certificate the
// library refused - in its words, which describe the certificate's shape.
func noneReadable(entries []entry) error {
	first := entries[0]
	if len(entries) == 1 {
		return refuse(fmt.Sprintf("The input holds a certificate this program's X.509 library cannot read: %s.",
			libraryWords(first.err)))
	}
	return refuse(fmt.Sprintf("The input holds %d certificates and this program's X.509 library can read none "+
		"of them - the first: %s.", len(entries), libraryWords(first.err)))
}

// data is what was found, for a script.
func (j judged) data() Data {
	d := Data{Form: j.in.form, Certificates: []Certificate{}, Unreadable: []Unreadable{}, Chain: j.chain.Chain,
		Skipped: append([]Skipped{}, j.in.skipped...)}
	for _, e := range j.in.entries {
		if e.cert == nil {
			d.Unreadable = append(d.Unreadable, Unreadable{Number: e.number, Reason: libraryWords(e.err)})
		} else {
			d.Certificates = append(d.Certificates, describe(e))
		}
	}
	return d
}

// checkOrder is the order checks of one status are listed in: the
// certificates one by one, then the chain, then the input as a whole.
var checkOrder = []string{
	"validity", "signature", "key_size", "subject_alt_name", "chain", "chain_order", "chain_unrelated",
	"duplicates", "private_key", "unreadable",
}
