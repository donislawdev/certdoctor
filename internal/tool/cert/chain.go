package cert

import (
	"fmt"
	"slices"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
	"github.com/donislawdev/certdoctor/internal/tool/prose"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// The ends of a chain, as Chain.End names them.
const (
	endSelfSigned = "self_signed"
	endNoIssuer   = "issuer_not_given"
)

// Chain is the chain the input holds, by certificate numbers.
type Chain struct {
	// Path starts at the first certificate read and follows each one to the
	// certificate of the input that issued it.
	Path []int `json:"path"`
	// InOrder says the path is the input's own order, with nothing between.
	InOrder bool `json:"in_order"`
	// End is self_signed when the path ends at a certificate that issued
	// itself, issuer_not_given when the last one's issuer is not in the input.
	End string `json:"end"`
	// Outside are the certificates read that are not on the path and not a
	// copy of one that is.
	Outside []int `json:"outside"`
	// Duplicates are the groups of certificates that are the same one.
	Duplicates [][]int `json:"duplicates"`
}

// chained is the chain worked out, with what the checks need beside it.
type chained struct {
	Chain
	certs []entry
	// bundle says the first certificate is an authority, so the input is read
	// as a set of authorities and what stands outside the path is not judged.
	bundle bool
	// leafLater is the first certificate that is not an authority, when the
	// first one is - zero when there is none.
	leafLater int
}

// chainOf works out the chain of the certificates read, in input order.
func chainOf(read []entry) chained {
	ch := chained{Chain: Chain{Outside: []int{}, Duplicates: [][]int{}}, certs: read}
	distinct := ch.dropDuplicates(read)
	current := distinct[0]
	ch.Path = []int{current.number}
	used := map[int]bool{current.number: true}
	for ch.End == "" {
		if certfacts.SelfSigned(current.cert) {
			ch.End = endSelfSigned
			break
		}
		next, ok := issuerAmong(current, distinct, used)
		if !ok {
			ch.End = endNoIssuer
			break
		}
		ch.Path, used[next.number], current = append(ch.Path, next.number), true, next
	}
	ch.InOrder = true
	for i, number := range ch.Path {
		ch.InOrder = ch.InOrder && distinct[i].number == number
	}
	for _, e := range distinct {
		if !used[e.number] {
			ch.Outside = append(ch.Outside, e.number)
		}
	}
	ch.bundle = distinct[0].cert.IsCA
	for _, e := range distinct {
		if ch.bundle && ch.leafLater == 0 && !e.cert.IsCA {
			ch.leafLater = e.number
		}
	}
	return ch
}

// dropDuplicates is read without the certificates that repeat an earlier one,
// and records each group.
func (ch *chained) dropDuplicates(read []entry) []entry {
	var distinct []entry
	groups := map[string][]int{}
	var order []string
	for _, e := range read {
		fp := certfacts.FingerprintSHA256(e.der)
		if _, seen := groups[fp]; !seen {
			distinct, order = append(distinct, e), append(order, fp)
		}
		groups[fp] = append(groups[fp], e.number)
	}
	for _, fp := range order {
		if len(groups[fp]) > 1 {
			ch.Duplicates = append(ch.Duplicates, groups[fp])
		}
	}
	return distinct
}

// issuerAmong is the first certificate of the input, not on the path yet,
// that issued child.
func issuerAmong(child entry, among []entry, used map[int]bool) (entry, bool) {
	for _, e := range among {
		if !used[e.number] && certfacts.IssuedBy(child.cert, e.cert) {
			return e, true
		}
	}
	return entry{}, false
}

// byNumber is the certificate numbered n.
func (ch chained) byNumber(n int) entry {
	for _, e := range ch.certs {
		if e.number == n {
			return e
		}
	}
	return entry{}
}

// chainCheck says where the chain goes and where it ends (RFC 8446 section
// 4.4.2 and RFC 5246 section 7.4.2: the root may be left out).
func (ch chained) chainCheck() spec.Check {
	first, last := ch.byNumber(ch.Path[0]), ch.byNumber(ch.Path[len(ch.Path)-1])
	route := ch.route()
	switch {
	case ch.End == endSelfSigned && len(ch.Path) == 1 && len(ch.certs) == 1:
		return spec.Check{ID: "chain", Status: status.Pass, Summary: "It issued itself (self-signed), so a client " +
			"trusts it only where it was added to a trust store."}
	case ch.End == endSelfSigned && len(ch.Path) == 1:
		return spec.Check{ID: "chain", Status: status.Pass, Summary: fmt.Sprintf("%s issued itself, and "+
			"the rest is read as a set of authorities, not as its chain.", upper(label(first)))}
	case ch.End == endSelfSigned:
		return spec.Check{ID: "chain", Status: status.Pass, Summary: fmt.Sprintf("%s, which issued itself - "+
			"the chain is complete here. A server may leave that root out (RFC 8446 section 4.4.2).", route)}
	case len(ch.Path) == 1 && !first.cert.IsCA:
		return spec.Check{ID: "chain", Status: status.Warn, Summary: fmt.Sprintf("The issuer of %s, %s, is "+
			"not in the input. A server that sends only this certificate leaves each client to have the issuer "+
			"already, and a client without it cannot build the chain.", label(first), certfacts.Name(first.cert.Issuer))}
	default:
		return spec.Check{ID: "chain", Status: status.Pass, Summary: fmt.Sprintf("%s. The issuer of %s, %s, "+
			"is not in the input: if it is a root, that is as it should be - a server may leave the root out "+
			"(RFC 8446 section 4.4.2) - and if it is not, a client without it cannot build the chain.",
			route, label(last), certfacts.Name(last.cert.Issuer))}
	}
}

// route says the path in words: "Certificate 1 is issued by 2, and 2 by 3".
func (ch chained) route() string {
	if len(ch.Path) == 1 {
		return fmt.Sprintf("Certificate %d stands alone", ch.Path[0])
	}
	steps := []string{fmt.Sprintf("Certificate %d is issued by %d", ch.Path[0], ch.Path[1])}
	for i := 1; i+1 < len(ch.Path); i++ {
		steps = append(steps, fmt.Sprintf("%d by %d", ch.Path[i], ch.Path[i+1]))
	}
	if len(steps) == 1 {
		return steps[0]
	}
	return strings.Join(steps[:len(steps)-1], ", ") + " and " + steps[len(steps)-1]
}

// orderCheck judges the order of a chain of two or more certificates: the
// sender's own certificate first, each followed by its issuer (RFC 5246
// section 7.4.2 requires it, RFC 8446 section 4.4.2 recommends it and asks
// every client to cope with any order after the first).
func (ch chained) orderCheck() (spec.Check, bool) {
	switch {
	case ch.leafLater != 0:
		return spec.Check{ID: "chain_order", Status: status.Warn, Summary: fmt.Sprintf("%s is not an "+
			"authority, so it is somebody's own certificate, and it is not first - the sender's own certificate "+
			"must come first (RFC 8446 section 4.4.2).", upper(label(ch.byNumber(ch.leafLater))))}, true
	case ch.bundle || len(ch.Path) < 2:
		return spec.Check{}, false
	case !ch.InOrder:
		return spec.Check{ID: "chain_order", Status: status.Warn, Summary: fmt.Sprintf("The chain runs %s, "+
			"which is not the order of the input. TLS 1.2 requires each certificate to be followed by the one "+
			"that issued it (RFC 5246 section 7.4.2), and TLS 1.3 recommends it (RFC 8446 section 4.4.2).",
			numbers(ch.Path))}, true
	default:
		return spec.Check{ID: "chain_order", Status: status.Pass,
			Summary: "In order: each certificate is followed by the one that issued it."}, true
	}
}

// unrelatedCheck names the certificates outside the chain, unless the input
// is a set of authorities.
func (ch chained) unrelatedCheck() (spec.Check, bool) {
	if ch.bundle || len(ch.Outside) == 0 {
		return spec.Check{}, false
	}
	return spec.Check{ID: "chain_unrelated", Status: status.Warn, Summary: fmt.Sprintf("%s %s not part of "+
		"the chain that starts with certificate %d. A client should ignore %s (RFC 8446 section 4.4.2), so a "+
		"server sending %s sends bytes nobody uses.", upper(certificates(ch.Outside)),
		pluralWord(len(ch.Outside), "is", "are"), ch.Path[0], pluralWord(len(ch.Outside), "it", "them"),
		pluralWord(len(ch.Outside), "it", "them"))}, true
}

// duplicateCheck names the certificates given more than once.
func (ch chained) duplicateCheck() (spec.Check, bool) {
	if len(ch.Duplicates) == 0 {
		return spec.Check{}, false
	}
	var groups []string
	for _, g := range ch.Duplicates {
		groups = append(groups, certificates(g))
	}
	return spec.Check{ID: "duplicates", Status: status.Warn, Summary: fmt.Sprintf("The same certificate "+
		"more than once: %s - each group has one SHA-256.", strings.Join(groups, "; "))}, true
}

// numbers writes certificate numbers as "1, 3 and 2".
func numbers(ns []int) string {
	var words []string
	for _, n := range ns {
		words = append(words, fmt.Sprint(n))
	}
	return prose.List(words)
}

// certificates writes "certificate 4" or "certificates 2 and 4".
func certificates(ns []int) string {
	return pluralWord(len(ns), "certificate ", "certificates ") + numbers(slices.Clone(ns))
}
