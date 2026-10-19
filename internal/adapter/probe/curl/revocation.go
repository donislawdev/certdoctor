package curl

import "crypto/x509"

// namesRevocation says whether the server's certificate names anywhere to check
// whether it was revoked - a CRL distribution point or an OCSP responder.
//
// THE LEAF ALONE, AND THAT IS MEASURED RATHER THAN CHOSEN. Probe S25,
// 2026-10-20, both curl builds on the owner's machine on Schannel, with the root
// in this account's Root store: a leaf naming no address failed with
// CRYPT_E_NO_REVOCATION_CHECK, while a leaf naming one under an intermediate that
// named none went through, and so did a leaf whose list sat behind a closed
// port. With --cacert curl takes a path of its own that refused all three, which
// is why a configuration file - the one place --cacert hides - stops this row
// before it gets here.
//
// AN OCSP RESPONDER COUNTS AS AN ADDRESS, AND THAT IS A JUDGEMENT. S25 served
// revocation lists only. What it costs if wrong: a leaf naming a responder and no
// list is reported as accepted, and curl refuses it.
//
// WHETHER THE LEAF IS ITS OWN ANCHOR IS NOT ASKED HERE. L4 already decides
// whether a certificate signed itself, and a second copy of that rule is the
// shape OBS50 measured four times - the trust layer reads L4's answer instead.
func namesRevocation(der []byte) (bool, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return false, err
	}
	return len(leaf.CRLDistributionPoints) > 0 || len(leaf.OCSPServer) > 0, nil
}
