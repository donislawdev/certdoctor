package probe

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// goRefuses holds every key the Go library refuses in any chain, whatever pool
// of roots a caller hands it - ADR113. Certificate.Verify drops each chain in
// which some certificate carries one of these keys, and the programs this one
// judges carry no such list, so a refusal it may have caused says nothing about
// them.
//
// SOURCE, inviolable rule 18: distrustedSPKIHashes in src/crypto/x509/verify.go
// of go1.27.3, golang/go commit 7f86f957633e for golang/go#82345, read
// 2026-10-21. Each entry is the SHA-256 of a certificate's SubjectPublicKeyInfo
// in lowercase hexadecimal. TestTheKeysAreTheOnesThisGoRefuses compares this
// copy with the file of the Go running the tests, so an entry a later release
// adds turns a test red instead of a row quietly back into a false refusal.
var goRefuses = map[string]bool{
	"ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105": true,
	"49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f": true,
	"e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41": true,
	"5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0": true,
	"43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b": true,
	"63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8": true,
	"ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6": true,
	"92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30": true,
}

// refusedByGo is what a row says when the Go library may have made its refusal.
const refusedByGo = "the chain or this store holds a certificate whose key the Go library refuses in every chain " +
	"from go1.27.3 on (GO-2026-6809), which the program judged here may not, so whether it accepts this chain " +
	"cannot be told"

// carriesKeyGoRefuses reports whether any of these certificates carries a key
// from goRefuses, hashed the way Go hashes it.
func carriesKeyGoRefuses(certificates []*x509.Certificate) bool {
	for _, c := range certificates {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		if goRefuses[hex.EncodeToString(sum[:])] {
			return true
		}
	}
	return false
}
