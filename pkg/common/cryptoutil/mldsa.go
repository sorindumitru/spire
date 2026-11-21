package cryptoutil

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha3"
)

// MLDSAExternalMu computes the ML-DSA message representative μ for a pure
// ML-DSA signature over message with an empty context, as defined in FIPS 204
// Algorithm 7 and RFC 9881 ("external μ"):
//
//	tr = SHAKE256(pk, 64)
//	μ  = SHAKE256(tr || IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M, 64)
//
// A signature produced over μ (for example, by crypto/mldsa with
// crypto.MLDSAMu, or a KMS "external mu" signing operation) verifies as a pure
// ML-DSA signature over message.
func MLDSAExternalMu(publicKey *mldsa.PublicKey, message []byte) []byte {
	tr := sha3.SumSHAKE256(publicKey.Bytes(), 64)

	h := sha3.NewSHAKE256()
	_, _ = h.Write(tr)
	// Pure ML-DSA domain separator, followed by the length of the (empty) context.
	_, _ = h.Write([]byte{0x00, 0x00})
	_, _ = h.Write(message)
	mu := make([]byte, crypto.MLDSAMu.Size())
	_, _ = h.Read(mu)
	return mu
}
