package cryptoutil

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMLDSAExternalMu(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			privateKey, err := mldsa.GenerateKey(params)
			require.NoError(t, err)

			for _, size := range []int{0, 32, 4096, 4097, 64 * 1024} {
				message := make([]byte, size)
				_, err := rand.Read(message)
				require.NoError(t, err)

				mu := MLDSAExternalMu(privateKey.PublicKey(), message)
				require.Len(t, mu, crypto.MLDSAMu.Size())

				// Signing over μ must produce a signature that verifies over
				// the full message with pure ML-DSA, which proves μ is
				// computed the same way the standard library computes it.
				signature, err := privateKey.Sign(rand.Reader, mu, crypto.MLDSAMu)
				require.NoError(t, err)
				require.NoError(t, mldsa.Verify(privateKey.PublicKey(), message, signature, nil), "message size %d", size)
			}
		})
	}
}
