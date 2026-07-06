package bio

import "crypto/sha256"

// clientDataHash returns the SHA-256 hash of clientDataJSON.
func clientDataHash(clientDataJSON []byte) []byte {
	h := sha256.Sum256(clientDataJSON)
	return h[:]
}
