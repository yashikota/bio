package bio

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// buildClientDataJSON constructs the clientDataJSON bytes (like a browser would).
func buildClientDataJSON(typ, origin string, challenge []byte) ([]byte, error) {
	cd := collectedClientData{
		Type:      typ,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    origin,
	}
	b, err := json.Marshal(cd)
	if err != nil {
		return nil, fmt.Errorf("bio: marshal clientDataJSON: %w", err)
	}
	return b, nil
}

// clientDataHash returns the SHA-256 hash of clientDataJSON.
func clientDataHash(clientDataJSON []byte) []byte {
	h := sha256.Sum256(clientDataJSON)
	return h[:]
}

// rpIDOrigin converts a plain RP ID (e.g. "example.com") to its origin form.
func rpIDOrigin(rpID string) string {
	return "https://" + rpID
}
