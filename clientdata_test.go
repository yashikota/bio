package bio

import (
	"crypto/sha256"
	"testing"
)

func TestClientDataHash(t *testing.T) {
	data := []byte(`{"type":"webauthn.get","challenge":"abc","origin":"https://example.com","crossOrigin":false}`)
	got := clientDataHash(data)
	want := sha256.Sum256(data)
	if len(got) != 32 {
		t.Errorf("hash length = %d, want 32", len(got))
	}
	for i, b := range want {
		if got[i] != b {
			t.Errorf("hash mismatch at byte %d", i)
			break
		}
	}
}
