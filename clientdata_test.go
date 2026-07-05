package bio

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestBuildClientDataJSON(t *testing.T) {
	challenge := []byte("test-challenge-bytes")
	got, err := buildClientDataJSON("webauthn.create", "https://example.com", challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(got, &cd); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if cd.Type != "webauthn.create" {
		t.Errorf("type = %q, want %q", cd.Type, "webauthn.create")
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	if cd.Challenge != wantChallenge {
		t.Errorf("challenge = %q, want %q", cd.Challenge, wantChallenge)
	}
	if cd.Origin != "https://example.com" {
		t.Errorf("origin = %q, want %q", cd.Origin, "https://example.com")
	}
	if cd.CrossOrigin {
		t.Error("crossOrigin should be false for platform authenticator")
	}
}

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

func TestRPIDOrigin(t *testing.T) {
	tests := []struct {
		rpID string
		want string
	}{
		{"example.com", "https://example.com"},
		{"sub.example.com", "https://sub.example.com"},
		{"localhost", "https://localhost"},
	}
	for _, tt := range tests {
		got := rpIDOrigin(tt.rpID)
		if got != tt.want {
			t.Errorf("rpIDOrigin(%q) = %q, want %q", tt.rpID, got, tt.want)
		}
	}
}
