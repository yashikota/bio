package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Client data types (WebAuthn §5.8.1).
const (
	TypeCreate = "webauthn.create"
	TypeGet    = "webauthn.get"
)

// ErrClientData is returned when clientDataJSON does not match the request.
var ErrClientData = errors.New("webauthn: invalid client data")

// CheckClientData verifies that clientDataJSON is a JSON object whose "type"
// is wantType and whose "challenge" is the base64url encoding of challenge.
// The origin is not checked: only the relying party knows which origins are valid.
func CheckClientData(clientDataJSON []byte, wantType string, challenge []byte) error {
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return fmt.Errorf("%w: %w", ErrClientData, err)
	}
	if cd.Type != wantType {
		return fmt.Errorf("%w: type %q, want %q", ErrClientData, cd.Type, wantType)
	}
	if cd.Origin == "" {
		return fmt.Errorf("%w: missing origin", ErrClientData)
	}
	got, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(cd.Challenge, "="))
	if err != nil {
		return fmt.Errorf("%w: challenge is not base64url: %w", ErrClientData, err)
	}
	if !bytes.Equal(got, challenge) {
		return fmt.Errorf("%w: challenge does not match", ErrClientData)
	}
	return nil
}
