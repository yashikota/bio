// Package webauthntest verifies authenticator output the way a real relying
// party would, using github.com/go-webauthn/webauthn as an independent oracle.
// It is only imported by tests.
package webauthntest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// RP is a relying party used by tests.
type RP struct {
	ID     string
	Origin string
}

// Default is the relying party used throughout the tests.
var Default = RP{ID: "example.com", Origin: "https://example.com"}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ClientData builds clientDataJSON as a browser would.
func (rp RP) ClientData(typ string, challenge []byte) []byte {
	b, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   b64(challenge),
		"origin":      rp.Origin,
		"crossOrigin": false,
	})
	if err != nil {
		panic(err)
	}
	return b
}

// VerifyRegistration runs the WebAuthn §7.1 registration ceremony checks and
// returns the credential's COSE public key.
func (rp RP) VerifyRegistration(challenge, credID, attestationObject, clientDataJSON []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"id":    b64(credID),
		"rawId": b64(credID),
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": b64(attestationObject),
			"clientDataJSON":    b64(clientDataJSON),
		},
	})
	if err != nil {
		return nil, err
	}
	pcc, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("parse registration: %w", err)
	}
	params := []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}
	if _, err := pcc.Verify(b64(challenge), rp.ID, []string{rp.Origin}, nil, nil,
		protocol.TopOriginDefaultVerificationMode, false, true, true, nil, params,
		protocol.AttestationPolicy{}, protocol.SignaturePolicy{}); err != nil {
		return nil, fmt.Errorf("verify registration: %w", describe(err))
	}
	return pcc.Response.AttestationObject.AuthData.AttData.CredentialPublicKey, nil
}

// VerifyAssertion runs the WebAuthn §7.2 authentication ceremony checks
// against a public key returned by VerifyRegistration, and returns the
// signature counter.
func (rp RP) VerifyAssertion(challenge, credID, authenticatorData, signature, userHandle, clientDataJSON, publicKey []byte) (uint32, error) {
	resp := map[string]any{
		"authenticatorData": b64(authenticatorData),
		"clientDataJSON":    b64(clientDataJSON),
		"signature":         b64(signature),
	}
	if len(userHandle) > 0 {
		resp["userHandle"] = b64(userHandle)
	}
	body, err := json.Marshal(map[string]any{
		"id":       b64(credID),
		"rawId":    b64(credID),
		"type":     "public-key",
		"response": resp,
	})
	if err != nil {
		return 0, err
	}
	par, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return 0, fmt.Errorf("parse assertion: %w", describe(err))
	}
	if err := par.Verify(b64(challenge), rp.ID, "", []string{rp.Origin}, nil, nil,
		protocol.TopOriginDefaultVerificationMode, false, true, true, publicKey, protocol.SignaturePolicy{}); err != nil {
		return 0, fmt.Errorf("verify assertion: %w", describe(err))
	}
	return par.Response.AuthenticatorData.Counter, nil
}

// describe adds go-webauthn's DevInfo, which holds the actual reason.
func describe(err error) error {
	pe := &protocol.Error{}
	if errors.As(err, &pe) {
		return fmt.Errorf("%w (%s)", err, pe.DevInfo)
	}
	return err
}
