package webauthn

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Authenticator data flags (WebAuthn §6.1).
const (
	FlagUP = 1 << 0 // User Present
	FlagUV = 1 << 2 // User Verified
	FlagAT = 1 << 6 // Attested credential data included
	FlagED = 1 << 7 // Extension data included
)

// AuthDataMinLen is the length of authenticator data without attested credential data.
const AuthDataMinLen = 32 + 1 + 4

// COSE algorithm identifiers used here.
const (
	COSEAlgES256 = -7
)

// ErrMalformedAuthData is returned when authenticator data cannot be parsed.
var ErrMalformedAuthData = errors.New("webauthn: malformed authenticator data")

// BuildAuthenticatorData builds authenticator data that includes attested
// credential data, as returned by MakeCredential.
func BuildAuthenticatorData(rpID string, flags byte, signCount uint32, aaguid [16]byte, credentialID, cosePublicKey []byte) ([]byte, error) {
	if len(credentialID) > math.MaxUint16 {
		return nil, fmt.Errorf("webauthn: credential ID too long (%d bytes)", len(credentialID))
	}
	out := BuildAssertionAuthData(rpID, flags|FlagAT, signCount)
	out = append(out, aaguid[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(credentialID)))
	out = append(out, credentialID...)
	out = append(out, cosePublicKey...)
	return out, nil
}

// BuildAssertionAuthData builds authenticator data without attested
// credential data, as returned by GetAssertion.
func BuildAssertionAuthData(rpID string, flags byte, signCount uint32) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, AuthDataMinLen)
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, signCount)
	return out
}

// AuthData is parsed authenticator data.
type AuthData struct {
	RPIDHash     [32]byte
	Flags        byte
	SignCount    uint32
	AAGUID       [16]byte
	CredentialID []byte
	PublicKey    []byte // COSE-encoded, only when FlagAT is set
}

// ParseAuthData parses authenticator data. Extension data, if present, is ignored.
func ParseAuthData(b []byte) (*AuthData, error) {
	if len(b) < AuthDataMinLen {
		return nil, ErrMalformedAuthData
	}
	ad := &AuthData{Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	copy(ad.RPIDHash[:], b[:32])
	if ad.Flags&FlagAT == 0 {
		return ad, nil
	}
	rest := b[AuthDataMinLen:]
	if len(rest) < 18 {
		return nil, ErrMalformedAuthData
	}
	copy(ad.AAGUID[:], rest[:16])
	idLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if len(rest) < idLen {
		return nil, ErrMalformedAuthData
	}
	ad.CredentialID = append([]byte(nil), rest[:idLen]...)
	rest = rest[idLen:]
	keyLen, err := itemLength(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: public key: %w", ErrMalformedAuthData, err)
	}
	ad.PublicKey = append([]byte(nil), rest[:keyLen]...)
	return ad, nil
}

// PublicKeyFromAuthData extracts the COSE public key from authenticator data
// that contains attested credential data.
func PublicKeyFromAuthData(b []byte) ([]byte, error) {
	ad, err := ParseAuthData(b)
	if err != nil {
		return nil, err
	}
	if ad.PublicKey == nil {
		return nil, fmt.Errorf("%w: no attested credential data", ErrMalformedAuthData)
	}
	return ad.PublicKey, nil
}

// EncodeAttestationObjectNone builds a "none" attestation object (WebAuthn §8.7).
func EncodeAttestationObjectNone(authData []byte) []byte {
	return EncodeMap(
		EncodeText("fmt"), EncodeText("none"),
		EncodeText("attStmt"), EncodeMap(),
		EncodeText("authData"), EncodeBytes(authData),
	)
}

// SignedData returns authData || SHA-256(clientDataJSON), the message an
// assertion signature covers (WebAuthn §6.3.3). It never aliases authData.
func SignedData(authData, clientDataJSON []byte) []byte {
	h := sha256.Sum256(clientDataJSON)
	out := make([]byte, 0, len(authData)+len(h))
	out = append(out, authData...)
	return append(out, h[:]...)
}
