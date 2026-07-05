//go:build darwin

package darwin

import (
	"crypto/sha256"
	"encoding/binary"
)

// Flags for authenticator data (FIDO2 spec §6.1).
const (
	FlagUP = 1 << 0 // User Present
	FlagUV = 1 << 2 // User Verified
	FlagAT = 1 << 6 // Attested credential data included
)

// BuildAuthenticatorData builds the authenticator data structure for MakeCredential.
//
// rpID: relying party ID string
// flags: combination of FlagUP, FlagUV, FlagAT
// signCount: always 0 for Secure Enclave (hardware manages it)
// aaguid: 16 zero bytes (no AAGUID for self-attestation)
// credentialID: the credential ID bytes
// cosePublicKey: COSE-encoded EC P-256 public key
func BuildAuthenticatorData(rpID string, flags byte, signCount uint32, aaguid [16]byte, credentialID []byte, cosePublicKey []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))

	var out []byte
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)

	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	out = append(out, sc[:]...)

	// Attested credential data
	out = append(out, aaguid[:]...)
	var credIDLen [2]byte
	binary.BigEndian.PutUint16(credIDLen[:], uint16(len(credentialID)))
	out = append(out, credIDLen[:]...)
	out = append(out, credentialID...)
	out = append(out, cosePublicKey...)

	return out
}

// BuildGetAssertionAuthData builds authenticator data for GetAssertion (no attested credential data).
func BuildGetAssertionAuthData(rpID string, flags byte, signCount uint32) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	var out []byte
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	out = append(out, sc[:]...)
	return out
}
