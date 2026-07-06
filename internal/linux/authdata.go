//go:build linux

package linux

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	FlagUP = 1 << 0
	FlagUV = 1 << 2
	FlagAT = 1 << 6
)

func BuildAuthenticatorData(rpID string, flags byte, signCount uint32, aaguid [16]byte, credentialID []byte, cosePublicKey []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	var out []byte
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	out = append(out, sc[:]...)
	out = append(out, aaguid[:]...)
	var credIDLen [2]byte
	binary.BigEndian.PutUint16(credIDLen[:], uint16(len(credentialID)))
	out = append(out, credIDLen[:]...)
	out = append(out, credentialID...)
	out = append(out, cosePublicKey...)
	return out
}

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

// EncodeCOSEES256 encodes an uncompressed EC P-256 public key point into COSE ES256 format.
// rawKey must be the 65-byte uncompressed point (0x04 || x || y).
func EncodeCOSEES256(rawKey []byte) []byte {
	x := rawKey[1:33]
	y := rawKey[33:65]
	return EncodeMap(
		EncodeUint(1), EncodeUint(2), // kty: EC2
		EncodeUint(3), EncodeNegInt(6), // alg: ES256 (-7 = negint(6))
		EncodeNegInt(0), EncodeUint(1), // crv: P-256 (1)
		EncodeNegInt(1), EncodeBytes(x), // x
		EncodeNegInt(2), EncodeBytes(y), // y
	)
}
