package webauthn

import (
	"crypto/ecdh"
	"fmt"
)

// p256CoordLen is the byte length of a P-256 field element.
const p256CoordLen = 32

// UncompressedP256 builds the 65-byte uncompressed point 0x04 || X || Y.
// Coordinates shorter than 32 bytes (some TPMs strip leading zeros) are
// left-padded. The result is checked to be a valid point on P-256.
func UncompressedP256(x, y []byte) ([]byte, error) {
	if len(x) > p256CoordLen || len(y) > p256CoordLen {
		return nil, fmt.Errorf("webauthn: P-256 coordinate too long (x=%d y=%d)", len(x), len(y))
	}
	raw := make([]byte, 1+2*p256CoordLen)
	raw[0] = 0x04
	copy(raw[1+p256CoordLen-len(x):1+p256CoordLen], x)
	copy(raw[1+2*p256CoordLen-len(y):], y)
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, fmt.Errorf("webauthn: invalid P-256 point: %w", err)
	}
	return raw, nil
}

// EncodeCOSEES256 encodes an uncompressed P-256 point (0x04 || X || Y) as a
// COSE_Key for ES256 (RFC 9053 §7.1.1).
func EncodeCOSEES256(raw []byte) ([]byte, error) {
	if len(raw) != 1+2*p256CoordLen || raw[0] != 0x04 {
		return nil, fmt.Errorf("webauthn: unexpected public key format (len=%d)", len(raw))
	}
	x := raw[1 : 1+p256CoordLen]
	y := raw[1+p256CoordLen:]
	return EncodeMap(
		EncodeInt(1), EncodeInt(2), // kty: EC2
		EncodeInt(3), EncodeInt(COSEAlgES256), // alg: ES256
		EncodeInt(-1), EncodeInt(1), // crv: P-256
		EncodeInt(-2), EncodeBytes(x), // x
		EncodeInt(-3), EncodeBytes(y), // y
	), nil
}
