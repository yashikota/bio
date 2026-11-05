// Package webauthn holds the platform-independent parts of the authenticator:
// a minimal CBOR encoder, authenticator data construction and parsing, COSE key
// encoding, and client data validation. It has no build tags so that its tests
// run on every CI platform.
package webauthn

import (
	"encoding/binary"
	"errors"
)

// CBOR major types (RFC 8949 §3.1).
const (
	majorUint   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	majorSimple = 7
)

// EncodeBytes encodes a CBOR byte string (major type 2).
func EncodeBytes(b []byte) []byte {
	return append(encodeHead(majorBytes, uint64(len(b))), b...)
}

// EncodeText encodes a CBOR text string (major type 3).
func EncodeText(s string) []byte {
	return append(encodeHead(majorText, uint64(len(s))), s...)
}

// EncodeUint encodes a CBOR unsigned integer (major type 0).
func EncodeUint(n uint64) []byte {
	return encodeHead(majorUint, n)
}

// EncodeInt encodes a signed integer as major type 0 or 1.
func EncodeInt(n int64) []byte {
	if n >= 0 {
		return encodeHead(majorUint, uint64(n))
	}
	// CBOR negative integers encode -1-n.
	return encodeHead(majorNegInt, uint64(-1-n))
}

// EncodeBool encodes a CBOR boolean.
func EncodeBool(b bool) []byte {
	if b {
		return []byte{0xf5}
	}
	return []byte{0xf4}
}

// EncodeMap encodes a CBOR map from pre-encoded key-value pairs:
// [key0, val0, key1, val1, ...]. It panics on an odd number of items,
// which is always a programming error.
func EncodeMap(pairs ...[]byte) []byte {
	if len(pairs)%2 != 0 {
		panic("webauthn.EncodeMap: odd number of items")
	}
	out := encodeHead(majorMap, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

func encodeHead(major byte, n uint64) []byte {
	mt := major << 5
	switch {
	case n <= 23:
		return []byte{mt | byte(n)}
	case n <= 0xff:
		return []byte{mt | 24, byte(n)}
	case n <= 0xffff:
		b := [3]byte{mt | 25}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b[:]
	case n <= 0xffffffff:
		b := [5]byte{mt | 26}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b[:]
	default:
		b := [9]byte{mt | 27}
		binary.BigEndian.PutUint64(b[1:], n)
		return b[:]
	}
}

// ErrMalformedCBOR is returned when CBOR input cannot be parsed.
var ErrMalformedCBOR = errors.New("webauthn: malformed CBOR")

// maxDepth bounds nesting so that hostile input cannot exhaust the stack.
const maxDepth = 16

// itemLength returns the encoded length of the first CBOR data item in b.
// Only definite-length items are supported, which is all that WebAuthn
// authenticators produce (CTAP2 canonical CBOR).
func itemLength(b []byte) (int, error) {
	return itemLengthDepth(b, 0)
}

func itemLengthDepth(b []byte, depth int) (int, error) {
	if depth > maxDepth {
		return 0, ErrMalformedCBOR
	}
	major, arg, hdr, err := decodeHead(b)
	if err != nil {
		return 0, err
	}
	switch major {
	case majorUint, majorNegInt:
		return hdr, nil
	case majorBytes, majorText:
		if arg > uint64(len(b)-hdr) {
			return 0, ErrMalformedCBOR
		}
		return hdr + int(arg), nil
	case majorArray, majorMap:
		n := arg
		if major == majorMap {
			if n > uint64(len(b)) {
				return 0, ErrMalformedCBOR
			}
			n *= 2
		}
		if n > uint64(len(b)) {
			return 0, ErrMalformedCBOR
		}
		off := hdr
		for range n {
			l, err := itemLengthDepth(b[off:], depth+1)
			if err != nil {
				return 0, err
			}
			off += l
		}
		return off, nil
	case majorTag:
		l, err := itemLengthDepth(b[hdr:], depth+1)
		if err != nil {
			return 0, err
		}
		return hdr + l, nil
	default: // majorSimple: simple values and floats carry no payload beyond the head.
		return hdr, nil
	}
}

// decodeHead parses a CBOR initial byte and its argument.
func decodeHead(b []byte) (major byte, arg uint64, hdrLen int, err error) {
	if len(b) == 0 {
		return 0, 0, 0, ErrMalformedCBOR
	}
	major = b[0] >> 5
	info := b[0] & 0x1f
	switch {
	case info <= 23:
		return major, uint64(info), 1, nil
	case info == 24:
		if len(b) < 2 {
			return 0, 0, 0, ErrMalformedCBOR
		}
		return major, uint64(b[1]), 2, nil
	case info == 25:
		if len(b) < 3 {
			return 0, 0, 0, ErrMalformedCBOR
		}
		return major, uint64(binary.BigEndian.Uint16(b[1:])), 3, nil
	case info == 26:
		if len(b) < 5 {
			return 0, 0, 0, ErrMalformedCBOR
		}
		return major, uint64(binary.BigEndian.Uint32(b[1:])), 5, nil
	case info == 27:
		if len(b) < 9 {
			return 0, 0, 0, ErrMalformedCBOR
		}
		return major, binary.BigEndian.Uint64(b[1:]), 9, nil
	default: // 28-30 reserved, 31 indefinite length
		return 0, 0, 0, ErrMalformedCBOR
	}
}
