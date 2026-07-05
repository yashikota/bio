//go:build darwin

package darwin

import "encoding/binary"

// EncodeBytes encodes a CBOR byte string (major type 2).
func EncodeBytes(b []byte) []byte {
	return append(encodeHead(2, uint64(len(b))), b...)
}

// EncodeText encodes a CBOR text string (major type 3).
func EncodeText(s string) []byte {
	return append(encodeHead(3, uint64(len(s))), []byte(s)...)
}

// EncodeUint encodes a CBOR unsigned integer (major type 0).
func EncodeUint(n uint64) []byte {
	return encodeHead(0, n)
}

// EncodeNegInt encodes a CBOR negative integer (major type 1).
// The decoded value is -1 - n, so n=0 encodes -1, n=6 encodes -7, etc.
func EncodeNegInt(n uint64) []byte {
	return encodeHead(1, n)
}

// EncodeMap encodes a CBOR map from pre-encoded key-value pairs.
// pairs must be even-length: [key0, val0, key1, val1, ...].
func EncodeMap(pairs ...[]byte) []byte {
	if len(pairs)%2 != 0 {
		panic("cbor.EncodeMap: odd number of pairs")
	}
	n := len(pairs) / 2
	out := encodeHead(5, uint64(n))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

// EncodeBool encodes a CBOR boolean (major type 7, simple values 20/21).
func EncodeBool(b bool) []byte {
	if b {
		return []byte{0xf5} // simple(21) = true
	}
	return []byte{0xf4} // simple(20) = false
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
