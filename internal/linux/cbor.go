//go:build linux

package linux

import "encoding/binary"

func EncodeBytes(b []byte) []byte {
	return append(encodeHead(2, uint64(len(b))), b...)
}

func EncodeText(s string) []byte {
	return append(encodeHead(3, uint64(len(s))), []byte(s)...)
}

func EncodeUint(n uint64) []byte {
	return encodeHead(0, n)
}

func EncodeNegInt(n uint64) []byte {
	return encodeHead(1, n)
}

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
