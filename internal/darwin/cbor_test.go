//go:build darwin

package darwin

import (
	"bytes"
	"testing"
)

func TestEncodeUint(t *testing.T) {
	tests := []struct {
		n    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{23, []byte{0x17}},
		{24, []byte{0x18, 0x18}},
		{255, []byte{0x18, 0xff}},
		{256, []byte{0x19, 0x01, 0x00}},
	}
	for _, tt := range tests {
		got := EncodeUint(tt.n)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("EncodeUint(%d) = %x, want %x", tt.n, got, tt.want)
		}
	}
}

func TestEncodeNegInt(t *testing.T) {
	// CBOR major type 1: value = -1 - n
	// -7 = EncodeNegInt(6)  → 0x26
	// -1 = EncodeNegInt(0)  → 0x20
	tests := []struct {
		n    uint64
		want []byte
	}{
		{0, []byte{0x20}}, // -1
		{6, []byte{0x26}}, // -7 (ES256 alg)
	}
	for _, tt := range tests {
		got := EncodeNegInt(tt.n)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("EncodeNegInt(%d) = %x, want %x", tt.n, got, tt.want)
		}
	}
}

func TestEncodeText(t *testing.T) {
	got := EncodeText("fmt")
	// "fmt" = 3 bytes, major type 3 = 0x63, then 'f','m','t'
	want := []byte{0x63, 'f', 'm', 't'}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeText(%q) = %x, want %x", "fmt", got, want)
	}
}

func TestEncodeBytes(t *testing.T) {
	got := EncodeBytes([]byte{0x01, 0x02, 0x03})
	// 3 bytes, major type 2 = 0x43
	want := []byte{0x43, 0x01, 0x02, 0x03}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeBytes = %x, want %x", got, want)
	}
}

func TestEncodeMap_empty(t *testing.T) {
	got := EncodeMap()
	// empty map = 0xa0
	if !bytes.Equal(got, []byte{0xa0}) {
		t.Errorf("EncodeMap() = %x, want a0", got)
	}
}

func TestEncodeMap_oneEntry(t *testing.T) {
	got := EncodeMap(EncodeUint(1), EncodeUint(2))
	// map(1) = 0xa1, key=1 (0x01), val=2 (0x02)
	want := []byte{0xa1, 0x01, 0x02}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeMap(1,2) = %x, want %x", got, want)
	}
}

func TestEncodeBool(t *testing.T) {
	if !bytes.Equal(EncodeBool(true), []byte{0xf5}) {
		t.Error("EncodeBool(true) should be 0xf5")
	}
	if !bytes.Equal(EncodeBool(false), []byte{0xf4}) {
		t.Error("EncodeBool(false) should be 0xf4")
	}
}
