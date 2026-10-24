package webauthn

import (
	"bytes"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The encoder is checked against an independent decoder rather than against
// hand-written byte strings, so a shared misunderstanding cannot hide a bug.

func decode(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := cbor.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %x: %v", b, err)
	}
	return v
}

func TestEncodeIntRoundTrip(t *testing.T) {
	for _, n := range []int64{0, 1, 23, 24, 255, 256, 65535, 65536, math.MaxUint32, math.MaxUint32 + 1, math.MaxInt64,
		-1, -7, -24, -25, -256, -257, -65537, math.MinInt64} {
		var got int64
		if err := cbor.Unmarshal(EncodeInt(n), &got); err != nil {
			t.Fatalf("EncodeInt(%d): %v", n, err)
		}
		if got != n {
			t.Errorf("EncodeInt(%d) decoded as %d", n, got)
		}
	}
}

func TestEncodeUintIsCanonical(t *testing.T) {
	// CTAP2 requires the shortest encoding.
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint64{0, 23, 24, 255, 256, 65535, 65536, math.MaxUint32, math.MaxUint32 + 1, math.MaxUint64} {
		want, err := em.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		if got := EncodeUint(n); !bytes.Equal(got, want) {
			t.Errorf("EncodeUint(%d) = %x, want %x", n, got, want)
		}
	}
}

func TestEncodeStringsAndMap(t *testing.T) {
	long := bytes.Repeat([]byte{0xab}, 300)
	m := EncodeMap(
		EncodeText("fmt"), EncodeText("none"),
		EncodeText("b"), EncodeBytes(long),
		EncodeText("t"), EncodeBool(true),
		EncodeText("f"), EncodeBool(false),
		EncodeText("empty"), EncodeMap(),
	)
	got, ok := decode(t, m).(map[any]any)
	if !ok {
		t.Fatalf("not a map: %T", decode(t, m))
	}
	if got["fmt"] != "none" || got["t"] != true || got["f"] != false {
		t.Errorf("unexpected values: %v", got)
	}
	if b, _ := got["b"].([]byte); !bytes.Equal(b, long) {
		t.Errorf("byte string mismatch")
	}
	if e, _ := got["empty"].(map[any]any); len(e) != 0 {
		t.Errorf("empty map = %v", got["empty"])
	}
}

func TestEncodeMapOddPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	odd := [][]byte{EncodeUint(1)}
	EncodeMap(odd...) //nolint:staticcheck // the odd count is the point of the test
}

func TestItemLength(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
		bad  bool
	}{
		{"uint", []byte{0x18, 0xff, 0x00}, 2, false},
		{"bytes", append(EncodeBytes([]byte{1, 2, 3}), 0xff), 4, false},
		{"nested map", append(EncodeMap(EncodeInt(1), EncodeMap(EncodeInt(-1), EncodeText("x"))), 0x00), 6, false},
		{"tag", []byte{0xc1, 0x01}, 2, false},
		{"float64", []byte{0xfb, 0, 0, 0, 0, 0, 0, 0, 0}, 9, false},
		{"empty", nil, 0, true},
		{"truncated bytes", []byte{0x43, 1, 2}, 0, true},
		{"truncated head", []byte{0x19, 0x01}, 0, true},
		{"indefinite", []byte{0x5f, 0x41, 0x00, 0xff}, 0, true},
		{"huge map count", []byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := itemLength(tt.in)
			if tt.bad {
				if err == nil {
					t.Fatalf("itemLength(%x) = %d, want error", tt.in, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("itemLength(%x) = %d, %v; want %d", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestItemLengthDepthLimit(t *testing.T) {
	deep := append(bytes.Repeat([]byte{0x81}, 100), 0x00) // [[[[...0...]]]]
	if _, err := itemLength(deep); err == nil {
		t.Error("expected error for deeply nested input")
	}
}

// FuzzEncodeInt checks every integer survives an encode/decode round trip.
func FuzzEncodeInt(f *testing.F) {
	for _, s := range []int64{0, 23, 24, -1, -24, -25, math.MaxInt64, math.MinInt64} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, n int64) {
		var got int64
		if err := cbor.Unmarshal(EncodeInt(n), &got); err != nil || got != n {
			t.Fatalf("EncodeInt(%d) -> %d, %v", n, got, err)
		}
	})
}

// FuzzItemLength compares the item-length parser with fxamacker/cbor on
// arbitrary input: whenever both accept it, they must agree on the length,
// and the parser must never panic.
func FuzzItemLength(f *testing.F) {
	f.Add(EncodeMap(EncodeInt(1), EncodeInt(2)))
	f.Add(EncodeBytes([]byte("hello")))
	f.Add([]byte{0xc1, 0x81, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		n, err := itemLength(b)
		if err != nil {
			return
		}
		if n <= 0 || n > len(b) {
			t.Fatalf("itemLength(%x) = %d out of range", b, n)
		}
		var v cbor.RawMessage
		rest, derr := cbor.UnmarshalFirst(b, &v)
		if derr != nil {
			// fxamacker rejects some well-formed input we accept (e.g. invalid UTF-8, duplicate keys).
			return
		}
		if want := len(b) - len(rest); want != n {
			t.Fatalf("itemLength(%x) = %d, fxamacker says %d", b, n, want)
		}
	})
}
