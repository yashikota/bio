//go:build darwin

package darwin

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestBuildGetAssertionAuthData(t *testing.T) {
	rpID := "example.com"
	flags := byte(FlagUP | FlagUV)
	signCount := uint32(0)

	got := BuildGetAssertionAuthData(rpID, flags, signCount)

	// Must be exactly 37 bytes: 32 (rpIDHash) + 1 (flags) + 4 (signCount)
	if len(got) != 37 {
		t.Fatalf("authData length = %d, want 37", len(got))
	}

	// rpIDHash
	wantHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(got[:32], wantHash[:]) {
		t.Error("rpIDHash mismatch")
	}

	// flags
	if got[32] != flags {
		t.Errorf("flags = 0x%02x, want 0x%02x", got[32], flags)
	}

	// signCount (big-endian)
	gotCount := binary.BigEndian.Uint32(got[33:37])
	if gotCount != signCount {
		t.Errorf("signCount = %d, want %d", gotCount, signCount)
	}
}

func TestBuildAuthenticatorData(t *testing.T) {
	rpID := "example.com"
	flags := byte(FlagUP | FlagUV | FlagAT)
	var aaguid [16]byte
	credID := []byte{0x01, 0x02, 0x03, 0x04}
	coseKey := []byte{0xa5} // minimal placeholder

	got := BuildAuthenticatorData(rpID, flags, 0, aaguid, credID, coseKey)

	// Minimum: 32 + 1 + 4 + 16 + 2 + len(credID) + len(coseKey)
	minLen := 32 + 1 + 4 + 16 + 2 + len(credID) + len(coseKey)
	if len(got) < minLen {
		t.Fatalf("authData length = %d, want >= %d", len(got), minLen)
	}

	// rpIDHash
	wantHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(got[:32], wantHash[:]) {
		t.Error("rpIDHash mismatch")
	}

	// AAGUID (all zeros at offset 37)
	if !bytes.Equal(got[37:53], make([]byte, 16)) {
		t.Error("AAGUID should be zero")
	}

	// credIDLen (big-endian uint16 at offset 53)
	credIDLen := binary.BigEndian.Uint16(got[53:55])
	if int(credIDLen) != len(credID) {
		t.Errorf("credIDLen = %d, want %d", credIDLen, len(credID))
	}

	// credID bytes
	if !bytes.Equal(got[55:55+len(credID)], credID) {
		t.Error("credID mismatch")
	}
}

func TestFlagConstants(t *testing.T) {
	if FlagUP != 0x01 {
		t.Errorf("FlagUP = 0x%02x, want 0x01", FlagUP)
	}
	if FlagUV != 0x04 {
		t.Errorf("FlagUV = 0x%02x, want 0x04", FlagUV)
	}
	if FlagAT != 0x40 {
		t.Errorf("FlagAT = 0x%02x, want 0x40", FlagAT)
	}
}
