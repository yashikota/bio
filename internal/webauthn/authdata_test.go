package webauthn

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestBuildAndParseAuthData(t *testing.T) {
	aaguid := [16]byte{1, 2, 3}
	credID := bytes.Repeat([]byte{0x42}, 32)
	key := testCOSEKey(t)

	b, err := BuildAuthenticatorData("example.com", FlagUP|FlagUV, 7, aaguid, credID, key)
	if err != nil {
		t.Fatal(err)
	}
	ad, err := ParseAuthData(b)
	if err != nil {
		t.Fatal(err)
	}
	if ad.RPIDHash != sha256.Sum256([]byte("example.com")) {
		t.Error("rpIdHash mismatch")
	}
	if ad.Flags != FlagUP|FlagUV|FlagAT {
		t.Errorf("flags = %#x, want AT added", ad.Flags)
	}
	if ad.SignCount != 7 || ad.AAGUID != aaguid || !bytes.Equal(ad.CredentialID, credID) || !bytes.Equal(ad.PublicKey, key) {
		t.Errorf("round trip mismatch: %+v", ad)
	}

	// Trailing extension data must not end up in the public key.
	withExt := append(append([]byte(nil), b...), EncodeMap(EncodeText("credProtect"), EncodeInt(1))...)
	pk, err := PublicKeyFromAuthData(withExt)
	if err != nil || !bytes.Equal(pk, key) {
		t.Errorf("PublicKeyFromAuthData with extensions = %x, %v", pk, err)
	}
}

func TestBuildAssertionAuthData(t *testing.T) {
	b := BuildAssertionAuthData("example.com", FlagUP|FlagUV, 0x01020304)
	if len(b) != AuthDataMinLen {
		t.Fatalf("len = %d, want %d", len(b), AuthDataMinLen)
	}
	ad, err := ParseAuthData(b)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Flags != FlagUP|FlagUV || ad.SignCount != 0x01020304 || ad.PublicKey != nil {
		t.Errorf("unexpected %+v", ad)
	}
	if _, err := PublicKeyFromAuthData(b); err == nil {
		t.Error("expected error: no attested credential data")
	}
}

func TestBuildAuthenticatorDataRejectsLongCredentialID(t *testing.T) {
	_, err := BuildAuthenticatorData("x", 0, 0, [16]byte{}, make([]byte, 1<<16), nil)
	if err == nil {
		t.Fatal("expected error for a credential ID longer than 65535 bytes")
	}
}

func TestParseAuthDataMalformed(t *testing.T) {
	good, err := BuildAuthenticatorData("example.com", FlagUP, 0, [16]byte{}, []byte{1, 2, 3}, testCOSEKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 10, AuthDataMinLen + 5, AuthDataMinLen + 18 + 1, len(good) - 1} {
		if _, err := ParseAuthData(good[:n]); err == nil {
			t.Errorf("ParseAuthData(truncated to %d) succeeded", n)
		}
	}
}

func TestSignedDataDoesNotAlias(t *testing.T) {
	authData := make([]byte, AuthDataMinLen, 100) // spare capacity invites aliasing bugs
	cd := []byte(`{}`)
	got := SignedData(authData, cd)
	h := sha256.Sum256(cd)
	if !bytes.Equal(got[AuthDataMinLen:], h[:]) {
		t.Error("hash suffix mismatch")
	}
	got[0] = 0xff
	if authData[0] == 0xff {
		t.Error("SignedData aliases authData")
	}
}

func TestEncodeAttestationObjectNone(t *testing.T) {
	ao := EncodeAttestationObjectNone([]byte{9, 9})
	m := decode(t, ao).(map[any]any)
	if m["fmt"] != "none" || !bytes.Equal(m["authData"].([]byte), []byte{9, 9}) {
		t.Errorf("unexpected %v", m)
	}
	if st, ok := m["attStmt"].(map[any]any); !ok || len(st) != 0 {
		t.Errorf("attStmt = %v", m["attStmt"])
	}
}

func FuzzParseAuthData(f *testing.F) {
	good, _ := BuildAuthenticatorData("example.com", FlagUP, 0, [16]byte{}, []byte{1, 2, 3}, EncodeMap(EncodeInt(1), EncodeInt(2)))
	f.Add(good)
	f.Add(BuildAssertionAuthData("example.com", FlagUP, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		ad, err := ParseAuthData(b)
		if err != nil {
			return
		}
		if ad.Flags&FlagAT != 0 && ad.PublicKey == nil {
			t.Fatal("AT set but no public key")
		}
	})
}

func FuzzBuildAuthenticatorData(f *testing.F) {
	f.Add("example.com", []byte{1, 2, 3}, uint32(0))
	f.Fuzz(func(t *testing.T, rpID string, credID []byte, signCount uint32) {
		key := EncodeMap(EncodeInt(1), EncodeInt(2))
		b, err := BuildAuthenticatorData(rpID, FlagUP, signCount, [16]byte{}, credID, key)
		if err != nil {
			if len(credID) <= 0xffff {
				t.Fatal(err)
			}
			return
		}
		ad, err := ParseAuthData(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ad.CredentialID, credID) || ad.SignCount != signCount || !bytes.Equal(ad.PublicKey, key) {
			t.Fatalf("round trip mismatch")
		}
	})
}

func TestCheckClientData(t *testing.T) {
	ch := []byte("challenge-bytes")
	ok := `{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLWJ5dGVz","origin":"https://example.com"}`
	tests := []struct {
		name, json, typ string
		wantErr         string
	}{
		{"ok", ok, TypeGet, ""},
		{"padded challenge", strings.Replace(ok, "Ynl0ZXM", "Ynl0ZXM=", 1), TypeGet, ""},
		{"wrong type", ok, TypeCreate, "type"},
		{"wrong challenge", strings.Replace(ok, "Y2hh", "AAAA", 1), TypeGet, "challenge"},
		{"no origin", `{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLWJ5dGVz"}`, TypeGet, "origin"},
		{"not json", `nope`, TypeGet, "invalid"},
		{"bad base64", strings.Replace(ok, "Y2hh", "Y2h!", 1), TypeGet, "base64url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckClientData([]byte(tt.json), tt.typ, ch)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
