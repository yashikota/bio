package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/yashikota/bio/internal/webauthntest"
)

func testRawKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return k, raw
}

func testCOSEKey(t *testing.T) []byte {
	t.Helper()
	_, raw := testRawKey(t)
	k, err := EncodeCOSEES256(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncodeCOSEES256(t *testing.T) {
	_, raw := testRawKey(t)
	b, err := EncodeCOSEES256(raw)
	if err != nil {
		t.Fatal(err)
	}
	var m map[int]any
	if err := cbor.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m[1] != uint64(2) || m[3] != int64(-7) || m[-1] != uint64(1) {
		t.Errorf("kty/alg/crv = %v %v %v", m[1], m[3], m[-1])
	}
	if !bytes.Equal(m[-2].([]byte), raw[1:33]) || !bytes.Equal(m[-3].([]byte), raw[33:]) {
		t.Error("x/y mismatch")
	}
	if _, err := EncodeCOSEES256(raw[:64]); err == nil {
		t.Error("expected error for short key")
	}
}

func TestUncompressedP256Pads(t *testing.T) {
	// Find a key whose X starts with a zero byte, then strip it.
	for range 2000 {
		_, raw := testRawKey(t)
		if raw[1] != 0 {
			continue
		}
		got, err := UncompressedP256(raw[2:33], raw[33:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatal("padding mismatch")
		}
		return
	}
	t.Skip("no key with a leading zero byte found")
}

func TestUncompressedP256RejectsInvalid(t *testing.T) {
	if _, err := UncompressedP256(make([]byte, 32), make([]byte, 32)); err == nil {
		t.Error("expected error for a point not on the curve")
	}
	if _, err := UncompressedP256(make([]byte, 33), nil); err == nil {
		t.Error("expected error for a long coordinate")
	}
}

// TestRelyingPartyAcceptsOutput is the oracle test: what this package builds
// must pass a real relying party's registration and assertion checks.
func TestRelyingPartyAcceptsOutput(t *testing.T) {
	rp := webauthntest.Default
	priv, raw := testRawKey(t)
	cose, err := EncodeCOSEES256(raw)
	if err != nil {
		t.Fatal(err)
	}
	credID := []byte("credential-id-0123456789abcdef")

	regChallenge := []byte("registration-challenge-32-bytes!")
	authData, err := BuildAuthenticatorData(rp.ID, FlagUP|FlagUV, 0, [16]byte{}, credID, cose)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := rp.VerifyRegistration(regChallenge, credID, EncodeAttestationObjectNone(authData), rp.ClientData(TypeCreate, regChallenge))
	if err != nil {
		t.Fatal(err)
	}

	for i := uint32(1); i <= 2; i++ {
		ch := []byte("assertion-challenge-32-bytes!!!!")
		cd := rp.ClientData(TypeGet, ch)
		ad := BuildAssertionAuthData(rp.ID, FlagUP|FlagUV, i)
		digest := sha256.Sum256(SignedData(ad, cd))
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		count, err := rp.VerifyAssertion(ch, credID, ad, sig, nil, cd, pub)
		if err != nil {
			t.Fatal(err)
		}
		if count != i {
			t.Errorf("counter = %d, want %d", count, i)
		}
	}

	// A wrong RP ID must be rejected, proving the oracle actually checks.
	bad := BuildAssertionAuthData("evil.example", FlagUP|FlagUV, 3)
	cd := rp.ClientData(TypeGet, []byte("c"))
	digest := sha256.Sum256(SignedData(bad, cd))
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if _, err := rp.VerifyAssertion([]byte("c"), credID, bad, sig, nil, cd, pub); err == nil {
		t.Error("oracle accepted an assertion for the wrong RP ID")
	}
}
