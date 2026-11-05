//go:build linux

package linux_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/yashikota/bio/internal/linux"
	"github.com/yashikota/bio/internal/linux/linuxtest"
)

func parseKey(t *testing.T, raw []byte) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.ParseUncompressedPublicKey(ellipticP256(), raw)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return k
}

func TestTPMSignaturesVerify(t *testing.T) {
	tpm := linuxtest.StartSwtpm(t)
	if !tpm.Available() {
		t.Fatal("swtpm not available")
	}
	pub, priv, raw, err := tpm.CreateKey(nil)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	key := parseKey(t, raw)
	for _, msg := range []string{"hello", "", "a longer message that is certainly more than one block of SHA-256 input data"} {
		sig, err := tpm.Sign(pub, priv, nil, []byte(msg))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		d := sha256.Sum256([]byte(msg))
		if !ecdsa.VerifyASN1(key, d[:], sig) {
			t.Fatalf("signature over %q does not verify", msg)
		}
	}
}

func TestTPMRejectsOtherKeysBlobs(t *testing.T) {
	tpm := linuxtest.StartSwtpm(t)
	pubA, _, rawA, err := tpm.CreateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, privB, _, err := tpm.CreateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Mixing blobs from two keys must fail to load rather than sign with the wrong key.
	if sig, err := tpm.Sign(pubA, privB, nil, []byte("x")); err == nil {
		d := sha256.Sum256([]byte("x"))
		if ecdsa.VerifyASN1(parseKey(t, rawA), d[:], sig) {
			t.Fatal("mixed blobs produced a valid signature")
		}
		t.Fatal("mixed blobs loaded")
	}
	tampered := append([]byte(nil), privB...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := tpm.Sign(pubA, tampered, nil, []byte("x")); err == nil {
		t.Fatal("tampered private blob loaded")
	}
}

func TestTPMPIN(t *testing.T) {
	tpm := linuxtest.StartSwtpm(t)
	pin := []byte("1234")
	pub, priv, raw, err := tpm.CreateKey(pin)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := tpm.Sign(pub, priv, pin, []byte("x"))
	if err != nil {
		t.Fatalf("Sign with PIN: %v", err)
	}
	d := sha256.Sum256([]byte("x"))
	if !ecdsa.VerifyASN1(parseKey(t, raw), d[:], sig) {
		t.Fatal("signature does not verify")
	}
	_, err = tpm.Sign(pub, priv, []byte("0000"), []byte("x"))
	var te *linux.TPMError
	if !errors.As(err, &te) || !te.IsAuthFailure() || te.Code == 0 {
		t.Fatalf("wrong PIN: err = %v, want an auth failure with a TPM code", err)
	}
}

func TestTPMUnavailable(t *testing.T) {
	tpm := linux.NewTPMWithOpener(func() (transportTPM, error) { return nil, errors.New("no device") })
	if tpm.Available() {
		t.Error("Available() = true")
	}
	if _, _, _, err := tpm.CreateKey(nil); err == nil {
		t.Error("CreateKey succeeded without a TPM")
	}
}
