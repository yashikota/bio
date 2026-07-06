//go:build linux

package linux

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

var tpmPaths = []string{"/dev/tpmrm0", "/dev/tpm0"}

// OpenTPMFunc is the function used to open a TPM transport. It can be replaced in tests.
var OpenTPMFunc = defaultOpenTPM

func defaultOpenTPM() (transport.TPMCloser, error) {
	return openTPMFromPaths(tpmPaths)
}

func openTPMFromPaths(paths []string) (transport.TPMCloser, error) {
	for _, p := range paths {
		t, err := linuxtpm.Open(p)
		if err == nil {
			return t, nil
		}
	}
	return nil, fmt.Errorf("no TPM device found (tried %v)", paths)
}

// eccKeyTemplate is the TPMT_PUBLIC template for a non-restricted ECDSA P-256 signing key.
var eccKeyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{
						HashAlg: tpm2.TPMAlgSHA256,
					},
				),
			},
			CurveID: tpm2.TPMECCNistP256,
		},
	),
	Unique: tpm2.NewTPMUPublicID(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		},
	),
}

func openTPM() (transport.TPMCloser, error) {
	return OpenTPMFunc()
}

// IsTPMAvailable reports whether a TPM2 device is accessible.
func IsTPMAvailable() bool {
	t, err := OpenTPMFunc()
	if err != nil {
		return false
	}
	t.Close()
	return true
}

// createSRK creates (or re-creates) the ECC SRK under the owner hierarchy.
// Returns the transient handle and its name; caller must flush when done.
func createSRK(t transport.TPM) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("CreatePrimary SRK: %w", err)
	}
	return rsp.ObjectHandle, rsp.Name, nil
}

// CreateKey generates a new ECDSA P-256 key under the SRK.
// Returns (publicBlob, privateBlob, uncompressedECPoint).
func CreateKey() (pub []byte, priv []byte, rawPubKey []byte, err error) {
	t, err := openTPM()
	if err != nil {
		return nil, nil, nil, &TPMError{Op: "CreateKey", Err: err}
	}
	defer t.Close()

	srkHandle, srkName, err := createSRK(t)
	if err != nil {
		return nil, nil, nil, &TPMError{Op: "CreateKey", Err: err}
	}
	defer tpm2.FlushContext{FlushHandle: srkHandle}.Execute(t) //nolint:errcheck

	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(eccKeyTemplate),
	}.Execute(t)
	if err != nil {
		return nil, nil, nil, &TPMError{Op: "CreateKey/Create", Err: err}
	}

	pubBytes := tpm2.Marshal(rsp.OutPublic)
	privBytes := tpm2.Marshal(rsp.OutPrivate)

	// Extract raw EC point (uncompressed: 0x04 || x || y)
	pub2b, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, nil, &TPMError{Op: "CreateKey/pub-contents", Err: err}
	}
	eccPub, err := pub2b.Unique.ECC()
	if err != nil {
		return nil, nil, nil, &TPMError{Op: "CreateKey/ecc-unique", Err: err}
	}
	x := eccPub.X.Buffer
	y := eccPub.Y.Buffer
	raw := make([]byte, 1+len(x)+len(y))
	raw[0] = 0x04
	copy(raw[1:], x)
	copy(raw[1+len(x):], y)

	return pubBytes, privBytes, raw, nil
}

type ecdsaSig struct {
	R, S *big.Int
}

// Sign loads the key from blobs, signs dataToSign with ECDSA-SHA256, and returns a DER-encoded signature.
func Sign(pubBlob, privBlob, dataToSign []byte) ([]byte, error) {
	t, err := openTPM()
	if err != nil {
		return nil, &TPMError{Op: "Sign", Err: err}
	}
	defer t.Close()

	srkHandle, srkName, err := createSRK(t)
	if err != nil {
		return nil, &TPMError{Op: "Sign", Err: err}
	}
	defer tpm2.FlushContext{FlushHandle: srkHandle}.Execute(t) //nolint:errcheck

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBlob)
	if err != nil {
		return nil, &TPMError{Op: "Sign/unmarshal-pub", Err: err}
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBlob)
	if err != nil {
		return nil, &TPMError{Op: "Sign/unmarshal-priv", Err: err}
	}

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: *priv,
		InPublic:  *pub,
	}.Execute(t)
	if err != nil {
		return nil, &TPMError{Op: "Sign/Load", Err: err}
	}
	defer tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(t) //nolint:errcheck

	digest := sha256.Sum256(dataToSign)

	signRsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(t)
	if err != nil {
		return nil, &TPMError{Op: "Sign/Sign", Err: err}
	}

	eccSig, err := signRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, &TPMError{Op: "Sign/ecdsa-sig", Err: err}
	}

	derSig, err := asn1.Marshal(ecdsaSig{
		R: new(big.Int).SetBytes(eccSig.SignatureR.Buffer),
		S: new(big.Int).SetBytes(eccSig.SignatureS.Buffer),
	})
	if err != nil {
		return nil, &TPMError{Op: "Sign/asn1", Err: err}
	}

	return derSig, nil
}
