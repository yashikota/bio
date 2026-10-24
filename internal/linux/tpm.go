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

	"github.com/yashikota/bio/internal/webauthn"
)

var tpmPaths = []string{"/dev/tpmrm0", "/dev/tpm0"}

// TPM creates and uses ECDSA P-256 keys wrapped by the TPM's storage root key.
type TPM struct {
	open func() (transport.TPMCloser, error)
}

// NewTPM returns a TPM that talks to the kernel resource manager (/dev/tpmrm0, falling back to /dev/tpm0).
func NewTPM() *TPM {
	return &TPM{open: func() (transport.TPMCloser, error) { return openTPMFromPaths(tpmPaths) }}
}

// NewTPMWithOpener returns a TPM that uses open for every operation. Tests use it to connect to swtpm.
func NewTPMWithOpener(open func() (transport.TPMCloser, error)) *TPM {
	return &TPM{open: open}
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

// keyTemplate is the TPMT_PUBLIC template for a non-restricted ECDSA P-256 signing key.
// With an authorization value (a PIN), dictionary-attack protection is left on
// so that the TPM rate-limits guesses.
func keyTemplate(withAuth bool) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                !withAuth,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
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
}

// Available reports whether a TPM2 device can be opened.
func (tp *TPM) Available() bool {
	t, err := tp.open()
	if err != nil {
		return false
	}
	t.Close()
	return true
}

// createSRK derives the ECC storage root key under the owner hierarchy.
// CreatePrimary is deterministic for a given template and seed, so the same
// SRK comes back every time and blobs created earlier keep loading. A
// provisioned persistent SRK is deliberately not used: its template may differ,
// and switching parents would orphan existing credentials.
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

// CreateKey generates a new ECDSA P-256 key under the SRK, optionally
// protected by auth. It returns the public and private blobs to store and the
// uncompressed public point.
func (tp *TPM) CreateKey(auth []byte) (pub, priv, rawPubKey []byte, err error) {
	t, err := tp.open()
	if err != nil {
		return nil, nil, nil, newTPMError("CreateKey/open", err)
	}
	defer t.Close()

	srkHandle, srkName, err := createSRK(t)
	if err != nil {
		return nil, nil, nil, newTPMError("CreateKey/srk", err)
	}
	defer tpm2.FlushContext{FlushHandle: srkHandle}.Execute(t) //nolint:errcheck

	create := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.New2B(keyTemplate(len(auth) > 0)),
	}
	if len(auth) > 0 {
		create.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth}},
		}
	}
	rsp, err := create.Execute(t)
	if err != nil {
		return nil, nil, nil, newTPMError("CreateKey/create", err)
	}

	pubContents, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, nil, newTPMError("CreateKey/public", err)
	}
	eccPub, err := pubContents.Unique.ECC()
	if err != nil {
		return nil, nil, nil, newTPMError("CreateKey/ecc", err)
	}
	raw, err := webauthn.UncompressedP256(eccPub.X.Buffer, eccPub.Y.Buffer)
	if err != nil {
		return nil, nil, nil, newTPMError("CreateKey/point", err)
	}
	return tpm2.Marshal(rsp.OutPublic), tpm2.Marshal(rsp.OutPrivate), raw, nil
}

type ecdsaSig struct {
	R, S *big.Int
}

// Sign loads the key from its blobs and returns a DER-encoded ECDSA-SHA256 signature over data.
func (tp *TPM) Sign(pubBlob, privBlob, auth, data []byte) ([]byte, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBlob)
	if err != nil {
		return nil, newTPMError("Sign/unmarshal-public", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBlob)
	if err != nil {
		return nil, newTPMError("Sign/unmarshal-private", err)
	}

	t, err := tp.open()
	if err != nil {
		return nil, newTPMError("Sign/open", err)
	}
	defer t.Close()

	srkHandle, srkName, err := createSRK(t)
	if err != nil {
		return nil, newTPMError("Sign/srk", err)
	}
	defer tpm2.FlushContext{FlushHandle: srkHandle}.Execute(t) //nolint:errcheck

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    *priv,
		InPublic:     *pub,
	}.Execute(t)
	if err != nil {
		return nil, newTPMError("Sign/load", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(t) //nolint:errcheck

	digest := sha256.Sum256(data)
	signRsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: loadRsp.ObjectHandle, Name: loadRsp.Name, Auth: tpm2.PasswordAuth(auth)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
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
		return nil, newTPMError("Sign/sign", err)
	}

	eccSig, err := signRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, newTPMError("Sign/signature", err)
	}
	der, err := asn1.Marshal(ecdsaSig{
		R: new(big.Int).SetBytes(eccSig.SignatureR.Buffer),
		S: new(big.Int).SetBytes(eccSig.SignatureS.Buffer),
	})
	if err != nil {
		return nil, newTPMError("Sign/asn1", err)
	}
	return der, nil
}
