//go:build windows

package winwebauthn

import (
	"context"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWebAuthn = windows.NewLazySystemDLL("webauthn.dll")

	procGetApiVersionNumber                           = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procIsUserVerifyingPlatformAuthenticatorAvailable = modWebAuthn.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	procAuthenticatorMakeCredential                   = modWebAuthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procAuthenticatorGetAssertion                     = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeCredentialAttestation                     = modWebAuthn.NewProc("WebAuthNFreeCredentialAttestation")
	procFreeAssertion                                 = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procGetCancellationID                             = modWebAuthn.NewProc("WebAuthNGetCancellationId")
	procCancelCurrentOperation                        = modWebAuthn.NewProc("WebAuthNCancelCurrentOperation")
	procDeletePlatformCredential                      = modWebAuthn.NewProc("WebAuthNDeletePlatformCredential")
)

// APIVersionNumber returns the WebAuthn API version supported by this OS.
// Returns 0 if webauthn.dll is not available.
func APIVersionNumber() uint32 {
	if err := modWebAuthn.Load(); err != nil {
		return 0
	}
	if err := procGetApiVersionNumber.Find(); err != nil {
		return 0
	}
	r, _, _ := procGetApiVersionNumber.Call()
	return uint32(r)
}

// IsAvailable returns true if a user-verifying platform authenticator (Windows Hello) is available.
func IsAvailable() (bool, error) {
	if APIVersionNumber() == 0 {
		return false, nil
	}
	var available int32 // BOOL
	hr, _, _ := procIsUserVerifyingPlatformAuthenticatorAvailable.Call(
		uintptr(unsafe.Pointer(&available)),
	)
	if err := HRESULTToError("IsAvailable", hr); err != nil {
		return false, err
	}
	return available != 0, nil
}

// pinner pins Go memory reachable from the structs handed to webauthn.dll.
// syscall only keeps the direct arguments alive and in place; pointers stored
// inside those structs need runtime.Pinner to be valid for the C side.
type pinner struct{ runtime.Pinner }

func (p *pinner) pinUTF16(s *uint16) {
	if s != nil {
		p.Pin(s)
	}
}

func (p *pinner) pinBytes(b *byte) {
	if b != nil {
		p.Pin(b)
	}
}

// credentialList builds a WEBAUTHN_CREDENTIAL_LIST for ids, pinning everything it allocates.
func credentialList(p *pinner, ids [][]byte, typ *uint16) *CredentialList {
	if len(ids) == 0 {
		return nil
	}
	creds := make([]*CredentialEx, len(ids))
	for i, id := range ids {
		c := &CredentialEx{Version: WebAuthnCredentialExVersion1, IDLen: uint32(len(id)), Type: typ}
		if len(id) > 0 {
			idCopy := append([]byte(nil), id...)
			c.ID = &idCopy[0]
			p.Pin(c.ID)
		}
		p.Pin(c)
		creds[i] = c
	}
	p.Pin(&creds[0])
	list := &CredentialList{Count: uint32(len(creds)), Creds: &creds[0]}
	p.Pin(list)
	return list
}

func clientData(p *pinner, json []byte) *ClientData {
	cd := &ClientData{
		Version:        WebAuthnClientDataVersion1,
		ClientDataJSON: uint32(len(json)),
		HashAlgID:      UTF16PtrFromString(WebAuthnHashAlgorithmSHA256),
	}
	if len(json) > 0 {
		cd.PBClientData = &json[0]
	}
	p.pinUTF16(cd.HashAlgID)
	p.pinBytes(cd.PBClientData)
	return cd
}

// MakeCredentialParams holds Go-typed parameters for MakeCredential.
type MakeCredentialParams struct {
	HWND             uintptr
	RPID             string
	RPName           string
	UserID           []byte
	UserName         string
	UserDisplayName  string
	ClientDataJSON   []byte
	Algorithms       []int32 // COSE algorithm IDs
	UserVerification uint32
	AttestationPref  uint32
	TimeoutMS        uint32
	ExcludeIDs       [][]byte
}

// MakeCredentialResult holds the output from a MakeCredential call.
type MakeCredentialResult struct {
	CredentialID      []byte
	AttestationObject []byte
	AuthenticatorData []byte
}

// MakeCredential calls WebAuthNAuthenticatorMakeCredential with the platform
// authenticator (Windows Hello) only.
func MakeCredential(ctx context.Context, params *MakeCredentialParams) (*MakeCredentialResult, error) {
	if err := modWebAuthn.Load(); err != nil {
		return nil, fmt.Errorf("webauthn: dll not available: %w", err)
	}
	if len(params.Algorithms) == 0 {
		return nil, &WinError{Op: "MakeCredential", Kind: WinErrInvalidParam, HR: toHR(NTE_INVALID_PARAMETER)}
	}

	var p pinner
	defer p.Unpin()

	rp := &RPEntityInformation{
		Version: WebAuthnRPEntityInformationVersion1,
		ID:      UTF16PtrFromString(params.RPID),
		Name:    UTF16PtrFromString(params.RPName),
	}
	p.pinUTF16(rp.ID)
	p.pinUTF16(rp.Name)

	user := &UserEntityInformation{
		Version:     WebAuthnUserEntityInformationVersion1,
		IDLen:       uint32(len(params.UserID)),
		Name:        UTF16PtrFromString(params.UserName),
		DisplayName: UTF16PtrFromString(params.UserDisplayName),
	}
	if len(params.UserID) > 0 {
		user.ID = &params.UserID[0]
	}
	p.pinBytes(user.ID)
	p.pinUTF16(user.Name)
	p.pinUTF16(user.DisplayName)

	pubKeyType := UTF16PtrFromString(WebAuthnCredentialTypePublicKey)
	p.pinUTF16(pubKeyType)
	coseParams := make([]CoseCredentialParameter, len(params.Algorithms))
	for i, alg := range params.Algorithms {
		coseParams[i] = CoseCredentialParameter{Version: WebAuthnCoseCredentialParameterVersion1, Type: pubKeyType, Algorithm: alg}
	}
	p.Pin(&coseParams[0])
	coseCredParams := &CoseCredentialParameters{Count: uint32(len(coseParams)), Params: &coseParams[0]}

	cd := clientData(&p, params.ClientDataJSON)

	timeoutMS := params.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = 60000
	}
	opts := &AuthMakeCredentialOptions{
		Version:                         WebAuthnAuthenticatorMakeCredentialOptionsVersion3,
		TimeoutMilliseconds:             timeoutMS,
		AuthenticatorAttachment:         WebAuthnAuthenticatorAttachmentPlatform,
		UserVerificationRequirement:     params.UserVerification,
		AttestationConveyancePreference: params.AttestationPref,
		ExcludeCredentialList:           credentialList(&p, params.ExcludeIDs, pubKeyType),
	}
	cancelID := new(GUID)
	if err := getCancellationID(cancelID); err == nil {
		opts.CancellationID = cancelID
		p.Pin(cancelID)
	}

	type result struct {
		r   *MakeCredentialResult
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var attestation *CredentialAttestation
		hr, _, _ := procAuthenticatorMakeCredential.Call(
			params.HWND,
			uintptr(unsafe.Pointer(rp)),
			uintptr(unsafe.Pointer(user)),
			uintptr(unsafe.Pointer(coseCredParams)),
			uintptr(unsafe.Pointer(cd)),
			uintptr(unsafe.Pointer(opts)),
			uintptr(unsafe.Pointer(&attestation)),
		)
		if err := HRESULTToError("MakeCredential", hr); err != nil {
			ch <- result{err: err}
			return
		}
		if attestation == nil {
			ch <- result{err: fmt.Errorf("webauthn: MakeCredential returned nil attestation")}
			return
		}
		res := copyAttestationResult(attestation)
		procFreeCredentialAttestation.Call(uintptr(unsafe.Pointer(attestation))) //nolint:errcheck
		ch <- result{r: res}
	}()

	select {
	case res := <-ch:
		return res.r, res.err
	case <-ctx.Done():
		cancelOperation(cancelID)
		<-ch // the call returns once canceled; the pinned memory must outlive it
		return nil, ctx.Err()
	}
}

func copyAttestationResult(a *CredentialAttestation) *MakeCredentialResult {
	res := &MakeCredentialResult{}
	if a.CredentialIDLen > 0 && a.CredentialID != nil {
		res.CredentialID = append([]byte(nil), unsafe.Slice(a.CredentialID, a.CredentialIDLen)...)
	}
	if a.AttestationObjectLen > 0 && a.AttestationObject != nil {
		res.AttestationObject = append([]byte(nil), unsafe.Slice(a.AttestationObject, a.AttestationObjectLen)...)
	}
	if a.AuthenticatorDataLen > 0 && a.AuthenticatorData != nil {
		res.AuthenticatorData = append([]byte(nil), unsafe.Slice(a.AuthenticatorData, a.AuthenticatorDataLen)...)
	}
	return res
}

// GetAssertionParams holds Go-typed parameters for GetAssertion.
type GetAssertionParams struct {
	HWND             uintptr
	RPID             string
	ClientDataJSON   []byte
	AllowIDs         [][]byte
	UserVerification uint32
	TimeoutMS        uint32
}

// GetAssertionResult holds the output from a GetAssertion call.
type GetAssertionResult struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
	UserID            []byte
}

// GetAssertion calls WebAuthNAuthenticatorGetAssertion with the platform authenticator only.
func GetAssertion(ctx context.Context, params *GetAssertionParams) (*GetAssertionResult, error) {
	if err := modWebAuthn.Load(); err != nil {
		return nil, fmt.Errorf("webauthn: dll not available: %w", err)
	}

	var p pinner
	defer p.Unpin()

	rpID := UTF16PtrFromString(params.RPID)
	cd := clientData(&p, params.ClientDataJSON)
	pubKeyType := UTF16PtrFromString(WebAuthnCredentialTypePublicKey)
	p.pinUTF16(pubKeyType)

	timeoutMS := params.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = 60000
	}
	opts := &AuthGetAssertionOptions{
		Version:                     WebAuthnAuthenticatorGetAssertionOptionsVersion4,
		TimeoutMilliseconds:         timeoutMS,
		AuthenticatorAttachment:     WebAuthnAuthenticatorAttachmentPlatform,
		UserVerificationRequirement: params.UserVerification,
		AllowCredentialList:         credentialList(&p, params.AllowIDs, pubKeyType),
	}
	cancelID := new(GUID)
	if err := getCancellationID(cancelID); err == nil {
		opts.CancellationID = cancelID
		p.Pin(cancelID)
	}

	type result struct {
		r   *GetAssertionResult
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var assertion *Assertion
		hr, _, _ := procAuthenticatorGetAssertion.Call(
			params.HWND,
			uintptr(unsafe.Pointer(rpID)),
			uintptr(unsafe.Pointer(cd)),
			uintptr(unsafe.Pointer(opts)),
			uintptr(unsafe.Pointer(&assertion)),
		)
		if err := HRESULTToError("GetAssertion", hr); err != nil {
			ch <- result{err: err}
			return
		}
		if assertion == nil {
			ch <- result{err: fmt.Errorf("webauthn: GetAssertion returned nil assertion")}
			return
		}
		res := copyAssertionResult(assertion)
		procFreeAssertion.Call(uintptr(unsafe.Pointer(assertion))) //nolint:errcheck
		ch <- result{r: res}
	}()

	select {
	case res := <-ch:
		return res.r, res.err
	case <-ctx.Done():
		cancelOperation(cancelID)
		<-ch
		return nil, ctx.Err()
	}
}

func copyAssertionResult(a *Assertion) *GetAssertionResult {
	res := &GetAssertionResult{}
	if a.AuthenticatorDataLen > 0 && a.AuthenticatorData != nil {
		res.AuthenticatorData = append([]byte(nil), unsafe.Slice(a.AuthenticatorData, a.AuthenticatorDataLen)...)
	}
	if a.SignatureLen > 0 && a.Signature != nil {
		res.Signature = append([]byte(nil), unsafe.Slice(a.Signature, a.SignatureLen)...)
	}
	if a.Credential.IDLen > 0 && a.Credential.ID != nil {
		res.CredentialID = append([]byte(nil), unsafe.Slice(a.Credential.ID, a.Credential.IDLen)...)
	}
	if a.UserIDLen > 0 && a.UserID != nil {
		res.UserID = append([]byte(nil), unsafe.Slice(a.UserID, a.UserIDLen)...)
	}
	return res
}

// DeletePlatformCredential deletes a Windows Hello credential (API version 4+).
func DeletePlatformCredential(credentialID []byte) error {
	if len(credentialID) == 0 {
		return &WinError{Op: "DeletePlatformCredential", Kind: WinErrInvalidParam, HR: toHR(NTE_INVALID_PARAMETER)}
	}
	if APIVersionNumber() < WebAuthnAPIVersion4 {
		return &WinError{Op: "DeletePlatformCredential", Kind: WinErrNotSupported, HR: toHR(NTE_NOT_SUPPORTED)}
	}
	if err := procDeletePlatformCredential.Find(); err != nil {
		return &WinError{Op: "DeletePlatformCredential", Kind: WinErrNotSupported, HR: toHR(NTE_NOT_SUPPORTED)}
	}
	hr, _, _ := procDeletePlatformCredential.Call(uintptr(len(credentialID)), uintptr(unsafe.Pointer(&credentialID[0])))
	return HRESULTToError("DeletePlatformCredential", hr)
}

func getCancellationID(id *GUID) error {
	if err := procGetCancellationID.Find(); err != nil {
		return err
	}
	hr, _, _ := procGetCancellationID.Call(uintptr(unsafe.Pointer(id)))
	return HRESULTToError("GetCancellationID", hr)
}

func cancelOperation(id *GUID) {
	if err := procCancelCurrentOperation.Find(); err != nil {
		return
	}
	procCancelCurrentOperation.Call(uintptr(unsafe.Pointer(id))) //nolint:errcheck
}
