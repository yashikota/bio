//go:build windows

package winwebauthn

import (
	"context"
	"fmt"
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
	procGetErrorName                                  = modWebAuthn.NewProc("WebAuthNGetErrorName")
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

// MakeCredentialParams holds Go-typed parameters for MakeCredential.
type MakeCredentialParams struct {
	HWND            uintptr
	RPID            string
	RPName          string
	UserID          []byte
	UserName        string
	UserDisplayName string
	Challenge       []byte
	ClientDataJSON  []byte
	Algorithms      []int32 // COSE algorithm IDs
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

// MakeCredential calls WebAuthNAuthenticatorMakeCredential.
func MakeCredential(ctx context.Context, params *MakeCredentialParams) (*MakeCredentialResult, error) {
	if err := modWebAuthn.Load(); err != nil {
		return nil, fmt.Errorf("webauthn: dll not available: %w", err)
	}

	// RP info
	rp := RPEntityInformation{
		Version: WebAuthnRPEntityInformationVersion1,
		ID:      UTF16PtrFromString(params.RPID),
		Name:    UTF16PtrFromString(params.RPName),
	}

	// User info
	user := UserEntityInformation{
		Version:     WebAuthnUserEntityInformationVersion1,
		IDLen:       uint32(len(params.UserID)),
		Name:        UTF16PtrFromString(params.UserName),
		DisplayName: UTF16PtrFromString(params.UserDisplayName),
	}
	if len(params.UserID) > 0 {
		user.ID = &params.UserID[0]
	}

	// COSE credential parameters
	coseParams := make([]CoseCredentialParameter, len(params.Algorithms))
	pubKeyType := UTF16PtrFromString(WebAuthnCredentialTypePublicKey)
	for i, alg := range params.Algorithms {
		coseParams[i] = CoseCredentialParameter{
			Version:   WebAuthnCoseCredentialParameterVersion1,
			Type:      pubKeyType,
			Algorithm: alg,
		}
	}
	coseCredParams := CoseCredentialParameters{
		Count:  uint32(len(coseParams)),
		Params: &coseParams[0],
	}

	// Client data
	hashAlg := UTF16PtrFromString(WebAuthnHashAlgorithmSHA256)
	clientData := ClientData{
		Version:        WebAuthnClientDataVersion1,
		ClientDataJSON: uint32(len(params.ClientDataJSON)),
		HashAlgID:      hashAlg,
	}
	if len(params.ClientDataJSON) > 0 {
		clientData.PBClientData = &params.ClientDataJSON[0]
	}

	// Options
	timeoutMS := params.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = 60000 // 60 second default
	}
	opts := AuthMakeCredentialOptions{
		Version:                         WebAuthnAuthenticatorMakeCredentialOptionsVersion3,
		TimeoutMilliseconds:             timeoutMS,
		UserVerificationRequirement:     params.UserVerification,
		AttestationConveyancePreference: params.AttestationPref,
	}

	// Cancellation ID for context support
	var cancelID GUID
	if err := getCancellationID(&cancelID); err == nil {
		opts.CancellationID = &cancelID
	}

	// Exclude credentials
	if len(params.ExcludeIDs) > 0 {
		excludeEx := make([]*CredentialEx, len(params.ExcludeIDs))
		for i, id := range params.ExcludeIDs {
			credEx := &CredentialEx{
				Version: WebAuthnCredentialExVersion1,
				IDLen:   uint32(len(id)),
				Type:    pubKeyType,
			}
			if len(id) > 0 {
				idCopy := append([]byte(nil), id...)
				credEx.ID = &idCopy[0]
			}
			excludeEx[i] = credEx
		}
		excludeList := &CredentialList{
			Count: uint32(len(excludeEx)),
			Creds: &excludeEx[0],
		}
		opts.ExcludeCredentialList = excludeList
	}

	// Channel for async result
	type result struct {
		r   *MakeCredentialResult
		err error
	}
	ch := make(chan result, 1)

	go func() {
		var attestation *CredentialAttestation
		hr, _, _ := procAuthenticatorMakeCredential.Call(
			params.HWND,
			uintptr(unsafe.Pointer(&rp)),
			uintptr(unsafe.Pointer(&user)),
			uintptr(unsafe.Pointer(&coseCredParams)),
			uintptr(unsafe.Pointer(&clientData)),
			uintptr(unsafe.Pointer(&opts)),
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
		procFreeCredentialAttestation.Call(uintptr(unsafe.Pointer(attestation)))
		ch <- result{r: res}
	}()

	select {
	case res := <-ch:
		return res.r, res.err
	case <-ctx.Done():
		cancelOperation(&cancelID)
		<-ch // wait for goroutine to finish
		return nil, context.DeadlineExceeded
	}
}

func copyAttestationResult(a *CredentialAttestation) *MakeCredentialResult {
	res := &MakeCredentialResult{}
	if a.CredentialIDLen > 0 && a.CredentialID != nil {
		res.CredentialID = append([]byte(nil), (*[1 << 20]byte)(unsafe.Pointer(a.CredentialID))[:a.CredentialIDLen]...)
	}
	if a.AttestationObjectLen > 0 && a.AttestationObject != nil {
		res.AttestationObject = append([]byte(nil), (*[1 << 20]byte)(unsafe.Pointer(a.AttestationObject))[:a.AttestationObjectLen]...)
	}
	if a.AuthenticatorDataLen > 0 && a.AuthenticatorData != nil {
		res.AuthenticatorData = append([]byte(nil), (*[1 << 20]byte)(unsafe.Pointer(a.AuthenticatorData))[:a.AuthenticatorDataLen]...)
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

// GetAssertion calls WebAuthNAuthenticatorGetAssertion.
func GetAssertion(ctx context.Context, params *GetAssertionParams) (*GetAssertionResult, error) {
	if err := modWebAuthn.Load(); err != nil {
		return nil, fmt.Errorf("webauthn: dll not available: %w", err)
	}

	rpID := UTF16PtrFromString(params.RPID)
	hashAlg := UTF16PtrFromString(WebAuthnHashAlgorithmSHA256)

	clientData := ClientData{
		Version:        WebAuthnClientDataVersion1,
		ClientDataJSON: uint32(len(params.ClientDataJSON)),
		HashAlgID:      hashAlg,
	}
	if len(params.ClientDataJSON) > 0 {
		clientData.PBClientData = &params.ClientDataJSON[0]
	}

	timeoutMS := params.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = 60000
	}
	opts := AuthGetAssertionOptions{
		Version:                     WebAuthnAuthenticatorGetAssertionOptionsVersion4,
		TimeoutMilliseconds:         timeoutMS,
		UserVerificationRequirement: params.UserVerification,
	}

	// Cancellation
	var cancelID GUID
	if err := getCancellationID(&cancelID); err == nil {
		opts.CancellationID = &cancelID
	}

	// Allow credentials
	pubKeyType := UTF16PtrFromString(WebAuthnCredentialTypePublicKey)
	if len(params.AllowIDs) > 0 {
		allowEx := make([]*CredentialEx, len(params.AllowIDs))
		for i, id := range params.AllowIDs {
			credEx := &CredentialEx{
				Version: WebAuthnCredentialExVersion1,
				IDLen:   uint32(len(id)),
				Type:    pubKeyType,
			}
			if len(id) > 0 {
				idCopy := append([]byte(nil), id...)
				credEx.ID = &idCopy[0]
			}
			allowEx[i] = credEx
		}
		allowList := &CredentialList{
			Count: uint32(len(allowEx)),
			Creds: &allowEx[0],
		}
		opts.AllowCredentialList = allowList
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
			uintptr(unsafe.Pointer(&clientData)),
			uintptr(unsafe.Pointer(&opts)),
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
		procFreeAssertion.Call(uintptr(unsafe.Pointer(assertion)))
		ch <- result{r: res}
	}()

	select {
	case res := <-ch:
		return res.r, res.err
	case <-ctx.Done():
		cancelOperation(&cancelID)
		<-ch
		return nil, context.DeadlineExceeded
	}
}

func copyAssertionResult(a *Assertion) *GetAssertionResult {
	res := &GetAssertionResult{}
	if a.AuthenticatorDataLen > 0 && a.AuthenticatorData != nil {
		res.AuthenticatorData = append([]byte(nil), (*[1 << 20]byte)(unsafe.Pointer(a.AuthenticatorData))[:a.AuthenticatorDataLen]...)
	}
	if a.SignatureLen > 0 && a.Signature != nil {
		res.Signature = append([]byte(nil), (*[1 << 20]byte)(unsafe.Pointer(a.Signature))[:a.SignatureLen]...)
	}
	if a.Credential.IDLen > 0 && a.Credential.ID != nil {
		res.CredentialID = append([]byte(nil), (*[1 << 20]byte)(unsafe.Pointer(a.Credential.ID))[:a.Credential.IDLen]...)
	}
	if a.UserIDLen > 0 && a.UserID != nil {
		res.UserID = append([]byte(nil), (*[1 << 20]byte)(unsafe.Pointer(a.UserID))[:a.UserIDLen]...)
	}
	return res
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
	procCancelCurrentOperation.Call(uintptr(unsafe.Pointer(id)))
}
