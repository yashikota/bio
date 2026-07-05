//go:build windows

package winwebauthn

import "unsafe"

// RPEntityInformation corresponds to WEBAUTHN_RP_ENTITY_INFORMATION.
type RPEntityInformation struct {
	Version uint32
	ID      *uint16 // PCWSTR
	Name    *uint16 // PCWSTR
	Icon    *uint16 // PCWSTR (may be nil)
}

// UserEntityInformation corresponds to WEBAUTHN_USER_ENTITY_INFORMATION.
type UserEntityInformation struct {
	Version     uint32
	IDLen       uint32
	ID          *byte   // PBYTE
	Name        *uint16 // PCWSTR
	Icon        *uint16 // PCWSTR (may be nil, deprecated in v4)
	DisplayName *uint16 // PCWSTR
}

// CoseCredentialParameter corresponds to WEBAUTHN_COSE_CREDENTIAL_PARAMETER.
type CoseCredentialParameter struct {
	Version   uint32
	Type      *uint16 // PCWSTR, always "public-key"
	Algorithm int32   // LONG (COSE algorithm value)
}

// CoseCredentialParameters corresponds to WEBAUTHN_COSE_CREDENTIAL_PARAMETERS.
type CoseCredentialParameters struct {
	Count  uint32
	Params *CoseCredentialParameter
}

// ClientData corresponds to WEBAUTHN_CLIENT_DATA.
type ClientData struct {
	Version        uint32
	ClientDataJSON uint32  // cbClientDataJSON (size)
	PBClientData   *byte   // PBYTE
	HashAlgID      *uint16 // PCWSTR, e.g. "SHA-256"
}

// Credential corresponds to WEBAUTHN_CREDENTIAL.
type Credential struct {
	Version uint32
	IDLen   uint32
	ID      *byte
	Type    *uint16 // PCWSTR "public-key"
}

// Credentials corresponds to WEBAUTHN_CREDENTIALS.
type Credentials struct {
	Count uint32
	Creds *Credential
}

// CredentialEx corresponds to WEBAUTHN_CREDENTIAL_EX (v1 fields only).
type CredentialEx struct {
	Version   uint32
	IDLen     uint32
	ID        *byte
	Type      *uint16 // PCWSTR
	Transport uint32  // DWORD
}

// CredentialList corresponds to WEBAUTHN_CREDENTIAL_LIST.
type CredentialList struct {
	Count uint32
	Creds **CredentialEx
}

// AuthMakeCredentialOptions corresponds to WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS (v3 fields).
type AuthMakeCredentialOptions struct {
	Version                         uint32
	TimeoutMilliseconds             uint32
	CredentialList                  Credentials
	Extensions                      Extensions
	AuthenticatorAttachment         uint32
	RequireResidentKey              int32 // BOOL
	UserVerificationRequirement     uint32
	AttestationConveyancePreference uint32
	Flags                           uint32
	// v2:
	CancellationID *GUID
	// v3:
	ExcludeCredentialList *CredentialList
}

// AuthGetAssertionOptions corresponds to WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS (v4 fields).
type AuthGetAssertionOptions struct {
	Version                     uint32
	TimeoutMilliseconds         uint32
	CredentialList              Credentials
	Extensions                  Extensions
	AuthenticatorAttachment     uint32
	UserVerificationRequirement uint32
	Flags                       uint32
	// v2:
	U2FAppID       *uint16 // PCWSTR
	IsU2FAppIDUsed *int32  // BOOL*
	// v3:
	CancellationID *GUID
	// v4:
	AllowCredentialList *CredentialList
}

// CredentialAttestation corresponds to WEBAUTHN_CREDENTIAL_ATTESTATION.
type CredentialAttestation struct {
	Version               uint32
	FormatType            *uint16 // PCWSTR
	AuthenticatorDataLen  uint32
	AuthenticatorData     *byte
	AttestationLen        uint32
	Attestation           *byte
	AttestationDecodeType uint32
	AttestationDecode     uintptr
	AttestationObjectLen  uint32
	AttestationObject     *byte
	CredentialIDLen       uint32
	CredentialID          *byte
	Extensions            Extensions
	// v3:
	Transport uint32
}

// Assertion corresponds to WEBAUTHN_ASSERTION.
type Assertion struct {
	Version              uint32
	AuthenticatorDataLen uint32
	AuthenticatorData    *byte
	SignatureLen         uint32
	Signature            *byte
	Credential           Credential
	UserIDLen            uint32
	UserID               *byte
}

// Extensions corresponds to WEBAUTHN_EXTENSIONS (used as a zero-size placeholder).
type Extensions struct {
	Count      uint32
	Extensions uintptr // *WEBAUTHN_EXTENSION (we never use extensions, so pointer is nil)
}

// GUID corresponds to Windows GUID.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// Verify critical struct sizes to catch alignment bugs at init time.
var _ = [1]struct{}{}

var _ unsafe.Pointer // ensure unsafe is used
