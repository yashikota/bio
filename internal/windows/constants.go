//go:build windows

package winwebauthn

// WebAuthn API version numbers
const (
	WebAuthnAPIVersion1 = 1
	WebAuthnAPIVersion2 = 2
	WebAuthnAPIVersion3 = 3
	WebAuthnAPIVersion4 = 4
)

// HRESULT values
const (
	S_OK                = 0
	NTE_NOT_SUPPORTED   = int32(-2146893783) // 0x80090029
	NTE_INVALID_PARAMETER = int32(-2146893805) // 0x80090013
	ERROR_CANCELLED     = int32(-2147023673) // 0x800704C7
	ERROR_TIMEOUT_WIN   = int32(-2147023436) // 0x800704B4
	ERROR_NOT_FOUND     = int32(-2147023728) // 0x80070490
)

// User verification requirement values
const (
	WebAuthnUserVerificationRequirementAny         = 0
	WebAuthnUserVerificationRequirementRequired    = 1
	WebAuthnUserVerificationRequirementPreferred   = 2
	WebAuthnUserVerificationRequirementDiscouraged = 3
)

// Attestation conveyance values
const (
	WebAuthnAttestationConveyancePreferenceAny      = 0
	WebAuthnAttestationConveyancePreferenceNone     = 1
	WebAuthnAttestationConveyancePreferenceDirect   = 2
	WebAuthnAttestationConveyancePreferenceIndirect = 3
)

// Authenticator attachment
const (
	WebAuthnAuthenticatorAttachmentAny          = 0
	WebAuthnAuthenticatorAttachmentPlatform     = 1
	WebAuthnAuthenticatorAttachmentCrossPlatform = 2
)

// COSE algorithm values
const (
	WebAuthnCoseAlgorithmECDSAP256withSHA256    = -7
	WebAuthnCoseAlgorithmRSASSAPKCS1withSHA256  = -257
)

// Public key credential type
const WebAuthnCredentialTypePublicKey = "public-key"

// Hash algorithm
const WebAuthnHashAlgorithmSHA256 = "SHA-256"

// Current struct version numbers
const (
	WebAuthnRPEntityInformationVersion1     = 1
	WebAuthnUserEntityInformationVersion1   = 1
	WebAuthnClientDataVersion1              = 1
	WebAuthnCoseCredentialParameterVersion1 = 1
	WebAuthnCredentialVersion1              = 1
	WebAuthnCredentialExVersion1            = 1
	WebAuthnAuthenticatorMakeCredentialOptionsVersion1 = 1
	WebAuthnAuthenticatorMakeCredentialOptionsVersion2 = 2
	WebAuthnAuthenticatorMakeCredentialOptionsVersion3 = 3
	WebAuthnAuthenticatorMakeCredentialOptionsVersion4 = 4
	WebAuthnAuthenticatorGetAssertionOptionsVersion1   = 1
	WebAuthnAuthenticatorGetAssertionOptionsVersion4   = 4
	WebAuthnAssertionVersion1 = 1
)
