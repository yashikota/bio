package bio

import "time"

// RelyingParty identifies the relying party.
type RelyingParty struct {
	ID   string
	Name string
}

// User identifies the user for the credential.
type User struct {
	ID          []byte
	Name        string
	DisplayName string
}

// COSEAlgorithm represents a COSE algorithm identifier.
type COSEAlgorithm int

const (
	AlgES256 COSEAlgorithm = -7
	AlgRS256 COSEAlgorithm = -257
	AlgEdDSA COSEAlgorithm = -8
)

// CredentialParameter specifies an acceptable credential type and algorithm.
type CredentialParameter struct {
	Type      string
	Algorithm COSEAlgorithm
}

// CredentialDescriptor identifies a previously created credential.
type CredentialDescriptor struct {
	Type string
	ID   []byte
}

// AttestationConveyance controls attestation statement delivery.
type AttestationConveyance string

const (
	AttestationNone     AttestationConveyance = "none"
	AttestationIndirect AttestationConveyance = "indirect"
	AttestationDirect   AttestationConveyance = "direct"
)

// UserVerification requirement for the operation.
type UserVerification string

const (
	UVRequired    UserVerification = "required"
	UVPreferred   UserVerification = "preferred"
	UVDiscouraged UserVerification = "discouraged"
)

// MakeCredentialOptions configures a credential creation request.
type MakeCredentialOptions struct {
	RP                 RelyingParty
	User               User
	Challenge          []byte
	PubKeyCredParams   []CredentialParameter
	ExcludeCredentials []CredentialDescriptor
	Attestation        AttestationConveyance
	UserVerification   UserVerification
	Timeout            time.Duration
	// ClientDataJSON is the serialized client data (RFC 8785 / WebAuthn §5.8.1).
	// The caller is responsible for constructing it with the correct type, challenge,
	// and origin. Its SHA-256 hash is used as the clientDataHash during signing.
	// The same bytes are returned unchanged in Credential.ClientDataJSON.
	ClientDataJSON []byte
}

// GetAssertionOptions configures an assertion request.
type GetAssertionOptions struct {
	RPID             string
	Challenge        []byte
	AllowCredentials []CredentialDescriptor
	UserVerification UserVerification
	Timeout          time.Duration
	// ClientDataJSON is the serialized client data (RFC 8785 / WebAuthn §5.8.1).
	// The caller is responsible for constructing it with the correct type, challenge,
	// and origin. Its SHA-256 hash is used as the clientDataHash during signing.
	// The same bytes are returned unchanged in Assertion.ClientDataJSON.
	ClientDataJSON []byte
}

// Credential is the result of a successful MakeCredential operation.
type Credential struct {
	ID                []byte
	PublicKey         []byte // COSE-encoded
	AttestationObject []byte // CBOR-encoded
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Transport         []string
}

// Assertion is the result of a successful GetAssertion operation.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
	ClientDataJSON    []byte
}
