# bio

A CGo-free FIDO2/WebAuthn biometric authentication library for Go, supporting macOS (Touch ID / Face ID), Windows (Windows Hello), and Linux (fprintd + TPM2).

## Features

- **No CGo** — uses [purego](https://github.com/ebitengine/purego) on macOS, `golang.org/x/sys` on Windows, and D-Bus + TPM2 on Linux
- **FIDO2/WebAuthn compatible** — produces standard `AttestationObject`, `AuthenticatorData`, and `Signature` outputs
- **Context-aware** — all blocking calls respect `context.Context` cancellation and timeouts
- **Cross-platform** — single API across macOS, Windows, and Linux; returns `ErrUnsupportedPlatform` on other OSes

## Platform support

| Platform | Authenticator | Biometry |
|---|---|---|
| macOS | Secure Enclave / Keychain | Touch ID, Face ID |
| Windows | Windows Hello | PIN, fingerprint, face |
| Linux | fprintd + TPM2 | Fingerprint |

## Requirements

- Go 1.22+
- macOS 12+, Windows 10 (build 17763) / Windows 11, or Linux with fprintd and TPM2

## Installation

```sh
go get github.com/yashikota/bio
```

## Quick start

### Check availability

```go
authn, err := bio.New()
if err != nil {
    log.Fatal(err)
}

info, err := authn.Available(context.Background())
if err != nil {
    log.Fatal(err)
}
fmt.Printf("available=%v type=%v enrolled=%v\n", info.Available, info.BiometryType, info.Enrolled)
```

### Register a credential

```go
challenge := make([]byte, 32)
rand.Read(challenge)

userID := make([]byte, 16)
rand.Read(userID)

ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
defer cancel()

cred, err := authn.MakeCredential(ctx, bio.MakeCredentialOptions{
    RP:        bio.RelyingParty{ID: "example.com", Name: "Example Corp"},
    User:      bio.User{ID: userID, Name: "alice@example.com", DisplayName: "Alice"},
    Challenge: challenge,
    PubKeyCredParams: []bio.CredentialParameter{
        {Type: "public-key", Algorithm: bio.AlgES256},
    },
    UserVerification: bio.UVRequired,
})
```

`cred.ID` is the credential ID to store server-side. `cred.AttestationObject` and `cred.ClientDataJSON` can be sent to a WebAuthn server for verification.

### Authenticate

```go
challenge := make([]byte, 32)
rand.Read(challenge)

assertion, err := authn.GetAssertion(ctx, bio.GetAssertionOptions{
    RPID:      "example.com",
    Challenge: challenge,
    AllowCredentials: []bio.CredentialDescriptor{
        {Type: "public-key", ID: credID},
    },
    UserVerification: bio.UVRequired,
})
```

Send `assertion.AuthenticatorData`, `assertion.Signature`, and `assertion.ClientDataJSON` to your server for verification.

## API

### `bio.New(opts ...Option) (Authenticator, error)`

Returns a platform-specific `Authenticator`. Platform-specific options:

| Option | Platform | Description |
|---|---|---|
| `WithLocalizedReason(string)` | macOS | Prompt text shown in the biometric dialog |
| `WithHWND(uintptr)` | Windows | Parent window handle |
| `WithVerifyTimeout(time.Duration)` | Linux | Timeout for fingerprint scan (default 30s) |

### `Authenticator` interface

```go
type Authenticator interface {
    Available(ctx context.Context) (BiometryInfo, error)
    MakeCredential(ctx context.Context, opts MakeCredentialOptions) (*Credential, error)
    GetAssertion(ctx context.Context, opts GetAssertionOptions) (*Assertion, error)
}
```

### Key types

```go
type BiometryInfo struct {
    Available    bool
    BiometryType BiometryType  // BiometryTouchID, BiometryFaceID, BiometryOpticID, BiometryHello, BiometryFingerprint
    Enrolled     bool
}

type Credential struct {
    ID                []byte
    PublicKey         []byte // COSE-encoded
    AttestationObject []byte // CBOR-encoded
    ClientDataJSON    []byte
    AuthenticatorData []byte
    Transport         []string
}

type Assertion struct {
    CredentialID      []byte
    AuthenticatorData []byte
    Signature         []byte
    UserHandle        []byte
    ClientDataJSON    []byte
}
```

### COSE algorithms

| Constant | Value | Algorithm |
|---|---|---|
| `AlgES256` | -7 | ECDSA with P-256 and SHA-256 |
| `AlgRS256` | -257 | RSASSA-PKCS1-v1_5 with SHA-256 |
| `AlgEdDSA` | -8 | EdDSA |

## Error handling

```go
var (
    ErrUnsupportedPlatform // OS is not supported
    ErrNotAvailable        // biometric hardware not present
    ErrNotEnrolled         // no biometrics enrolled
    ErrUserCanceled        // user dismissed the prompt
    ErrTimeout             // operation timed out
    ErrCredentialExcluded  // credential already exists (MakeCredential)
    ErrNoCredentials       // no matching credential found (GetAssertion)
    ErrInvalidParameter    // missing required field
)
```

Platform-specific errors are wrapped in `*PlatformError` and can be inspected with `errors.As`.

## Examples

Runnable examples are in [`examples/`](./examples/):

```sh
go run ./examples/check     # check biometric availability
go run ./examples/register  # create a credential
go run ./examples/login     # authenticate with the credential
```
