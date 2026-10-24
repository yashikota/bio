# bio

A CGo-free FIDO2/WebAuthn biometric authentication library for Go, supporting macOS (Touch ID / Face ID), Windows (Windows Hello), and Linux (fprintd + TPM2).

## Features

- **No CGo** — uses [purego](https://github.com/ebitengine/purego) on macOS, `golang.org/x/sys` on Windows, and D-Bus + TPM2 on Linux
- **FIDO2/WebAuthn compatible** — produces standard `AttestationObject`, `AuthenticatorData`, and `Signature` outputs
- **Context-aware** — all blocking calls respect `context.Context` cancellation and timeouts
- **Cross-platform** — single API across macOS, Windows, and Linux; returns `ErrUnsupportedPlatform` on other OSes

## Platform support

| Platform | Keys | User verification | Enforced by |
|---|---|---|---|
| macOS (default) | Software P-256 key in the login Keychain | Touch ID / Face ID / Optic ID via LocalAuthentication | This library |
| macOS + `WithSecureEnclave()` | Secure Enclave key with a biometric access-control policy | Touch ID / Face ID / Optic ID | The OS (needs a signed app with the `keychain-access-groups` entitlement) |
| Windows | Windows Hello (platform authenticator only) | PIN, fingerprint, face | The OS |
| Linux | TPM 2.0 key, blob in `$XDG_DATA_HOME/<namespace>` | Fingerprint via fprintd | This library |
| Linux + `WithPINPrompt()` | TPM 2.0 key with the PIN as its authorization value | Fingerprint, then PIN | The TPM (PIN only, with dictionary-attack lockout) |

### Security model

On macOS (default) and Linux the biometric check happens in this process: the
operating system does not refuse to sign without it. Code running as the same
user can read the Keychain item or the TPM key blob and sign without a finger.
The authenticator data still carries the UV flag, so a relying party cannot
tell the difference. Use `WithSecureEnclave()` on macOS or `WithPINPrompt()` on
Linux when that matters. Keys never leave the TPM or Secure Enclave, but they
can be used by anyone who can talk to it as you.

Attestation is always `none`. Discoverable credentials (empty
`AllowCredentials`) work only on Windows.

## Requirements

- Go 1.26+
- macOS 12+, Windows 10 (build 17763) / Windows 11, or Linux with fprintd and TPM2

## Installation

```sh
go get github.com/yashikota/bio
```

## Quick start

`ClientDataJSON` is required: in a browser flow the client builds it, and
its `challenge` must be the base64url encoding of `Challenge`. Requests where
they disagree fail with `ErrInvalidParameter` before any prompt is shown.

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
challenge := make([]byte, 32) // from your server
rand.Read(challenge)

clientDataJSON, _ := json.Marshal(map[string]any{
    "type":      "webauthn.create",
    "challenge": base64.RawURLEncoding.EncodeToString(challenge),
    "origin":    "https://example.com",
})

cred, err := authn.MakeCredential(ctx, bio.MakeCredentialOptions{
    RP:             bio.RelyingParty{ID: "example.com", Name: "Example Corp"},
    User:           bio.User{ID: userID, Name: "alice@example.com", DisplayName: "Alice"},
    Challenge:      challenge,
    ClientDataJSON: clientDataJSON,
    PubKeyCredParams: []bio.CredentialParameter{
        {Type: "public-key", Algorithm: bio.AlgES256},
    },
    UserVerification: bio.UVRequired,
})
```

Send `cred.ID`, `cred.AttestationObject` and `cred.ClientDataJSON` to your
WebAuthn server. `cred.PublicKey` is the COSE public key on every platform.

### Authenticate

```go
assertion, err := authn.GetAssertion(ctx, bio.GetAssertionOptions{
    RPID:           "example.com",
    Challenge:      challenge,
    ClientDataJSON: clientDataJSON, // "type": "webauthn.get"
    AllowCredentials: []bio.CredentialDescriptor{
        {Type: "public-key", ID: credID},
    },
    UserVerification: bio.UVRequired,
})
```

Send `assertion.AuthenticatorData`, `assertion.Signature`,
`assertion.UserHandle` and `assertion.ClientDataJSON` to your server.

## API

### `bio.New(opts ...Option) (Authenticator, error)`

Returns a platform-specific `Authenticator`. Platform-specific options:

| Option | Platform | Description |
|---|---|---|
| `WithLocalizedReason(string)` | macOS | Prompt text (default: "Register with <RP>" / "Sign in to <RP ID>") |
| `WithSecureEnclave()` | macOS | OS-enforced biometric keys in the Secure Enclave (signed apps only) |
| `WithHWND(uintptr)` | Windows | Parent window handle |
| `WithVerifyTimeout(time.Duration)` | Linux | Timeout for a fingerprint scan (default 30s) |
| `WithPINPrompt(func(ctx) (string, error))` | Linux | Protect new TPM keys with a PIN |
| `WithNamespace(string)` | macOS, Linux | Keep this app's credentials apart from other apps (default "bio") |

`MakeCredentialOptions.Timeout` / `GetAssertionOptions.Timeout` and the
context deadline apply on every platform.

### `Authenticator` interface

```go
type Authenticator interface {
    Available(ctx context.Context) (BiometryInfo, error)
    MakeCredential(ctx context.Context, opts MakeCredentialOptions) (*Credential, error)
    GetAssertion(ctx context.Context, opts GetAssertionOptions) (*Assertion, error)
    DeleteCredential(ctx context.Context, rpID string, credentialID []byte) error
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
    ErrInvalidParameter    // missing or inconsistent field (checked before any prompt)
    ErrUnsupportedAlgorithm // no requested PubKeyCredParams algorithm is supported
)
```

Timeouts and cancellation return `ErrTimeout` / `ErrUserCanceled` that also
wrap `context.DeadlineExceeded` / `context.Canceled`. Platform-specific errors
are wrapped in `*PlatformError` and can be inspected with `errors.As`.

## Examples

Runnable examples are in [`examples/`](./examples/):

```sh
go run ./examples/check     # check biometric availability
go run ./examples/register  # create a credential and verify it like a server would
go run ./examples/login     # sign in and verify the assertion like a server would
```

The examples verify their output with an independent WebAuthn
implementation, so a run on real hardware ends with "verified by the relying
party: OK" or with the reason it was rejected.

## Development

See [TESTING.md](./TESTING.md) for how the tests are organised and how to run them.
