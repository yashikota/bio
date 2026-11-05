# Testing

Most of this library talks to hardware, so the tests are layered: the closer
a layer is to the hardware, the less it can run in CI, and the more the layers
below it must catch.

| Layer | What it checks | Where | Runs on |
|---|---|---|---|
| Encoding | CBOR, COSE, authenticator data, client data | `internal/webauthn` | every OS |
| Oracle | Output is accepted by a real relying party ([go-webauthn](https://github.com/go-webauthn/webauthn)) | `internal/webauthntest`, used by the layers below | every OS |
| Fuzzing | Encoders round-trip; the parser agrees with fxamacker/cbor and never panics | `internal/webauthn/*_test.go` | CI `fuzz` job |
| Contract | Every authenticator behaves the same: validation before prompting, error mapping, timeouts, exclusion, deletion | `contract_test.go` (`runContract`) | every OS |
| Platform integration | Real OS code with only the biometric sensor faked | see below | CI |
| Hardware | Touch ID / Windows Hello / a fingerprint reader | `examples/` | by hand |

## The contract

`runContract` in `contract_test.go` is run against:

- `TestContract_Fake`: the shared macOS/Linux flow (`core.go`) with a fake
  verifier and in-memory software keys, on every OS.
- `TestContract_Linux`: the real Linux stack (D-Bus client, TPM code on
  [swtpm](https://github.com/stefanberger/swtpm), credential store) with a fake
  fprintd on a private `dbus-daemon`.
- `TestContract_DarwinKeychain`: the real Keychain code with faked Touch ID.
  It writes to the login Keychain, so it only runs with `BIO_KEYCHAIN_TESTS=1`.
- `TestContract_WindowsFakeDLL`: the Windows authenticator with an emulated
  `webauthn.dll` that returns the HRESULTs Windows does.

When you add a behaviour, add it to the contract, not to one platform.

## Running the tests

```sh
task test          # everything that can run here
task cover         # plus the total coverage
task fuzz          # each fuzz target for 30s (FUZZTIME=5m task fuzz for longer)
task lint          # golangci-lint for linux, darwin, windows and freebsd
```

On Linux, install `swtpm` and `dbus-daemon` to run the integration tests;
without them those tests are skipped. CI sets `BIO_REQUIRE_LINUX_DEPS=1`,
which turns a missing tool into a failure so the job cannot go green by
skipping.

## On real hardware

CI machines have no biometrics, so before a release run on each platform:

```sh
go run ./examples/check
go run ./examples/register
go run ./examples/login
```

Both `register` and `login` verify their result with go-webauthn and print
`OK` or the reason the relying party rejected it. Also try cancelling the
prompt (expect `ErrUserCanceled`) and, on macOS, a signed build with
`WithSecureEnclave()`.
