//go:build windows

package bio

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/yashikota/bio/internal/webauthn"
	winwebauthn "github.com/yashikota/bio/internal/windows"
)

// fakeWebAuthnDLL emulates webauthn.dll with software keys, returning the
// same HRESULTs Windows does, so the Windows authenticator's own logic
// (validation, parameter mapping, error mapping, PublicKey extraction) is
// tested without Windows Hello.
type fakeWebAuthnDLL struct {
	mu       sync.Mutex
	keys     *softwareKeyStore
	cancel   bool
	block    bool
	calls    int
	lastMake *winwebauthn.MakeCredentialParams
}

func hrErr(op string, hr int32) error { return winwebauthn.HRESULTToError(op, uintptr(uint32(hr))) }

// prompt emulates the Windows Hello dialog.
func (f *fakeWebAuthnDLL) prompt(ctx context.Context, op string) error {
	f.mu.Lock()
	f.calls++
	cancel, block := f.cancel, f.block
	f.cancel = false
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	if cancel {
		return hrErr(op, winwebauthn.NTE_USER_CANCELLED)
	}
	return nil
}

func (f *fakeWebAuthnDLL) makeCredential(ctx context.Context, p *winwebauthn.MakeCredentialParams) (*winwebauthn.MakeCredentialResult, error) {
	f.mu.Lock()
	f.lastMake = p
	f.mu.Unlock()
	if !slices.Contains(p.Algorithms, int32(AlgES256)) {
		return nil, hrErr("MakeCredential", winwebauthn.NTE_NOT_SUPPORTED)
	}
	if err := f.prompt(ctx, "MakeCredential"); err != nil {
		return nil, err
	}
	for _, id := range p.ExcludeIDs {
		if _, err := f.keys.Lookup(p.RPID, id); err == nil {
			return nil, hrErr("MakeCredential", winwebauthn.NTE_EXISTS)
		}
	}
	credID := make([]byte, 16)
	rand.Read(credID)
	raw, err := f.keys.Create(ctx, nil, p.RPID, credID, User{ID: p.UserID})
	if err != nil {
		return nil, err
	}
	cose, _ := webauthn.EncodeCOSEES256(raw)
	authData, _ := webauthn.BuildAuthenticatorData(p.RPID, webauthn.FlagUP|webauthn.FlagUV, 0, [16]byte{}, credID, cose)
	return &winwebauthn.MakeCredentialResult{
		CredentialID:      credID,
		AttestationObject: webauthn.EncodeAttestationObjectNone(authData),
		AuthenticatorData: authData,
	}, nil
}

func (f *fakeWebAuthnDLL) getAssertion(ctx context.Context, p *winwebauthn.GetAssertionParams) (*winwebauthn.GetAssertionResult, error) {
	var key *storedKey
	for _, id := range p.AllowIDs {
		if k, err := f.keys.Lookup(p.RPID, id); err == nil {
			key = k
			break
		}
	}
	if err := f.prompt(ctx, "GetAssertion"); err != nil {
		return nil, err
	}
	if key == nil {
		return nil, hrErr("GetAssertion", winwebauthn.NTE_NOT_FOUND)
	}
	count, _ := f.keys.NextSignCount(p.RPID, key)
	authData := webauthn.BuildAssertionAuthData(p.RPID, webauthn.FlagUP|webauthn.FlagUV, count)
	sig, err := f.keys.Sign(ctx, nil, key, webauthn.SignedData(authData, p.ClientDataJSON))
	if err != nil {
		return nil, err
	}
	return &winwebauthn.GetAssertionResult{CredentialID: key.CredentialID, AuthenticatorData: authData, Signature: sig, UserID: key.UserHandle}, nil
}

func (f *fakeWebAuthnDLL) deleteCredential(id []byte) error {
	f.keys.mu.Lock()
	defer f.keys.mu.Unlock()
	for k := range f.keys.keys {
		if bytes.HasSuffix([]byte(k), append([]byte{0}, id...)) {
			delete(f.keys.keys, k)
			return nil
		}
	}
	return hrErr("DeletePlatformCredential", winwebauthn.NTE_NOT_FOUND)
}

func (f *fakeWebAuthnDLL) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newFakeWindows() (*windowsAuthenticator, *fakeWebAuthnDLL) {
	f := &fakeWebAuthnDLL{keys: newSoftwareKeyStore()}
	return &windowsAuthenticator{cfg: newConfig(nil), api: winAPI{
		isAvailable:      func() (bool, error) { return true, nil },
		makeCredential:   f.makeCredential,
		getAssertion:     f.getAssertion,
		deleteCredential: f.deleteCredential,
		resolveHWND:      func(h uintptr) uintptr { return h },
	}}, f
}

func TestContract_WindowsFakeDLL(t *testing.T) {
	runContract(t, func(t *testing.T) contractEnv {
		a, f := newFakeWindows()
		return contractEnv{
			Authn:            a,
			CancelNextVerify: func() { f.cancel = true },
			BlockVerify:      func() { f.block = true },
			VerifyCalls:      f.Calls,
			Discoverable:     true,
			SignCounter:      true,
		}
	})
}

func TestWindows_ParameterMapping(t *testing.T) {
	a, f := newFakeWindows()
	a.cfg.hwnd = 0x1234
	c := newContractCase(t)
	opts := c.makeOpts(t)
	opts.PubKeyCredParams = nil
	opts.Timeout = 1500 * time.Millisecond
	opts.Attestation = AttestationDirect
	if _, err := a.MakeCredential(t.Context(), opts); err != nil {
		t.Fatal(err)
	}
	p := f.lastMake
	if p.HWND != 0x1234 || p.TimeoutMS != 1500 || p.UserVerification != winwebauthn.WebAuthnUserVerificationRequirementRequired ||
		p.AttestationPref != winwebauthn.WebAuthnAttestationConveyancePreferenceDirect || !slices.Equal(p.Algorithms, []int32{-7, -257}) {
		t.Errorf("unexpected params %+v", p)
	}
}

func TestTimeoutMS(t *testing.T) {
	for d, want := range map[time.Duration]uint32{
		0: 60000, -time.Second: 60000, time.Microsecond: 1, 2 * time.Second: 2000, 1000 * time.Hour: 1<<32 - 1,
	} {
		if got := timeoutMS(d); got != want {
			t.Errorf("timeoutMS(%v) = %d, want %d", d, got, want)
		}
	}
}

func TestMapWinError(t *testing.T) {
	tests := []struct {
		op   string
		hr   int32
		want error
	}{
		{"MakeCredential", winwebauthn.ERROR_CANCELLED, ErrUserCanceled},
		{"MakeCredential", winwebauthn.NTE_USER_CANCELLED, ErrUserCanceled},
		{"MakeCredential", winwebauthn.ERROR_TIMEOUT_WIN, ErrTimeout},
		{"MakeCredential", winwebauthn.NTE_EXISTS, ErrCredentialExcluded},
		{"MakeCredential", winwebauthn.NTE_NOT_SUPPORTED, ErrUnsupportedAlgorithm},
		{"GetAssertion", winwebauthn.NTE_NOT_FOUND, ErrNoCredentials},
		{"GetAssertion", winwebauthn.NTE_INVALID_PARAMETER, ErrInvalidParameter},
	}
	for _, tt := range tests {
		if got := mapWinError(hrErr(tt.op, tt.hr)); !errors.Is(got, tt.want) {
			t.Errorf("%s 0x%08X: got %v, want %v", tt.op, uint32(tt.hr), got, tt.want)
		}
	}
	var pe *PlatformError
	if err := mapWinError(hrErr("GetAssertion", winwebauthn.NTE_NOT_SUPPORTED)); !errors.As(err, &pe) {
		t.Errorf("NotSupported outside MakeCredential: %v", err)
	}
	if err := mapWinError(context.DeadlineExceeded); !errors.Is(err, ErrTimeout) {
		t.Errorf("deadline: %v", err)
	}
}

// TestWindowsAvailableSmoke calls the real webauthn.dll.
func TestWindowsAvailableSmoke(t *testing.T) {
	a := &windowsAuthenticator{cfg: newConfig(nil), api: systemWinAPI}
	info, err := a.Available(t.Context())
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	t.Logf("Available = %+v", info)
}
