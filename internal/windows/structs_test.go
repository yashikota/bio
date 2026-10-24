//go:build windows

package winwebauthn

import (
	"errors"
	"testing"
	"unsafe"
)

// The expected sizes and offsets are those of the C structs in webauthn.h
// (Windows SDK) on 64-bit Windows. A wrong field order or a missing field
// shifts everything after it, and the DLL then reads garbage.
func TestStructLayout64(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("layout table is for 64-bit Windows")
	}
	type field struct {
		name string
		got  uintptr
		want uintptr
	}
	var (
		rp   RPEntityInformation
		user UserEntityInformation
		cp   CoseCredentialParameter
		cps  CoseCredentialParameters
		cd   ClientData
		cr   Credential
		crs  Credentials
		crx  CredentialEx
		crl  CredentialList
		ext  Extensions
		mco  AuthMakeCredentialOptions
		gao  AuthGetAssertionOptions
		att  CredentialAttestation
		asr  Assertion
		guid GUID
	)
	checks := []field{
		{"RPEntityInformation", unsafe.Sizeof(rp), 32},
		{"RPEntityInformation.ID", unsafe.Offsetof(rp.ID), 8},
		{"RPEntityInformation.Icon", unsafe.Offsetof(rp.Icon), 24},

		{"UserEntityInformation", unsafe.Sizeof(user), 40},
		{"UserEntityInformation.ID", unsafe.Offsetof(user.ID), 8},
		{"UserEntityInformation.DisplayName", unsafe.Offsetof(user.DisplayName), 32},

		{"CoseCredentialParameter", unsafe.Sizeof(cp), 24},
		{"CoseCredentialParameter.Algorithm", unsafe.Offsetof(cp.Algorithm), 16},
		{"CoseCredentialParameters", unsafe.Sizeof(cps), 16},

		{"ClientData", unsafe.Sizeof(cd), 24},
		{"ClientData.PBClientData", unsafe.Offsetof(cd.PBClientData), 8},
		{"ClientData.HashAlgID", unsafe.Offsetof(cd.HashAlgID), 16},

		{"Credential", unsafe.Sizeof(cr), 24},
		{"Credentials", unsafe.Sizeof(crs), 16},
		{"CredentialEx", unsafe.Sizeof(crx), 32},
		{"CredentialEx.Transport", unsafe.Offsetof(crx.Transport), 24},
		{"CredentialList", unsafe.Sizeof(crl), 16},
		{"Extensions", unsafe.Sizeof(ext), 16},

		{"AuthMakeCredentialOptions", unsafe.Sizeof(mco), 80},
		{"AuthMakeCredentialOptions.CredentialList", unsafe.Offsetof(mco.CredentialList), 8},
		{"AuthMakeCredentialOptions.Extensions", unsafe.Offsetof(mco.Extensions), 24},
		{"AuthMakeCredentialOptions.AuthenticatorAttachment", unsafe.Offsetof(mco.AuthenticatorAttachment), 40},
		{"AuthMakeCredentialOptions.UserVerificationRequirement", unsafe.Offsetof(mco.UserVerificationRequirement), 48},
		{"AuthMakeCredentialOptions.Flags", unsafe.Offsetof(mco.Flags), 56},
		{"AuthMakeCredentialOptions.CancellationID", unsafe.Offsetof(mco.CancellationID), 64},
		{"AuthMakeCredentialOptions.ExcludeCredentialList", unsafe.Offsetof(mco.ExcludeCredentialList), 72},

		{"AuthGetAssertionOptions", unsafe.Sizeof(gao), 88},
		{"AuthGetAssertionOptions.UserVerificationRequirement", unsafe.Offsetof(gao.UserVerificationRequirement), 44},
		{"AuthGetAssertionOptions.U2FAppID", unsafe.Offsetof(gao.U2FAppID), 56},
		{"AuthGetAssertionOptions.CancellationID", unsafe.Offsetof(gao.CancellationID), 72},
		{"AuthGetAssertionOptions.AllowCredentialList", unsafe.Offsetof(gao.AllowCredentialList), 80},

		{"CredentialAttestation", unsafe.Sizeof(att), 120},
		{"CredentialAttestation.AuthenticatorData", unsafe.Offsetof(att.AuthenticatorData), 24},
		{"CredentialAttestation.AttestationDecode", unsafe.Offsetof(att.AttestationDecode), 56},
		{"CredentialAttestation.AttestationObject", unsafe.Offsetof(att.AttestationObject), 72},
		{"CredentialAttestation.CredentialID", unsafe.Offsetof(att.CredentialID), 88},
		{"CredentialAttestation.Extensions", unsafe.Offsetof(att.Extensions), 96},
		{"CredentialAttestation.Transport", unsafe.Offsetof(att.Transport), 112},

		{"Assertion", unsafe.Sizeof(asr), 72},
		{"Assertion.Signature", unsafe.Offsetof(asr.Signature), 24},
		{"Assertion.Credential", unsafe.Offsetof(asr.Credential), 32},
		{"Assertion.UserIDLen", unsafe.Offsetof(asr.UserIDLen), 56},
		{"Assertion.UserID", unsafe.Offsetof(asr.UserID), 64},

		{"GUID", unsafe.Sizeof(guid), 16},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestHRESULTToError(t *testing.T) {
	tests := []struct {
		hr   int32
		want WinErrorKind
	}{
		{ERROR_CANCELLED, WinErrUserCanceled},
		{NTE_USER_CANCELLED, WinErrUserCanceled},
		{ERROR_TIMEOUT_WIN, WinErrTimeout},
		{NTE_INVALID_PARAMETER, WinErrInvalidParam},
		{E_INVALIDARG, WinErrInvalidParam},
		{ERROR_NOT_FOUND, WinErrNoCredentials},
		{NTE_NOT_FOUND, WinErrNoCredentials},
		{NTE_EXISTS, WinErrExists},
		{NTE_NOT_SUPPORTED, WinErrNotSupported},
		{-1, WinErrPlatform},
	}
	for _, tt := range tests {
		err := HRESULTToError("op", uintptr(uint32(tt.hr)))
		we := &WinError{}
		ok := errors.As(err, &we)
		if !ok || we.Kind != tt.want || we.HR != uint32(tt.hr) {
			t.Errorf("HRESULT 0x%08X: got %v, want kind %v", uint32(tt.hr), err, tt.want)
		}
	}
	if err := HRESULTToError("op", S_OK); err != nil {
		t.Errorf("S_OK: %v", err)
	}
}

// TestDLLSmoke loads webauthn.dll on the CI runner. Windows Server has the
// DLL but usually no Windows Hello, so only "does not crash" is checked.
func TestDLLSmoke(t *testing.T) {
	v := APIVersionNumber()
	t.Logf("WebAuthn API version %d", v)
	if v == 0 {
		t.Skip("webauthn.dll not present")
	}
	if _, err := IsAvailable(); err != nil {
		t.Errorf("IsAvailable: %v", err)
	}
}

func TestUTF16(t *testing.T) {
	if UTF16PtrFromString("") != nil {
		t.Error("empty string should map to nil")
	}
	if got := GoStringFromUTF16Ptr(UTF16PtrFromString("例え")); got != "例え" {
		t.Errorf("round trip = %q", got)
	}
}
