//go:build darwin

package darwin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// CoreFoundation / Security types (opaque pointers).
type cfTypeRef uintptr
type cfStringRef cfTypeRef
type cfDataRef cfTypeRef
type cfDictionaryRef cfTypeRef
type cfMutableDictionaryRef cfTypeRef
type cfNumberRef cfTypeRef
type cfErrorRef cfTypeRef
type secKeyRef cfTypeRef
type secAccessControlRef cfTypeRef

var (
	secOnce sync.Once
	secErr  error

	fnCFStringCreateWithCString         func(alloc, cStr uintptr, encoding uint32) cfStringRef
	fnCFDataCreate                      func(alloc uintptr, bytes uintptr, length int) cfDataRef
	fnCFDictionaryCreateMutable         func(alloc uintptr, capacity int, keyCallBacks, valueCallBacks uintptr) cfMutableDictionaryRef
	fnCFDictionaryAddValue              func(dict cfMutableDictionaryRef, key, value uintptr)
	fnCFNumberCreate                    func(alloc uintptr, theType int, valuePtr uintptr) cfNumberRef
	fnCFRelease                         func(cf cfTypeRef)
	fnCFDataGetBytePtr                  func(data cfDataRef) uintptr
	fnCFDataGetLength                   func(data cfDataRef) int
	fnCFErrorGetCode                    func(err cfErrorRef) int64
	fnCFErrorCopyDescription            func(err cfErrorRef) cfStringRef
	fnCFStringGetLength                 func(s cfStringRef) int
	fnCFStringGetMaximumSizeForEncoding func(length int, encoding uint32) int
	fnCFStringGetCString                func(s cfStringRef, buf uintptr, bufSize int, encoding uint32) bool

	fnSecAccessControlCreateWithFlags  func(alloc uintptr, protection uintptr, flags uint64, err *cfErrorRef) secAccessControlRef
	fnSecKeyCreateRandomKey            func(parameters cfDictionaryRef, err *cfErrorRef) secKeyRef
	fnSecKeyCopyPublicKey              func(key secKeyRef) secKeyRef
	fnSecKeyCopyExternalRepresentation func(key secKeyRef, err *cfErrorRef) cfDataRef
	fnSecKeyCreateSignature            func(key secKeyRef, algorithm cfStringRef, dataToSign cfDataRef, err *cfErrorRef) cfDataRef
	fnSecItemDelete                    func(query cfDictionaryRef) int32
	fnSecItemCopyMatching              func(query cfDictionaryRef, result *uintptr) int32
	fnSecItemAdd                       func(attrs cfDictionaryRef, result *uintptr) int32

	// Constants loaded with Dlsym.
	kCFAllocatorDefault                             uintptr
	kCFBooleanTrue                                  uintptr
	kCFTypeDictionaryKeyCallBacks                   uintptr
	kCFTypeDictionaryValueCallBacks                 uintptr
	kSecAttrKeyType                                 uintptr
	kSecAttrKeyTypeECSECPrimeRandom                 uintptr
	kSecAttrKeySizeInBits                           uintptr
	kSecAttrKeyClass                                uintptr
	kSecAttrKeyClassPrivate                         uintptr
	kSecAttrTokenID                                 uintptr
	kSecAttrTokenIDSecureEnclave                    uintptr
	kSecAttrAccessControl                           uintptr
	kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly uintptr
	kSecAttrLabel                                   uintptr
	kSecAttrApplicationTag                          uintptr
	kSecAttrIsPermanent                             uintptr
	kSecAttrService                                 uintptr
	kSecAttrAccount                                 uintptr
	kSecPrivateKeyAttrs                             uintptr
	kSecUseDataProtectionKeychain                   uintptr
	kSecUseAuthenticationContext                    uintptr
	kSecKeyAlgorithmECDSASignatureMessageX962SHA256 uintptr
	kSecClass                                       uintptr
	kSecClassKey                                    uintptr
	kSecClassGenericPassword                        uintptr
	kSecReturnRef                                   uintptr
	kSecReturnData                                  uintptr
	kSecValueData                                   uintptr
	kSecMatchLimit                                  uintptr
	kSecMatchLimitOne                               uintptr
)

const (
	kCFStringEncodingUTF8 = uint32(0x08000100)
	kCFNumberSInt32Type   = 3

	// SecAccessControlCreateFlags (CF_OPTIONS, not exported as symbols). Source: Security/SecAccessControl.h
	kSecAccessControlBiometryCurrentSet uint64 = 1 << 3
	kSecAccessControlPrivateKeyUsage    uint64 = 1 << 30
)

// OSStatus values.
const (
	errSecSuccess            = int32(0)
	errSecDuplicateItem      = int32(-25299)
	errSecItemNotFound       = int32(-25300)
	errSecMissingEntitlement = int64(-34018)
)

func loadSecurity() error {
	secOnce.Do(func() {
		if err := loadMemcpy(); err != nil {
			secErr = fmt.Errorf("darwin: load libSystem: %w", err)
			return
		}
		cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			secErr = fmt.Errorf("darwin: load CoreFoundation: %w", err)
			return
		}
		sec, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			secErr = fmt.Errorf("darwin: load Security: %w", err)
			return
		}

		purego.RegisterLibFunc(&fnCFStringCreateWithCString, cf, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&fnCFDataCreate, cf, "CFDataCreate")
		purego.RegisterLibFunc(&fnCFDictionaryCreateMutable, cf, "CFDictionaryCreateMutable")
		purego.RegisterLibFunc(&fnCFDictionaryAddValue, cf, "CFDictionaryAddValue")
		purego.RegisterLibFunc(&fnCFNumberCreate, cf, "CFNumberCreate")
		purego.RegisterLibFunc(&fnCFRelease, cf, "CFRelease")
		purego.RegisterLibFunc(&fnCFDataGetBytePtr, cf, "CFDataGetBytePtr")
		purego.RegisterLibFunc(&fnCFDataGetLength, cf, "CFDataGetLength")
		purego.RegisterLibFunc(&fnCFErrorGetCode, cf, "CFErrorGetCode")
		purego.RegisterLibFunc(&fnCFErrorCopyDescription, cf, "CFErrorCopyDescription")
		purego.RegisterLibFunc(&fnCFStringGetLength, cf, "CFStringGetLength")
		purego.RegisterLibFunc(&fnCFStringGetMaximumSizeForEncoding, cf, "CFStringGetMaximumSizeForEncoding")
		purego.RegisterLibFunc(&fnCFStringGetCString, cf, "CFStringGetCString")

		purego.RegisterLibFunc(&fnSecAccessControlCreateWithFlags, sec, "SecAccessControlCreateWithFlags")
		purego.RegisterLibFunc(&fnSecKeyCreateRandomKey, sec, "SecKeyCreateRandomKey")
		purego.RegisterLibFunc(&fnSecKeyCopyPublicKey, sec, "SecKeyCopyPublicKey")
		purego.RegisterLibFunc(&fnSecKeyCopyExternalRepresentation, sec, "SecKeyCopyExternalRepresentation")
		purego.RegisterLibFunc(&fnSecKeyCreateSignature, sec, "SecKeyCreateSignature")
		purego.RegisterLibFunc(&fnSecItemDelete, sec, "SecItemDelete")
		purego.RegisterLibFunc(&fnSecItemCopyMatching, sec, "SecItemCopyMatching")
		purego.RegisterLibFunc(&fnSecItemAdd, sec, "SecItemAdd")

		// Pointer-typed constants (CFStringRef etc.): Dlsym returns the
		// variable's address, which holds the value.
		ptrs := []struct {
			dst    *uintptr
			handle uintptr
			name   string
		}{
			{&kCFAllocatorDefault, cf, "kCFAllocatorDefault"},
			{&kCFBooleanTrue, cf, "kCFBooleanTrue"},
			{&kSecAttrKeyType, sec, "kSecAttrKeyType"},
			{&kSecAttrKeyTypeECSECPrimeRandom, sec, "kSecAttrKeyTypeECSECPrimeRandom"},
			{&kSecAttrKeySizeInBits, sec, "kSecAttrKeySizeInBits"},
			{&kSecAttrKeyClass, sec, "kSecAttrKeyClass"},
			{&kSecAttrKeyClassPrivate, sec, "kSecAttrKeyClassPrivate"},
			{&kSecAttrTokenID, sec, "kSecAttrTokenID"},
			{&kSecAttrTokenIDSecureEnclave, sec, "kSecAttrTokenIDSecureEnclave"},
			{&kSecAttrAccessControl, sec, "kSecAttrAccessControl"},
			{&kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, sec, "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"},
			{&kSecAttrLabel, sec, "kSecAttrLabel"},
			{&kSecAttrApplicationTag, sec, "kSecAttrApplicationTag"},
			{&kSecAttrIsPermanent, sec, "kSecAttrIsPermanent"},
			{&kSecAttrService, sec, "kSecAttrService"},
			{&kSecAttrAccount, sec, "kSecAttrAccount"},
			{&kSecPrivateKeyAttrs, sec, "kSecPrivateKeyAttrs"},
			{&kSecUseDataProtectionKeychain, sec, "kSecUseDataProtectionKeychain"},
			{&kSecUseAuthenticationContext, sec, "kSecUseAuthenticationContext"},
			{&kSecKeyAlgorithmECDSASignatureMessageX962SHA256, sec, "kSecKeyAlgorithmECDSASignatureMessageX962SHA256"},
			{&kSecClass, sec, "kSecClass"},
			{&kSecClassKey, sec, "kSecClassKey"},
			{&kSecClassGenericPassword, sec, "kSecClassGenericPassword"},
			{&kSecReturnRef, sec, "kSecReturnRef"},
			{&kSecReturnData, sec, "kSecReturnData"},
			{&kSecValueData, sec, "kSecValueData"},
			{&kSecMatchLimit, sec, "kSecMatchLimit"},
			{&kSecMatchLimitOne, sec, "kSecMatchLimitOne"},
		}
		for _, p := range ptrs {
			sym, err := purego.Dlsym(p.handle, p.name)
			if err != nil {
				secErr = fmt.Errorf("darwin: Dlsym %s: %w", p.name, err)
				return
			}
			*p.dst = derefUintptr(sym)
		}
		// The dictionary callbacks are structs: their address is the value. Do not dereference.
		for _, p := range []struct {
			dst  *uintptr
			name string
		}{
			{&kCFTypeDictionaryKeyCallBacks, "kCFTypeDictionaryKeyCallBacks"},
			{&kCFTypeDictionaryValueCallBacks, "kCFTypeDictionaryValueCallBacks"},
		} {
			sym, err := purego.Dlsym(cf, p.name)
			if err != nil {
				secErr = fmt.Errorf("darwin: Dlsym %s: %w", p.name, err)
				return
			}
			*p.dst = sym
		}
	})
	return secErr
}

func release(ref cfTypeRef) {
	if ref != 0 {
		fnCFRelease(ref)
	}
}

// cfStringToGo copies a CFString into a Go string.
func cfStringToGo(s cfStringRef) string {
	if s == 0 {
		return ""
	}
	size := fnCFStringGetMaximumSizeForEncoding(fnCFStringGetLength(s), kCFStringEncodingUTF8) + 1
	buf := make([]byte, size)
	if !fnCFStringGetCString(s, uintptr(unsafe.Pointer(&buf[0])), size, kCFStringEncodingUTF8) {
		return ""
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// cfErr converts a CFErrorRef into a SecError and releases it.
func cfErr(op string, e cfErrorRef) error {
	if e == 0 {
		return &SecError{Op: op, Desc: "unknown error"}
	}
	defer release(cfTypeRef(e))
	se := &SecError{Op: op, Status: fnCFErrorGetCode(e)}
	if desc := fnCFErrorCopyDescription(e); desc != 0 {
		se.Desc = cfStringToGo(desc)
		release(cfTypeRef(desc))
	}
	return se
}

func cfString(s string) cfStringRef {
	cstr := append([]byte(s), 0)
	return fnCFStringCreateWithCString(kCFAllocatorDefault, uintptr(unsafe.Pointer(&cstr[0])), kCFStringEncodingUTF8)
}

func cfData(b []byte) cfDataRef {
	if len(b) == 0 {
		return fnCFDataCreate(kCFAllocatorDefault, 0, 0)
	}
	return fnCFDataCreate(kCFAllocatorDefault, uintptr(unsafe.Pointer(&b[0])), len(b))
}

// cfDataToBytes copies CFData into Go memory and releases it.
func cfDataToBytes(data cfDataRef) []byte {
	if data == 0 {
		return nil
	}
	defer release(cfTypeRef(data))
	return copyBytesFromC(fnCFDataGetBytePtr(data), fnCFDataGetLength(data))
}

func cfInt32(n int32) cfNumberRef {
	return fnCFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, uintptr(unsafe.Pointer(&n)))
}

// dict is a CFMutableDictionary that also owns the CF objects added to it.
type dict struct {
	ref   cfMutableDictionaryRef
	owned []cfTypeRef
}

func newDict() *dict {
	return &dict{ref: fnCFDictionaryCreateMutable(kCFAllocatorDefault, 0, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)}
}

func (d *dict) set(key, value uintptr) *dict {
	fnCFDictionaryAddValue(d.ref, key, value)
	return d
}

// setOwned adds a CF object that the dictionary's owner created and must release.
func (d *dict) setOwned(key uintptr, value cfTypeRef) *dict {
	d.owned = append(d.owned, value)
	return d.set(key, uintptr(value))
}

func (d *dict) release() {
	for _, o := range d.owned {
		release(o)
	}
	release(cfTypeRef(d.ref))
}

func (d *dict) cf() cfDictionaryRef { return cfDictionaryRef(d.ref) }

// KeyOptions selects where a key lives.
type KeyOptions struct {
	// SecureEnclave creates the key in the Secure Enclave, usable only after
	// biometric authentication (needs a signed app with the
	// keychain-access-groups entitlement). Otherwise the key is a software key
	// in the login Keychain without an OS-enforced access policy.
	SecureEnclave bool
}

// CreateKey creates a permanent EC P-256 private key tagged with tag and
// returns its uncompressed public point.
func CreateKey(label string, tag []byte, opts KeyOptions) ([]byte, error) {
	if err := loadSecurity(); err != nil {
		return nil, err
	}
	privAttrs := newDict()
	defer privAttrs.release()
	privAttrs.set(kSecAttrIsPermanent, kCFBooleanTrue).
		setOwned(kSecAttrApplicationTag, cfTypeRef(cfData(tag))).
		setOwned(kSecAttrLabel, cfTypeRef(cfString(label)))

	params := newDict()
	defer params.release()
	params.set(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom).
		setOwned(kSecAttrKeySizeInBits, cfTypeRef(cfInt32(256)))

	if opts.SecureEnclave {
		var acErr cfErrorRef
		ac := fnSecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
			kSecAccessControlBiometryCurrentSet|kSecAccessControlPrivateKeyUsage, &acErr)
		if ac == 0 {
			return nil, cfErr("SecAccessControlCreateWithFlags", acErr)
		}
		privAttrs.setOwned(kSecAttrAccessControl, cfTypeRef(ac))
		params.set(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave).
			set(kSecUseDataProtectionKeychain, kCFBooleanTrue)
	}
	params.set(kSecPrivateKeyAttrs, uintptr(privAttrs.ref))

	var keyErr cfErrorRef
	key := fnSecKeyCreateRandomKey(params.cf(), &keyErr)
	if key == 0 {
		return nil, cfErr("SecKeyCreateRandomKey", keyErr)
	}
	defer release(cfTypeRef(key))
	raw, err := publicKeyRaw(key)
	if err != nil {
		_ = DeleteKey(tag, opts)
		return nil, err
	}
	return raw, nil
}

// publicKeyRaw returns the 65-byte uncompressed public point of a private key.
func publicKeyRaw(priv secKeyRef) ([]byte, error) {
	pub := fnSecKeyCopyPublicKey(priv)
	if pub == 0 {
		return nil, &SecError{Op: "SecKeyCopyPublicKey", Desc: "no public key"}
	}
	defer release(cfTypeRef(pub))
	var exportErr cfErrorRef
	data := fnSecKeyCopyExternalRepresentation(pub, &exportErr)
	if data == 0 {
		return nil, cfErr("SecKeyCopyExternalRepresentation", exportErr)
	}
	raw := cfDataToBytes(data)
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, &SecError{Op: "SecKeyCopyExternalRepresentation", Desc: fmt.Sprintf("unexpected public key format (len=%d)", len(raw))}
	}
	return raw, nil
}

func keyQuery(tag []byte, opts KeyOptions) *dict {
	q := newDict()
	q.set(kSecClass, kSecClassKey).
		set(kSecAttrKeyClass, kSecAttrKeyClassPrivate).
		setOwned(kSecAttrApplicationTag, cfTypeRef(cfData(tag)))
	if opts.SecureEnclave {
		q.set(kSecUseDataProtectionKeychain, kCFBooleanTrue)
	}
	return q
}

// KeyExists reports whether a private key with tag exists, without authenticating.
func KeyExists(tag []byte, opts KeyOptions) (bool, error) {
	if err := loadSecurity(); err != nil {
		return false, err
	}
	q := keyQuery(tag, opts)
	defer q.release()
	q.set(kSecMatchLimit, kSecMatchLimitOne)
	switch status := fnSecItemCopyMatching(q.cf(), nil); status {
	case errSecSuccess:
		return true, nil
	case errSecItemNotFound:
		return false, nil
	default:
		return false, &SecError{Op: "SecItemCopyMatching", Status: int64(status)}
	}
}

// Sign signs data with ECDSA-SHA256 using the key tagged tag and returns a
// DER signature. auth, when non-nil, is an LAContext the user already
// authenticated, which a Secure Enclave key requires instead of prompting again.
func Sign(tag []byte, opts KeyOptions, auth *LAContext, data []byte) ([]byte, error) {
	if err := loadSecurity(); err != nil {
		return nil, err
	}
	q := keyQuery(tag, opts)
	defer q.release()
	q.set(kSecReturnRef, kCFBooleanTrue).set(kSecMatchLimit, kSecMatchLimitOne)
	if auth != nil && opts.SecureEnclave {
		q.set(kSecUseAuthenticationContext, uintptr(auth.ID()))
	}
	var result uintptr
	switch status := fnSecItemCopyMatching(q.cf(), &result); status {
	case errSecSuccess:
	case errSecItemNotFound:
		return nil, ErrNotFound
	default:
		return nil, &SecError{Op: "SecItemCopyMatching", Status: int64(status)}
	}
	key := secKeyRef(result)
	defer release(cfTypeRef(key))

	in := cfData(data)
	defer release(cfTypeRef(in))
	var sigErr cfErrorRef
	sig := fnSecKeyCreateSignature(key, cfStringRef(kSecKeyAlgorithmECDSASignatureMessageX962SHA256), in, &sigErr)
	if sig == 0 {
		return nil, cfErr("SecKeyCreateSignature", sigErr)
	}
	return cfDataToBytes(sig), nil
}

// DeleteKey deletes the private key tagged tag. It returns ErrNotFound if there is none.
func DeleteKey(tag []byte, opts KeyOptions) error {
	if err := loadSecurity(); err != nil {
		return err
	}
	q := keyQuery(tag, opts)
	defer q.release()
	return deleteStatus(fnSecItemDelete(q.cf()))
}

func deleteStatus(status int32) error {
	switch status {
	case errSecSuccess:
		return nil
	case errSecItemNotFound:
		return ErrNotFound
	default:
		return &SecError{Op: "SecItemDelete", Status: int64(status)}
	}
}

// The user handle is kept in a generic password item next to the key,
// because key items have no attribute for arbitrary data.

func dataQuery(service string, account []byte, opts KeyOptions) *dict {
	q := newDict()
	q.set(kSecClass, kSecClassGenericPassword).
		setOwned(kSecAttrService, cfTypeRef(cfString(service))).
		setOwned(kSecAttrAccount, cfTypeRef(cfString(base64.RawURLEncoding.EncodeToString(account))))
	if opts.SecureEnclave {
		q.set(kSecUseDataProtectionKeychain, kCFBooleanTrue)
	}
	return q
}

// StoreData stores value under (service, account), replacing any existing item.
func StoreData(service string, account, value []byte, opts KeyOptions) error {
	if err := loadSecurity(); err != nil {
		return err
	}
	if err := DeleteData(service, account, opts); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	q := dataQuery(service, account, opts)
	defer q.release()
	q.setOwned(kSecValueData, cfTypeRef(cfData(value)))
	if status := fnSecItemAdd(q.cf(), nil); status != errSecSuccess {
		return &SecError{Op: "SecItemAdd", Status: int64(status)}
	}
	return nil
}

// LoadData returns the value stored under (service, account), or ErrNotFound.
func LoadData(service string, account []byte, opts KeyOptions) ([]byte, error) {
	if err := loadSecurity(); err != nil {
		return nil, err
	}
	q := dataQuery(service, account, opts)
	defer q.release()
	q.set(kSecReturnData, kCFBooleanTrue).set(kSecMatchLimit, kSecMatchLimitOne)
	var result uintptr
	switch status := fnSecItemCopyMatching(q.cf(), &result); status {
	case errSecSuccess:
		return cfDataToBytes(cfDataRef(result)), nil
	case errSecItemNotFound:
		return nil, ErrNotFound
	default:
		return nil, &SecError{Op: "SecItemCopyMatching", Status: int64(status)}
	}
}

// DeleteData deletes the item under (service, account). It returns ErrNotFound if there is none.
func DeleteData(service string, account []byte, opts KeyOptions) error {
	if err := loadSecurity(); err != nil {
		return err
	}
	q := dataQuery(service, account, opts)
	defer q.release()
	return deleteStatus(fnSecItemDelete(q.cf()))
}

// KeychainTag builds the application tag for a credential.
func KeychainTag(namespace, rpID string, credentialID []byte) []byte {
	tag := []byte(namespace + ":" + rpID + ":")
	return append(tag, credentialID...)
}
