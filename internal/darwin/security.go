//go:build darwin

package darwin

import (
	"crypto/rand"
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
	secOnce   sync.Once
	secErr    error
	cfHandle  uintptr
	secHandle uintptr

	// CoreFoundation functions
	fnCFStringCreateWithCString func(alloc, cStr uintptr, encoding uint32) cfStringRef
	fnCFDataCreate              func(alloc uintptr, bytes uintptr, length int) cfDataRef
	fnCFDictionaryCreateMutable func(alloc uintptr, capacity int, keyCallBacks, valueCallBacks uintptr) cfMutableDictionaryRef
	fnCFDictionaryAddValue      func(dict cfMutableDictionaryRef, key, value uintptr)
	fnCFNumberCreate            func(alloc uintptr, theType int, valuePtr uintptr) cfNumberRef
	fnCFRelease                 func(cf cfTypeRef)
	fnCFDataGetBytePtr          func(data cfDataRef) uintptr
	fnCFDataGetLength           func(data cfDataRef) int

	// Security functions
	fnSecAccessControlCreateWithFlags  func(alloc uintptr, protection uintptr, flags uint64, err *cfErrorRef) secAccessControlRef
	fnSecKeyCreateRandomKey            func(parameters cfDictionaryRef, err *cfErrorRef) secKeyRef
	fnSecKeyCopyPublicKey              func(key secKeyRef) secKeyRef
	fnSecKeyCopyExternalRepresentation func(key secKeyRef, err *cfErrorRef) cfDataRef
	fnSecKeyCreateSignature            func(key secKeyRef, algorithm cfStringRef, dataToSign cfDataRef, err *cfErrorRef) cfDataRef
	fnSecItemDelete                    func(query cfDictionaryRef) int32
	fnSecItemCopyMatching              func(query cfDictionaryRef, result *uintptr) int32
	fnSecItemAdd                       func(attrs cfDictionaryRef, result *uintptr) int32

	// CFError inspection
	fnCFErrorGetCode         func(err cfErrorRef) int64
	fnCFErrorCopyDescription func(err cfErrorRef) cfStringRef
	fnCFStringGetCString     func(s cfStringRef, buf uintptr, bufSize int, encoding uint32) bool

	// CF constants loaded via Dlsym
	kCFAllocatorDefault                             uintptr
	kSecAttrKeyTypeECSECPrimeRandom                 uintptr
	kSecAttrTokenIDSecureEnclave                    uintptr
	kSecAttrKeyType                                 uintptr
	kSecAttrKeySizeInBits                           uintptr
	kSecAttrTokenID                                 uintptr
	kSecAttrAccessControl                           uintptr
	kSecAttrLabel                                   uintptr
	kSecAttrApplicationTag                          uintptr
	kSecAttrIsPermanent                             uintptr
	kSecUseDataProtectionKeychain                   uintptr
	kCFBooleanTrue                                  uintptr
	kCFBooleanFalse                                 uintptr
	kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly uintptr
	kSecKeyAlgorithmECDSASignatureMessageX962SHA256 uintptr
	kSecPrivateKeyAttrs                             uintptr

	// CF dictionary callbacks (must be passed to CFDictionaryCreateMutable)
	kCFTypeDictionaryKeyCallBacks   uintptr
	kCFTypeDictionaryValueCallBacks uintptr

	// For Keychain queries
	kSecClass         uintptr
	kSecClassKey      uintptr
	kSecReturnRef     uintptr
	kSecMatchLimit    uintptr
	kSecMatchLimitOne uintptr
	kSecValueRef      uintptr
)

const (
	kCFStringEncodingUTF8 = uint32(0x08000100)
	kCFNumberSInt32Type   = 3

	// SecAccessControlCreateFlags enum values (CF_OPTIONS, not exported as dylib symbols).
	// Source: Security/SecAccessControl.h
	kSecAccessControlBiometryAny        uint64 = 1 << 1 // kSecAccessControlTouchIDAny renamed
	kSecAccessControlBiometryCurrentSet uint64 = 1 << 3 // kSecAccessControlTouchIDCurrentSet renamed
	kSecAccessControlPrivateKeyUsage    uint64 = 1 << 30
)

// OSStatus values.
const (
	errSecSuccess      = int32(0)
	errSecItemNotFound = int32(-25300)
)

func loadSecurity() {
	secOnce.Do(func() {
		var err error
		cfHandle, err = purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			secErr = fmt.Errorf("darwin: load CoreFoundation: %w", err)
			return
		}
		secHandle, err = purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			secErr = fmt.Errorf("darwin: load Security: %w", err)
			return
		}

		purego.RegisterLibFunc(&fnCFStringCreateWithCString, cfHandle, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&fnCFDataCreate, cfHandle, "CFDataCreate")
		purego.RegisterLibFunc(&fnCFDictionaryCreateMutable, cfHandle, "CFDictionaryCreateMutable")
		purego.RegisterLibFunc(&fnCFDictionaryAddValue, cfHandle, "CFDictionaryAddValue")
		purego.RegisterLibFunc(&fnCFNumberCreate, cfHandle, "CFNumberCreate")
		purego.RegisterLibFunc(&fnCFRelease, cfHandle, "CFRelease")
		purego.RegisterLibFunc(&fnCFDataGetBytePtr, cfHandle, "CFDataGetBytePtr")
		purego.RegisterLibFunc(&fnCFDataGetLength, cfHandle, "CFDataGetLength")

		purego.RegisterLibFunc(&fnSecAccessControlCreateWithFlags, secHandle, "SecAccessControlCreateWithFlags")
		purego.RegisterLibFunc(&fnSecKeyCreateRandomKey, secHandle, "SecKeyCreateRandomKey")
		purego.RegisterLibFunc(&fnSecKeyCopyPublicKey, secHandle, "SecKeyCopyPublicKey")
		purego.RegisterLibFunc(&fnSecKeyCopyExternalRepresentation, secHandle, "SecKeyCopyExternalRepresentation")
		purego.RegisterLibFunc(&fnSecKeyCreateSignature, secHandle, "SecKeyCreateSignature")
		purego.RegisterLibFunc(&fnSecItemDelete, secHandle, "SecItemDelete")
		purego.RegisterLibFunc(&fnSecItemCopyMatching, secHandle, "SecItemCopyMatching")
		purego.RegisterLibFunc(&fnSecItemAdd, secHandle, "SecItemAdd")
		purego.RegisterLibFunc(&fnCFErrorGetCode, cfHandle, "CFErrorGetCode")
		purego.RegisterLibFunc(&fnCFErrorCopyDescription, cfHandle, "CFErrorCopyDescription")
		purego.RegisterLibFunc(&fnCFStringGetCString, cfHandle, "CFStringGetCString")

		// loadPtr loads a pointer-type CF/Sec constant (CFStringRef, etc.).
		// Dlsym returns the address of the symbol; we dereference to get the actual value.
		// derefUintptr is implemented in assembly to avoid go vet unsafeptr false positive.
		loadPtr := func(handle uintptr, name string) uintptr {
			sym, err := purego.Dlsym(handle, name)
			if err != nil {
				secErr = fmt.Errorf("darwin: Dlsym %s: %w", name, err)
				return 0
			}
			return derefUintptr(sym)
		}

		kCFAllocatorDefault = loadPtr(cfHandle, "kCFAllocatorDefault")
		kCFBooleanTrue = loadPtr(cfHandle, "kCFBooleanTrue")
		kCFBooleanFalse = loadPtr(cfHandle, "kCFBooleanFalse")
		kSecAttrKeyTypeECSECPrimeRandom = loadPtr(secHandle, "kSecAttrKeyTypeECSECPrimeRandom")
		kSecAttrTokenIDSecureEnclave = loadPtr(secHandle, "kSecAttrTokenIDSecureEnclave")
		kSecAttrKeyType = loadPtr(secHandle, "kSecAttrKeyType")
		kSecAttrKeySizeInBits = loadPtr(secHandle, "kSecAttrKeySizeInBits")
		kSecAttrTokenID = loadPtr(secHandle, "kSecAttrTokenID")
		kSecAttrAccessControl = loadPtr(secHandle, "kSecAttrAccessControl")
		kSecAttrLabel = loadPtr(secHandle, "kSecAttrLabel")
		kSecAttrApplicationTag = loadPtr(secHandle, "kSecAttrApplicationTag")
		kSecAttrIsPermanent = loadPtr(secHandle, "kSecAttrIsPermanent")
		kSecUseDataProtectionKeychain = loadPtr(secHandle, "kSecUseDataProtectionKeychain")
		kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly = loadPtr(secHandle, "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly")
		kSecKeyAlgorithmECDSASignatureMessageX962SHA256 = loadPtr(secHandle, "kSecKeyAlgorithmECDSASignatureMessageX962SHA256")
		kSecPrivateKeyAttrs = loadPtr(secHandle, "kSecPrivateKeyAttrs")
		// kCFTypeDictionaryKeyCallBacks/ValueCallBacks are structs, not pointer-typed variables.
		// Dlsym returns the struct's address directly — do NOT dereference (unlike CFStringRef constants).
		sym, symErr := purego.Dlsym(cfHandle, "kCFTypeDictionaryKeyCallBacks")
		if symErr != nil {
			secErr = fmt.Errorf("darwin: Dlsym kCFTypeDictionaryKeyCallBacks: %w", symErr)
			return
		}
		kCFTypeDictionaryKeyCallBacks = sym
		sym, symErr = purego.Dlsym(cfHandle, "kCFTypeDictionaryValueCallBacks")
		if symErr != nil {
			secErr = fmt.Errorf("darwin: Dlsym kCFTypeDictionaryValueCallBacks: %w", symErr)
			return
		}
		kCFTypeDictionaryValueCallBacks = sym
		kSecClass = loadPtr(secHandle, "kSecClass")
		kSecClassKey = loadPtr(secHandle, "kSecClassKey")
		kSecReturnRef = loadPtr(secHandle, "kSecReturnRef")
		kSecMatchLimit = loadPtr(secHandle, "kSecMatchLimit")
		kSecMatchLimitOne = loadPtr(secHandle, "kSecMatchLimitOne")
		kSecValueRef = loadPtr(secHandle, "kSecValueRef")

	})
}

// cfErrorString extracts a human-readable description from a CFErrorRef.
func cfErrorString(e cfErrorRef) string {
	if e == 0 {
		return "unknown"
	}
	code := fnCFErrorGetCode(e)
	desc := fnCFErrorCopyDescription(e)
	if desc == 0 {
		return fmt.Sprintf("code=%d", code)
	}
	defer fnCFRelease(cfTypeRef(desc))
	buf := make([]byte, 256)
	fnCFStringGetCString(desc, uintptr(unsafe.Pointer(&buf[0])), len(buf), kCFStringEncodingUTF8)
	msg := string(buf[:])
	if i := len(msg); i > 0 {
		for i > 0 && msg[i-1] == 0 {
			i--
		}
		msg = msg[:i]
	}
	return fmt.Sprintf("code=%d %s", code, msg)
}

// cfString creates a CFStringRef from a Go string. Caller must CFRelease.
func cfString(s string) cfStringRef {
	cstr := append([]byte(s), 0)
	return fnCFStringCreateWithCString(kCFAllocatorDefault, uintptr(unsafe.Pointer(&cstr[0])), kCFStringEncodingUTF8)
}

// cfData creates a CFDataRef from a []byte. Caller must CFRelease.
func cfData(b []byte) cfDataRef {
	if len(b) == 0 {
		return fnCFDataCreate(kCFAllocatorDefault, 0, 0)
	}
	return fnCFDataCreate(kCFAllocatorDefault, uintptr(unsafe.Pointer(&b[0])), len(b))
}

// cfDataToBytes copies CFData contents to a Go []byte and releases the CFData.
// The CFDataGetBytePtr return value is a C pointer to CF-managed memory.
// We use a fixed-size array type routed through derefBytesN (assembly) to copy
// the bytes without triggering go vet unsafeptr on the C pointer.
func cfDataToBytes(data cfDataRef) []byte {
	if data == 0 {
		return nil
	}
	defer fnCFRelease(cfTypeRef(data))
	n := fnCFDataGetLength(data)
	if n == 0 {
		return nil
	}
	ptr := fnCFDataGetBytePtr(data)
	return copyBytesFromC(ptr, n)
}

// cfInt32 creates a CFNumberRef for an int32. Caller must CFRelease.
func cfInt32(n int32) cfNumberRef {
	return fnCFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, uintptr(unsafe.Pointer(&n)))
}

// cfMutableDict creates an empty CFMutableDictionary. Caller must CFRelease.
func cfMutableDict(capacity int) cfMutableDictionaryRef {
	return fnCFDictionaryCreateMutable(kCFAllocatorDefault, capacity, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)
}

// dictSet adds a key-value pair to a CFMutableDictionary.
func dictSet(dict cfMutableDictionaryRef, key, value uintptr) {
	fnCFDictionaryAddValue(dict, key, value)
}

// GenerateCredentialID generates a random 32-byte credential ID.
func GenerateCredentialID() ([]byte, error) {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("darwin: generate credential ID: %w", err)
	}
	return id, nil
}

// CreateBiometricKey creates an EC P-256 key stored in the default Keychain.
// Biometric verification is handled separately by the caller (LAContext.evaluatePolicy)
// before calling Sign. This avoids the keychain-access-groups entitlement required
// for Secure Enclave or access-control-bound keys.
// label is used as kSecAttrLabel. tag is used as kSecAttrApplicationTag for Keychain lookup.
// Returns the private key ref (caller must CFRelease via ReleaseKey).
func CreateBiometricKey(label string, tag []byte) (secKeyRef, error) {
	loadSecurity()
	if secErr != nil {
		return 0, secErr
	}

	cfLabel := cfString(label)
	defer fnCFRelease(cfTypeRef(cfLabel))

	cfTag := cfData(tag)
	defer fnCFRelease(cfTypeRef(cfTag))

	keySizeBits := cfInt32(256)
	defer fnCFRelease(cfTypeRef(keySizeBits))

	// Private key attributes: permanent storage, tagged for later lookup.
	privAttrs := cfMutableDict(4)
	defer fnCFRelease(cfTypeRef(privAttrs))
	dictSet(privAttrs, kSecAttrIsPermanent, kCFBooleanTrue)
	dictSet(privAttrs, kSecAttrApplicationTag, uintptr(cfTag))
	dictSet(privAttrs, kSecAttrLabel, uintptr(cfLabel))

	params := cfMutableDict(5)
	defer fnCFRelease(cfTypeRef(params))
	dictSet(params, kSecAttrKeyType, uintptr(kSecAttrKeyTypeECSECPrimeRandom))
	dictSet(params, kSecAttrKeySizeInBits, uintptr(keySizeBits))
	dictSet(params, kSecPrivateKeyAttrs, uintptr(privAttrs))

	var keyErr cfErrorRef
	defer func() {
		if keyErr != 0 {
			fnCFRelease(cfTypeRef(keyErr))
		}
	}()
	key := fnSecKeyCreateRandomKey(cfDictionaryRef(params), &keyErr)
	if key == 0 {
		return 0, fmt.Errorf("darwin: SecKeyCreateRandomKey failed: %s", cfErrorString(keyErr))
	}
	return key, nil
}

// SecKeyRefValue is an opaque handle to a SecKey object.
// Callers must call ReleaseKey when done.
type SecKeyRefValue = secKeyRef

// ReleaseKey releases a SecKey CF object.
func ReleaseKey(key secKeyRef) {
	if key != 0 {
		fnCFRelease(cfTypeRef(key))
	}
}

// ExportPublicKeyCOSE exports the public key of a Secure Enclave key in COSE ES256 format.
// The raw EC public key from Apple is 65 bytes: 0x04 || X (32) || Y (32).
func ExportPublicKeyCOSE(privKey secKeyRef) ([]byte, error) {
	pubKey := fnSecKeyCopyPublicKey(privKey)
	if pubKey == 0 {
		return nil, fmt.Errorf("darwin: SecKeyCopyPublicKey returned nil")
	}
	defer fnCFRelease(cfTypeRef(pubKey))

	var exportErr cfErrorRef
	defer func() {
		if exportErr != 0 {
			fnCFRelease(cfTypeRef(exportErr))
		}
	}()
	rawData := fnSecKeyCopyExternalRepresentation(pubKey, &exportErr)
	if rawData == 0 {
		return nil, fmt.Errorf("darwin: SecKeyCopyExternalRepresentation failed")
	}
	raw := cfDataToBytes(rawData) // releases rawData

	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("darwin: unexpected public key format (len=%d)", len(raw))
	}
	x := raw[1:33]
	y := raw[33:65]

	// COSE ES256 map:
	//  1: 2    (kty: EC2)
	//  3: -7   (alg: ES256)
	// -1: 1    (crv: P-256)
	// -2: x    (x coordinate)
	// -3: y    (y coordinate)
	cose := EncodeMap(
		EncodeUint(1), EncodeUint(2),
		EncodeUint(3), EncodeNegInt(6), // -7 = negint(6)
		EncodeNegInt(0), EncodeUint(1), // -1 = negint(0), crv P-256 = 1
		EncodeNegInt(1), EncodeBytes(x), // -2 = negint(1), x
		EncodeNegInt(2), EncodeBytes(y), // -3 = negint(2), y
	)
	return cose, nil
}

// Sign signs dataToSign with the Secure Enclave key using ECDSA-SHA256.
// Returns DER-encoded signature. The OS will show a biometric prompt.
func Sign(privKey secKeyRef, dataToSign []byte) ([]byte, error) {
	// Use the loaded CF constant for the algorithm string.
	alg := cfStringRef(kSecKeyAlgorithmECDSASignatureMessageX962SHA256)

	data := cfData(dataToSign)
	defer fnCFRelease(cfTypeRef(data))

	var sigErr cfErrorRef
	defer func() {
		if sigErr != 0 {
			fnCFRelease(cfTypeRef(sigErr))
		}
	}()
	sigData := fnSecKeyCreateSignature(privKey, alg, data, &sigErr)
	if sigData == 0 {
		return nil, fmt.Errorf("darwin: SecKeyCreateSignature failed")
	}
	return cfDataToBytes(sigData), nil
}

// LookupPrivateKey finds a Secure Enclave private key in the Keychain by tag.
func LookupPrivateKey(tag []byte) (secKeyRef, error) {
	loadSecurity()
	if secErr != nil {
		return 0, secErr
	}

	cfTag := cfData(tag)
	defer fnCFRelease(cfTypeRef(cfTag))

	query := cfMutableDict(5)
	defer fnCFRelease(cfTypeRef(query))
	dictSet(query, kSecClass, uintptr(kSecClassKey))
	dictSet(query, kSecAttrApplicationTag, uintptr(cfTag))
	dictSet(query, kSecReturnRef, kCFBooleanTrue)
	dictSet(query, kSecMatchLimit, uintptr(kSecMatchLimitOne))

	var result uintptr
	status := fnSecItemCopyMatching(cfDictionaryRef(query), &result)
	if status == errSecItemNotFound {
		return 0, fmt.Errorf("darwin: credential not found in keychain")
	}
	if status != errSecSuccess {
		return 0, fmt.Errorf("darwin: SecItemCopyMatching status=%d", status)
	}
	return secKeyRef(result), nil
}

// KeychainTag builds the Keychain application tag from rpID and credentialID.
func KeychainTag(rpID string, credentialID []byte) []byte {
	tag := []byte("bio:" + rpID + ":")
	tag = append(tag, credentialID...)
	return tag
}

// CredentialIDFromTag extracts the credential ID from a Keychain tag.
func CredentialIDFromTag(tag []byte, rpID string) []byte {
	prefix := []byte("bio:" + rpID + ":")
	if len(tag) <= len(prefix) {
		return nil
	}
	return tag[len(prefix):]
}
