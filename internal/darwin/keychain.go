//go:build darwin

package darwin

import "fmt"

// StoreCredentialMetadata stores RP ID and credential ID metadata.
// The actual private key is stored by SecKeyCreateRandomKey (kSecAttrIsPermanent=true).
// This is a no-op placeholder; lookup is done via kSecAttrApplicationTag on the key itself.
func StoreCredentialMetadata(rpID string, credentialID []byte) error {
	_ = rpID
	_ = credentialID
	return nil
}

// DeleteCredential removes a credential's private key from the Keychain.
func DeleteCredential(rpID string, credentialID []byte) error {
	loadSecurity()
	if secErr != nil {
		return secErr
	}

	tag := KeychainTag(rpID, credentialID)
	cfTag := cfData(tag)
	defer fnCFRelease(cfTypeRef(cfTag))

	query := cfMutableDict(3)
	defer fnCFRelease(cfTypeRef(query))
	dictSet(query, kSecClass, uintptr(kSecClassKey))
	dictSet(query, kSecAttrApplicationTag, uintptr(cfTag))

	status := fnSecItemDelete(cfDictionaryRef(query))
	if status != errSecSuccess && status != errSecItemNotFound {
		return fmt.Errorf("darwin: SecItemDelete status=%d", status)
	}
	return nil
}
