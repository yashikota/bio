//go:build windows

package winwebauthn

import "golang.org/x/sys/windows"

// UTF16PtrFromString converts a Go string to a *uint16 (UTF-16) for Windows API calls.
// Returns nil for empty strings.
func UTF16PtrFromString(s string) *uint16 {
	if s == "" {
		return nil
	}
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// GoStringFromUTF16Ptr converts a *uint16 Windows string to a Go string.
func GoStringFromUTF16Ptr(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}
