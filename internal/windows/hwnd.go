//go:build windows

package winwebauthn

import "golang.org/x/sys/windows"

var (
	modUser32               = windows.NewLazySystemDLL("user32.dll")
	modKernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetForegroundWindow = modUser32.NewProc("GetForegroundWindow")
	procGetConsoleWindow    = modKernel32.NewProc("GetConsoleWindow")
)

// ResolveHWND returns a suitable window handle for WebAuthn calls.
// Priority: provided > foreground window > console window > 0 (desktop).
func ResolveHWND(provided uintptr) uintptr {
	if provided != 0 {
		return provided
	}
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd != 0 {
		return hwnd
	}
	hwnd, _, _ = procGetConsoleWindow.Call()
	return hwnd
}
