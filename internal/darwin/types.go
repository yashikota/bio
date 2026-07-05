//go:build darwin

package darwin

// LAPolicy values
const (
	LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
	LAPolicyDeviceOwnerAuthentication               = 2
)

// LABiometryType values
const (
	LABiometryTypeNone    = 0
	LABiometryTypeTouchID = 1
	LABiometryTypeFaceID  = 2
	LABiometryTypeOpticID = 4
)

// LAError codes
const (
	LAErrorAuthenticationFailed = -1
	LAErrorUserCancel           = -2
	LAErrorUserFallback         = -3
	LAErrorSystemCancel         = -4
	LAErrorPasscodeNotSet       = -5
	LAErrorBiometryNotAvailable = -6 // was LAErrorTouchIDNotAvailable before macOS 10.13/iOS 11
	LAErrorBiometryNotEnrolled  = -7
	LAErrorBiometryLockout      = -8
	LAErrorAppCancel            = -9
	LAErrorInvalidContext       = -10
	LAErrorNotInteractive       = -1004
)
