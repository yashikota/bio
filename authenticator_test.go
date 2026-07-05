package bio

import "testing"

func TestBiometryTypeString(t *testing.T) {
	tests := []struct {
		bt   BiometryType
		want string
	}{
		{BiometryTouchID, "TouchID"},
		{BiometryFaceID, "FaceID"},
		{BiometryOpticID, "OpticID"},
		{BiometryHello, "WindowsHello"},
		{BiometryNone, "None"},
		{BiometryType(99), "None"},
	}
	for _, tt := range tests {
		got := tt.bt.String()
		if got != tt.want {
			t.Errorf("BiometryType(%d).String() = %q, want %q", int(tt.bt), got, tt.want)
		}
	}
}
