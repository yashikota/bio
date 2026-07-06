//go:build windows

package bio

type config struct {
	hwnd uintptr
}

func defaultConfig() *config {
	return &config{}
}

// WithHWND sets the parent window handle (Windows only).
func WithHWND(hwnd uintptr) Option {
	return func(c *config) { c.hwnd = hwnd }
}
