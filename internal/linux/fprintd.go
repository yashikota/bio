//go:build linux

package linux

import (
	"context"
	"fmt"
	"os/user"

	"github.com/godbus/dbus/v5"
)

const (
	fprintService   = "net.reactivated.Fprint"
	fprintManager   = "/net/reactivated/Fprint/Manager"
	fprintManagerIF = "net.reactivated.Fprint.Manager"
	fprintDeviceIF  = "net.reactivated.Fprint.Device"
)

// FprintdClient wraps a D-Bus connection to fprintd.
type FprintdClient struct {
	conn   *dbus.Conn
	device dbus.BusObject
}

// NewFprintdClient connects to the system bus and resolves the default fingerprint device.
func NewFprintdClient() (*FprintdClient, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, &FprintdError{Op: "connect", Status: err.Error()}
	}

	mgr := conn.Object(fprintService, dbus.ObjectPath(fprintManager))
	var devicePath dbus.ObjectPath
	if err := mgr.Call(fprintManagerIF+".GetDefaultDevice", 0).Store(&devicePath); err != nil {
		conn.Close()
		return nil, &FprintdError{Op: "GetDefaultDevice", Status: err.Error()}
	}

	device := conn.Object(fprintService, devicePath)
	return &FprintdClient{conn: conn, device: device}, nil
}

// Close releases the D-Bus connection.
func (c *FprintdClient) Close() error {
	return c.conn.Close()
}

// HasEnrolledFingerprints reports whether the current user has enrolled fingerprints.
func (c *FprintdClient) HasEnrolledFingerprints() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, &FprintdError{Op: "current-user", Status: err.Error()}
	}

	var fingers []string
	if err := c.device.Call(fprintDeviceIF+".ListEnrolledFingers", 0, u.Username).Store(&fingers); err != nil {
		// fprintd returns an error when no fingers are enrolled
		return false, nil
	}
	return len(fingers) > 0, nil
}

// Verify performs a fingerprint verification. Blocks until the user scans their finger,
// the context is canceled, or an unrecoverable error occurs.
func (c *FprintdClient) Verify(ctx context.Context) error {
	u, err := user.Current()
	if err != nil {
		return &FprintdError{Op: "current-user", Status: err.Error()}
	}

	if err := c.device.Call(fprintDeviceIF+".Claim", 0, u.Username).Err; err != nil {
		return &FprintdError{Op: "Claim", Status: err.Error()}
	}
	defer c.device.Call(fprintDeviceIF+".Release", 0) //nolint:errcheck

	if err := c.conn.AddMatchSignal(
		dbus.WithMatchObjectPath(c.device.Path()),
		dbus.WithMatchInterface(fprintDeviceIF),
		dbus.WithMatchMember("VerifyStatus"),
	); err != nil {
		return &FprintdError{Op: "AddMatchSignal", Status: err.Error()}
	}

	sigCh := make(chan *dbus.Signal, 8)
	c.conn.Signal(sigCh)
	defer func() {
		c.conn.RemoveSignal(sigCh)
		c.device.Call(fprintDeviceIF+".VerifyStop", 0) //nolint:errcheck
	}()

	if err := c.device.Call(fprintDeviceIF+".VerifyStart", 0, "any").Err; err != nil {
		return &FprintdError{Op: "VerifyStart", Status: err.Error()}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig, ok := <-sigCh:
			if !ok {
				return &FprintdError{Op: "Verify", Status: "signal channel closed"}
			}
			if sig.Name != fprintDeviceIF+".VerifyStatus" {
				continue
			}
			if len(sig.Body) < 2 {
				continue
			}
			result, _ := sig.Body[0].(string)
			done, _ := sig.Body[1].(bool)

			switch result {
			case "verify-match":
				return nil
			case "verify-retry-scan", "verify-swipe-too-short",
				"verify-finger-not-centered", "verify-remove-and-retry":
				// transient; keep waiting
				continue
			case "verify-no-match":
				if done {
					return &FprintdError{Op: "Verify", Status: fmt.Sprintf("verify-no-match")}
				}
				continue
			case "verify-disconnected":
				return &FprintdError{Op: "Verify", Status: "verify-disconnected"}
			default:
				if done {
					return &FprintdError{Op: "Verify", Status: result}
				}
			}
		}
	}
}
