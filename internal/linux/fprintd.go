//go:build linux

package linux

import (
	"context"
	"errors"
	"os/user"

	"github.com/godbus/dbus/v5"
)

const (
	fprintService   = "net.reactivated.Fprint"
	fprintManager   = "/net/reactivated/Fprint/Manager"
	fprintManagerIF = "net.reactivated.Fprint.Manager"
	fprintDeviceIF  = "net.reactivated.Fprint.Device"
)

// Fprintd connects to the fprintd fingerprint daemon.
type Fprintd struct {
	connect func() (*dbus.Conn, error)
}

// NewFprintd returns an Fprintd that uses the system bus.
func NewFprintd() *Fprintd {
	return &Fprintd{connect: func() (*dbus.Conn, error) { return dbus.ConnectSystemBus() }}
}

// NewFprintdWithAddress returns an Fprintd that uses the bus at address.
// Tests use it with a private dbus-daemon running a fake fprintd.
func NewFprintdWithAddress(address string) *Fprintd {
	return &Fprintd{connect: func() (*dbus.Conn, error) { return dbus.Connect(address) }}
}

// FprintdClient is a connection to fprintd's default fingerprint device.
type FprintdClient struct {
	conn   *dbus.Conn
	device dbus.BusObject
}

// Open connects to the bus and resolves the default fingerprint device.
func (f *Fprintd) Open() (*FprintdClient, error) {
	conn, err := f.connect()
	if err != nil {
		return nil, &FprintdError{Op: "connect", Status: err.Error()}
	}
	mgr := conn.Object(fprintService, dbus.ObjectPath(fprintManager))
	var devicePath dbus.ObjectPath
	if err := mgr.Call(fprintManagerIF+".GetDefaultDevice", 0).Store(&devicePath); err != nil {
		conn.Close()
		return nil, &FprintdError{Op: "GetDefaultDevice", Status: dbusStatus(err)}
	}
	return &FprintdClient{conn: conn, device: conn.Object(fprintService, devicePath)}, nil
}

// dbusStatus returns fprintd's error name (e.g. net.reactivated.Fprint.Error.NoEnrolledPrints) when there is one.
func dbusStatus(err error) string {
	if e, ok := errors.AsType[dbus.Error](err); ok {
		return e.Name
	}
	if e, ok := errors.AsType[*dbus.Error](err); ok {
		return e.Name
	}
	return err.Error()
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
		if dbusStatus(err) == "net.reactivated.Fprint.Error.NoEnrolledPrints" {
			return false, nil
		}
		return false, &FprintdError{Op: "ListEnrolledFingers", Status: dbusStatus(err)}
	}
	return len(fingers) > 0, nil
}

// Verify performs a fingerprint verification. It blocks until the user scans
// a matching finger, the context is done, or verification fails.
func (c *FprintdClient) Verify(ctx context.Context) error {
	u, err := user.Current()
	if err != nil {
		return &FprintdError{Op: "current-user", Status: err.Error()}
	}

	if err := c.device.Call(fprintDeviceIF+".Claim", 0, u.Username).Err; err != nil {
		return &FprintdError{Op: "Claim", Status: dbusStatus(err)}
	}
	defer c.device.Call(fprintDeviceIF+".Release", 0)

	match := []dbus.MatchOption{
		dbus.WithMatchObjectPath(c.device.Path()),
		dbus.WithMatchInterface(fprintDeviceIF),
		dbus.WithMatchMember("VerifyStatus"),
	}
	if err := c.conn.AddMatchSignal(match...); err != nil {
		return &FprintdError{Op: "AddMatchSignal", Status: err.Error()}
	}
	defer c.conn.RemoveMatchSignal(match...) //nolint:errcheck

	sigCh := make(chan *dbus.Signal, 8)
	c.conn.Signal(sigCh)
	defer c.conn.RemoveSignal(sigCh)

	if err := c.device.Call(fprintDeviceIF+".VerifyStart", 0, "any").Err; err != nil {
		return &FprintdError{Op: "VerifyStart", Status: dbusStatus(err)}
	}
	defer c.device.Call(fprintDeviceIF+".VerifyStop", 0)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig, ok := <-sigCh:
			if !ok {
				return &FprintdError{Op: "Verify", Status: "signal channel closed"}
			}
			if sig.Name != fprintDeviceIF+".VerifyStatus" || sig.Path != c.device.Path() || len(sig.Body) < 2 {
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
			case "verify-no-match":
				if done {
					return &FprintdError{Op: "Verify", Status: result}
				}
			case "verify-disconnected":
				return &FprintdError{Op: "Verify", Status: result}
			default:
				if done {
					return &FprintdError{Op: "Verify", Status: result}
				}
			}
		}
	}
}
