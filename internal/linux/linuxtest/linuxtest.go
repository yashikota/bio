//go:build linux

// Package linuxtest runs the Linux backends against stand-ins: swtpm for the
// TPM and a fake fprintd on a private D-Bus daemon. It is only imported by tests.
package linuxtest

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/yashikota/bio/internal/linux"
)

// Require reports whether a missing helper binary must fail the test instead
// of skipping it. CI sets BIO_REQUIRE_LINUX_DEPS=1 so that a broken install
// cannot turn the integration tests silently green.
func Require() bool { return os.Getenv("BIO_REQUIRE_LINUX_DEPS") == "1" }

func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if Require() {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// StartSwtpm launches a software TPM for the duration of the test and returns a TPM connected to it.
func StartSwtpm(t *testing.T) *linux.TPM {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		skipOrFail(t, "swtpm not installed: %v", err)
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "tpm.sock")
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("swtpm", "socket",
		"--tpm2",
		"--tpmstate", "dir="+state,
		"--ctrl", "type=unixio,path="+filepath.Join(dir, "ctrl.sock"),
		"--server", "type=unixio,path="+socket,
		"--flags", "not-need-init,startup-clear",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})
	waitFor(t, func() bool { _, err := os.Stat(socket); return err == nil })
	return linux.NewTPMWithOpener(func() (transport.TPMCloser, error) { return linuxudstpm.Open(socket) })
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for helper to start")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Status is one VerifyStatus signal.
type Status struct {
	Result string
	Done   bool
}

// FakeFprintd implements the parts of fprintd's D-Bus API that bio uses.
type FakeFprintd struct {
	// Address is the private bus address; pass it to linux.NewFprintdWithAddress.
	Address string

	mu           sync.Mutex
	enrolled     []string
	claimError   string
	scripts      [][]Status // one per VerifyStart; when empty, Match is used
	claimed      bool
	block        bool
	verifyStarts int
	conn         *dbus.Conn
}

// Match is the default script: a retry, then a match.
var Match = []Status{{Result: "verify-retry-scan", Done: false}, {Result: "verify-match", Done: true}}

const devicePath = dbus.ObjectPath("/net/reactivated/Fprint/Device/0")

// StartFakeFprintd starts a private dbus-daemon with a fake fprintd on it.
func StartFakeFprintd(t *testing.T) *FakeFprintd {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		skipOrFail(t, "dbus-daemon not installed: %v", err)
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(fmt.Sprintf(busConfig, dir)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("dbus-daemon", "--config-file="+conf, "--nofork", "--print-address")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start dbus-daemon: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("read bus address: %v", err)
	}

	f := &FakeFprintd{Address: strings.TrimSpace(addr), enrolled: []string{"right-index-finger"}}
	conn, err := dbus.Connect(f.Address)
	if err != nil {
		t.Fatalf("connect to private bus: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	f.conn = conn

	if err := conn.ExportMethodTable(map[string]any{
		"GetDefaultDevice": func() (dbus.ObjectPath, *dbus.Error) { return devicePath, nil },
	}, "/net/reactivated/Fprint/Manager", "net.reactivated.Fprint.Manager"); err != nil {
		t.Fatal(err)
	}
	if err := conn.ExportMethodTable(map[string]any{
		"ListEnrolledFingers": f.listEnrolled,
		"Claim":               f.claim,
		"Release":             f.release,
		"VerifyStart":         f.verifyStart,
		"VerifyStop":          func() *dbus.Error { return nil },
	}, devicePath, "net.reactivated.Fprint.Device"); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.RequestName("net.reactivated.Fprint", dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("RequestName: %v %v", reply, err)
	}
	return f
}

const busConfig = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=%s</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`

func fprintError(name string) *dbus.Error {
	return dbus.NewError("net.reactivated.Fprint.Error."+name, []any{name})
}

func (f *FakeFprintd) listEnrolled(string) ([]string, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.enrolled) == 0 {
		return nil, fprintError("NoEnrolledPrints")
	}
	return f.enrolled, nil
}

func (f *FakeFprintd) claim(string) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimError != "" {
		return fprintError(f.claimError)
	}
	if f.claimed {
		return fprintError("AlreadyInUse")
	}
	f.claimed = true
	return nil
}

func (f *FakeFprintd) release() *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimed = false
	return nil
}

func (f *FakeFprintd) verifyStart(string) *dbus.Error {
	f.mu.Lock()
	f.verifyStarts++
	script := Match
	if f.block {
		script = nil
	} else if len(f.scripts) > 0 {
		script, f.scripts = f.scripts[0], f.scripts[1:]
	}
	f.mu.Unlock()
	go func() {
		for _, s := range script {
			time.Sleep(5 * time.Millisecond)
			f.conn.Emit(devicePath, "net.reactivated.Fprint.Device.VerifyStatus", s.Result, s.Done) //nolint:errcheck
		}
	}()
	return nil
}

// Script queues the signals sent after the next VerifyStart. An empty script
// sends nothing, so verification waits until its context is done.
func (f *FakeFprintd) Script(statuses ...Status) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, statuses)
}

// Block makes every later verification send no signals, so that it waits until its context is done.
func (f *FakeFprintd) Block() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block = true
}

// SetEnrolled sets the fingers ListEnrolledFingers reports.
func (f *FakeFprintd) SetEnrolled(fingers ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolled = fingers
}

// FailClaim makes Claim fail with net.reactivated.Fprint.Error.<name>; "" clears it.
func (f *FakeFprintd) FailClaim(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimError = name
}

// VerifyStarts counts verification attempts.
func (f *FakeFprintd) VerifyStarts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifyStarts
}

// Claimed reports whether the device is currently claimed (it must be released after every Verify).
func (f *FakeFprintd) Claimed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.claimed
}
