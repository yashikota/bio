//go:build linux && integration

package linux_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"github.com/yashikota/bio/internal/linux"
)

// startSwtpm launches swtpm in the background and returns a cleanup function.
// The socket path is <dir>/tpm.sock.
func startSwtpm(t *testing.T) (socketPath string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	socketPath = filepath.Join(dir, "tpm.sock")

	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}

	cmd := exec.Command("swtpm", "socket",
		"--tpm2",
		"--tpmstate", "dir="+stateDir,
		"--ctrl", "type=unixio,path="+filepath.Join(dir, "ctrl.sock"),
		"--server", "type=unixio,path="+socketPath,
		"--flags", "not-need-init,startup-clear",
		"--log", "level=0",
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Skipf("swtpm not available: %v", err)
	}

	// Wait until the socket appears
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(socketPath); err != nil {
		cmd.Process.Kill()
		t.Fatalf("swtpm socket did not appear: %v", err)
	}

	cleanup = func() {
		cmd.Process.Kill()
		cmd.Wait()
	}
	return socketPath, cleanup
}

// withSwtpm overrides linux.OpenTPMFunc to use the given swtpm socket.
func withSwtpm(socketPath string) (restore func()) {
	orig := linux.OpenTPMFunc
	linux.OpenTPMFunc = func() (transport.TPMCloser, error) {
		return linuxudstpm.Open(socketPath)
	}
	return func() { linux.OpenTPMFunc = orig }
}

func TestTPMCreateAndSign(t *testing.T) {
	socketPath, cleanup := startSwtpm(t)
	defer cleanup()
	defer withSwtpm(socketPath)()

	pub, priv, rawPubKey, err := linux.CreateKey()
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Fatal("CreateKey returned empty blobs")
	}
	if len(rawPubKey) != 65 || rawPubKey[0] != 0x04 {
		t.Fatalf("unexpected raw public key: len=%d prefix=0x%02x", len(rawPubKey), rawPubKey[0])
	}

	data := []byte("hello from bio integration test")
	sig, err := linux.Sign(pub, priv, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}
}

func TestTPMEncodeCOSEES256(t *testing.T) {
	socketPath, cleanup := startSwtpm(t)
	defer cleanup()
	defer withSwtpm(socketPath)()

	_, _, rawPubKey, err := linux.CreateKey()
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	cose := linux.EncodeCOSEES256(rawPubKey)
	if len(cose) == 0 {
		t.Fatal("EncodeCOSEES256 returned empty bytes")
	}
	// CBOR map begins with 0xa5 (5-entry map)
	if cose[0] != 0xa5 {
		t.Errorf("COSE header byte = 0x%02x, want 0xa5", cose[0])
	}
}
