//go:build linux

package linux

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func newTestStore(t *testing.T) *CredentialStore {
	t.Helper()
	s, err := OpenCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreCRUD(t *testing.T) {
	s := newTestStore(t)
	rec := &CredentialRecord{RPID: "example.com", CredentialID: []byte{1, 2}, UserHandle: []byte("u")}
	if err := s.Save(rec); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&CredentialRecord{RPID: "example.com", CredentialID: []byte{1, 2}}); err == nil {
		t.Error("duplicate Save succeeded")
	}
	got, err := s.Lookup("example.com", []byte{1, 2})
	if err != nil || string(got.UserHandle) != "u" || got.CreatedAt.IsZero() {
		t.Fatalf("Lookup = %+v, %v", got, err)
	}
	if _, err := s.Lookup("other.example", []byte{1, 2}); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("Lookup other RP: %v", err)
	}
	for want := uint32(1); want <= 3; want++ {
		n, err := s.IncrementSignCount("example.com", []byte{1, 2})
		if err != nil || n != want {
			t.Fatalf("IncrementSignCount = %d, %v; want %d", n, err, want)
		}
	}
	if err := s.Delete("example.com", []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("example.com", []byte{1, 2}); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("second Delete: %v", err)
	}
}

func TestStoreFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested")
	s, err := OpenCredentialStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&CredentialRecord{RPID: "x", CredentialID: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700 | os.ModeDir, s.path: 0o600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != want {
			t.Errorf("%s mode = %v, want %v", path, fi.Mode(), want)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "credentials.json" && e.Name() != "credentials.lock" {
			t.Errorf("leftover file %s", e.Name())
		}
	}
}

func TestStoreCorruptFile(t *testing.T) {
	s := newTestStore(t)
	if err := os.WriteFile(s.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup("x", []byte{1}); err == nil {
		t.Error("Lookup on a corrupt file succeeded")
	}
	// A failed write must not replace the corrupt file with an empty store.
	if err := s.Save(&CredentialRecord{RPID: "x", CredentialID: []byte{1}}); err == nil {
		t.Error("Save on a corrupt file succeeded")
	}
	if b, _ := os.ReadFile(s.path); string(b) != "{not json" {
		t.Error("corrupt file was overwritten")
	}
}

func TestCredentialDir(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/data")
	if d, _ := credentialDir("app"); d != "/data/app" {
		t.Errorf("dir = %q", d)
	}
	t.Setenv("XDG_DATA_HOME", "relative/path") // the XDG spec says to ignore relative paths
	t.Setenv("HOME", "/home/test")
	if d, _ := credentialDir("app"); d != "/home/test/.local/share/app" {
		t.Errorf("dir = %q", d)
	}
}

const (
	childDirEnv = "BIO_STORE_CHILD_DIR"
	childN      = 50
)

// TestStoreConcurrentProcesses increments one counter from several processes
// at once. Without the file lock, read-modify-write races lose updates.
func TestStoreConcurrentProcesses(t *testing.T) {
	if dir := os.Getenv(childDirEnv); dir != "" {
		s, err := OpenCredentialStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		for range childN {
			if _, err := s.IncrementSignCount("example.com", []byte{1}); err != nil {
				t.Fatal(err)
			}
		}
		return
	}

	s := newTestStore(t)
	if err := s.Save(&CredentialRecord{RPID: "example.com", CredentialID: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	const procs = 4
	var wg sync.WaitGroup
	errs := make(chan error, procs)
	for range procs {
		wg.Go(func() {
			cmd := exec.Command(os.Args[0], "-test.run=^TestStoreConcurrentProcesses$")
			cmd.Env = append(os.Environ(), childDirEnv+"="+filepath.Dir(s.path))
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("child: %w\n%s", err, out)
			}
		})
	}
	// Writers in this process too, on separate file descriptors.
	for range 2 {
		wg.Go(func() {
			for range childN {
				if _, err := s.IncrementSignCount("example.com", []byte{1}); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	rec, err := s.Lookup("example.com", []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if want := uint32((procs + 2) * childN); rec.SignCount != want {
		t.Fatalf("sign count = %d, want %d (updates were lost)", rec.SignCount, want)
	}
}
