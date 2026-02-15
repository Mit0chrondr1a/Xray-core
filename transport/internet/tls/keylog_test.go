package tls_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	. "github.com/xtls/xray-core/transport/internet/tls"
)

func TestMasterKeyLogWriterModeAndCache(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "master-keys.log")
	first := MasterKeyLogWriter(logPath)
	if first == nil {
		t.Fatal("expected key log writer")
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("failed to stat key log: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("key log mode is too permissive: %o", info.Mode().Perm())
	}

	second := MasterKeyLogWriter(logPath)
	if second == nil {
		t.Fatal("expected cached key log writer")
	}
	if first != second {
		t.Fatal("expected cached writer to be reused")
	}
}

func TestMasterKeyLogWriterDisabled(t *testing.T) {
	if MasterKeyLogWriter("") != nil {
		t.Fatal("empty path should disable key logging")
	}
	if MasterKeyLogWriter("none") != nil {
		t.Fatal("\"none\" should disable key logging")
	}
}

func TestMasterKeyLogWriterRefusesInsecurePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission tests not reliable on Windows")
	}

	// Clear any cached writers and env override.
	CloseMasterKeyLogWriters()
	t.Setenv("XRAY_ALLOW_INSECURE_KEYLOG", "")

	logPath := filepath.Join(t.TempDir(), "insecure-keys.log")
	// Create file with world-readable permissions.
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	w := MasterKeyLogWriter(logPath)
	if w != nil {
		t.Fatal("expected nil writer for 0644 keylog file without override")
	}
}

func TestMasterKeyLogWriterAllowsInsecureWithEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission tests not reliable on Windows")
	}

	CloseMasterKeyLogWriters()
	t.Setenv("XRAY_ALLOW_INSECURE_KEYLOG", "1")

	logPath := filepath.Join(t.TempDir(), "insecure-keys-override.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	w := MasterKeyLogWriter(logPath)
	if w == nil {
		t.Fatal("expected writer with XRAY_ALLOW_INSECURE_KEYLOG=1 override")
	}

	// Cleanup
	CloseMasterKeyLogWriters()
}
