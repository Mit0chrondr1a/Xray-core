package tls_test

import (
	"os"
	"path/filepath"
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
