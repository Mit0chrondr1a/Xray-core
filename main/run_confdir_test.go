package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/cmdarg"
)

func TestGetConfigFilePathConfDirDoesNotAccumulateEntries(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "a.json")
	if err := os.WriteFile(confPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	originalConfigFiles := append(cmdarg.Arg(nil), configFiles...)
	originalConfigDir := configDir
	defer func() {
		configFiles = originalConfigFiles
		configDir = originalConfigDir
	}()

	configFiles = cmdarg.Arg{"cli.json"}
	configDir = tempDir

	files1, err := getConfigFilePath(false)
	if err != nil {
		t.Fatalf("first getConfigFilePath failed: %v", err)
	}

	files2, err := getConfigFilePath(false)
	if err != nil {
		t.Fatalf("second getConfigFilePath failed: %v", err)
	}

	if len(files1) != 2 {
		t.Fatalf("unexpected first file count: got %d, want 2", len(files1))
	}
	if len(files2) != 2 {
		t.Fatalf("unexpected second file count: got %d, want 2", len(files2))
	}
	if files1[0] != "cli.json" || files2[0] != "cli.json" {
		t.Fatalf("expected cli config preserved at index 0, got %q and %q", files1[0], files2[0])
	}
	if files1[1] != confPath || files2[1] != confPath {
		t.Fatalf("expected confdir config once, got %q and %q", files1[1], files2[1])
	}
	if len(configFiles) != 1 || configFiles[0] != "cli.json" {
		t.Fatalf("global configFiles was mutated: %#v", configFiles)
	}
}
