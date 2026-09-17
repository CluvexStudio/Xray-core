package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The `singbox` subcommand runs a complete sing-box config on the engine built into this binary; the
// desktop client starts sing-box configs through it.
func TestSingboxCommandChecksAConfig(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	os.WriteFile(good, []byte(`{
		"log": {"level": "warn"},
		"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"rules": [{"action": "sniff"}], "final": "direct"}
	}`), 0o600)
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"outbounds": [{"type": "no-such-protocol"}]}`), 0o600)

	defer func(path string, test bool, workDir string) {
		*singboxConfigPath, *singboxTest, *singboxWorkDir = path, test, workDir
	}(*singboxConfigPath, *singboxTest, *singboxWorkDir)

	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)

	*singboxTest = true
	*singboxWorkDir = filepath.Join(dir, "work")
	*singboxConfigPath = good
	if err := runSingbox(); err != nil {
		t.Fatalf("a valid config was refused: %v", err)
	}

	*singboxConfigPath = bad
	err := runSingbox()
	if err == nil || !strings.Contains(err.Error(), "decode config") {
		t.Fatalf("an invalid config must fail to decode, got %v", err)
	}

	*singboxConfigPath = ""
	if err := runSingbox(); err == nil {
		t.Fatal("a missing -c must be an error")
	}
}
