package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCmd(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := run(context.Background(), args, strings.NewReader(stdin), &out, &errb)
	return out.String() + errb.String(), err
}

func TestHashToken(t *testing.T) {
	out, err := runCmd(t, "incident-bot-example-token-change-me-0000000000000000\n", "hash-token")
	if err != nil || strings.TrimSpace(out) != "6020d5c9e13c9c96240ac34086bcd20e1ea488f57c1284809da815abd57b7cf0" {
		t.Fatalf("got %q %v", out, err)
	}
	if _, err := runCmd(t, "short\n", "hash-token"); err == nil {
		t.Fatal("short token accepted")
	}
}

func TestValidateExample(t *testing.T) {
	out, err := runCmd(t, "", "validate", "--config", filepath.Join("..", "..", "examples", "gateway.yaml"))
	if err != nil || !strings.Contains(out, "config and policy are valid") || !strings.Contains(out, "principal incident-bot (profile readonly-agent)") {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestAuditVerify(t *testing.T) {
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(file, []byte("{broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCmd(t, "", "audit", "verify", "--file", file); err == nil {
		t.Fatal("broken log verified")
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"audit"}, {"approvals"}} {
		if _, err := runCmd(t, "", args...); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
	t.Setenv("MCPGW_ADMIN_TOKEN", "")
	if _, err := runCmd(t, "", "approvals", "list"); err == nil || !strings.Contains(err.Error(), "MCPGW_ADMIN_TOKEN") {
		t.Fatalf("got %v", err)
	}
	if out, err := runCmd(t, "", "version"); err != nil || strings.TrimSpace(out) != "dev" {
		t.Fatalf("version: %q %v", out, err)
	}
}
