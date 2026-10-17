package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hashA = "6020d5c9e13c9c96240ac34086bcd20e1ea488f57c1284809da815abd57b7cf0"
const hashB = "40f2ef4161a7e8cfce233cd120fbac2f58ac935976b426be450dffe441dc8f71"

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const valid = `
policy_file: policy.yaml
server: { http_listen: "127.0.0.1:8080", stdio_principal: local }
principals:
  - { name: local, profile: ops }
  - { name: bot, profile: reader, token_sha256: ` + hashA + ` }
approvers:
  - { name: alice, token_sha256: ` + hashB + ` }
credentials:
  kube: { type: kubeconfig, context: kind-gw }
  aws:  { type: aws_web_identity, role_arn: "arn:aws:iam::1:role/r", token_file: /var/run/token, region: ${AWS_REGION_UNDER_TEST} }
kubernetes: { read_credential: kube, write_credential: kube }
aws: { read_credential: aws, write_credential: aws }
terraform: { credential: kube, workspaces: { net: ./infra/net } }
`

func TestLoadValidWithDefaultsAndEnv(t *testing.T) {
	t.Setenv("AWS_REGION_UNDER_TEST", "eu-west-1")
	p := write(t, valid)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.AdminListen != "127.0.0.1:8081" || c.Audit.File != "audit.jsonl" || c.Limits.MaxOutputBytes != 65536 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Credentials["aws"].Region != "eu-west-1" {
		t.Fatal("env not expanded")
	}
	if got := c.Path("./infra/net"); got != filepath.Join(filepath.Dir(p), "infra/net") {
		t.Fatalf("relative path: %s", got)
	}
	if got := c.Path("/abs"); got != "/abs" {
		t.Fatalf("absolute path: %s", got)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Setenv("AWS_REGION_UNDER_TEST", "eu-west-1")
	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"unset env var": {func(s string) string { return strings.Replace(s, "AWS_REGION_UNDER_TEST", "NOT_SET_ANYWHERE_X", 1) }, "NOT_SET_ANYWHERE_X"},
		"unknown field": {func(s string) string { return s + "polcy: x\n" }, "field polcy not found"},
		"shared token":  {func(s string) string { return strings.Replace(s, hashB, hashA, 1) }, "share a token"},
		"bad hash":      {func(s string) string { return strings.Replace(s, hashA, "abc", 1) }, "64 hex"},
		"unknown credential": {func(s string) string {
			return strings.Replace(s, "write_credential: kube", "write_credential: nope", 1)
		}, "unknown credential \"nope\""},
		"same listeners": {func(s string) string {
			return strings.Replace(s, `http_listen: "127.0.0.1:8080"`, `http_listen: "127.0.0.1:8081"`, 1)
		}, "must differ"},
		"unknown stdio": {func(s string) string {
			return strings.Replace(s, "stdio_principal: local", "stdio_principal: ghost", 1)
		}, "not in principals"},
		"bad credential type": {func(s string) string { return strings.Replace(s, "type: kubeconfig", "type: magic", 1) }, "unknown type"},
		"approver name clash": {func(s string) string { return strings.Replace(s, "name: alice", "name: bot", 1) }, "same name"},
		"no policy":           {func(s string) string { return strings.Replace(s, "policy_file: policy.yaml", "", 1) }, "policy_file is required"},
		"empty tf workspaces": {func(s string) string {
			return strings.Replace(s, "workspaces: { net: ./infra/net }", "workspaces: {}", 1)
		}, "terraform.workspaces"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, tc.mutate(valid)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestExpandEnvEscape(t *testing.T) {
	got, err := expandEnv("a $${LITERAL} $HOME_NOT_EXPANDED")
	if err != nil || got != "a ${LITERAL} $HOME_NOT_EXPANDED" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := expandEnv("x ${UNCLOSED"); err == nil {
		t.Fatal("unclosed must fail")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "examples", "gateway.yaml")); err != nil {
		t.Fatal(err)
	}
}
