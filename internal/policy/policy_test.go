package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPolicy = `
version: 1
default: deny
profiles:
  reader:
    rules:
      - tool: k8s_get
        effect: allow
      - tool: "k8s_*"
        effect: deny
        when:
          namespace: { in: [kube-system] }
        reason: platform namespace
  operator:
    extends: [reader]
    rules:
      - tool: k8s_scale
        effect: allow
      - tool: k8s_scale
        effect: ask
        when:
          dry_run: { equals: "false" }
      - tool: k8s_scale
        effect: deny
        when:
          replicas: { max: 0 }
          namespace: { glob: ["prod-*"] }
      - tool: k8s_scale
        effect: deny
        when:
          replicas: { min: 21 }
`

var known = []string{"k8s_get", "k8s_logs", "k8s_scale", "aws_ec2_reboot_instance"}

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src), known)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestEvaluate(t *testing.T) {
	p := mustParse(t, testPolicy)
	cases := []struct {
		name    string
		profile string
		tool    string
		args    map[string]any
		want    Effect
		rule    string
	}{
		{"reader may get", "reader", "k8s_get", map[string]any{"namespace": "default"}, Allow, "allow k8s_get"},
		{"deny beats allow in kube-system", "reader", "k8s_get", map[string]any{"namespace": "kube-system"}, Deny, "deny k8s_* when namespace"},
		{"no rule means default deny", "reader", "k8s_logs", map[string]any{"namespace": "default"}, Deny, "default"},
		{"reader cannot scale", "reader", "k8s_scale", map[string]any{"namespace": "default", "replicas": 2.0, "dry_run": false}, Deny, "default"},
		{"operator dry run is allowed", "operator", "k8s_scale", map[string]any{"namespace": "default", "replicas": 2.0, "dry_run": true}, Allow, "allow k8s_scale"},
		{"operator real run asks", "operator", "k8s_scale", map[string]any{"namespace": "default", "replicas": 2.0, "dry_run": false}, Ask, "ask k8s_scale when dry_run"},
		{"scale prod to zero denied", "operator", "k8s_scale", map[string]any{"namespace": "prod-eu", "replicas": 0.0, "dry_run": false}, Deny, "deny k8s_scale when namespace,replicas"},
		{"scale non-prod to zero asks", "operator", "k8s_scale", map[string]any{"namespace": "dev", "replicas": 0.0, "dry_run": false}, Ask, "ask k8s_scale when dry_run"},
		{"min bound denies large scale even in dry run", "operator", "k8s_scale", map[string]any{"namespace": "dev", "replicas": 30.0, "dry_run": true}, Deny, "deny k8s_scale when replicas"},
		{"inherited deny applies to operator", "operator", "k8s_scale", map[string]any{"namespace": "kube-system", "replicas": 1.0, "dry_run": true}, Deny, "deny k8s_* when namespace"},
		{"unknown profile denied", "nobody", "k8s_get", map[string]any{}, Deny, "unknown-profile"},
		{"missing argument does not match a condition", "operator", "k8s_scale", map[string]any{"namespace": "dev", "replicas": 1.0}, Allow, "allow k8s_scale"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := p.Evaluate(tc.profile, tc.tool, tc.args)
			if d.Effect != tc.want || d.Rule != tc.rule {
				t.Fatalf("got %s (%s), want %s (%s)", d.Effect, d.Rule, tc.want, tc.rule)
			}
		})
	}
}

func TestEvaluateNonNumberAgainstMax(t *testing.T) {
	p := mustParse(t, testPolicy)
	// A string where a number is expected must not satisfy a numeric condition.
	d := p.Evaluate("operator", "k8s_scale", map[string]any{"namespace": "prod-eu", "replicas": "0", "dry_run": false})
	if d.Effect != Ask {
		t.Fatalf("got %s, want ask", d.Effect)
	}
}

func TestDefaultAllowIsHonoured(t *testing.T) {
	p := mustParse(t, "version: 1\ndefault: ask\nprofiles:\n  x:\n    rules: []\n")
	if d := p.Evaluate("x", "k8s_get", nil); d.Effect != Ask {
		t.Fatalf("got %s, want ask", d.Effect)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]struct {
		src  string
		want string
	}{
		"wrong version":    {"version: 2\nprofiles: {x: {rules: []}}", "version: want 1"},
		"no profiles":      {"version: 1\nprofiles: {}", "at least one profile"},
		"bad effect":       {"version: 1\nprofiles: {x: {rules: [{tool: k8s_get, effect: maybe}]}}", "effect \"maybe\""},
		"typo in tool":     {"version: 1\nprofiles: {x: {rules: [{tool: k8s_gte, effect: allow}]}}", "matches no tool"},
		"unknown field":    {"version: 1\nprofiles: {x: {rules: [{tool: k8s_get, effect: allow, wehn: {}}]}}", "field wehn not found"},
		"unknown extends":  {"version: 1\nprofiles: {x: {extends: [y], rules: []}}", "extends unknown profile"},
		"cycle":            {"version: 1\nprofiles: {x: {extends: [y], rules: []}, y: {extends: [x], rules: []}}", "extends cycle"},
		"empty condition":  {"version: 1\nprofiles: {x: {rules: [{tool: k8s_get, effect: allow, when: {namespace: {}}}]}}", "empty condition"},
		"bad default":      {"version: 1\ndefault: yes\nprofiles: {x: {rules: []}}", "default"},
		"conditional used": {"version: 1\nprofiles: {x: {rules: [{tool: k8s_get, effect: conditional}]}}", "is not allow, ask or deny"},
		"missing tool":     {"version: 1\nprofiles: {x: {rules: [{effect: allow}]}}", "tool is required"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src), known)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestExplain(t *testing.T) {
	p := mustParse(t, testPolicy)
	got := p.Explain("operator", []string{"k8s_get", "k8s_logs", "k8s_scale", "aws_ec2_reboot_instance"})
	want := map[string]Effect{
		"k8s_get":                 Conditional, // allowed, but denied in kube-system
		"k8s_logs":                Deny,        // default deny, and the only condition also denies
		"k8s_scale":               Conditional,
		"aws_ec2_reboot_instance": Deny,
	}
	for tool, eff := range want {
		if got[tool] != eff {
			t.Errorf("%s: got %s, want %s", tool, got[tool], eff)
		}
	}
	simple := mustParse(t, "version: 1\nprofiles: {x: {rules: [{tool: k8s_get, effect: allow}, {tool: k8s_logs, effect: deny}, {tool: k8s_logs, effect: allow, when: {namespace: {in: [a]}}}]}}")
	got = simple.Explain("x", []string{"k8s_get", "k8s_logs"})
	if got["k8s_get"] != Allow || got["k8s_logs"] != Deny {
		t.Fatalf("got %v", got)
	}
}

func TestLoadExampleFile(t *testing.T) {
	file := filepath.Join("..", "..", "examples", "policy.yaml")
	if _, err := os.Stat(file); err != nil {
		t.Skip("example policy not present")
	}
	all := []string{"gateway_policy", "k8s_get", "k8s_logs", "k8s_scale", "k8s_rollout_restart", "k8s_delete_pod",
		"aws_ec2_describe_instances", "aws_cloudwatch_alarms", "aws_ec2_reboot_instance", "azure_resource_list", "azure_vm_restart", "terraform_plan"}
	p, err := Load(file, all)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checks := []struct {
		profile, tool string
		args          map[string]any
		want          Effect
	}{
		{"readonly-agent", "k8s_get", map[string]any{"namespace": "payments"}, Allow},
		{"readonly-agent", "k8s_get", map[string]any{"namespace": "kube-system"}, Deny},
		{"readonly-agent", "k8s_scale", map[string]any{"namespace": "payments", "replicas": 3.0, "dry_run": true}, Deny},
		{"ops-agent", "k8s_scale", map[string]any{"namespace": "payments", "replicas": 3.0, "dry_run": true}, Allow},
		{"ops-agent", "k8s_scale", map[string]any{"namespace": "payments", "replicas": 3.0, "dry_run": false}, Ask},
		{"ops-agent", "k8s_scale", map[string]any{"namespace": "payments", "replicas": 0.0, "dry_run": false}, Deny},
		{"ops-agent", "k8s_delete_pod", map[string]any{"namespace": "payments", "pod": "x", "dry_run": false}, Deny},
		{"ops-agent", "k8s_delete_pod", map[string]any{"namespace": "sandbox-1", "pod": "x", "dry_run": false}, Ask},
		{"ops-agent", "aws_ec2_reboot_instance", map[string]any{"region": "eu-west-1", "instance_id": "i-0123456789abcdef0", "dry_run": false}, Ask},
	}
	for _, c := range checks {
		if d := p.Evaluate(c.profile, c.tool, c.args); d.Effect != c.want {
			t.Errorf("%s %s %v: got %s (%s), want %s", c.profile, c.tool, c.args, d.Effect, d.Rule, c.want)
		}
	}
}
