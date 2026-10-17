//go:build e2e

// Package e2e drives the real gateway binary over stdio against a real Kubernetes API server.
//
//	E2E_KUBE_CONTEXT=kwok-gw go test -tags e2e -v ./test/e2e/
//
// It needs kubectl on PATH and a cluster in the current kubeconfig (kind, kwok or any test
// cluster). It creates the namespace e2e-payments and deletes it at the end.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ns            = "e2e-payments"
	approverToken = "e2e-approver-token-0123456789abcdef0123456789"
)

func kubectl(t *testing.T, kctx string, args ...string) string {
	t.Helper()
	out, err := exec.Command("kubectl", append([]string{"--context", kctx}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestGatewayAgainstARealCluster(t *testing.T) {
	kctx := os.Getenv("E2E_KUBE_CONTEXT")
	if kctx == "" {
		kctx = "kind-gw"
	}
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	dir := t.TempDir()

	bin := filepath.Join(dir, "mcp-cloud-ops-gateway")
	build := exec.Command("go", "build", "-o", bin, "./cmd/mcp-cloud-ops-gateway")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// Fixture: a namespace and a deployment with one replica.
	_ = exec.Command("kubectl", "--context", kctx, "delete", "namespace", ns, "--wait=false").Run()
	time.Sleep(2 * time.Second)
	kubectl(t, kctx, "create", "namespace", ns)
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "--context", kctx, "delete", "namespace", ns, "--wait=false").Run()
	})
	kubectl(t, kctx, "create", "deployment", "api", "--image=nginx:1.27", "--replicas=1", "-n", ns)

	admin := freePort(t)
	sum := sha256.Sum256([]byte(approverToken))
	policy, _ := os.ReadFile(filepath.Join(root, "examples", "policy.yaml"))
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), policy, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`
server: { admin_listen: %q, stdio_principal: local-agent }
policy_file: policy.yaml
audit: { file: audit.jsonl }
principals: [ { name: local-agent, profile: ops-agent } ]
approvers: [ { name: on-call-human, token_sha256: %s } ]
credentials: { cluster: { type: kubeconfig, context: %s } }
kubernetes: { read_credential: cluster, write_credential: cluster }
`, admin, hex.EncodeToString(sum[:]), kctx)
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// The child needs kubectl and the kubeconfig; it gets PATH and HOME from the gateway's runner.
	cmd := exec.Command(bin, "serve", "--config", cfgPath, "--stdio")
	cmd.Stderr = os.Stderr

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	callTool := func(name string, args map[string]any) map[string]any {
		t.Helper()
		start := time.Now()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := map[string]any{}
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, &out)
		a, _ := json.Marshal(args)
		t.Logf("%-20s %s -> status=%v rule=%q (%s)", name, a, out["status"], out["rule"], time.Since(start).Round(time.Millisecond))
		return out
	}

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tools served: %d", len(tools.Tools))

	if out := callTool("k8s_get", map[string]any{"resource": "deployments", "namespace": ns}); out["status"] != "ok" {
		t.Fatalf("read: %v", out)
	}
	if out := callTool("k8s_get", map[string]any{"resource": "pods", "namespace": "kube-system"}); out["status"] != "denied" {
		t.Fatalf("kube-system read: %v", out)
	}
	if out := callTool("k8s_scale", map[string]any{"namespace": ns, "deployment": "api", "replicas": 3, "dry_run": true}); out["status"] != "ok" {
		t.Fatalf("dry run: %v", out)
	}
	if got := kubectl(t, kctx, "get", "deployment", "api", "-n", ns, "-o", "jsonpath={.spec.replicas}"); got != "1" {
		t.Fatalf("dry run changed replicas to %s", got)
	}

	out := callTool("k8s_scale", map[string]any{"namespace": ns, "deployment": "api", "replicas": 3, "justification": "e2e"})
	id, _ := out["approval_id"].(string)
	if out["status"] != "approval_required" || id == "" {
		t.Fatalf("expected approval_required: %v", out)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+admin+"/v1/approvals/"+id+"/approve", strings.NewReader(`{"note":"e2e"}`))
	req.Header.Set("Authorization", "Bearer "+approverToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("approve: %v %v", err, resp)
	}
	resp.Body.Close()

	if out := callTool("k8s_scale", map[string]any{"namespace": ns, "deployment": "api", "replicas": 3, "approval_id": id}); out["status"] != "ok" || out["approved_by"] != "on-call-human" {
		t.Fatalf("approved scale: %v", out)
	}
	if got := kubectl(t, kctx, "get", "deployment", "api", "-n", ns, "-o", "jsonpath={.spec.replicas}"); got != "3" {
		t.Fatalf("replicas = %s, want 3", got)
	}
	if out := callTool("k8s_scale", map[string]any{"namespace": ns, "deployment": "api", "replicas": 3, "approval_id": id}); out["status"] != "denied" {
		t.Fatalf("approval reused: %v", out)
	}
	if out := callTool("k8s_delete_pod", map[string]any{"namespace": ns, "pod": "api-0"}); out["status"] != "denied" {
		t.Fatalf("delete pod: %v", out)
	}
	if out := callTool("k8s_rollout_restart", map[string]any{"namespace": ns, "deployment": "api", "dry_run": true}); out["status"] != "ok" {
		t.Fatalf("restart dry run: %v", out)
	}

	_ = cs.Close()
	verify, err := exec.Command(bin, "audit", "verify", "--file", filepath.Join(dir, "audit.jsonl")).CombinedOutput()
	if err != nil {
		t.Fatalf("audit verify: %v\n%s", err, verify)
	}
	t.Logf("audit verify: %s", strings.Join(strings.Fields(string(verify)), " "))
}
