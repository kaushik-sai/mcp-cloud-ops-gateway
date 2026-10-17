package tools

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/creds"
	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/runner"
)

type rec struct {
	cmd runner.Cmd
	res runner.Result
}

func (r *rec) Run(_ context.Context, c runner.Cmd) (runner.Result, error) {
	r.cmd = c
	return r.res, nil
}

func argv(r *rec) string { return r.cmd.Name + " " + strings.Join(r.cmd.Args, " ") }

var cfg = Config{
	TerraformWorkspaces: map[string]string{"network": "/work/network"},
	AzureSubscriptions:  map[string]string{"prod": "00000000-0000-0000-0000-000000000001"},
}

func TestKubernetesArgv(t *testing.T) {
	r := &rec{}
	x := Exec{Runner: r, Lease: creds.Lease{KubeContext: "kind-gw"}, Cfg: cfg}
	ctx := context.Background()

	in := K8sGetIn{Resource: "nodes"}
	if err := K8sGet.Prepare(&in, cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = K8sGet.Run(ctx, x, in)
	if got := argv(r); got != "kubectl --request-timeout=30s --context kind-gw get nodes --output json" {
		t.Fatalf("cluster-scoped get: %s", got)
	}

	logs := K8sLogsIn{Pod: "api-1", Container: "app", Previous: true}
	_ = K8sLogs.Prepare(&logs, cfg)
	_, _ = K8sLogs.Run(ctx, x, logs)
	if !strings.HasSuffix(argv(r), "logs api-1 --namespace default --tail 100 --container app --previous") {
		t.Fatalf("logs: %s", argv(r))
	}

	scale := K8sScaleIn{Deployment: "api", Replicas: 2, DryRun: true}
	_ = K8sScale.Prepare(&scale, cfg)
	_, _ = K8sScale.Run(ctx, x, scale)
	if !strings.HasSuffix(argv(r), "scale deployment/api --namespace default --replicas 2 --dry-run=server") {
		t.Fatalf("scale: %s", argv(r))
	}

	restart := K8sRestartIn{Namespace: "payments", Deployment: "api"}
	_ = K8sRolloutRestart.Prepare(&restart, cfg)
	_, _ = K8sRolloutRestart.Run(ctx, x, restart)
	if !strings.HasSuffix(argv(r), "rollout restart deployment/api --namespace payments") {
		t.Fatalf("restart: %s", argv(r))
	}
	restart.DryRun = true
	_, _ = K8sRolloutRestart.Run(ctx, x, restart)
	if !strings.Contains(argv(r), "patch deployment/api --namespace payments --type merge --patch") || !strings.HasSuffix(argv(r), "--dry-run=server") {
		t.Fatalf("restart dry run: %s", argv(r))
	}

	del := K8sDeletePodIn{Pod: "api-1"}
	_ = K8sDeletePod.Prepare(&del, cfg)
	_, _ = K8sDeletePod.Run(ctx, x, del)
	if !strings.HasSuffix(argv(r), "delete pod api-1 --namespace default --wait=false") {
		t.Fatalf("delete: %s", argv(r))
	}
}

func TestPrepareRejects(t *testing.T) {
	cases := map[string]error{
		"logs too many lines": K8sLogs.Prepare(&K8sLogsIn{Pod: "p", TailLines: 5000}, cfg),
		"scale too high":      K8sScale.Prepare(&K8sScaleIn{Deployment: "d", Replicas: 51}, cfg),
		"scale negative":      K8sScale.Prepare(&K8sScaleIn{Deployment: "d", Replicas: -1}, cfg),
		"flag as deployment":  K8sScale.Prepare(&K8sScaleIn{Deployment: "--all"}, cfg),
		"long justification":  K8sScale.Prepare(&K8sScaleIn{Deployment: "d", Approval: Approval{Justification: strings.Repeat("x", 501)}}, cfg),
		"bad approval id":     K8sScale.Prepare(&K8sScaleIn{Deployment: "d", Approval: Approval{ApprovalID: "apr_../../x"}}, cfg),
		"unknown workspace":   TerraformPlan.Prepare(&TerraformPlanIn{Workspace: "prod"}, cfg),
		"path as workspace":   TerraformPlan.Prepare(&TerraformPlanIn{Workspace: "/etc"}, cfg),
		"bad region":          AWSAlarms.Prepare(&AWSAlarmsIn{Region: "eu-west-1; id"}, cfg),
		"bad alarm state":     AWSAlarms.Prepare(&AWSAlarmsIn{Region: "eu-west-1", State: "BROKEN"}, cfg),
		"bad instance id":     AWSDescribeInstances.Prepare(&AWSDescribeInstancesIn{Region: "eu-west-1", InstanceIDs: []string{"i-xyz"}}, cfg),
		"too many instances":  AWSDescribeInstances.Prepare(&AWSDescribeInstancesIn{Region: "eu-west-1", InstanceIDs: make([]string, 21)}, cfg),
		"unknown sub alias":   AzureResources.Prepare(&AzureResourcesIn{Subscription: "dev", ResourceGroup: "rg"}, cfg),
		"bad resource group":  AzureResources.Prepare(&AzureResourcesIn{Subscription: "prod", ResourceGroup: "rg/../x"}, cfg),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTerraformPlan(t *testing.T) {
	r := &rec{res: runner.Result{ExitCode: 2, Stdout: "Plan: 1 to add"}}
	in := TerraformPlanIn{Workspace: "network"}
	if err := TerraformPlan.Prepare(&in, cfg); err != nil {
		t.Fatal(err)
	}
	out, _ := TerraformPlan.Run(context.Background(), Exec{Runner: r, Cfg: cfg}, in)
	if argv(r) != "terraform -chdir=/work/network plan -input=false -no-color -lock=false -detailed-exitcode" {
		t.Fatalf("argv: %s", argv(r))
	}
	if out.Failed || out.ExitCode != 2 || !strings.Contains(out.Text, "Changes pending") || r.cmd.Env["TF_IN_AUTOMATION"] != "1" {
		t.Fatalf("out %+v env %v", out, r.cmd.Env)
	}
}

func TestAWS(t *testing.T) {
	r := &rec{}
	x := Exec{Runner: r, Lease: creds.Lease{Env: map[string]string{"AWS_ACCESS_KEY_ID": "x"}}}
	in := AWSDescribeInstancesIn{Region: "eu-west-1", InstanceIDs: []string{"i-0123456789abcdef0"}}
	_ = AWSDescribeInstances.Prepare(&in, cfg)
	_, _ = AWSDescribeInstances.Run(context.Background(), x, in)
	if argv(r) != "aws ec2 describe-instances --region eu-west-1 --instance-ids i-0123456789abcdef0 --output json --no-cli-pager" || r.cmd.Env["AWS_ACCESS_KEY_ID"] != "x" {
		t.Fatalf("argv: %s", argv(r))
	}
	r.res = runner.Result{ExitCode: 254, Stderr: "An error occurred (DryRunOperation)"}
	reboot := AWSRebootIn{Region: "eu-west-1", InstanceID: "i-0123456789abcdef0", DryRun: true}
	out, _ := AWSReboot.Run(context.Background(), x, reboot)
	if out.Failed || !strings.Contains(out.Text, "Dry run passed") {
		t.Fatalf("dry run: %+v", out)
	}
}

type fakeHTTP struct {
	req    *http.Request
	status int
	body   string
}

func (f *fakeHTTP) Do(r *http.Request) (*http.Response, error) {
	f.req = r
	return &http.Response{StatusCode: f.status, Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

func TestAzure(t *testing.T) {
	h := &fakeHTTP{status: 200, body: `{"value":[]}`}
	x := Exec{HTTP: h, Lease: creds.Lease{Bearer: "tok"}, Cfg: Config{AzureSubscriptions: cfg.AzureSubscriptions, ARMEndpoint: "https://arm.test"}}
	in := AzureResourcesIn{Subscription: "prod", ResourceGroup: "rg-app"}
	if err := AzureResources.Prepare(&in, x.Cfg); err != nil {
		t.Fatal(err)
	}
	out, err := AzureResources.Run(context.Background(), x, in)
	if err != nil || out.Failed {
		t.Fatalf("%+v %v", out, err)
	}
	if h.req.URL.String() != "https://arm.test/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-app/resources?api-version=2021-04-01" ||
		h.req.Header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("request %s %v", h.req.URL, h.req.Header)
	}

	h.status, h.body = 202, ""
	vm := AzureVMRestartIn{Subscription: "prod", ResourceGroup: "rg-app", VM: "vm-1"}
	out, _ = AzureVMRestart.Run(context.Background(), x, vm)
	if h.req.Method != http.MethodPost || !strings.Contains(out.Text, "Accepted") {
		t.Fatalf("restart: %s %+v", h.req.Method, out)
	}

	h.status, h.body = 403, `{"error":{"code":"AuthorizationFailed"}}`
	out, _ = AzureResources.Run(context.Background(), x, in)
	if !out.Failed || !strings.Contains(out.Text, "403") {
		t.Fatalf("403: %+v", out)
	}

	if _, err := AzureResources.Run(context.Background(), Exec{HTTP: h, Cfg: x.Cfg}, in); err == nil {
		t.Fatal("missing bearer must fail")
	}
}

func TestSlimKubeJSON(t *testing.T) {
	in := `{"items":[{"metadata":{"name":"a","managedFields":[{}],"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}","keep":"1"}}}]}`
	out := slimKubeJSON(in)
	if strings.Contains(out, "managedFields") || strings.Contains(out, "last-applied") || !strings.Contains(out, `"keep"`) {
		t.Fatalf("got %s", out)
	}
	if slimKubeJSON("not json") != "not json" {
		t.Fatal("non-JSON must pass through")
	}
}
