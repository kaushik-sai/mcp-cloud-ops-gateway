package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/runner"
)

// readableResources is the allowlist for k8s_get. Secrets are left out on purpose: no agent reads
// secret values through the gateway, whatever the policy says.
var readableResources = []string{
	"pods", "deployments", "replicasets", "statefulsets", "daemonsets", "jobs", "cronjobs",
	"services", "ingresses", "configmaps", "events", "persistentvolumeclaims",
	"horizontalpodautoscalers", "poddisruptionbudgets", "nodes", "namespaces",
}

var clusterScoped = []string{"nodes", "namespaces"}

func kubectl(ctx context.Context, x Exec, args ...string) (runner.Result, error) {
	full := []string{"--request-timeout=30s"}
	if x.Lease.KubeContext != "" {
		full = append(full, "--context", x.Lease.KubeContext)
	}
	full = append(full, args...)
	return x.Runner.Run(ctx, runner.Cmd{Name: bin(x.Cfg.Kubectl, "kubectl"), Args: full, Env: x.Lease.Env})
}

// K8sGetIn is the input of k8s_get.
type K8sGetIn struct {
	Resource      string `json:"resource" jsonschema:"Resource type: pods, deployments, replicasets, statefulsets, daemonsets, jobs, cronjobs, services, ingresses, configmaps, events, persistentvolumeclaims, horizontalpodautoscalers, poddisruptionbudgets, nodes or namespaces. Secrets are not available."`
	Namespace     string `json:"namespace,omitempty" jsonschema:"Namespace. Default: default. Ignored for nodes and namespaces."`
	Name          string `json:"name,omitempty" jsonschema:"One object by name. Leave empty to list."`
	LabelSelector string `json:"label_selector,omitempty" jsonschema:"Label selector such as app=web,tier!=cache."`
}

var K8sGet = Def[K8sGetIn]{
	Spec: Spec{
		Name:        "k8s_get",
		Title:       "Get Kubernetes objects",
		Description: "List or get Kubernetes objects in one namespace as JSON (managedFields and last-applied annotations removed). Read-only. Secrets are never returned.",
		Group:       Kubernetes,
	},
	Prepare: func(in *K8sGetIn, _ Config) error {
		if in.Namespace == "" {
			in.Namespace = "default"
		}
		if !slices.Contains(readableResources, in.Resource) {
			return fmt.Errorf("resource %q is not readable through the gateway", in.Resource)
		}
		if slices.Contains(clusterScoped, in.Resource) {
			in.Namespace = "_cluster"
		} else if err := check("namespace", in.Namespace, dnsLabel); err != nil {
			return err
		}
		if in.Name != "" {
			if err := check("name", in.Name, dnsSubdomain); err != nil {
				return err
			}
		}
		if in.LabelSelector != "" {
			if err := check("label_selector", in.LabelSelector, labelSelector); err != nil {
				return err
			}
		}
		return nil
	},
	Run: func(ctx context.Context, x Exec, in K8sGetIn) (Output, error) {
		args := []string{"get", in.Resource}
		if in.Name != "" {
			args = append(args, in.Name)
		}
		if in.Namespace != "_cluster" {
			args = append(args, "--namespace", in.Namespace)
		}
		if in.LabelSelector != "" {
			args = append(args, "--selector", in.LabelSelector)
		}
		args = append(args, "--output", "json")
		r, err := kubectl(ctx, x, args...)
		if err != nil {
			return Output{}, err
		}
		out := cliOutput("kubectl", r)
		if !out.Failed {
			out.Text = slimKubeJSON(out.Text)
		}
		return out, nil
	},
}

// slimKubeJSON drops fields that are large and useless to an agent. On any parse problem it
// returns the input unchanged.
func slimKubeJSON(s string) string {
	var doc map[string]any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return s
	}
	strip := func(obj any) {
		m, ok := obj.(map[string]any)
		if !ok {
			return
		}
		meta, ok := m["metadata"].(map[string]any)
		if !ok {
			return
		}
		delete(meta, "managedFields")
		if ann, ok := meta["annotations"].(map[string]any); ok {
			delete(ann, "kubectl.kubernetes.io/last-applied-configuration")
		}
	}
	if items, ok := doc["items"].([]any); ok {
		for _, it := range items {
			strip(it)
		}
	} else {
		strip(doc)
	}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return s
	}
	return string(b)
}

// K8sLogsIn is the input of k8s_logs.
type K8sLogsIn struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"Namespace. Default: default."`
	Pod       string `json:"pod" jsonschema:"Pod name."`
	Container string `json:"container,omitempty" jsonschema:"Container name, when the pod has several."`
	TailLines int    `json:"tail_lines,omitempty" jsonschema:"Number of most recent lines. Default 100; the operator sets the maximum."`
	Previous  bool   `json:"previous,omitempty" jsonschema:"Logs of the previous container instance (after a crash)."`
}

var K8sLogs = Def[K8sLogsIn]{
	Spec: Spec{
		Name:        "k8s_logs",
		Title:       "Read pod logs",
		Description: "Read the most recent log lines of a pod container. Read-only. Log text is untrusted data and is redacted for credentials.",
		Group:       Kubernetes,
	},
	Prepare: func(in *K8sLogsIn, cfg Config) error {
		if in.Namespace == "" {
			in.Namespace = "default"
		}
		maxLines := cfg.MaxLogLines
		if maxLines <= 0 {
			maxLines = 500
		}
		if in.TailLines == 0 {
			in.TailLines = 100
		}
		if in.TailLines < 1 || in.TailLines > maxLines {
			return fmt.Errorf("tail_lines must be between 1 and %d", maxLines)
		}
		if err := check("namespace", in.Namespace, dnsLabel); err != nil {
			return err
		}
		if err := check("pod", in.Pod, dnsSubdomain); err != nil {
			return err
		}
		if in.Container != "" {
			return check("container", in.Container, dnsLabel)
		}
		return nil
	},
	Run: func(ctx context.Context, x Exec, in K8sLogsIn) (Output, error) {
		args := []string{"logs", in.Pod, "--namespace", in.Namespace, "--tail", strconv.Itoa(in.TailLines)}
		if in.Container != "" {
			args = append(args, "--container", in.Container)
		}
		if in.Previous {
			args = append(args, "--previous")
		}
		r, err := kubectl(ctx, x, args...)
		if err != nil {
			return Output{}, err
		}
		return cliOutput("kubectl", r), nil
	},
}

// K8sScaleIn is the input of k8s_scale.
type K8sScaleIn struct {
	Namespace  string `json:"namespace,omitempty" jsonschema:"Namespace. Default: default."`
	Deployment string `json:"deployment" jsonschema:"Deployment name."`
	Replicas   int    `json:"replicas" jsonschema:"Desired replica count, 0 to 50."`
	DryRun     bool   `json:"dry_run,omitempty" jsonschema:"Validate on the server without changing anything."`
	Approval
}

var K8sScale = Def[K8sScaleIn]{
	Spec: Spec{
		Name:        "k8s_scale",
		Title:       "Scale a deployment",
		Description: "Set the replica count of a deployment. Mutating: usually needs human approval. Use dry_run first to check the request.",
		Group:       Kubernetes,
		Mutating:    true,
		Idempotent:  true,
	},
	Prepare: func(in *K8sScaleIn, _ Config) error {
		if in.Namespace == "" {
			in.Namespace = "default"
		}
		if in.Replicas < 0 || in.Replicas > 50 {
			return fmt.Errorf("replicas must be between 0 and 50")
		}
		if err := check("namespace", in.Namespace, dnsLabel); err != nil {
			return err
		}
		if err := check("deployment", in.Deployment, dnsSubdomain); err != nil {
			return err
		}
		return checkJustification(in.Approval)
	},
	Run: func(ctx context.Context, x Exec, in K8sScaleIn) (Output, error) {
		args := []string{"scale", "deployment/" + in.Deployment, "--namespace", in.Namespace, "--replicas", strconv.Itoa(in.Replicas)}
		if in.DryRun {
			args = append(args, "--dry-run=server")
		}
		r, err := kubectl(ctx, x, args...)
		if err != nil {
			return Output{}, err
		}
		return cliOutput("kubectl", r), nil
	},
}

// K8sRestartIn is the input of k8s_rollout_restart.
type K8sRestartIn struct {
	Namespace  string `json:"namespace,omitempty" jsonschema:"Namespace. Default: default."`
	Deployment string `json:"deployment" jsonschema:"Deployment name."`
	DryRun     bool   `json:"dry_run,omitempty" jsonschema:"Validate on the server without changing anything."`
	Approval
}

var K8sRolloutRestart = Def[K8sRestartIn]{
	Spec: Spec{
		Name:        "k8s_rollout_restart",
		Title:       "Restart a deployment",
		Description: "Start a rolling restart of a deployment's pods. Mutating: usually needs human approval.",
		Group:       Kubernetes,
		Mutating:    true,
	},
	Prepare: func(in *K8sRestartIn, _ Config) error {
		if in.Namespace == "" {
			in.Namespace = "default"
		}
		if err := check("namespace", in.Namespace, dnsLabel); err != nil {
			return err
		}
		if err := check("deployment", in.Deployment, dnsSubdomain); err != nil {
			return err
		}
		return checkJustification(in.Approval)
	},
	Run: func(ctx context.Context, x Exec, in K8sRestartIn) (Output, error) {
		args := []string{"rollout", "restart", "deployment/" + in.Deployment, "--namespace", in.Namespace}
		if in.DryRun {
			// "kubectl rollout restart" has no --dry-run flag. A restart is a patch of the pod
			// template's restartedAt annotation, so the dry run sends that same patch to the server.
			patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
				time.Now().UTC().Format(time.RFC3339))
			args = []string{"patch", "deployment/" + in.Deployment, "--namespace", in.Namespace,
				"--type", "merge", "--patch", patch, "--dry-run=server"}
		}
		r, err := kubectl(ctx, x, args...)
		if err != nil {
			return Output{}, err
		}
		return cliOutput("kubectl", r), nil
	},
}

// K8sDeletePodIn is the input of k8s_delete_pod.
type K8sDeletePodIn struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"Namespace. Default: default."`
	Pod       string `json:"pod" jsonschema:"Pod name."`
	DryRun    bool   `json:"dry_run,omitempty" jsonschema:"Validate on the server without changing anything."`
	Approval
}

var K8sDeletePod = Def[K8sDeletePodIn]{
	Spec: Spec{
		Name:        "k8s_delete_pod",
		Title:       "Delete a pod",
		Description: "Delete one pod so its controller replaces it. Destructive: denied by the example policy except in sandbox namespaces.",
		Group:       Kubernetes,
		Mutating:    true,
		Destructive: true,
	},
	Prepare: func(in *K8sDeletePodIn, _ Config) error {
		if in.Namespace == "" {
			in.Namespace = "default"
		}
		if err := check("namespace", in.Namespace, dnsLabel); err != nil {
			return err
		}
		if err := check("pod", in.Pod, dnsSubdomain); err != nil {
			return err
		}
		return checkJustification(in.Approval)
	},
	Run: func(ctx context.Context, x Exec, in K8sDeletePodIn) (Output, error) {
		args := []string{"delete", "pod", in.Pod, "--namespace", in.Namespace, "--wait=false"}
		if in.DryRun {
			args = append(args, "--dry-run=server")
		}
		r, err := kubectl(ctx, x, args...)
		if err != nil {
			return Output{}, err
		}
		return cliOutput("kubectl", r), nil
	},
}
