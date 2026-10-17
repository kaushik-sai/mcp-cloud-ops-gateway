package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/runner"
)

// ---------------------------------------------------------------- Terraform

// TerraformPlanIn is the input of terraform_plan.
type TerraformPlanIn struct {
	Workspace string `json:"workspace" jsonschema:"Name of a Terraform workspace the operator configured (not a path)."`
}

var TerraformPlan = Def[TerraformPlanIn]{
	Spec: Spec{
		Name:        "terraform_plan",
		Title:       "Terraform plan",
		Description: "Run terraform plan in an operator-configured workspace and return the plan text. Read-only: no apply, no state lock. Exit code 2 means changes are pending.",
		Group:       Terraform,
		Idempotent:  true,
	},
	Prepare: func(in *TerraformPlanIn, cfg Config) error {
		if err := check("workspace", in.Workspace, alias); err != nil {
			return err
		}
		if _, ok := cfg.TerraformWorkspaces[in.Workspace]; !ok {
			return fmt.Errorf("workspace %q is not configured", in.Workspace)
		}
		return nil
	},
	Run: func(ctx context.Context, x Exec, in TerraformPlanIn) (Output, error) {
		dir := x.Cfg.TerraformWorkspaces[in.Workspace]
		// -lock=false: a plan never holds the state lock, so an agent cannot block a real apply.
		// -detailed-exitcode: 0 no changes, 1 error, 2 changes present.
		r, err := x.Runner.Run(ctx, runner.Cmd{
			Name: bin(x.Cfg.Terraform, "terraform"),
			Args: []string{"-chdir=" + dir, "plan", "-input=false", "-no-color", "-lock=false", "-detailed-exitcode"},
			Env:  withEnv(x.Lease.Env, map[string]string{"TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}),
		})
		if err != nil {
			return Output{}, err
		}
		if r.ExitCode == 2 {
			return Output{Source: "terraform", Text: "Changes pending (exit code 2).\n" + r.Stdout, ExitCode: 2}, nil
		}
		return cliOutput("terraform", r), nil
	},
}

func withEnv(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------- AWS

func awsCLI(ctx context.Context, x Exec, args ...string) (runner.Result, error) {
	full := append(args, "--output", "json", "--no-cli-pager")
	return x.Runner.Run(ctx, runner.Cmd{Name: bin(x.Cfg.AWSCLI, "aws"), Args: full, Env: x.Lease.Env})
}

// AWSDescribeInstancesIn is the input of aws_ec2_describe_instances.
type AWSDescribeInstancesIn struct {
	Region      string   `json:"region" jsonschema:"AWS region, for example eu-west-1."`
	InstanceIDs []string `json:"instance_ids,omitempty" jsonschema:"Instance IDs to describe, at most 20. Empty lists all instances in the region."`
}

var AWSDescribeInstances = Def[AWSDescribeInstancesIn]{
	Spec: Spec{
		Name:        "aws_ec2_describe_instances",
		Title:       "Describe EC2 instances",
		Description: "Describe EC2 instances in one region. Read-only, using short-lived credentials from the gateway's reader role.",
		Group:       AWS,
	},
	Prepare: func(in *AWSDescribeInstancesIn, _ Config) error {
		if err := check("region", in.Region, awsRegion); err != nil {
			return err
		}
		if len(in.InstanceIDs) > 20 {
			return fmt.Errorf("at most 20 instance_ids")
		}
		for _, id := range in.InstanceIDs {
			if err := check("instance id", id, ec2InstanceID); err != nil {
				return err
			}
		}
		return nil
	},
	Run: func(ctx context.Context, x Exec, in AWSDescribeInstancesIn) (Output, error) {
		args := []string{"ec2", "describe-instances", "--region", in.Region}
		if len(in.InstanceIDs) > 0 {
			args = append(args, "--instance-ids")
			args = append(args, in.InstanceIDs...)
		}
		r, err := awsCLI(ctx, x, args...)
		if err != nil {
			return Output{}, err
		}
		return cliOutput("aws", r), nil
	},
}

// AWSAlarmsIn is the input of aws_cloudwatch_alarms.
type AWSAlarmsIn struct {
	Region string `json:"region" jsonschema:"AWS region, for example eu-west-1."`
	State  string `json:"state,omitempty" jsonschema:"Alarm state: ALARM (default), OK or INSUFFICIENT_DATA."`
}

var AWSAlarms = Def[AWSAlarmsIn]{
	Spec: Spec{
		Name:        "aws_cloudwatch_alarms",
		Title:       "List CloudWatch alarms",
		Description: "List CloudWatch metric alarms in one region by state (default ALARM). Read-only.",
		Group:       AWS,
	},
	Prepare: func(in *AWSAlarmsIn, _ Config) error {
		if in.State == "" {
			in.State = "ALARM"
		}
		switch in.State {
		case "ALARM", "OK", "INSUFFICIENT_DATA":
		default:
			return fmt.Errorf("state %q is not ALARM, OK or INSUFFICIENT_DATA", in.State)
		}
		return check("region", in.Region, awsRegion)
	},
	Run: func(ctx context.Context, x Exec, in AWSAlarmsIn) (Output, error) {
		r, err := awsCLI(ctx, x, "cloudwatch", "describe-alarms", "--region", in.Region, "--state-value", in.State)
		if err != nil {
			return Output{}, err
		}
		return cliOutput("aws", r), nil
	},
}

// AWSRebootIn is the input of aws_ec2_reboot_instance.
type AWSRebootIn struct {
	Region     string `json:"region" jsonschema:"AWS region, for example eu-west-1."`
	InstanceID string `json:"instance_id" jsonschema:"The instance to reboot."`
	DryRun     bool   `json:"dry_run,omitempty" jsonschema:"Ask EC2 to check permissions without rebooting."`
	Approval
}

var AWSReboot = Def[AWSRebootIn]{
	Spec: Spec{
		Name:        "aws_ec2_reboot_instance",
		Title:       "Reboot an EC2 instance",
		Description: "Reboot one EC2 instance, using the operator role. Mutating: usually needs human approval.",
		Group:       AWS,
		Mutating:    true,
	},
	Prepare: func(in *AWSRebootIn, _ Config) error {
		if err := check("region", in.Region, awsRegion); err != nil {
			return err
		}
		if err := check("instance_id", in.InstanceID, ec2InstanceID); err != nil {
			return err
		}
		return checkJustification(in.Approval)
	},
	Run: func(ctx context.Context, x Exec, in AWSRebootIn) (Output, error) {
		args := []string{"ec2", "reboot-instances", "--region", in.Region, "--instance-ids", in.InstanceID}
		if in.DryRun {
			args = append(args, "--dry-run")
		}
		r, err := awsCLI(ctx, x, args...)
		if err != nil {
			return Output{}, err
		}
		// EC2 reports a successful dry run as the DryRunOperation "error".
		if in.DryRun && strings.Contains(r.Stderr, "DryRunOperation") {
			return Output{Source: "aws", Text: "Dry run passed: the request would have succeeded."}, nil
		}
		return cliOutput("aws", r), nil
	},
}

// ---------------------------------------------------------------- Azure (Resource Manager REST)

func arm(ctx context.Context, x Exec, method, path string) (Output, error) {
	if x.Lease.Bearer == "" {
		return Output{}, fmt.Errorf("azure: no access token; the tool's credential must be azure_federated")
	}
	base := strings.TrimRight(x.Cfg.ARMEndpoint, "/")
	if base == "" {
		base = "https://management.azure.com"
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		return Output{}, err
	}
	req.Header.Set("Authorization", "Bearer "+x.Lease.Bearer)
	req.Header.Set("Accept", "application/json")
	doer := x.HTTP
	if doer == nil {
		doer = http.DefaultClient
	}
	resp, err := doer.Do(req)
	if err != nil {
		return Output{}, fmt.Errorf("azure: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Output{}, fmt.Errorf("azure: read response: %w", err)
	}
	out := Output{Source: "azure-resource-manager", Text: string(body), ExitCode: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusAccepted && len(body) == 0:
		out.Text = "Accepted: Azure started the operation (HTTP 202)."
	case resp.StatusCode >= 300:
		out.Failed = true
		out.Text = fmt.Sprintf("Azure Resource Manager returned HTTP %d.\n%s", resp.StatusCode, body)
	}
	return out, nil
}

func subscriptionID(cfg Config, aliasName string) (string, error) {
	id, ok := cfg.AzureSubscriptions[aliasName]
	if !ok {
		return "", fmt.Errorf("subscription alias %q is not configured", aliasName)
	}
	return id, nil
}

// AzureResourcesIn is the input of azure_resource_list.
type AzureResourcesIn struct {
	Subscription  string `json:"subscription" jsonschema:"Subscription alias the operator configured (not the ID)."`
	ResourceGroup string `json:"resource_group" jsonschema:"Resource group name."`
}

var AzureResources = Def[AzureResourcesIn]{
	Spec: Spec{
		Name:        "azure_resource_list",
		Title:       "List Azure resources",
		Description: "List the resources in one Azure resource group. Read-only, using a short-lived Entra ID token from workload identity federation.",
		Group:       Azure,
	},
	Prepare: func(in *AzureResourcesIn, cfg Config) error {
		if err := check("subscription", in.Subscription, alias); err != nil {
			return err
		}
		if _, err := subscriptionID(cfg, in.Subscription); err != nil {
			return err
		}
		return check("resource_group", in.ResourceGroup, azureName)
	},
	Run: func(ctx context.Context, x Exec, in AzureResourcesIn) (Output, error) {
		sub, _ := subscriptionID(x.Cfg, in.Subscription)
		path := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/resources?api-version=2021-04-01",
			url.PathEscape(sub), url.PathEscape(in.ResourceGroup))
		return arm(ctx, x, http.MethodGet, path)
	},
}

// AzureVMRestartIn is the input of azure_vm_restart.
type AzureVMRestartIn struct {
	Subscription  string `json:"subscription" jsonschema:"Subscription alias the operator configured (not the ID)."`
	ResourceGroup string `json:"resource_group" jsonschema:"Resource group name."`
	VM            string `json:"vm" jsonschema:"Virtual machine name."`
	Approval
}

var AzureVMRestart = Def[AzureVMRestartIn]{
	Spec: Spec{
		Name:        "azure_vm_restart",
		Title:       "Restart an Azure VM",
		Description: "Restart one Azure virtual machine, using the operator identity. Mutating: usually needs human approval. Azure has no dry run for this call.",
		Group:       Azure,
		Mutating:    true,
	},
	Prepare: func(in *AzureVMRestartIn, cfg Config) error {
		if err := check("subscription", in.Subscription, alias); err != nil {
			return err
		}
		if _, err := subscriptionID(cfg, in.Subscription); err != nil {
			return err
		}
		if err := check("resource_group", in.ResourceGroup, azureName); err != nil {
			return err
		}
		if err := check("vm", in.VM, azureName); err != nil {
			return err
		}
		return checkJustification(in.Approval)
	},
	Run: func(ctx context.Context, x Exec, in AzureVMRestartIn) (Output, error) {
		sub, _ := subscriptionID(x.Cfg, in.Subscription)
		path := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s/restart?api-version=2024-07-01",
			url.PathEscape(sub), url.PathEscape(in.ResourceGroup), url.PathEscape(in.VM))
		return arm(ctx, x, http.MethodPost, path)
	},
}
