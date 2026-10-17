// Package tools defines the operations the gateway exposes to agents.
//
// Each tool is a Def: a static spec (name, description, hints), a Prepare step that fills
// defaults and validates every argument against a strict pattern, and a Run step that performs
// the operation through the runner (CLIs) or an HTTP client (REST APIs). Tool descriptions are
// compiled in, never read from config or a remote source, so they cannot be swapped to mislead the
// agent ("tool poisoning"). Agents choose targets by alias (a Terraform workspace name, an Azure
// subscription alias), never by path or ID, so the operator decides what exists.
package tools

import (
	"context"
	"fmt"
	"regexp"

	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/creds"
	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/runner"
)

// Group names the platform a tool acts on; the gateway picks credentials by group.
type Group string

const (
	Kubernetes Group = "kubernetes"
	AWS        Group = "aws"
	Azure      Group = "azure"
	Terraform  Group = "terraform"
)

// Spec describes a tool to MCP clients and to the gateway.
type Spec struct {
	Name        string
	Title       string
	Description string
	Group       Group
	// Mutating tools change the environment. They use the group's write credential and accept
	// approval_id and justification.
	Mutating    bool
	Destructive bool
	Idempotent  bool
}

// Config holds what the operator decided: binaries and named targets.
type Config struct {
	Kubectl   string
	Terraform string
	AWSCLI    string
	// TerraformWorkspaces maps a workspace name the agent may use to a directory.
	TerraformWorkspaces map[string]string
	// AzureSubscriptions maps an alias the agent may use to a subscription ID.
	AzureSubscriptions map[string]string
	// ARMEndpoint is the Azure Resource Manager base URL. Default https://management.azure.com.
	ARMEndpoint string
	// MaxLogLines caps k8s_logs. Default 500.
	MaxLogLines int
}

// Exec is what Run gets: the runner, an HTTP client, the credentials for this call and config.
type Exec struct {
	Runner runner.Runner
	HTTP   creds.HTTPDoer
	Lease  creds.Lease
	Cfg    Config
}

// Output is a tool's raw result, before the gateway redacts and fences it.
type Output struct {
	// Source names where the text came from, for example "kubectl".
	Source string
	Text   string
	// ExitCode of the CLI, or the HTTP status for REST calls.
	ExitCode int
	// Failed means the operation did not succeed; Text then explains why.
	Failed bool
}

// Approval is embedded in the input of every mutating tool.
type Approval struct {
	ApprovalID    string `json:"approval_id,omitempty" jsonschema:"ID of a human approval for this exact call. Leave empty on the first call; the gateway returns an ID when approval is needed."`
	Justification string `json:"justification,omitempty" jsonschema:"Why this change is needed, shown to the human approver. Max 500 characters."`
}

// GetApproval lets the gateway read the embedded fields from any input type.
func (a Approval) GetApproval() Approval { return a }

// Def is a tool definition for input type In.
type Def[In any] struct {
	Spec    Spec
	Prepare func(in *In, cfg Config) error
	Run     func(ctx context.Context, x Exec, in In) (Output, error)
}

// Argument patterns. Every value that reaches a CLI matches one of these first, so none can start
// with "-" (no flag injection) or carry shell syntax (there is no shell anyway).
var (
	dnsLabel      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	dnsSubdomain  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	labelSelector = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_./-]*[A-Za-z0-9])?\s*(=|==|!=)\s*[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?(\s*,\s*[A-Za-z0-9]([A-Za-z0-9_./-]*[A-Za-z0-9])?\s*(=|==|!=)\s*[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?)*$`)
	awsRegion     = regexp.MustCompile(`^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-[0-9]$`)
	ec2InstanceID = regexp.MustCompile(`^i-[0-9a-f]{8}([0-9a-f]{9})?$`)
	alias         = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	azureName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.()-]{0,88}[A-Za-z0-9_()]$|^[A-Za-z0-9]$`)
)

func check(field, value string, re *regexp.Regexp) error {
	if !re.MatchString(value) {
		return fmt.Errorf("%s %q is not valid", field, value)
	}
	return nil
}

func checkJustification(a Approval) error {
	if len(a.Justification) > 500 {
		return fmt.Errorf("justification is longer than 500 characters")
	}
	if a.ApprovalID != "" && !regexp.MustCompile(`^apr_[a-z2-7]{16}$`).MatchString(a.ApprovalID) {
		return fmt.Errorf("approval_id %q is not valid", a.ApprovalID)
	}
	return nil
}

// cliOutput turns a CLI result into an Output: stdout on success, stderr (and stdout) on failure.
func cliOutput(source string, r runner.Result) Output {
	if r.ExitCode == 0 {
		return Output{Source: source, Text: r.Stdout}
	}
	text := fmt.Sprintf("%s exited with code %d.\n%s", source, r.ExitCode, r.Stderr)
	if r.Stdout != "" {
		text += "\n" + r.Stdout
	}
	return Output{Source: source, Text: text, ExitCode: r.ExitCode, Failed: true}
}

func bin(configured, fallback string) string {
	if configured != "" {
		return configured
	}
	return fallback
}
