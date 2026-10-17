# Extending the gateway

Three kinds of change are small and local: a tool in an existing group, a new group (a new cloud), and a new credential adapter. This page gives the steps with code that follows the existing files. Names such as `K8sRolloutStatus` and `gcp_federated` are examples; they do not exist in the repo.

Read [CONFIGURATION.md](CONFIGURATION.md) first for the config and policy fields. The request pipeline is in [DESIGN.md](../DESIGN.md).

## How the pieces fit

| Piece | File | Role |
|---|---|---|
| `tools.Def[In]` | `internal/tools/` | One tool: `Spec`, `Prepare`, `Run` |
| `catalog` | `internal/gateway/gateway.go` | Tool name to registrar. Maps a name to `def(tools.X)`. |
| `groupTools` | `internal/gateway/gateway.go` | Group to tool names, in the order clients see them |
| `EnabledTools`, `AllTools` | `internal/gateway/gateway.go` | Which tools a config serves, and which the policy may name |
| `lease()` | `internal/gateway/gateway.go` | Picks the read or write credential for a tool's group |
| `config.Config` | `internal/config/config.go` | The file format and its validation |
| `creds.Provider` | `internal/creds/creds.go` | Turns a credential entry into a `Lease` |
| `Providers()` | `internal/gateway/gateway.go` | Builds providers from the credential entries |

The gateway, not the tool, does identity, policy, approval, audit, credentials, redaction and fencing. A tool only validates its arguments and runs one operation.

## A. Add a tool to an existing group

Example: a read tool `k8s_rollout_status` in the `kubernetes` group.

### 1. Input struct, `Def`, `Prepare`, `Run`

Put it next to the other tools of the group (`internal/tools/kubernetes.go`). The input struct has one field per argument. The `json` tag is the argument name an agent sends and the name a policy condition uses. The `jsonschema` tag is the description shown to the agent. Every argument that is optional has `omitempty`.

```go
// K8sRolloutStatusIn is the input of k8s_rollout_status.
type K8sRolloutStatusIn struct {
	Namespace  string `json:"namespace,omitempty" jsonschema:"Namespace. Default: default."`
	Deployment string `json:"deployment" jsonschema:"Deployment name."`
}

var K8sRolloutStatus = Def[K8sRolloutStatusIn]{
	Spec: Spec{
		Name:        "k8s_rollout_status",
		Title:       "Rollout status of a deployment",
		Description: "Report whether a deployment's rollout is complete. Read-only.",
		Group:       Kubernetes,
		// Mutating, Destructive and Idempotent stay false for a read tool.
	},
	Prepare: func(in *K8sRolloutStatusIn, _ Config) error {
		if in.Namespace == "" {
			in.Namespace = "default"
		}
		if err := check("namespace", in.Namespace, dnsLabel); err != nil {
			return err
		}
		return check("deployment", in.Deployment, dnsSubdomain)
	},
	Run: func(ctx context.Context, x Exec, in K8sRolloutStatusIn) (Output, error) {
		r, err := kubectl(ctx, x, "rollout", "status", "deployment/"+in.Deployment,
			"--namespace", in.Namespace, "--watch=false")
		if err != nil {
			return Output{}, err
		}
		return cliOutput("kubectl", r), nil
	},
}
```

Rules for the pieces:

- `Spec.Name` is unique, lower snake case, and starts with the group prefix (`k8s_`, `aws_`, `azure_`, `terraform_`).
- `Prepare` fills defaults first, then validates every value that reaches a CLI or URL with a pattern from `tools.go` (`dnsLabel`, `dnsSubdomain`, `labelSelector`, `awsRegion`, `ec2InstanceID`, `alias`, `azureName`) through `check(field, value, re)`. Add a new anchored pattern there if none fits.
- `Run` builds argv as separate elements. Use the group's helper (`kubectl`, `awsCLI`, `arm`) or `x.Runner.Run(ctx, runner.Cmd{...})`. Return `Output` through `cliOutput(source, r)` for CLIs.
- Do not read the environment, files or the network in `Prepare`. It must be pure so tests need no CLI.

For a mutating tool, embed `Approval` in the input and call `checkJustification` at the end of `Prepare`:

```go
type K8sCordonIn struct {
	Node   string `json:"node" jsonschema:"Node name."`
	DryRun bool   `json:"dry_run,omitempty" jsonschema:"Validate on the server without changing anything."`
	Approval
}

// In Spec: Mutating: true (add Destructive: true if it deletes or cannot be undone,
// Idempotent: true if repeating it has no further effect).
// At the end of Prepare:
//     return checkJustification(in.Approval)
```

`Approval` supplies the `approval_id` and `justification` arguments. The gateway reads them through `GetApproval()` and removes them from the arguments the policy and the approval digest see.

### 2. Register it in the gateway

In `internal/gateway/gateway.go`, add the tool to the `catalog` map and to its group in `groupTools`:

```go
var groupTools = map[tools.Group][]string{
	tools.Kubernetes: {tools.K8sGet.Spec.Name, tools.K8sLogs.Spec.Name, tools.K8sRolloutStatus.Spec.Name, /* existing ... */},
	// ...
}

var catalog = map[string]registrar{
	// ...
	tools.K8sRolloutStatus.Spec.Name: def(tools.K8sRolloutStatus),
}
```

`New()` fails with "tool X has no registrar" if a name is in `groupTools` but not in `catalog`. `AllTools()` and `EnabledTools()` read `groupTools`, so nothing else changes for an existing group. `def` sets the MCP annotations from `Spec`: `ReadOnlyHint` is `!Mutating`, `DestructiveHint` is `Destructive`, `IdempotentHint` is `Idempotent` or not mutating.

### 3. Tests

In `internal/tools/tools_test.go`, use the `rec` fake runner and the package `cfg`:

```go
func TestK8sRolloutStatus(t *testing.T) {
	r := &rec{}
	x := Exec{Runner: r, Lease: creds.Lease{KubeContext: "kind-gw"}, Cfg: cfg}
	in := K8sRolloutStatusIn{Deployment: "api"}
	if err := K8sRolloutStatus.Prepare(&in, cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = K8sRolloutStatus.Run(context.Background(), x, in)
	want := "kubectl --request-timeout=30s --context kind-gw rollout status deployment/api --namespace default --watch=false"
	if argv(r) != want {
		t.Fatalf("argv: %s", argv(r))
	}
}
```

Add hostile values to the table in `TestPrepareRejects` (a value starting with `-`, one with `;`, one with `../`):

```go
"flag as deployment (status)": K8sRolloutStatus.Prepare(&K8sRolloutStatusIn{Deployment: "--all"}, cfg),
```

In `internal/gateway/gateway_test.go`:

- Add a rule for the tool to `testPolicy`. With no rule the default is deny, which also makes a good test.
- Add a call through the harness: `h := newHarness(t)`, `cs := h.stdioClient(t)`, `call(t, cs, "k8s_rollout_status", map[string]any{"deployment": "api"})`. Check `out["status"]` and `h.run.last().Args`.
- Update the tool count in `TestListToolsHasHintsAndOnlyConfiguredGroups` (it is `9`: the policy tool, 5 Kubernetes tools and 3 AWS tools).
- For a mutating tool, add the ask and approve flow, following `TestApprovalFlowOverAdminAPI`.

### 4. Policy

Add rules to `examples/policy.yaml`. `policy.Load` rejects a rule that names a tool the gateway does not know, so this also checks step 2. A read tool usually goes into `readonly-agent`. A mutating tool goes into the profiles that may use it, with `ask`; a destructive one is denied by default. For a mutating tool with a dry run, copy the `k8s_scale` pattern: `allow` plus an `ask` rule `when: { dry_run: { equals: "false" } }`.

If the tool has an argument that scopes it (namespace, region), consider a `deny` rule for the sensitive values.

### 5. Docs

- The tool table in `README.md` (tool, group, kind, what it does).
- The argument table in `docs/CONFIGURATION.md`.
- A numbered row in `docs/DECISIONS.md` if the tool needed a design choice.
- RBAC in `deploy/kubernetes/base/rbac.yaml` if a Kubernetes tool needs a verb the gateway's service account lacks. RBAC is the hard limit under the policy.

### 6. Check

```powershell
go build ./...
go test -race ./...
./bin/mcp-cloud-ops-gateway validate --config examples/gateway.yaml   # after go build -o bin/...
```

## B. Add a new group (example: GCP)

A group is a platform with its own credential choices and tools. Steps, in order.

### 1. Group constant

`internal/tools/tools.go`:

```go
const (
	Kubernetes Group = "kubernetes"
	AWS        Group = "aws"
	Azure      Group = "azure"
	Terraform  Group = "terraform"
	GCP        Group = "gcp"
)
```

### 2. Tool-side config

If tools need operator-chosen binaries or targets, add them to `tools.Config`:

```go
type Config struct {
	// ... existing fields
	// GCloud is the gcloud binary. Default "gcloud".
	GCloud string
	// GCPProjects maps an alias the agent may use to a project ID.
	GCPProjects map[string]string
}
```

Agents name targets by alias; the operator decides what exists.

### 3. Config section and validation

`internal/config/config.go`: add a struct, a pointer field on `Config`, and checks in `validate()`.

```go
type GCP struct {
	ReadCredential  string            `yaml:"read_credential"`
	WriteCredential string            `yaml:"write_credential"`
	CLI             string            `yaml:"cli,omitempty"`
	Projects        map[string]string `yaml:"projects"`
}

// In Config:
//     GCP *GCP `yaml:"gcp,omitempty"`

// In validate(), next to the other groups:
if g := c.GCP; g != nil {
	ref("gcp.read_credential", g.ReadCredential)
	ref("gcp.write_credential", g.WriteCredential)
	if len(g.Projects) == 0 {
		errs = append(errs, errors.New("gcp.projects: at least one alias is required"))
	}
}
```

`ref` checks that the name is set and exists in `credentials`. Add a test in `internal/config/config_test.go` for a missing credential and an empty alias map.

### 4. Gateway wiring

In `internal/gateway/gateway.go`:

```go
// ToolConfig:
if g := cfg.GCP; g != nil {
	tc.GCloud, tc.GCPProjects = g.CLI, g.Projects
}

// groupTools:
tools.GCP: {tools.GCPInstancesList.Spec.Name, tools.GCPInstanceReset.Spec.Name},

// AllTools: add tools.GCP to the group list in the loop.
for _, grp := range []tools.Group{tools.Kubernetes, tools.AWS, tools.Azure, tools.Terraform, tools.GCP} {

// EnabledTools:
if cfg.GCP != nil {
	out = append(out, groupTools[tools.GCP]...)
}

// lease():
case tools.GCP:
	name = pick(spec.Mutating, g.cfg.GCP.ReadCredential, g.cfg.GCP.WriteCredential)

// catalog: one def(...) line per tool.
```

Do not skip `AllTools` (the policy loader would then reject rules for the new tools) or the `lease()` case (without it the credential name is empty and every call fails with `credential "" is not configured`).

### 5. Tools, credential, tests, docs

- Write the tools as in recipe A, with `Group: GCP`.
- If the platform needs a new way to get credentials, add an adapter (recipe C).
- Tests: add the group to the harness config in `gateway_test.go` and check that its tools are listed only when the section is present, like `TestListToolsHasHintsAndOnlyConfiguredGroups`.
- Docs: group section in `CONFIGURATION.md`, tool rows in `README.md`, rules in `examples/policy.yaml`.
- Deployment: a `gcp:` block and credentials in `deploy/kubernetes/base/configmap.yaml` only if the base should enable it. Otherwise document it in the overlay.

## C. Add a credential adapter

A credential adapter turns a `credentials.<name>` entry into short-lived credentials. The gateway gives them to the tool as a `creds.Lease`: environment variables for a CLI (`Env`), a `--context` for kubectl (`KubeContext`), or a bearer token for REST (`Bearer`), plus `Expires`.

### 1. The interface

```go
type Provider interface {
	Lease(ctx context.Context) (Lease, error)
}
```

Implement it in `internal/creds/creds.go`. Use the shared `cache` so a lease is reused until 2 minutes before it expires, `readToken` for the OIDC token file, and `post` for the form POST (it takes an `HTTPDoer`, so tests fake it).

```go
// GCPFederated exchanges the platform's OIDC token for a Google access token through
// workload identity federation.
type GCPFederated struct {
	Audience  string
	TokenFile string
	HTTP      HTTPDoer

	c cache
}

func (g *GCPFederated) Lease(ctx context.Context) (Lease, error) {
	return g.c.get(ctx, g.fetch)
}

func (g *GCPFederated) fetch(ctx context.Context) (Lease, error) {
	tok, err := readToken(g.TokenFile)
	if err != nil {
		return Lease{}, err
	}
	form := url.Values{ /* the exchange request, with tok as the subject token */ }
	body, status, err := post(ctx, g.HTTP, "https://sts.googleapis.com/v1/token", form)
	if err != nil {
		return Lease{}, fmt.Errorf("gcp sts: %w", err)
	}
	// Decode body. On a non-200 status, return an error with the code and the first line of the
	// description only; never include the request or the token.
	return Lease{Bearer: accessToken, Expires: time.Now().Add(expiresIn)}, nil
}
```

### 2. Config type and validation

`internal/config/config.go`: add fields to `Credential` (with `omitempty`), then a case in `Credential.validate()` and in the comment on `Type`.

```go
// Credential:
//     Audience string `yaml:"audience,omitempty"`

case "gcp_federated":
	if cr.Audience == "" || cr.TokenFile == "" {
		return errors.New("gcp_federated needs audience and token_file")
	}
```

An unknown `type` already fails with `unknown type`, so a typo is caught. Add a test that a missing field is rejected.

### 3. Build the provider

`internal/gateway/gateway.go`, in `Providers()`. Resolve any path with `cfg.Path`:

```go
case "gcp_federated":
	out[name] = &creds.GCPFederated{Audience: c.Audience, TokenFile: cfg.Path(c.TokenFile), HTTP: doer}
```

### 4. Tests and docs

- `internal/creds/creds_test.go`: use `httptest.NewServer` and the `tokenFile` helper, as in `TestAWSWebIdentityExchangesAndCaches`. Check the request fields, the lease, the cache (one hit for two calls) and an error response that does not leak the token.
- `CONFIGURATION.md`: the field table and a full YAML example for the type.

## D. Security checklist for every new tool

A change that adds a tool is reviewed against this list. Tick each item in the PR.

1. **Strict argument patterns.** Every string that reaches a CLI, a URL or a file path matches an anchored regular expression or an allowlist in `Prepare`. No value may start with `-`. Numbers have explicit bounds. Lists have a maximum length.
2. **Defaults before validation.** `Prepare` fills defaults first. The policy sees the filled values.
3. **No shell.** Use `runner.Cmd{Name, Args}`. Never join strings into a command line, never run `sh -c`, never pass a user value as the program name. The binary name comes from config, not from input.
4. **Aliases, not paths or IDs.** Agents name a workspace, subscription or project by alias. The operator's config maps it to the directory or ID. A tool must look the alias up and fail if it is missing.
5. **Mutating tools are marked.** Set `Mutating: true` for anything that changes state, so it uses the write credential and the `ReadOnlyHint` is false. Set `Destructive` for deletes and irreversible changes. Embed `Approval` and call `checkJustification`.
6. **Policy defaults to deny.** Add the tool to `examples/policy.yaml` with the narrowest effect. A mutating tool is `ask` or `deny`, never a bare `allow` (a dry run may be `allow`).
7. **Dry run where the platform has one.** Offer `dry_run`, and say plainly in the description when the platform has none (see `azure_vm_restart`).
8. **No secrets in output.** The tool must not print tokens, keys, kubeconfigs or environment variables. Do not add a tool that reads Kubernetes Secrets or secret managers; `k8s_get` has an allowlist that leaves them out on purpose. The gateway redacts known credential shapes, but that is a second layer.
9. **Errors do not echo credentials.** Do not put request bodies, headers or leases into `error` values. The gateway redacts error text, but do not rely on it.
10. **Bound the work.** No unbounded output, loops or watches (`--watch=false`, `--tail`, size caps). The runner enforces `limits.command_timeout`, and REST reads should use `io.LimitReader`.
11. **Annotations are honest.** The tool description is compiled in, never read from config or a remote source. It says what the tool does and whether it mutates. `OpenWorldHint` is set by `def` for all tools.
12. **Credentials via the lease only.** Use `x.Lease.Env` or `x.Lease.Bearer`. Do not read the gateway's own environment in a tool. The runner gives children only `PATH`, `HOME` and the lease.
13. **Tests include hostile input.** `TestPrepareRejects` has a flag-like value, a shell metacharacter and a path traversal for each new string argument. A gateway test shows that an invalid call never reaches the runner.
14. **Docs and decision log.** README tool table, CONFIGURATION argument table, and `docs/DECISIONS.md` if a design choice was made.
