# Configuration reference

The gateway reads two files: a config file (`gateway.yaml`) and a policy file (`policy.yaml`). This page lists every field in both. It is derived from `internal/config/config.go` and `internal/policy/policy.go`. If the code and this page disagree, the code is right; please fix the page.

Both files reject unknown fields. A typo fails at start-up instead of silently disabling a control. Check a pair of files without starting the server:

```powershell
./bin/mcp-cloud-ops-gateway validate --config examples/gateway.yaml
```

`validate` prints the tools that would be served and, for each principal, the effect of each tool (`allow`, `ask`, `deny` or `conditional`).

## How the config file is read

### Environment variables

Before the YAML is parsed, the whole file text is scanned for `${NAME}` and each one is replaced by the environment variable `NAME`.

| Written | Result |
|---|---|
| `${NAME}` | The value of `NAME`. If `NAME` is not set, loading fails and lists every missing name. An empty but set variable is allowed. |
| `$${` | A literal `${`. Use it where a value must contain `${`. |
| `$` not followed by `{` | Left alone. |
| `${` with no closing `}` | Loading fails with "unclosed ${". |

Things to know:

- Expansion works on raw text, before YAML is parsed. It also applies inside YAML comments. A comment that contains `${SOMETHING}` makes loading fail if `SOMETHING` is unset. Write `$${SOMETHING}` in comments.
- There is no default syntax such as `${NAME:-x}`. A name is everything between `${` and the first `}`.
- The policy file is not expanded. Only `gateway.yaml` is.
- The variables must be set in the gateway's own environment. A Kubernetes ConfigMap does not expand them; set them as container `env`.

### Relative paths

Fields that hold a path are resolved by `Config.Path`:

1. A leading `~/` is replaced by the home directory of the user running the gateway.
2. An empty path stays empty. An absolute path is used as is.
3. Any other path is joined to the directory that holds the config file (not the current directory).

This applies to: `policy_file`, `audit.file`, `credentials.<name>.path`, `credentials.<name>.token_file`, and every directory under `terraform.workspaces`. It does not apply to `kubectl`, `cli`, `binary` (those are looked up on `PATH` or given as a path you control) or to `credentials.<name>.context`.

## Config file

Top-level sections:

| Section | Type | Required | Purpose |
|---|---|---|---|
| `server` | object | no | Listeners and the stdio principal |
| `policy_file` | string | yes | Path to the policy file |
| `audit` | object | no | Where the hash-chained log goes |
| `approvals` | object | no | Approval timing and queue size |
| `principals` | list | no | Agent identities |
| `approvers` | list | no | Humans who may decide approvals |
| `credentials` | map | no | Named credential providers |
| `kubernetes` | object | no | Enables the Kubernetes tools |
| `aws` | object | no | Enables the AWS tools |
| `azure` | object | no | Enables the Azure tools |
| `terraform` | object | no | Enables the Terraform tool |
| `limits` | object | no | Command time and output size |

A group section (`kubernetes`, `aws`, `azure`, `terraform`) turns that group's tools on. If a section is absent, its tools are not registered and not listed.

### server

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `server.name` | string | `mcp-cloud-ops-gateway` | no | Name the MCP server reports to clients |
| `server.http_listen` | string | empty (off) | no | `host:port` of the MCP endpoint (`/mcp`, streamable HTTP) plus `/healthz`. Bearer token required. |
| `server.admin_listen` | string | `127.0.0.1:8081` | no | `host:port` of the approval API. Approver tokens only. |
| `server.stdio_principal` | string | empty | no | The principal a stdio client acts as. Needed for `serve --stdio`. |

Validation:

- `http_listen` and `admin_listen` must differ (when `http_listen` is set).
- `stdio_principal`, when set, must name an entry in `principals`.
- `serve` needs `http_listen` or `--stdio`. With neither it stops with "nothing to serve". `--stdio` without `stdio_principal` is an error.

### policy_file

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `policy_file` | string | none | yes | Policy file path (see relative paths above) |

The policy is checked against every tool the gateway could serve (`gateway.AllTools()`), not only the enabled ones. A rule naming a tool that does not exist is an error.

### audit

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `audit.file` | string | `audit.jsonl` | no | Hash-chained JSON lines log. Resolved against the config directory. |
| `audit.mirror_stderr` | bool | `false` | no | Also write each record to stderr, so a log collector keeps the trail. |

If the audit log cannot be written before a call, the call does not run.

### approvals

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `approvals.pending_ttl` | duration | `15m` | no | How long a request waits for a human decision |
| `approvals.use_window` | duration | `5m` | no | How long an approved request stays usable |
| `approvals.max_pending_per_principal` | int | `20` | no | Cap on open requests per agent |

Durations use Go syntax (`90s`, `15m`, `1h`). A zero or negative value falls back to the default (the defaults are applied in `internal/approval`, not in the config package).

### principals

A list of agent identities. Each entry:

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `name` | string | none | yes | Identity, written to the audit log |
| `profile` | string | none | yes | Policy profile this agent uses |
| `token_sha256` | string | none | for HTTP | SHA-256 of the bearer token, 64 hex characters |

Validation:

- `name` and `profile` are required. A name may be listed only once.
- `token_sha256` must be 32 bytes in hex. Two callers, agents or approvers, may not share a hash.
- Every `profile` must exist in the policy file. This is checked when the gateway is built (`validate` and `serve`).
- A principal without `token_sha256` cannot call over HTTP. It can still be the `stdio_principal`.

Make a hash without putting the token in your shell history:

```powershell
$token = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })   # or: openssl rand -hex 32
$token | ./bin/mcp-cloud-ops-gateway hash-token
```

The `hash-token` command reads the token on stdin and prints the hash.

### approvers

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `name` | string | none | yes | Human identity, recorded as the approver |
| `token_sha256` | string | none | yes | SHA-256 of the approver's token |

Approver names and principal names share one namespace; a name may not appear in both lists. Agent tokens are rejected by the admin API.

### credentials

A map from a name you choose to a provider. The group sections refer to these names. Fields depend on `type`:

| Field | Type | Used by | Required when |
|---|---|---|---|
| `type` | string | all | always. One of `none`, `kubeconfig`, `in_cluster`, `aws_web_identity`, `azure_federated` |
| `path` | string | kubeconfig | `path` or `context` must be set |
| `context` | string | kubeconfig | `path` or `context` must be set |
| `token_file` | string | aws_web_identity, azure_federated | always for those types |
| `role_arn` | string | aws_web_identity | always |
| `region` | string | aws_web_identity | `region` or `sts_endpoint` |
| `sts_endpoint` | string | aws_web_identity | `region` or `sts_endpoint` |
| `duration` | duration | aws_web_identity | no. Default 15m. If set, 15m to 12h. |
| `session_policy` | string | aws_web_identity | no |
| `tenant_id` | string | azure_federated | always |
| `client_id` | string | azure_federated | always |
| `authority` | string | azure_federated | no |

Unknown `type` fails with `unknown type`. Fields that do not belong to the chosen type are accepted and ignored.

The config does not check that a credential's type fits the group. For example, pointing `azure.read_credential` at a `kubeconfig` credential loads fine and fails when a tool is called ("no access token; the tool's credential must be azure_federated"). Check with a real call.

Leases for `aws_web_identity` and `azure_federated` are cached and replaced 2 minutes before they expire. The call to get a lease times out after 20 seconds.

#### none

An empty lease. Use it for tools that need no credentials, or when the CLI finds them itself (for example Terraform with its own backend credentials). The child process still gets only `PATH` and `HOME`.

```yaml
credentials:
  anonymous:
    type: none
```

#### kubeconfig

Sets `KUBECONFIG` to `path` and passes `--context <context>` to `kubectl`. For local clusters and development. In production prefer `in_cluster`.

```yaml
credentials:
  local-cluster:
    type: kubeconfig
    path: ~/.kube/config     # optional if context is set; ~/ is expanded
    context: kind-gw         # optional if path is set
```

If only `context` is set, `KUBECONFIG` is not set and kubectl uses its default lookup.

#### in_cluster

Forwards `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT` so `kubectl` uses the pod's service account. It takes no other fields. Leasing fails if those variables are missing (the gateway is not in a pod). What the gateway may do is then limited by the RBAC bound to that service account, which is the hard limit under the policy.

```yaml
credentials:
  cluster:
    type: in_cluster
```

#### aws_web_identity

Exchanges the platform OIDC token in `token_file` for temporary credentials with `sts:AssumeRoleWithWebIdentity`. No static key is stored. The credentials are given to the AWS CLI as environment variables, with instance metadata and profiles switched off.

```yaml
credentials:
  aws-reader:
    type: aws_web_identity
    role_arn: arn:aws:iam::${AWS_ACCOUNT_ID}:role/mcp-gateway-reader
    token_file: /var/run/secrets/aws/token     # projected token, audience sts.amazonaws.com
    region: ${AWS_REGION}
    duration: 15m                              # 15m to 12h; default 15m
    session_policy: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:Describe*","cloudwatch:DescribeAlarms"],"Resource":"*"}]}'
  aws-operator:
    type: aws_web_identity
    role_arn: arn:aws:iam::${AWS_ACCOUNT_ID}:role/mcp-gateway-operator
    token_file: /var/run/secrets/aws/token
    region: ${AWS_REGION}
    sts_endpoint: http://localstack:4566/      # optional override; tests and LocalStack
```

| Field | Notes |
|---|---|
| `role_arn` | Required. Role to assume. |
| `token_file` | Required. Read on every refresh. An empty file is an error. |
| `region` | Required unless `sts_endpoint` is set. Also sets `AWS_REGION` for the CLI and picks the STS host `https://sts.<region>.amazonaws.com/`. |
| `duration` | Credential lifetime. Must be 15m to 12h if set. The role's own maximum still applies. |
| `session_policy` | Optional inline IAM policy sent as the STS `Policy`. The effective permissions are the intersection with the role, so it can only narrow. |
| `sts_endpoint` | Optional full STS URL. Replaces the regional host. |

Use two credentials, one reader role and one operator role, so read tools and mutating tools run with different permissions.

#### azure_federated

Exchanges the OIDC token in `token_file` for an Entra ID access token (client credentials with a JWT client assertion, no client secret). Scope is `https://management.azure.com/.default`. The token is sent as a bearer header to Azure Resource Manager.

```yaml
credentials:
  azure-reader:
    type: azure_federated
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_READER_CLIENT_ID}
    token_file: /var/run/secrets/azure/token
    authority: https://login.microsoftonline.com    # optional; sovereign clouds and tests
  azure-operator:
    type: azure_federated
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_OPERATOR_CLIENT_ID}
    token_file: /var/run/secrets/azure/token
```

| Field | Notes |
|---|---|
| `tenant_id`, `client_id`, `token_file` | All required. |
| `authority` | Optional. Default `https://login.microsoftonline.com`. A trailing `/` is removed. |

### Group sections

Each group names the credentials its tools use. A tool is mutating when its `Spec.Mutating` is true. Read tools lease from the read credential, mutating tools from the write credential. Setting both to the same name is allowed (the example does this for a local cluster).

| Section | Read tools use | Mutating tools use |
|---|---|---|
| `kubernetes` | `read_credential` | `write_credential` |
| `aws` | `read_credential` | `write_credential` |
| `azure` | `read_credential` | `write_credential` |
| `terraform` | `credential` | `credential` (its only tool, `terraform_plan`, is read-only) |

#### kubernetes

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `read_credential` | string | none | yes | Credential name for `k8s_get`, `k8s_logs` |
| `write_credential` | string | none | yes | Credential name for `k8s_scale`, `k8s_rollout_restart`, `k8s_delete_pod` |
| `kubectl` | string | `kubectl` | no | Binary name or path |
| `max_log_lines` | int | 500 when 0 or negative | no | Upper bound for `k8s_logs` `tail_lines` |

```yaml
kubernetes:
  read_credential: cluster
  write_credential: cluster
  kubectl: /usr/local/bin/kubectl
  max_log_lines: 500
```

#### aws

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `read_credential` | string | none | yes | For `aws_ec2_describe_instances`, `aws_cloudwatch_alarms` |
| `write_credential` | string | none | yes | For `aws_ec2_reboot_instance` |
| `cli` | string | `aws` | no | Binary name or path |

```yaml
aws:
  read_credential: aws-reader
  write_credential: aws-operator
```

#### azure

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `read_credential` | string | none | yes | For `azure_resource_list` |
| `write_credential` | string | none | yes | For `azure_vm_restart` |
| `subscriptions` | map string to string | none | yes, at least one | Alias to subscription ID. Agents send the alias. |
| `arm_endpoint` | string | `https://management.azure.com` | no | Resource Manager base URL (sovereign clouds, tests) |

```yaml
azure:
  read_credential: azure-reader
  write_credential: azure-operator
  subscriptions:
    prod: ${AZURE_PROD_SUBSCRIPTION_ID}
    dev: ${AZURE_DEV_SUBSCRIPTION_ID}
```

Aliases must match `^[a-z0-9][a-z0-9_-]{0,62}$` to be usable by an agent; the config does not check the alias names.

#### terraform

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `credential` | string | none | yes | Credential name; its lease environment is passed to Terraform |
| `binary` | string | `terraform` | no | Binary name or path |
| `workspaces` | map string to string | none | yes, at least one | Workspace name to directory. Agents send the name, never the path. |

```yaml
terraform:
  credential: aws-reader
  workspaces:
    network: ../infra/network     # relative to this config file
    platform: /srv/infra/platform
```

The tool runs `terraform plan` with `-lock=false`, so it never holds the state lock. Terraform runs with `TF_IN_AUTOMATION=1` and `TF_INPUT=0`. Names must match the same alias pattern as Azure aliases.

### limits

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `limits.command_timeout` | duration | `60s` | no | Time limit for each CLI command |
| `limits.max_output_bytes` | int | `65536` | no | Cap on the text returned to the agent after redaction |

The runner also caps each of stdout and stderr at 1 MiB, which is not configurable.

## Policy file

The policy file decides what each profile may do. Evaluation is pure: no I/O, no clock.

```yaml
version: 1
default: deny
profiles:
  <name>:
    description: text
    extends: [other-profile]
    rules:
      - tool: k8s_scale
        effect: ask
        when:
          namespace: { glob: ["prod-*"] }
        reason: text
```

### Top level

| Field | Type | Default | Required | Validation |
|---|---|---|---|---|
| `version` | int | none | yes | Must be `1` |
| `default` | string | `deny` | no | `allow`, `ask` or `deny`. Applied when no rule matches. |
| `profiles` | map | none | yes | At least one profile |

### Profile

| Field | Type | Required | What it does |
|---|---|---|---|
| `description` | string | no | For people |
| `extends` | list of strings | no | Profiles whose rules are added to this one. Each must exist. A cycle is an error. |
| `rules` | list | no | The profile's own rules |

`extends` adds rules, it does not override them. A child profile can only make a parent's outcome stricter, never looser, because the most restrictive effect wins. To give an agent less than another, do not extend the broader profile.

### Rule

| Field | Type | Required | What it does |
|---|---|---|---|
| `tool` | string | yes | A tool name or a glob such as `k8s_*`. Matching uses Go `path.Match`. A bad pattern is an error. |
| `effect` | string | yes | `allow`, `ask` or `deny` |
| `when` | map argument name to condition | no | All conditions must hold for the rule to match |
| `reason` | string | no | Shown to the agent on a decision and written to the audit log |

A rule whose `tool` matches no tool the gateway can serve (neither by name nor as a glob) is an error.

### Effects

| Effect | What the gateway does |
|---|---|
| `allow` | Runs the tool. |
| `ask` | Opens an approval request and returns `approval_required`. The agent repeats the same call with the `approval_id` after a human approves. The approval is for that exact call, single use and short-lived. |
| `deny` | Refuses. |

`conditional` is not an effect you write. `gateway_policy` and `validate` print it when a tool's answer depends on arguments.

### Conditions

A condition constrains one argument. Several fields in one condition must all hold. Several arguments in `when` must all hold. An empty condition (`{}`) is an error.

| Field | Type | Holds when |
|---|---|---|
| `in` | list of strings | The argument's string form equals one entry |
| `not_in` | list of strings | The argument's string form equals no entry |
| `glob` | list of strings | The string form matches at least one pattern (`path.Match`; `*` does not cross `/`). A bad pattern is an error. |
| `equals` | string | The string form equals it. Quote it: `equals: "false"`. |
| `min` | number | The argument is a number and is greater than or equal to `min` |
| `max` | number | The argument is a number and is less than or equal to `max` |

Semantics, exactly as implemented:

- **String form.** Strings are used as they are. Booleans become `true` or `false`. Numbers are printed without trailing zeros (`3`, not `3.000000`). A missing value would be the empty string, but see the next point.
- **A missing argument never matches.** If the argument name is not in the call, the whole rule does not match, whatever the condition says. That includes `not_in`.
- **Names are not checked.** The policy loader does not check that an argument name exists for the tool. A misspelled name in `when` makes the rule never match. Be careful with `deny` rules: use `validate` and the `gateway_policy` output to confirm the effect you expect.
- **`min` and `max` need a number.** If the argument is a string, boolean or list, the condition does not hold.
- **List arguments.** `instance_ids` is a list. Its string form is Go's print of the list, so `in`, `glob` and `equals` are not useful on it. Avoid conditions on list arguments.
- **Most restrictive wins.** Every rule that matches is collected. `deny` beats `ask`, and `ask` beats `allow`. The order of rules does not matter.
- **No match gives `default`.** The default is `deny` unless the file says otherwise. An unknown profile is always denied.
- **What the gateway passes.** The policy sees every field of the tool input after `Prepare` has filled defaults, including fields at their zero value (`dry_run: false`, `replicas: 0`, an empty string). `omitempty` is ignored. So `dry_run: { equals: "false" }` matches a call that simply leaves `dry_run` out, and `namespace` is `default` when the agent omits it. The approval fields `approval_id` and `justification` are not passed.
- **Cluster-scoped reads.** For `k8s_get` on `nodes` or `namespaces`, `Prepare` sets `namespace` to `_cluster`. A rule that denies `namespace` in a list of platform namespaces does not match these. To control them, match `resource`.
- **`gateway_policy`** is built in. It is not evaluated against the policy; any known principal can call it.

### Reading a decision

Each decision has an effect, a rule description (for example `ask k8s_scale when dry_run`), and the rule's `reason`. When nothing matches, the rule is `default`; for an unknown profile it is `unknown-profile`.

### Argument names for conditions

These are the JSON names of each tool's input fields. Types are what the policy sees: strings, numbers (floats), booleans, and lists. Mutating tools also accept `approval_id` and `justification`, which are not available to conditions.

| Tool | Arguments |
|---|---|
| `gateway_policy` | none |
| `k8s_get` | `resource` (string), `namespace` (string, default `default`, `_cluster` for nodes and namespaces), `name` (string), `label_selector` (string) |
| `k8s_logs` | `namespace` (string, default `default`), `pod` (string), `container` (string), `tail_lines` (number, default 100), `previous` (bool) |
| `k8s_scale` | `namespace` (string, default `default`), `deployment` (string), `replicas` (number, 0 to 50), `dry_run` (bool) |
| `k8s_rollout_restart` | `namespace` (string, default `default`), `deployment` (string), `dry_run` (bool) |
| `k8s_delete_pod` | `namespace` (string, default `default`), `pod` (string), `dry_run` (bool) |
| `aws_ec2_describe_instances` | `region` (string), `instance_ids` (list of strings) |
| `aws_cloudwatch_alarms` | `region` (string), `state` (string, default `ALARM`) |
| `aws_ec2_reboot_instance` | `region` (string), `instance_id` (string), `dry_run` (bool) |
| `azure_resource_list` | `subscription` (string), `resource_group` (string) |
| `azure_vm_restart` | `subscription` (string), `resource_group` (string), `vm` (string) |
| `terraform_plan` | `workspace` (string) |

Examples:

```yaml
# Only real scale-ups to 10 or fewer in production need a human; larger is denied.
- tool: k8s_scale
  effect: deny
  when:
    namespace: { glob: ["prod-*"] }
    replicas: { min: 11 }
  reason: Large scale-ups in production are done by a person.
# Reads in two regions only.
- tool: aws_*
  effect: deny
  when:
    region: { not_in: [eu-west-1, eu-central-1] }
```

## One file per environment

Keep one `gateway.yaml` and one `policy.yaml` for all environments. Put what differs in environment variables. The file below has no secrets and no environment names in it.

`gateway.yaml`:

```yaml
server:
  name: mcp-cloud-ops-gateway
  http_listen: 0.0.0.0:8080
  admin_listen: 0.0.0.0:8081
policy_file: /etc/mcp-gateway/policy.yaml
audit:
  file: /var/lib/mcp-gateway/audit.jsonl
  mirror_stderr: true
approvals:
  pending_ttl: ${APPROVAL_PENDING_TTL}
  use_window: 5m
principals:
  - name: incident-bot
    profile: readonly-agent
    token_sha256: ${INCIDENT_BOT_TOKEN_SHA256}
  - name: ops-agent
    profile: ${OPS_AGENT_PROFILE}
    token_sha256: ${OPS_AGENT_TOKEN_SHA256}
approvers:
  - name: on-call-human
    token_sha256: ${APPROVER_TOKEN_SHA256}
credentials:
  cluster:
    type: in_cluster
  aws-reader:
    type: aws_web_identity
    role_arn: arn:aws:iam::${AWS_ACCOUNT_ID}:role/mcp-gateway-reader
    token_file: /var/run/secrets/aws/token
    region: ${AWS_REGION}
kubernetes:
  read_credential: cluster
  write_credential: cluster
aws:
  read_credential: aws-reader
  write_credential: aws-reader
```

Set `OPS_AGENT_PROFILE` to `readonly-agent` in dev-readonly environments and `ops-agent` where changes are allowed. The profile name must exist in the policy file.

A Kustomize overlay supplies the values. This is a pattern, not a file in the repo. Add it to `deploy/kubernetes/overlays/<env>/kustomization.yaml`. The container is named `gateway`. Take the hashes from your secret manager and keep them out of Git if your rules say so (a hash is not a secret, but it identifies a token).

```yaml
patches:
  - target: { kind: Deployment, name: mcp-gateway }
    patch: |-
      - op: add
        path: /spec/template/spec/containers/0/env
        value:
          - { name: APPROVAL_PENDING_TTL, value: "10m" }
          - { name: OPS_AGENT_PROFILE, value: "ops-agent" }
          - { name: AWS_ACCOUNT_ID, value: "111122223333" }
          - { name: AWS_REGION, value: "eu-west-1" }
          - name: OPS_AGENT_TOKEN_SHA256
            valueFrom: { secretKeyRef: { name: mcp-gateway-tokens, key: ops-agent } }
          - name: INCIDENT_BOT_TOKEN_SHA256
            valueFrom: { secretKeyRef: { name: mcp-gateway-tokens, key: incident-bot } }
          - name: APPROVER_TOKEN_SHA256
            valueFrom: { secretKeyRef: { name: mcp-gateway-tokens, key: approver } }
```

To add an environment, copy an overlay folder and change the values. If an overlay leaves out a variable the file uses, the gateway refuses to start and names the variable.

To add environment-specific rules, add a profile that extends the shared one and give the principal that profile:

```yaml
profiles:
  ops-agent-prod:
    description: ops-agent plus a hard stop on production deletes.
    extends: [ops-agent]
    rules:
      - tool: k8s_delete_pod
        effect: deny
        when:
          namespace: { glob: ["prod-*"] }
        reason: Pods in production are deleted by a person.
```

Because the most restrictive effect wins, this overlay-style profile can only tighten the parent. Set `OPS_AGENT_PROFILE=ops-agent-prod` in production.

## What is verified

The loader, defaults, validation and policy evaluation are covered by unit tests (`internal/config`, `internal/policy`). AWS and Azure credential exchanges are verified against mock endpoints only; no live cloud account was used. See [EVIDENCE.md](EVIDENCE.md).
