# Design

## Goal

Let AI agents operate cloud and Kubernetes environments with least privilege, a human in the loop for changes, short-lived credentials and an audit trail that holds up in a review. Keep it small enough to read in an afternoon and change with confidence.

## Shape

One Go binary, two listeners, one config file per environment.

| Listener | Default | Who uses it | Auth |
|---|---|---|---|
| MCP, streamable HTTP at `/mcp` | `127.0.0.1:8080` | remote agents | bearer token per principal |
| MCP over stdio (`serve --stdio`) | stdin/stdout | the local process that started the gateway (Claude Code) | the configured `stdio_principal` |
| Admin API at `/v1/approvals` | `127.0.0.1:8081` | human approvers | bearer token per approver |

Agent tokens and approver tokens live in separate lists, and the config refuses a token hash that appears twice. An agent token is rejected by the admin API, so an agent cannot approve its own request even if it finds the address.

## Request pipeline

`internal/gateway/gateway.go` runs every tool call through the same steps. The order matters; each step is a gate the next one relies on.

1. **Identify.** HTTP: the bearer token's SHA-256 is compared in constant time against every principal's hash. stdio: the configured principal. No principal, no call. The HTTP server is built with no fallback principal, so a call that somehow skipped the auth middleware is still refused.
2. **Validate.** The MCP SDK validates the input against the tool's JSON Schema (unknown fields rejected). Then the tool's `Prepare` fills defaults (namespace `default`, 100 log lines) and checks every value against a strict pattern: DNS-1123 names, region format, instance ID format, aliases. Nothing that starts with `-` or carries shell syntax reaches a CLI.
3. **Policy.** `internal/policy` evaluates the principal's profile against the tool name and the arguments, including the defaults filled in step 2 and fields left at their zero value. All matching rules are collected; the most restrictive effect wins (deny > ask > allow); no match means the default, deny.
4. **Approval** (effect `ask`). Without `approval_id` the gateway opens a pending request and returns its ID. With `approval_id` it consumes the approval: it must be approved, unexpired, unused, and its digest must equal the digest of this principal, tool and arguments.
5. **Audit the decision.** The decision record is written and fsynced before anything runs. If the write fails, the call fails. Fail closed.
6. **Lease credentials.** The tool's group names two credential adapters, one for read tools and one for mutating tools. The adapter returns environment variables (AWS), a kube context (Kubernetes) or a bearer token (Azure ARM).
7. **Run.** CLIs run through `internal/runner`: argv only, no shell, a minimal environment (PATH, HOME and the lease), a timeout and capped output. REST calls (Azure) go through an injectable HTTP client.
8. **Redact, fence, cap.** `internal/redact` removes credential patterns. `internal/guard` wraps the text in `<untrusted-tool-output>`, neutralises fake closing tags, flags instruction-like text and caps the size.
9. **Audit the result** (exit code, duration, SHA-256 of the returned text, redaction count, injection flag) and return text plus a structured `Outcome`.

## Components

| Package | Responsibility | Depends on |
|---|---|---|
| `cmd/mcp-cloud-ops-gateway` | CLI: serve, validate, approvals, audit verify, hash-token | everything below |
| `internal/gateway` | the pipeline, MCP server construction, HTTP and admin handlers, credential adapter wiring | all internal packages, MCP Go SDK |
| `internal/policy` | parse, validate and evaluate policy; pure, no I/O | yaml.v3 |
| `internal/approval` | in-memory approval broker, digests, expiry | stdlib |
| `internal/audit` | hash-chained JSONL writer and verifier | stdlib |
| `internal/creds` | credential adapters: none, kubeconfig, in_cluster, aws_web_identity, azure_federated | stdlib |
| `internal/tools` | tool specs, input types, validation, command building | runner, creds |
| `internal/runner` | the one wrapper around `os/exec` | stdlib |
| `internal/redact`, `internal/guard` | output hygiene | stdlib |
| `internal/config` | config file loading, `${ENV}` expansion, validation | yaml.v3 |

Two third-party modules: the official MCP Go SDK and `gopkg.in/yaml.v3`. Everything else is the standard library. AWS and Azure token exchanges are plain HTTP calls, so there is no cloud SDK in the dependency tree.

## Policy model

```yaml
profiles:
  ops-agent:
    extends: [readonly-agent]
    rules:
      - { tool: k8s_scale, effect: allow }                                   # dry runs
      - { tool: k8s_scale, effect: ask, when: { dry_run: { equals: "false" } } }
      - tool: k8s_scale
        effect: deny
        when: { replicas: { max: 0 }, namespace: { glob: ["prod-*"] } }
```

- **Most restrictive wins.** There are no rule priorities to reason about. An exception ("dry runs need no approval") is written as a narrower `ask` rule next to a broad `allow`, not as an override.
- **Conditions:** `in`, `not_in`, `glob`, `equals`, `min`, `max`. Every condition in a rule must hold; a missing argument never matches. The gateway always passes every argument, defaults included, so a rule on `dry_run` sees `false` when the agent leaves it out.
- **Validated at start-up.** Unknown fields, unknown effects, empty conditions, `extends` cycles and rules naming a tool the binary does not have all fail `validate` and `serve`.
- **Explainable.** `gateway_policy` and `validate` show each tool's effect per profile, or `conditional` when argument conditions can change it.

The policy is the first gate. The platform's own permissions are the hard limit: the Kubernetes manifests give the gateway's service account a read ClusterRole without Secrets and write Roles only in named namespaces, and AWS session policies can narrow the assumed role further. A policy mistake cannot exceed what RBAC and IAM allow.

## Credentials

| Adapter | Use | What the tool gets |
|---|---|---|
| `kubeconfig` | dev, kind, kwok | `KUBECONFIG` and `--context` |
| `in_cluster` | gateway runs as a pod | the service account, via `KUBERNETES_SERVICE_HOST/PORT` |
| `aws_web_identity` | EKS (IRSA), GitHub Actions, any OIDC issuer | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (15 min default), metadata and profile fallbacks disabled |
| `azure_federated` | AKS workload identity, GitHub Actions | an Entra ID access token for ARM |
| `none` | tools that need nothing | nothing |

Leases are cached until two minutes before expiry and the token file is re-read on each refresh, so rotating projected tokens work.

## Scaling and replication

- **Replicate an environment:** copy `deploy/kubernetes/overlays/prod` to `overlays/prod-eu`, change the image digest, the IRSA role and any `${ENV}` values. The base does not change.
- **Add a cloud account or cluster:** add a credential adapter entry and point the group's `read_credential` / `write_credential` at it. For several clusters, run one gateway per cluster (blast radius stays one cluster) or one per team.
- **Scale out reads:** read-only profiles keep no state between calls, so a deployment serving only read principals can run several replicas behind a Service.
- **The current limit:** approvals are held in memory, so a deployment that serves `ask` rules must run one replica (the manifest uses `replicas: 1` and `Recreate`). An approval in flight is lost on restart; the agent asks again. Moving the broker to a shared store (Redis or Postgres, behind the same five methods) is the next step and is tracked in [docs/DECISIONS.md](docs/DECISIONS.md).
- **Audit volume:** one or two lines per call, fsynced. Mirror to stderr and let the platform's log pipeline ship it to write-once storage.

## Failure behaviour

| Failure | Behaviour |
|---|---|
| Audit log cannot be written | call refused before it runs |
| Audit log already broken at start-up | gateway refuses to start until the file is moved aside |
| Credential exchange fails | call fails with the provider's error code; nothing runs |
| CLI exits non-zero | result `failed`, stderr returned (redacted), exit code audited |
| CLI hangs | killed at `limits.command_timeout` |
| Huge output | capped at `limits.max_output_bytes`, truncation flagged |
| Approval expired or reused | refused, audited as `approval_rejected` |

## What it does not do

- It is not a general shell or a generic `kubectl` passthrough. Every tool is written, typed and reviewed.
- It does not decide what the agent should do; it decides what the agent may do.
- It does not store secrets. Tokens arrive as hashes, credentials as short-lived leases.
