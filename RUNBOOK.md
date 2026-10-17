# Runbook

Day-two operations. Commands are PowerShell; they are the same in bash apart from setting environment variables.

## Deploy

### Local (developer machine)

```powershell
go build -o bin/mcp-cloud-ops-gateway ./cmd/mcp-cloud-ops-gateway
./bin/mcp-cloud-ops-gateway validate --config examples/gateway.yaml
./bin/mcp-cloud-ops-gateway serve --config examples/gateway.yaml --stdio   # normally started by the MCP client
```

### Kubernetes

```powershell
docker build --build-arg VERSION=v0.1.0 -t <registry>/mcp-cloud-ops-gateway:v0.1.0 .
docker push <registry>/mcp-cloud-ops-gateway:v0.1.0
# put the pushed digest in deploy/kubernetes/overlays/prod/kustomization.yaml, then:
kubectl apply -k deploy/kubernetes/overlays/prod
kubectl -n mcp-gateway rollout status deployment/mcp-gateway
kubectl -n mcp-gateway logs deployment/mcp-gateway | Select-String '"listening"'
```

Before the first apply, replace the placeholder token hashes in the ConfigMap and the namespaces in `base/rbac.yaml`. See [deploy/kubernetes/README.md](deploy/kubernetes/README.md).

## Health

| Check | Command | Healthy |
|---|---|---|
| MCP listener | `curl http://127.0.0.1:8080/healthz` | `ok` |
| Admin listener | `curl http://127.0.0.1:8081/healthz` | `ok` |
| Config still valid | `mcp-cloud-ops-gateway validate --config gateway.yaml` | `config and policy are valid` |
| Audit chain | `mcp-cloud-ops-gateway audit verify --file audit.jsonl` | `"broken": false` |

## Add an agent

1. Generate a token and its hash:

   ```powershell
   $token = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })   # or: openssl rand -hex 32
   $token | ./bin/mcp-cloud-ops-gateway hash-token
   ```

   `Get-Random` is fine for a demo; for production use `openssl rand -hex 32` or `[System.Security.Cryptography.RandomNumberGenerator]`.
2. Add `{ name: <agent>, profile: <profile>, token_sha256: <hash> }` under `principals`.
3. `validate`, then restart (or roll) the gateway.
4. Give the token to the agent through its own secret store. Never put it in the config file or a repo.

## Rotate a token

Add the new hash as a second principal entry with a new name (`incident-bot-2`), roll the gateway, switch the agent, remove the old entry, roll again. Hashes must be unique, so two entries can never share a token.

## Approve or deny

```powershell
$env:MCPGW_ADMIN_URL   = 'http://127.0.0.1:8081'      # or the port-forwarded admin Service
$env:MCPGW_ADMIN_TOKEN = '<your approver token>'
./bin/mcp-cloud-ops-gateway approvals list
./bin/mcp-cloud-ops-gateway approvals show apr_abcdefghijklmnop
./bin/mcp-cloud-ops-gateway approvals approve apr_abcdefghijklmnop --note "INC-1234, p95 over SLO"
./bin/mcp-cloud-ops-gateway approvals deny apr_abcdefghijklmnop --note "use dry_run first"
```

In Kubernetes: `kubectl -n mcp-gateway port-forward svc/mcp-gateway-admin 8081:8081` from a namespace the NetworkPolicy allows, or run the CLI in a pod in a namespace labelled `mcp-gateway/approvers=true`.

Read before approving: the principal, tool, arguments and justification are all in `approvals show`. If the arguments differ from what the agent told the user, deny.

## Change the policy

1. Edit `policy.yaml`. Keep rules small; add a `reason` to every deny.
2. `mcp-cloud-ops-gateway validate --config gateway.yaml` shows the effect of every tool for every principal. Compare it with the previous output.
3. Add a case to `internal/policy/policy_test.go` (`TestLoadExampleFile`) if you changed the example policy.
4. Open a PR; `examples/policy.yaml` and `deploy/` are code-owned.
5. Roll the gateway. Policy is read at start-up.

## Read the audit log

```powershell
Get-Content audit.jsonl | ConvertFrom-Json | Where-Object outcome -eq 'denied' | Format-Table time, principal, tool, rule
Get-Content audit.jsonl | ConvertFrom-Json | Where-Object injection_suspected | Format-Table time, principal, tool
Get-Content audit.jsonl | ConvertFrom-Json | Where-Object event -eq 'approval_decided' | Format-Table time, approver, tool, outcome
```

Events: `startup`, `decision` (allowed, denied, invalid, approval_rejected), `approval_requested`, `approval_decided`, `result` (ok, failed, error), `shutdown`.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Gateway exits: `audit log ... is broken at line N` | the file was edited, truncated mid-line or two processes wrote to it | keep the file as evidence, move it aside, start with a new file, investigate line N |
| `config: environment variables not set: X` | a `${X}` reference with no variable | set it, or escape a literal with `$${` |
| `tool "..." matches no tool this gateway serves` | typo in a policy rule | fix the tool name; `validate` lists the tools |
| HTTP 401 on `/mcp` | wrong token, or its hash is not under `principals` | `hash-token` the token and compare |
| HTTP 401 on the admin API with an agent token | expected | use an approver token |
| `status: error`, `could not get credentials` | OIDC token file missing or the STS / Entra exchange refused | check the projected token mount, the role trust policy (audience, subject) or the federated credential |
| `in_cluster: KUBERNETES_SERVICE_HOST ... not set` | `in_cluster` used outside a pod | use `kubeconfig` locally |
| `status: failed`, `Forbidden` from kubectl | RBAC is tighter than the policy | correct: extend RBAC only if the policy is right |
| `Approval not accepted: approval was granted for a different call` | the agent changed an argument | the agent must repeat the exact call, or request a new approval |
| `approval expired` | not used within `use_window` after approval | request again |
| Output ends with `output cut at N bytes` | result larger than `limits.max_output_bytes` | narrow the query (name, label selector, tail_lines) |

## Recover

- **Pending approvals after a restart:** they are gone (in memory). Agents get `approval not found` and must request again.
- **Lost audit file (emptyDir):** the stderr mirror in your log pipeline is the copy. Enable `mirror_stderr` in every deployed environment.
- **Bad policy rolled out:** `kubectl -n mcp-gateway rollout undo deployment/mcp-gateway` after reverting the ConfigMap, or re-apply the previous overlay commit.
