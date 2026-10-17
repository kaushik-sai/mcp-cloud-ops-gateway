# Evidence

Real runs, with their results. Anything not listed here is not verified. Newest first.

## 2026-10-16: v0.1 build environment run

Environment: Linux cloud container (4 vCPU, 15 GiB), Go 1.25.14, kubectl v1.37.1 (SHA-256 checked), Docker 29.8.2. No cloud accounts.

### Unit and integration tests

```text
go test -race -count=1 ./...
11 packages ok, 108 tests passed, 0 failed
total statement coverage: 78.4%
  guard 100.0%  redact 100.0%  policy 94.3%  runner 93.9%  approval 89.0%  config 86.6%
  creds 86.1%   audit 82.9%    gateway 76.6% tools 73.9%   cmd 39.0%
```

The gateway tests run the full pipeline through a real MCP client and server (in-memory transport and streamable HTTP with bearer auth), with a fake runner in place of kubectl. They cover: allowed reads with the right argv and lease, invalid arguments never reaching the runner, deny and default deny, dry runs without approval, the full approval flow over the admin API (agent token refused, mismatched call refused, single use), redaction and injection flagging in output and audit log, fail-closed audit, and HTTP auth per principal.

### End-to-end: real binary, real Kubernetes API server

Cluster: kwok v0.8.0 (built from source through the Go module proxy) running a real kube-apiserver v1.36.1 (binary SHA-256 checked against dl.k8s.io) and etcd 3.6.10, with simulated nodes. kind v0.33.0 was tried first and its control plane would not start on this host's cgroup v1 (kubeadm `wait-control-plane` timed out with node images v1.37.0, v1.34.0, v1.33.1 and v1.32.2).

```text
E2E_KUBE_CONTEXT=kwok-gw go test -tags e2e -count=1 -v ./test/e2e/
tools served: 6
k8s_get             {"namespace":"e2e-payments","resource":"deployments"}                        -> ok                 allow k8s_get                (79ms)
k8s_get             {"namespace":"kube-system","resource":"pods"}                                -> denied             deny k8s_* when namespace    (1ms)
k8s_scale           {"deployment":"api","dry_run":true,"namespace":"e2e-payments","replicas":3}  -> ok                 allow k8s_scale              (61ms)
k8s_scale           {..., "justification":"e2e", "replicas":3}                                   -> approval_required  ask k8s_scale when dry_run   (2ms)
  approved through POST /v1/approvals/{id}/approve with the approver token
k8s_scale           {..., "approval_id":"apr_…", "replicas":3}                                   -> ok                 approved_by on-call-human    (65ms)
  kubectl confirms spec.replicas went 1 -> 3 (and stayed 1 after the dry run)
k8s_scale           same call, same approval_id again                                            -> denied             (single use)                 (4ms)
k8s_delete_pod      {"namespace":"e2e-payments","pod":"api-0"}                                   -> denied             default                      (2ms)
k8s_rollout_restart {"deployment":"api","dry_run":true,"namespace":"e2e-payments"}               -> ok                 allow k8s_rollout_restart    (72ms)
audit verify: { "records": 15, "broken": false }
--- PASS (4.02s)
```

The first e2e run found a real bug: `kubectl rollout restart` has no `--dry-run` flag. The dry run now sends the same restart patch with `kubectl patch --dry-run=server`, and a unit test pins the argv.

### Kubernetes manifests against the API server

`kubectl apply -k deploy/kubernetes/overlays/dev` against the kwok API server created all 12 objects (2 namespaces, ServiceAccount, Role, ClusterRole, 2 bindings, ConfigMap, 2 Services, Deployment, NetworkPolicy), so the manifests pass server-side schema validation. RBAC checked with impersonation:

| `kubectl auth can-i ... --as=system:serviceaccount:mcp-gateway:mcp-gateway` | Result |
|---|---|
| `list secrets -A` | no |
| `list pods -A` | yes |
| `get pods/log -n demo` | yes |
| `patch deployments/scale -n demo` | yes |
| `patch deployments -n default` | no |

`kubectl kustomize` renders `base`, `overlays/dev` and `overlays/prod`.

### Lint, workflows, image

| Check | Result |
|---|---|
| gofmt, go vet | clean |
| golangci-lint 2.15.0 (checksum verified) | 0 issues |
| actionlint 1.7.12 (checksum verified) | 0 findings |
| zizmor 1.31.1 (hash-pinned), offline audits | 0 findings |
| `docker build` (distroless, nonroot) | succeeds in 32 s; image content 23.3 MB; `version` and in-image `kubectl version --client` run |
| `validate --config examples/gateway.yaml` and the ConfigMap's config | valid |
| `Invoke-LocalChecks.ps1` under PowerShell 7.4.6 (hash verified) | gofmt, vet, test, actionlint pass; golangci-lint passed after one rename (builtin `max` shadowed) |

## Not verified

- **AWS and Azure live.** STS `AssumeRoleWithWebIdentity` and the Entra token exchange are tested against local mock servers that return the documented response shapes, including error responses. The aws CLI and ARM calls are tested with fakes. No real role trust, federated credential or API call was exercised.
- **Terraform live.** `terraform_plan` argv and exit-code handling are unit-tested; no real plan ran.
- **Pod logs end to end.** kwok has no kubelet, so `k8s_logs` is covered by unit and gateway tests only.
- **The gateway running inside the cluster.** The image builds and the manifests apply, but the pod was not run (kwok simulates pods without running containers), so `in_cluster` credentials and the NetworkPolicy are not verified on a real CNI.
- **govulncheck.** vuln.go.dev is blocked from this environment; it runs in CI (`security.yml`).
- **gitleaks and dependency-review.** Run in CI only.
- **Windows.** Code is portable Go and the scripts are PowerShell 7, but nothing was run on Windows here.
- **CI itself.** The workflows pass actionlint and zizmor; their first real run is on the PR.
