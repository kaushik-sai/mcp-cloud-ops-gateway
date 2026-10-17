# Security

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). Include the version (`mcp-cloud-ops-gateway version`), the config and policy shape (no tokens), and steps to reproduce. You will get an answer within a week.

## Supported versions

Only the latest release gets fixes while the project is at 0.x.

## Security model in one page

The gateway is a policy enforcement point between AI agents and infrastructure. Its guarantees:

1. **No call without a known principal.** Bearer tokens over HTTP, compared by SHA-256 in constant time; a configured principal over stdio.
2. **No call outside policy.** Default deny; the most restrictive matching rule wins; the policy sees every argument.
3. **No change without a human, when the policy says ask.** Approvals come only from the admin API with approver tokens, are bound to the exact call, single use and expire.
4. **No call without an audit record.** The decision is written and fsynced first; if that fails, nothing runs.
5. **No static cloud credentials.** Short-lived credentials from OIDC federation, scoped per tool group into read and write identities.
6. **No shell.** Arguments are validated against strict patterns and passed as argv.
7. **No secret reads.** Kubernetes Secrets are not exposed; output is redacted for common credential formats.

The platform's own permissions (Kubernetes RBAC, IAM, Azure RBAC) are the hard limit behind the policy. Configure them as tightly as the policy, so a policy mistake cannot exceed them. [deploy/kubernetes/base/rbac.yaml](deploy/kubernetes/base/rbac.yaml) shows the pattern.

The full threat list, controls and residual risks are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Operating it safely

- Generate tokens with at least 32 random bytes (`openssl rand -hex 32`) and store only their hashes in config. Keep approver tokens out of any environment an agent can read.
- Give each agent its own principal. Shared tokens make the audit log useless.
- Keep the admin listener off any network agents can reach (separate Service and NetworkPolicy in the manifests).
- Ship the audit log (stderr mirror) to write-once storage and run `audit verify` on the file during reviews.
- Treat `examples/` as examples. The tokens in comments there are public.

## Supply chain

- Two Go dependencies, pinned in `go.sum` and checked by the Go module mirror; `govulncheck` runs in CI and weekly.
- GitHub Actions pinned by commit SHA; Dependabot proposes updates with a 7-day cooldown.
- Tools downloaded in CI (golangci-lint, actionlint, gitleaks) are checked against their published SHA-256.
- Container base images are pinned by digest; kubectl in the image is checked against its SHA-256.
- gitleaks scans the full history on every PR and weekly.
