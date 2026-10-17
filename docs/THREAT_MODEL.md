# Threat model

Scope: the gateway process, its config, its two listeners and the credentials it obtains. The agent behind it is assumed to be capable, fallible and possibly steered by an attacker through the data it reads. The platform (Kubernetes API, AWS, Azure) is assumed to enforce its own permissions correctly.

## Assets

- The ability to change production (scale, restart, delete, reboot).
- Cloud credentials, even short-lived ones.
- Secrets that live in the systems the agent can read (pod logs, config maps, plan output).
- The audit trail.

## Actors

| Actor | Can | Cannot (by design) |
|---|---|---|
| Agent (benign but wrong) | call any tool its profile allows, with any arguments | exceed its profile; skip approval; see credentials |
| Agent steered by injected text | the same as above | the same as above; text in tool output has no authority |
| Attacker with network access to `:8080` | send requests | act without a valid token |
| Attacker with an agent token | act as that agent | approve; reach admin actions; act as another agent |
| Operator / approver | approve, deny, change config | approve their own agent's request under the same identity |

## Threats and controls

| # | Threat | Control | Where | Tested |
|---|---|---|---|---|
| T1 | Prompt injection in tool output steers the agent into a harmful change | output fenced as untrusted data, instruction-like text flagged and audited; any change still needs policy allow or a human approval bound to the exact call | `guard`, `gateway`, `approval` | `TestOutputIsRedactedAndInjectionFlagged`, `TestApprovalFlowOverAdminAPI` |
| T2 | Agent approves its own request | approvals only through the admin API, which accepts only approver tokens; approver name must differ from requester | `gateway/admin.go`, `approval` | `TestApprovalFlowOverAdminAPI`, `TestSelfApprovalAndEmptyApprover` |
| T3 | An approval is reused for a different or repeated call | digest of principal, tool and arguments; single use; short use window | `approval` | `TestApprovalIsBoundToTheCall`, `TestConcurrentConsumeOnlyOneWins` |
| T4 | Argument injection (`--all-namespaces`, `; rm -rf`, `$(id)`) | strict patterns per argument; argv only, no shell | `tools`, `runner` | `TestInvalidArgumentsNeverReachTheRunner`, `TestArgumentsAreNotInterpretedByAShell` |
| T5 | Policy bypass by omitting an argument the rule conditions on | the policy sees every argument including zero values and defaults | `gateway.argMap` | `TestApprovalFlowOverAdminAPI` (no `dry_run` sent, still asks) |
| T6 | Policy typo leaves a tool open | default deny; unknown fields, unknown tools and empty conditions fail start-up | `policy` | `TestParseErrors` |
| T7 | Agent reads secrets | Secrets are not a readable resource; output redaction for common credential formats | `tools/kubernetes.go`, `redact` | `TestInvalidArgumentsNeverReachTheRunner`, `redact` tests |
| T8 | Long-lived cloud keys leak | no static keys; OIDC exchange for 15-minute credentials; read and write roles separate; credentials only in the child's environment | `creds`, `runner` | `creds` tests, `TestEnvironmentIsMinimal` |
| T9 | Gateway's own secrets leak into a tool | child processes get PATH, HOME and the lease only | `runner` | `TestEnvironmentIsMinimal` |
| T10 | Audit log edited to hide an action | hash chain; verify on start-up and on demand; 0600 file mode; mirror to stderr for external storage | `audit` | `TestTamperingIsDetected` |
| T11 | Action runs without an audit record | decision record written and fsynced before the call; failure refuses the call | `gateway` | `TestAuditFailureFailsClosed` |
| T12 | Token guessing or timing attack | tokens hashed with SHA-256, compared in constant time against every entry; tokens of at least 32 characters | `gateway.TokenVerifier`, `hash-token` | `TestHTTPRequiresAKnownToken`, `TestHashToken` |
| T13 | Tool description swapped to mislead the agent (tool poisoning) | descriptions compiled into the binary, not read from config or a remote source | `tools` | review |
| T14 | Agent floods approvers | identical pending requests are reused; at most 20 pending per principal | `approval` | `TestDuplicateCreateAndPendingLimit` |
| T15 | Huge output exhausts memory or the context window | runner caps each stream at 1 MiB; gateway caps returned text (64 KiB default) | `runner`, `guard` | `TestTimeoutAndCap`, `TestTruncates` |
| T16 | DNS rebinding against the local HTTP listener | MCP SDK's localhost protection is on (default) | SDK | SDK tests |
| T17 | A policy mistake allows too much | platform permissions are the hard limit: RBAC without Secrets and write Roles only in named namespaces; IAM role plus optional session policy | `deploy/kubernetes/base/rbac.yaml`, `aws_web_identity.session_policy` | `kubectl auth can-i` checks in EVIDENCE |

## Residual risks

- **Local stdio mode trusts the local machine.** A local agent with shell access can read anything the user can, including an approver token in the same environment. Use stdio for development; keep approver tokens out of the agent's environment.
- **Redaction is pattern-based.** A secret in an unusual format can pass through. The control that matters is not exposing secret-bearing resources at all.
- **Injection detection is heuristic.** It is a signal for the audit log and the agent, not a guarantee. Approval for every change is the guarantee.
- **In-memory approvals.** A restart drops pending approvals (fail safe: the agent must ask again). Single replica for deployments that serve `ask` rules.
- **The approver is a human.** An approver who clicks approve without reading defeats the control. The admin API shows principal, tool, redacted arguments and justification to make reading easy.
- **Not verified against live AWS or Azure.** Request shapes follow the documented APIs and are tested against mocks; see EVIDENCE.
