# Kubernetes deployment

Layout: `base/` holds everything an environment shares; `overlays/<env>/` changes only what differs
(image, labels, service account annotations, config). To add an environment, copy an overlay folder.

    deploy/kubernetes/
      base/                 the files below
      overlays/dev/         locally built image, for kind or kwok
      overlays/prod/        registry image pinned by digest, IRSA annotation example

The files in `base/`:

| File | Purpose |
| --- | --- |
| `namespace.yaml` | `mcp-gateway` namespace, Pod Security `restricted`. |
| `serviceaccount.yaml` | The gateway's identity; its token is mounted for `kubectl` in-cluster auth. |
| `rbac.yaml` | Hard limit: cluster-wide read ClusterRole (no secrets); write Role only in `demo` (patch deployments/scale, delete pods). Also creates the example `demo` namespace. |
| `configmap.yaml` | `gateway.yaml` and `policy.yaml`. Holds only token SHA-256 hashes. |
| `deployment.yaml` | One replica (approvals are in memory), hardened pod, probes on `/healthz`. |
| `service.yaml` | `mcp-gateway` (8080) and a separate `mcp-gateway-admin` (8081), both ClusterIP. |
| `networkpolicy.yaml` | Deny ingress by default; 8080 from pods labelled `mcp-gateway/client=true`; 8081 from namespaces labelled `mcp-gateway/approvers=true`; egress to DNS and the API server. |

## Apply

    docker build -t mcp-cloud-ops-gateway:dev .
    kind load docker-image mcp-cloud-ops-gateway:dev   # or push to your registry
    kubectl apply -k deploy/kubernetes/overlays/dev
    kubectl label ns approvers-ns mcp-gateway/approvers=true   # who may reach the admin API

## What to change first

- Replace the placeholder `token_sha256` values in `base/configmap.yaml` (or a per-overlay copy) (`mcp-cloud-ops-gateway hash-token`).
- Set the image digest in `overlays/prod/kustomization.yaml`.
- In `base/rbac.yaml`, replace `demo` with your app namespaces, one Role + RoleBinding each.
- Tighten the API server egress CIDR in `base/networkpolicy.yaml`.
- For AWS web identity, uncomment the projected token volume and mount in `base/deployment.yaml`.
- The audit log is on an `emptyDir`; ship stderr (mirrored) to your log pipeline.
