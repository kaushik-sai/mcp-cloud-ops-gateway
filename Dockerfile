# syntax=docker/dockerfile:1.7

# ---- build stage -----------------------------------------------------------
# golang:1.25-bookworm, pinned by digest.
FROM golang@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS build

ARG VERSION=dev
ARG KUBECTL_VERSION=v1.37.1
ARG KUBECTL_SHA256=65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8
ARG TARGETARCH=amd64

WORKDIR /src

# kubectl: download, verify the pinned SHA-256, fail the build on mismatch.
# (The pinned hash is for linux/amd64; override KUBECTL_SHA256 for other arches.)
# Optional build secret `cacert` lets builds behind a TLS-intercepting proxy trust its CA:
#   docker build --secret id=cacert,src=/path/ca-bundle.crt .
RUN --mount=type=secret,id=cacert,required=false \
    if [ -s /run/secrets/cacert ]; then export CURL_CA_BUNDLE=/run/secrets/cacert; fi \
 && curl -fsSL -o /kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
 && echo "${KUBECTL_SHA256}  /kubectl" | sha256sum -c - \
 && chmod 0555 /kubectl

COPY go.mod go.sum ./
RUN --mount=type=secret,id=cacert,required=false \
    if [ -s /run/secrets/cacert ]; then export SSL_CERT_FILE=/run/secrets/cacert; fi \
 && go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-s -w -X github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/gateway.Version=${VERSION}" \
      -o /out/mcp-cloud-ops-gateway ./cmd/mcp-cloud-ops-gateway

# ---- runtime stage ---------------------------------------------------------
# gcr.io/distroless/static-debian12:nonroot, pinned by digest. No shell, no package manager.
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
LABEL org.opencontainers.image.title="mcp-cloud-ops-gateway" \
      org.opencontainers.image.description="Governed MCP server for cloud operations: policy, approvals, audit" \
      org.opencontainers.image.source="https://github.com/kaushik-sai/mcp-cloud-ops-gateway" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /kubectl /usr/local/bin/kubectl
COPY --from=build /out/mcp-cloud-ops-gateway /usr/local/bin/mcp-cloud-ops-gateway

USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/mcp-cloud-ops-gateway"]
CMD ["serve", "--config", "/etc/mcp-gateway/gateway.yaml"]
