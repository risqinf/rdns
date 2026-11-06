# syntax=docker/dockerfile:1
#
# rdns — multi-stage, static, minimal.
#
#   docker build -t rdns:local .
#   docker buildx build --platform linux/amd64,linux/arm64 -t rdns:local .
#
# One image ships all three binaries (rdns-client, rdns-server, rdns-certs);
# the compose services pick which one to run via `command:`. The binaries are
# CGO_ENABLED=0 static, so the runtime layer is plain Alpine (needed only for
# `nft` on the client side and CA roots for Let's Encrypt on the server side).

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22

# ─── build stage ─────────────────────────────────────────────────────────────
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

# Dependency layer first → cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=docker
# TARGETOS/TARGETARCH are provided automatically by buildx per platform.
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/rdns-client ./cmd/rdns-client; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/rdns-server ./cmd/rdns-server; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/rdns-certs  ./tools/rdns-certs

# ─── runtime stage ───────────────────────────────────────────────────────────
FROM alpine:${ALPINE_VERSION} AS runtime

# nftables: rdns-client shells out to `nft` to install its redirects.
# ca-certificates: the server verifies Let's Encrypt's TLS endpoint.
RUN apk add --no-cache nftables ca-certificates \
 && adduser -D -H -u 10001 rdns

COPY --from=builder /out/rdns-client /usr/local/bin/rdns-client
COPY --from=builder /out/rdns-server /usr/local/bin/rdns-server
COPY --from=builder /out/rdns-certs  /usr/local/bin/rdns-certs

# Config + PKI are mounted at runtime under /etc/rdns (see docker-compose.yml).
# The LE cert cache lives on a volume at /var/lib/rdns.
VOLUME ["/var/lib/rdns"]

USER 10001:10001

# Default role is the exit node; the client service overrides the command.
ENTRYPOINT ["/usr/local/bin/rdns-server"]
CMD ["-config", "/etc/rdns/server.yaml"]

LABEL org.opencontainers.image.title="rdns" \
      org.opencontainers.image.description="Domain-based split DNS & traffic router (client + server + certs)" \
      org.opencontainers.image.source="https://github.com/risqinf/rdns" \
      org.opencontainers.image.licenses="MIT"
