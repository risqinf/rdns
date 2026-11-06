# rdns — static Linux builds.
#
#   make build          # all three binaries → dist/ (static, stripped)
#   make client         # just rdns-client
#   make server         # just rdns-server
#   make certs          # just rdns-certs
#   make test           # go vet + go test ./...
#   make tidy           # go mod tidy
#
# Both binaries are built with CGO_ENABLED=0 so they're fully static and
# run on Alpine (musl) AND Rocky (glibc) with no runtime deps. The same
# build works for the decision node (Rocky) and exit node (Alpine).

VERSION   ?= v0.2.0
GO        ?= go
LDFLAGS   := -s -w -X main.version=$(VERSION)

# Build for common VPS arches (amd64 and arm64).
TARGETS := linux/amd64 linux/arm64

.PHONY: all build client server certs certs-windows test tidy clean dist \
        docker docker-multi smoke

all: build

build: client server certs

dist:
	@mkdir -p dist

client: dist
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "  rdns-client ($$os/$$arch)"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o "dist/rdns-client-$$os-$$arch" ./cmd/rdns-client || exit 1; \
	done

server: dist
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "  rdns-server ($$os/$$arch)"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o "dist/rdns-server-$$os-$$arch" ./cmd/rdns-server || exit 1; \
	done

certs: dist certs-windows
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "  rdns-certs ($$os/$$arch)"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o "dist/rdns-certs-$$os-$$arch" ./tools/rdns-certs || exit 1; \
	done

# rdns-certs also ships as a Windows .exe so the operator can mint the PKI
# from a Windows PC (SETUP.md §C.1). The other two binaries never run on
# Windows (they need Linux nftables / SO_MARK).
certs-windows: dist
	@echo "  rdns-certs (windows/amd64)"
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
		-o "dist/rdns-certs-windows-amd64.exe" ./tools/rdns-certs

test:
	$(GO) vet ./...
	$(GO) test ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf dist

# ─── Docker ─────────────────────────────────────────────────────────────────
# Single-platform image (fast, for the current arch):
docker:
	docker build -t rdns:$(VERSION) --build-arg VERSION=$(VERSION) .

# Multi-arch image (amd64 + arm64) via buildx. Requires a builder:
#   docker buildx create --use   (once)
docker-multi:
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t rdns:$(VERSION) --build-arg VERSION=$(VERSION) .

# Local end-to-end smoke test (exit + client + assertions on one host):
smoke:
	docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from smoke
	docker compose -f docker-compose.test.yml down -v
