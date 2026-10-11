.PHONY: setup setup-go setup-solidity check demo demo-graph demo-go demo-review demo-solidity doctor

export UV_CACHE_DIR := $(CURDIR)/.cache/uv
GO_CACHE := $(CURDIR)/.cache/go-extractor
GO_HELPER := $(CURDIR)/src/agent_audit_harness/extractors/go_helper
GO_HELPER_ENV := GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOPACKAGESDRIVER=off GOFLAGS=-mod=readonly GOMODCACHE="$(GO_CACHE)/mod" GOCACHE="$(GO_CACHE)/build"

setup:
	uv sync --locked

# Explicit dependency preparation may use the network; graph extraction stays offline.
setup-go:
	cd "$(GO_HELPER)" && $(GO_HELPER_ENV) go mod download golang.org/x/mod golang.org/x/tools golang.org/x/sync
	cd "$(GO_HELPER)" && $(GO_HELPER_ENV) go build -mod=readonly -o "$(GO_CACHE)/extractor" .

# Explicit preparation downloads locked packages; extraction never installs or downloads.
setup-solidity:
	mkdir -p .cache/solidity-extractor
	cp src/agent_audit_harness/extractors/solidity_helper/package*.json .cache/solidity-extractor/
	npm ci --ignore-scripts --no-audit --no-fund --cache "$(CURDIR)/.cache/npm" --prefix .cache/solidity-extractor

check:
	uv run --locked ruff check .
	uv run --locked ruff format --check .
	uv run --locked pytest -q

demo:
	mkdir -p runs
	audit_demo_dir=$$(mktemp -d runs/demo.XXXXXX); \
	uv run --locked audit-harness run examples/demo-target --replay examples/replay --output "$$audit_demo_dir" && \
	uv run --locked audit-harness run examples/demo-target --replay examples/replay --output "$$audit_demo_dir" --resume

demo-graph:
	mkdir -p runs
	uv run --locked audit-harness graph build examples/graph-target --output "$$(mktemp -d runs/graph-demo.XXXXXX)"

demo-go:
	mkdir -p runs
	uv run --locked audit-harness graph build examples/go-target --language go --output "$$(mktemp -d runs/go-demo.XXXXXX)"

demo-review:
	mkdir -p runs
	audit_review_dir=$$(mktemp -d runs/review-demo.XXXXXX); \
	uv run --locked audit-harness graph build examples/go-review-target --language go --output "$$audit_review_dir/graph" && \
	uv run --locked audit-harness recon examples/go-review-target --graph "$$audit_review_dir/graph/graph.json" --spec examples/go-review-plan.json --output "$$audit_review_dir/recon" && \
	uv run --locked audit-harness run examples/go-review-target --graph "$$audit_review_dir/graph/graph.json" --recon "$$audit_review_dir/recon/recon.json" --replay examples/go-review-replay --output "$$audit_review_dir/run" && \
	uv run --locked audit-harness run examples/go-review-target --graph "$$audit_review_dir/graph/graph.json" --recon "$$audit_review_dir/recon/recon.json" --replay examples/go-review-replay --output "$$audit_review_dir/run" --resume

demo-solidity:
	mkdir -p runs
	uv run --locked audit-harness graph build examples/solidity-target --language solidity --output "$$(mktemp -d runs/solidity-demo.XXXXXX)"

doctor:
	uv run --locked audit-harness doctor
