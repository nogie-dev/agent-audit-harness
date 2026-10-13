.PHONY: setup setup-go setup-solidity setup-static setup-validation-go check demo demo-benchmark demo-model-evaluation demo-model-evaluation-prospective demo-graph demo-go demo-review demo-solidity demo-python demo-static demo-models demo-recon demo-intake demo-poc demo-matrix demo-validation demo-judgment demo-go-http demo-go-file-selection demo-investigation doctor

export UV_CACHE_DIR := $(CURDIR)/.cache/uv
export VALIDATION_IMAGE
GO_CACHE := $(CURDIR)/.cache/go-extractor
GO_HELPER := $(CURDIR)/src/agent_audit_harness/extractors/go_helper
GO_HELPER_ENV := GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOPACKAGESDRIVER=off GOFLAGS=-mod=readonly GOMODCACHE="$(GO_CACHE)/mod" GOCACHE="$(GO_CACHE)/build"
VALIDATION_GO_IMAGE := golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee

setup:
	uv sync --locked

demo-investigation:
	mkdir -p runs
	audit_query_dir=$$(mktemp -d runs/investigation-demo.XXXXXX); \
	uv run --locked audit-harness graph build examples/go-http-target --language go --output "$$audit_query_dir/graph" && \
	uv run --locked audit-harness recon examples/go-http-target --graph "$$audit_query_dir/graph/graph.json" --spec examples/go-http-plan.json --output "$$audit_query_dir/recon" && \
	uv run --locked audit-harness run examples/go-http-target --graph "$$audit_query_dir/graph/graph.json" --recon "$$audit_query_dir/recon/recon.json" --replay examples/investigation-replay --query-bytes 32000 --output "$$audit_query_dir/review" && \
	uv run --locked audit-harness run examples/go-http-target --graph "$$audit_query_dir/graph/graph.json" --recon "$$audit_query_dir/recon/recon.json" --replay examples/investigation-replay --query-bytes 32000 --output "$$audit_query_dir/review" --resume

# Explicit image preparation downloads a pinned official toolchain; validate never pulls.
setup-validation-go:
	docker pull "$(VALIDATION_GO_IMAGE)"
	docker image inspect "$(VALIDATION_GO_IMAGE)" --format '{{.Id}}'

# Explicit dependency preparation may use the network; graph extraction stays offline.
setup-go:
	cd "$(GO_HELPER)" && $(GO_HELPER_ENV) go mod download golang.org/x/mod golang.org/x/tools golang.org/x/sync
	cd "$(GO_HELPER)" && $(GO_HELPER_ENV) go build -mod=readonly -o "$(GO_CACHE)/extractor" .

# Explicit preparation downloads locked packages; extraction never installs or downloads.
setup-solidity:
	mkdir -p .cache/solidity-extractor
	cp src/agent_audit_harness/extractors/solidity_helper/package*.json .cache/solidity-extractor/
	npm ci --ignore-scripts --no-audit --no-fund --cache "$(CURDIR)/.cache/npm" --prefix .cache/solidity-extractor

# Explicit preparation only; analysis uses the native core with local patterns and no login.
setup-static:
	uv venv .cache/semgrep --python .venv/bin/python --allow-existing
	uv pip sync --python .cache/semgrep/bin/python --require-hashes --only-binary :all: src/agent_audit_harness/analyzers/semgrep-requirements.txt
	.cache/semgrep/bin/python -I -c 'from importlib.resources import files; import shutil, certifi; bundle = files("semgrep.bin"); shutil.copy(bundle / "semgrep-core", ".cache/semgrep/semgrep-core"); libs = bundle / "libs"; shutil.copytree(libs, ".cache/semgrep/libs", dirs_exist_ok=True) if libs.is_dir() else None; shutil.copyfile(certifi.where(), ".cache/semgrep/ca.pem")'

check:
	uv run --locked ruff check .
	uv run --locked ruff format --check .
	uv run --locked pytest -q

demo:
	mkdir -p runs
	audit_demo_dir=$$(mktemp -d runs/demo.XXXXXX); \
	uv run --locked audit-harness run examples/demo-target --replay examples/replay --output "$$audit_demo_dir" && \
	uv run --locked audit-harness run examples/demo-target --replay examples/replay --output "$$audit_demo_dir" --resume

demo-benchmark:
	mkdir -p runs
	uv run --locked audit-harness benchmark-replay examples/demo-target \
		--truth examples/benchmark-truth.json --baseline-replay examples/replay \
		--candidate-replay examples/replay --output "$$(mktemp -d runs/benchmark-demo.XXXXXX)"

demo-model-evaluation:
	mkdir -p runs
	audit_eval_dir=$$(mktemp -d runs/model-eval-preflight.XXXXXX); \
	uv run --locked python examples/model_eval_preflight.py --output "$$audit_eval_dir"

demo-model-evaluation-prospective:
	mkdir -p runs
	audit_eval_dir=$$(mktemp -d runs/model-eval-prospective.XXXXXX); \
	uv run --locked python examples/model_eval_preflight.py --suite prospective --output "$$audit_eval_dir"

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
	uv run --locked audit-harness graph build examples/solidity-modifier-target --language solidity --output "$$(mktemp -d runs/modifier-flow-demo.XXXXXX)"

demo-python:
	mkdir -p runs
	uv run --locked audit-harness graph build examples/python-target --language python --output "$$(mktemp -d runs/python-demo.XXXXXX)"

demo-static:
	mkdir -p runs
	audit_static_dir=$$(mktemp -d runs/static-demo.XXXXXX); \
	uv run --locked audit-harness graph build examples/static-target --output "$$audit_static_dir/graph" && \
	uv run --locked audit-harness static examples/static-target --graph "$$audit_static_dir/graph/graph.json" --output "$$audit_static_dir/analysis" && \
	uv run --locked audit-harness recon examples/static-target --graph "$$audit_static_dir/graph/graph.json" --spec examples/static-plan.json --output "$$audit_static_dir/recon" && \
	uv run --locked audit-harness run examples/static-target --graph "$$audit_static_dir/graph/graph.json" --recon "$$audit_static_dir/recon/recon.json" --static "$$audit_static_dir/analysis/static.json" --replay examples/static-replay --output "$$audit_static_dir/run" && \
	uv run --locked audit-harness run examples/static-target --graph "$$audit_static_dir/graph/graph.json" --recon "$$audit_static_dir/recon/recon.json" --static "$$audit_static_dir/analysis/static.json" --replay examples/static-replay --output "$$audit_static_dir/run" --resume && \
	uv run --locked audit-harness run examples/static-target --graph "$$audit_static_dir/graph/graph.json" --recon "$$audit_static_dir/recon/recon.json" --static "$$audit_static_dir/analysis/static.json" --replay examples/static-investigation-replay --output "$$audit_static_dir/query-review" && \
	uv run --locked audit-harness run examples/static-target --graph "$$audit_static_dir/graph/graph.json" --recon "$$audit_static_dir/recon/recon.json" --static "$$audit_static_dir/analysis/static.json" --replay examples/static-investigation-replay --output "$$audit_static_dir/query-review" --resume

demo-models:
	mkdir -p runs
	audit_models_dir=$$(mktemp -d runs/models-demo.XXXXXX); \
	for audit_model_lang in python go; do \
	  audit_model_name=model; \
	  if [ "$$audit_model_lang" = go ]; then audit_model_name=model-go; fi; \
	  audit_model_dir="$$audit_models_dir/$$audit_model_lang"; \
	  uv run --locked audit-harness graph build "examples/$$audit_model_name-target" --language "$$audit_model_lang" --output "$$audit_model_dir/graph" && \
	  uv run --locked audit-harness static "examples/$$audit_model_name-target" --graph "$$audit_model_dir/graph/graph.json" --output "$$audit_model_dir/first" && \
	  uv run --locked audit-harness recon "examples/$$audit_model_name-target" --graph "$$audit_model_dir/graph/graph.json" --spec "examples/$$audit_model_name-plan.json" --output "$$audit_model_dir/recon" && \
	  uv run --locked audit-harness run "examples/$$audit_model_name-target" --graph "$$audit_model_dir/graph/graph.json" --recon "$$audit_model_dir/recon/recon.json" --static "$$audit_model_dir/first/static.json" --replay "examples/$$audit_model_name-replay" --output "$$audit_model_dir/review" && \
	  uv run --locked audit-harness run "examples/$$audit_model_name-target" --graph "$$audit_model_dir/graph/graph.json" --recon "$$audit_model_dir/recon/recon.json" --static "$$audit_model_dir/first/static.json" --replay "examples/$$audit_model_name-replay" --output "$$audit_model_dir/review" --resume || exit $$?; \
	done

demo-recon:
	mkdir -p runs
	audit_recon_dir=$$(mktemp -d runs/recon-demo.XXXXXX); \
	for audit_recon_lang in python go; do \
	  audit_recon_target=static-target; \
	  if [ "$$audit_recon_lang" = go ]; then audit_recon_target=go-review-target; fi; \
	  audit_recon_root="$$audit_recon_dir/$$audit_recon_lang"; \
	  uv run --locked audit-harness graph build "examples/$$audit_recon_target" --language "$$audit_recon_lang" --output "$$audit_recon_root/graph" && \
	  uv run --locked audit-harness static "examples/$$audit_recon_target" --graph "$$audit_recon_root/graph/graph.json" --output "$$audit_recon_root/static" && \
	  uv run --locked audit-harness recon "examples/$$audit_recon_target" --graph "$$audit_recon_root/graph/graph.json" --static "$$audit_recon_root/static/static.json" --replay "examples/recon-$$audit_recon_lang-replay" --output "$$audit_recon_root/proposal" && \
	  uv run --locked audit-harness recon "examples/$$audit_recon_target" --graph "$$audit_recon_root/graph/graph.json" --static "$$audit_recon_root/static/static.json" --replay "examples/recon-$$audit_recon_lang-replay" --output "$$audit_recon_root/proposal" --resume && \
	  uv run --locked audit-harness run "examples/$$audit_recon_target" --graph "$$audit_recon_root/graph/graph.json" --recon "$$audit_recon_root/proposal/recon.json" --static "$$audit_recon_root/static/static.json" --replay "examples/recon-$$audit_recon_lang-replay" --output "$$audit_recon_root/review" && \
	  uv run --locked audit-harness run "examples/$$audit_recon_target" --graph "$$audit_recon_root/graph/graph.json" --recon "$$audit_recon_root/proposal/recon.json" --static "$$audit_recon_root/static/static.json" --replay "examples/recon-$$audit_recon_lang-replay" --output "$$audit_recon_root/review" --resume || exit $$?; \
	done

demo-intake:
	mkdir -p runs
	audit_intake_dir=$$(mktemp -d runs/intake-demo.XXXXXX); \
	uv run --locked audit-harness import-review examples/judgment-target --spec examples/candidate-import.json --output "$$audit_intake_dir/review" && \
	uv run --locked audit-harness graph build examples/static-target --language python --output "$$audit_intake_dir/graph" && \
	uv run --locked audit-harness static examples/static-target --graph "$$audit_intake_dir/graph/graph.json" --output "$$audit_intake_dir/static" && \
	uv run --locked audit-harness import-review examples/static-target --spec examples/static-candidate-import.json --graph "$$audit_intake_dir/graph/graph.json" --static "$$audit_intake_dir/static/static.json" --output "$$audit_intake_dir/partial-review"

# A synthetic operator decision tests artifact binding only; no worker or model runs.
demo-poc:
	mkdir -p runs
	audit_poc_dir=$$(mktemp -d runs/poc-demo.XXXXXX); \
	uv run --locked audit-harness import-review examples/judgment-target --spec examples/candidate-import.json --output "$$audit_poc_dir/review" && \
	uv run --locked audit-harness poc examples/judgment-target --run "$$audit_poc_dir/review" --candidate f-d71ac5092c87347c --replay examples/poc-replay --output "$$audit_poc_dir/proposal" && \
	uv run --locked audit-harness poc examples/judgment-target --run "$$audit_poc_dir/review" --candidate f-d71ac5092c87347c --replay examples/poc-replay --output "$$audit_poc_dir/proposal" --resume && \
	uv run --locked audit-harness poc-review examples/judgment-target --run "$$audit_poc_dir/review" --proposal "$$audit_poc_dir/proposal" --decision approve --reviewer offline-fixture --rationale 'Synthetic contract decision only; no real security approval or execution.' --output "$$audit_poc_dir/researcher"

# Freeze synthetic build inputs and report missing runs; never invokes Docker or models.
demo-matrix:
	mkdir -p runs
	audit_matrix_dir=$$(mktemp -d runs/matrix-demo.XXXXXX); \
	uv run --locked audit-harness import-review examples/matrix-target --spec examples/matrix-candidate-import.json --output "$$audit_matrix_dir/review" && \
	uv run --locked audit-harness poc examples/matrix-target --run "$$audit_matrix_dir/review" --candidate f-7d72725d4bf39b4b --replay examples/matrix-replay --output "$$audit_matrix_dir/proposal" && \
	uv run --locked audit-harness poc-review examples/matrix-target --run "$$audit_matrix_dir/review" --proposal "$$audit_matrix_dir/proposal" --decision approve --reviewer offline-fixture --rationale 'Synthetic build contract decision; no actual approval or execution.' --output "$$audit_matrix_dir/approved" && \
	uv run --locked python examples/matrix-inputs.py "$$audit_matrix_dir" "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" && \
	uv run --locked audit-harness prepare-matrix examples/matrix-target --run "$$audit_matrix_dir/review" --spec "$$audit_matrix_dir/matrix-spec.json" --output "$$audit_matrix_dir/matrix" && \
	uv run --locked audit-harness judge-matrix "$$audit_matrix_dir/matrix" --output "$$audit_matrix_dir/judgment"

demo-validation:
	@test -n "$$VALIDATION_IMAGE" || { echo 'Set VALIDATION_IMAGE to a prepared local sha256 image ID'; exit 1; }
	mkdir -p runs
	audit_validation_dir=$$(mktemp -d runs/validation-demo.XXXXXX); \
	uv run --locked audit-harness run examples/validation-target --replay examples/validation-replay --output "$$audit_validation_dir/review" && \
	uv run --locked audit-harness validate examples/validation-target --run "$$audit_validation_dir/review" --recipe examples/validation-recipe.json --image "$$VALIDATION_IMAGE" --output "$$audit_validation_dir/worker"

doctor:
	uv run --locked audit-harness doctor

demo-judgment:
	@test -n "$$VALIDATION_IMAGE" || { echo 'Set VALIDATION_IMAGE to a prepared local sha256 image ID'; exit 1; }
	mkdir -p runs
	audit_judgment_dir=$$(mktemp -d runs/judgment-demo.XXXXXX); \
	uv run --locked audit-harness run examples/judgment-target --replay examples/judgment-replay --output "$$audit_judgment_dir/review" && \
	uv run --locked audit-harness validate examples/judgment-target --run "$$audit_judgment_dir/review" --recipe examples/judgment-baseline-recipe.json --image "$$VALIDATION_IMAGE" --output "$$audit_judgment_dir/baseline" && \
	uv run --locked audit-harness validate examples/judgment-target --run "$$audit_judgment_dir/review" --recipe examples/judgment-fixed-recipe.json --image "$$VALIDATION_IMAGE" --output "$$audit_judgment_dir/fixed" && \
	uv run --locked audit-harness judge "$$audit_judgment_dir/baseline" --fixed "$$audit_judgment_dir/fixed" --output "$$audit_judgment_dir/judgment"

demo-go-http:
	@test -n "$$VALIDATION_IMAGE" || { echo 'Set VALIDATION_IMAGE to the local ID from make setup-validation-go'; exit 1; }
	mkdir -p runs
	audit_http_dir=$$(mktemp -d runs/go-http-demo.XXXXXX); \
	if [ -n "$$VALIDATION_DOCKER_HOST" ]; then set -- --docker-host "$$VALIDATION_DOCKER_HOST"; else set --; fi; \
	uv run --locked audit-harness graph build examples/go-http-target --language go --output "$$audit_http_dir/graph" && \
	uv run --locked audit-harness recon examples/go-http-target --graph "$$audit_http_dir/graph/graph.json" --spec examples/go-http-plan.json --output "$$audit_http_dir/recon" && \
	uv run --locked audit-harness run examples/go-http-target --graph "$$audit_http_dir/graph/graph.json" --recon "$$audit_http_dir/recon/recon.json" --replay examples/go-http-replay --output "$$audit_http_dir/review" && \
	uv run --locked audit-harness run examples/go-http-target --graph "$$audit_http_dir/graph/graph.json" --recon "$$audit_http_dir/recon/recon.json" --replay examples/go-http-replay --output "$$audit_http_dir/review" --resume && \
	uv run --locked audit-harness validate examples/go-http-target --run "$$audit_http_dir/review" --recipe examples/go-http-baseline-recipe.json --image "$$VALIDATION_IMAGE" "$$@" --output "$$audit_http_dir/baseline" && \
	uv run --locked audit-harness validate examples/go-http-target --run "$$audit_http_dir/review" --recipe examples/go-http-fixed-recipe.json --image "$$VALIDATION_IMAGE" "$$@" --output "$$audit_http_dir/fixed" && \
	uv run --locked audit-harness judge "$$audit_http_dir/baseline" --fixed "$$audit_http_dir/fixed" --output "$$audit_http_dir/judgment" && \
	uv run --locked python -c 'import json,sys; result=json.load(open(sys.argv[1])); sys.exit(0 if result["verdict"] == "validated" and result["promotion"]["eligible"] else 1)' "$$audit_http_dir/judgment/judgment.json"

demo-go-file-selection:
	@test -n "$$VALIDATION_IMAGE" || { echo 'Set VALIDATION_IMAGE to the local ID from make setup-validation-go'; exit 1; }
	mkdir -p runs
	audit_file_dir=$$(mktemp -d runs/go-file-selection-demo.XXXXXX); \
	if [ -n "$$VALIDATION_DOCKER_HOST" ]; then set -- --docker-host "$$VALIDATION_DOCKER_HOST"; else set --; fi; \
	uv run --locked audit-harness graph build examples/go-file-selection-target --language go --output "$$audit_file_dir/graph" && \
	uv run --locked audit-harness recon examples/go-file-selection-target --graph "$$audit_file_dir/graph/graph.json" --spec examples/go-file-selection-plan.json --output "$$audit_file_dir/recon" && \
	uv run --locked audit-harness run examples/go-file-selection-target --graph "$$audit_file_dir/graph/graph.json" --recon "$$audit_file_dir/recon/recon.json" --replay examples/go-file-selection-replay --output "$$audit_file_dir/review" && \
	uv run --locked audit-harness validate examples/go-file-selection-target --run "$$audit_file_dir/review" --recipe examples/go-file-selection-baseline-recipe.json --image "$$VALIDATION_IMAGE" "$$@" --output "$$audit_file_dir/baseline" && \
	uv run --locked audit-harness validate examples/go-file-selection-target --run "$$audit_file_dir/review" --recipe examples/go-file-selection-fixed-recipe.json --image "$$VALIDATION_IMAGE" "$$@" --output "$$audit_file_dir/fixed" && \
	uv run --locked audit-harness judge "$$audit_file_dir/baseline" --fixed "$$audit_file_dir/fixed" --output "$$audit_file_dir/judgment" && \
	uv run --locked python -c 'import json,sys; result=json.load(open(sys.argv[1])); sys.exit(0 if result["verdict"] == "validated" and result["promotion"]["eligible"] else 1)' "$$audit_file_dir/judgment/judgment.json"
