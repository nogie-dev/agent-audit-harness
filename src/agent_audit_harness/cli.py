import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from .agents import CodexAgent, ReplayAgent
from .graph import build_graph, reachable, read_graph, resolve
from .judgment import judge
from .pipeline import MAX_AGENT_CALLS, index_target, prepare_review, run_pipeline, slice_summary
from .recon import build_recon
from .static_analysis import DEFAULT_RULES, build_static
from .validation import validate


def doctor() -> dict:
    tools = {
        name: shutil.which(name) is not None
        for name in ("uv", "git", "codex", "docker", "clang", "go", "node", "npm")
    }
    docker_running = False
    if tools["docker"]:
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            docker_running = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {
        "python": sys.version.split()[0],
        "tools": tools,
        "docker_running": docker_running,
        "offline_ready": sys.version_info >= (3, 12),
        "note": "Docker is required only for validate; source review and replay remain offline.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Call structure first, then bounded agent review")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("doctor", help="check local development prerequisites")
    graph = subcommands.add_parser("graph", help="extract/query static call structure")
    graph_commands = graph.add_subparsers(dest="graph_command", required=True)
    graph_build = graph_commands.add_parser(
        "build", help="extract C/C++, Go, Solidity or Python structure"
    )
    graph_build.add_argument("target", type=Path)
    graph_build.add_argument("--output", type=Path, required=True)
    graph_build.add_argument("--compilation-database", type=Path)
    graph_build.add_argument("--clang", default="clang", help="trusted local Clang executable")
    graph_build.add_argument("--go", default="go", help="trusted local Go executable")
    graph_build.add_argument("--node", default="node", help="trusted Node.js for pinned solc")
    graph_build.add_argument(
        "--language", choices=("auto", "c_cpp", "go", "solidity", "python"), default="auto"
    )
    graph_build.add_argument(
        "--timeout", type=int, default=30, help="seconds per extractor process"
    )
    for name in ("resolve", "reachable"):
        query = graph_commands.add_parser(name)
        query.add_argument("graph_file", type=Path)
        query.add_argument(
            "selector", help="function name/ID; resolve also accepts a file or package"
        )
        if name == "reachable":
            query.add_argument(
                "--files", action="store_true", help="print only reachable source paths"
            )
    plan = subcommands.add_parser("plan", help="inspect source scope without an agent call")
    static = subcommands.add_parser("static", help="attach source-checked static analyzer evidence")
    static.add_argument("target", type=Path)
    static.add_argument("--graph", type=Path, required=True)
    static.add_argument(
        "--rules", type=Path, default=DEFAULT_RULES, help="trusted local rule models"
    )
    static.add_argument("--output", type=Path, required=True)
    static.add_argument("--timeout", type=int, default=30, help="seconds per analyzer process")
    recon = subcommands.add_parser(
        "recon", help="bind research hypotheses to graph/source evidence"
    )
    recon.add_argument("target", type=Path)
    recon.add_argument("--graph", type=Path, required=True)
    recon_provider = recon.add_mutually_exclusive_group(required=True)
    recon_provider.add_argument("--spec", type=Path, help="researcher-supplied plan")
    recon_provider.add_argument("--replay", type=Path, help="recorded recon proposal")
    recon_provider.add_argument("--codex", action="store_true", help="request a recon proposal")
    recon.add_argument("--model", help="explicit Codex model")
    recon.add_argument("--static", type=Path, help="original static-role evidence")
    recon.add_argument("--input-bytes", type=int, default=16000)
    recon.add_argument("--max-calls", type=int, default=1, help="attempt cap, including retries")
    recon.add_argument("--timeout", type=int, default=180)
    recon.add_argument("--resume", action="store_true")
    recon.add_argument("--output", type=Path, required=True)
    run = subcommands.add_parser("run", help="run analysis and independent triage")
    for command in (plan, run):
        command.add_argument("target", type=Path)
        command.add_argument("--max-slices", type=int, default=8)
        command.add_argument("--slice-bytes", type=int, default=16_000)
        command.add_argument("--max-calls", type=int, default=16)
        command.add_argument("--max-queries", type=int, default=4, help="0..32 queries per slice")
        command.add_argument(
            "--repair-citations",
            action="store_true",
            help="allow one source-citation repair per call within --max-calls",
        )
        command.add_argument(
            "--query-bytes", type=int, default=16_000, help="query payload byte budget per slice"
        )
        command.add_argument("--graph", type=Path, help="v2 graph for relationship-based input")
        command.add_argument(
            "--recon", type=Path, help="source-backed recon artifact; requires --graph"
        )
        command.add_argument(
            "--static", type=Path, help="static evidence artifact; requires --graph and --recon"
        )
    provider = run.add_mutually_exclusive_group(required=True)
    provider.add_argument("--replay", type=Path, help="directory of recorded JSON responses")
    provider.add_argument(
        "--codex", action="store_true", help="invoke Codex; sends slices to the model"
    )
    run.add_argument("--model", help="explicit model for Codex; recorded in run identity")
    run.add_argument("--output", type=Path)
    run.add_argument("--timeout", type=int, default=180, help="seconds per Codex call")
    run.add_argument("--resume", action="store_true", help="reuse valid completed calls")
    benchmark = subcommands.add_parser(
        "benchmark-replay", help="compare two bounded offline reviews against source labels"
    )
    benchmark.add_argument("target", type=Path)
    benchmark.add_argument("--truth", type=Path, required=True)
    benchmark.add_argument("--baseline-replay", type=Path, required=True)
    benchmark.add_argument("--candidate-replay", type=Path, required=True)
    benchmark.add_argument("--candidate-graph", type=Path)
    benchmark.add_argument("--candidate-recon", type=Path)
    benchmark.add_argument("--candidate-static", type=Path)
    benchmark.add_argument("--max-slices", type=int, default=8)
    benchmark.add_argument("--slice-bytes", type=int, default=16_000)
    benchmark.add_argument("--max-calls", type=int, default=16)
    benchmark.add_argument("--max-queries", type=int, default=4)
    benchmark.add_argument("--query-bytes", type=int, default=16_000)
    benchmark.add_argument("--output", type=Path, required=True)
    compare = subcommands.add_parser(
        "benchmark-runs", help="compare two completed local runs without model calls"
    )
    compare.add_argument("target", type=Path)
    compare.add_argument("--truth", type=Path, required=True)
    compare.add_argument("--baseline", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    attempts = subcommands.add_parser(
        "benchmark-attempts", help="account for completed and failed Codex call attempts"
    )
    attempts.add_argument("run", type=Path)
    attempts.add_argument("--output", type=Path, required=True)
    summary = subcommands.add_parser(
        "benchmark-summary", help="summarize repeated completed-run comparisons without execution"
    )
    summary.add_argument("target", type=Path)
    summary.add_argument("--truth", type=Path, required=True)
    summary.add_argument("--report", type=Path, action="append", required=True)
    summary.add_argument("--output", type=Path, required=True)
    intake = subcommands.add_parser(
        "import-review", help="import source-backed external candidates"
    )
    intake.add_argument("target", type=Path)
    intake.add_argument("--spec", type=Path, required=True)
    intake.add_argument("--output", type=Path, required=True)
    intake.add_argument("--graph", type=Path)
    intake.add_argument("--static", type=Path)
    intake.add_argument("--input-bytes", type=int, default=16000)
    poc = subcommands.add_parser("poc", help="store a source-bound PoC proposal without execution")
    poc.add_argument("target", type=Path)
    poc.add_argument("--run", type=Path, required=True)
    poc.add_argument("--candidate", required=True)
    poc_provider = poc.add_mutually_exclusive_group(required=True)
    poc_provider.add_argument("--replay", type=Path)
    poc_provider.add_argument("--codex", action="store_true")
    poc.add_argument("--model")
    poc.add_argument("--input-bytes", type=int, default=16000)
    poc.add_argument("--support-file", action="append", default=[], dest="support_files")
    poc.add_argument("--max-calls", type=int, default=1)
    poc.add_argument("--timeout", type=int, default=180)
    poc.add_argument("--resume", action="store_true")
    poc.add_argument("--output", type=Path, required=True)
    poc_review = subcommands.add_parser(
        "poc-review", help="record explicit operator review of PoC data"
    )
    poc_review.add_argument("target", type=Path)
    poc_review.add_argument("--run", type=Path, required=True)
    poc_review.add_argument("--proposal", type=Path, required=True)
    poc_review.add_argument(
        "--decision", choices=("approve", "reject", "request_changes"), required=True
    )
    poc_review.add_argument("--reviewer", required=True)
    poc_review.add_argument("--rationale", required=True)
    poc_review.add_argument("--output", type=Path, required=True)
    validation = subcommands.add_parser("validate", help="execute an explicit recipe in isolation")
    validation.add_argument("target", type=Path)
    validation.add_argument("--run", type=Path, required=True, help="completed review directory")
    validation.add_argument(
        "--recipe", type=Path, required=True, help="explicit bounded argv recipe"
    )
    validation.add_argument("--image", required=True, help="prepared local sha256 image ID")
    validation.add_argument("--output", type=Path, required=True)
    validation.add_argument("--docker", default="docker", help="trusted local Docker executable")
    validation.add_argument("--docker-host", help="local unix:/// socket; no remote endpoints")
    validation.add_argument(
        "--poc-review", type=Path, help="explicit approved PoC researcher artifact directory"
    )
    validation.add_argument(
        "--configuration", help="declared build case ID passed as a literal argument"
    )
    matrix_prepare = subcommands.add_parser(
        "prepare-matrix", help="freeze reviewed build cases without execution"
    )
    matrix_prepare.add_argument("target", type=Path)
    matrix_prepare.add_argument("--run", type=Path, required=True)
    matrix_prepare.add_argument("--spec", type=Path, required=True)
    matrix_prepare.add_argument("--output", type=Path, required=True)
    matrix_validate = subcommands.add_parser(
        "validate-matrix", help="explicitly run frozen cases in isolated workers"
    )
    matrix_validate.add_argument("matrix", type=Path)
    matrix_validate.add_argument("--max-runs", type=int, default=8)
    matrix_validate.add_argument("--docker", default="docker")
    matrix_validate.add_argument("--docker-host")
    matrix_judge = subcommands.add_parser(
        "judge-matrix", help="judge retained before/after cases without execution"
    )
    matrix_judge.add_argument("matrix", type=Path)
    matrix_judge.add_argument("--output", type=Path, required=True)
    judgment = subcommands.add_parser(
        "judge", help="judge frozen validation evidence and promotion gates"
    )
    judgment.add_argument("baseline", type=Path, help="worker result directory")
    judgment.add_argument("--fixed", type=Path, help="worker run with declared source replacements")
    judgment.add_argument("--output", type=Path, required=True)
    chain = subcommands.add_parser(
        "prepare-chain", help="bind two validated primitives to a source-backed hypothesis"
    )
    chain.add_argument("first", type=Path, help="first immutable judgment directory")
    chain.add_argument("second", type=Path, help="second immutable judgment directory")
    chain.add_argument("--spec", type=Path, required=True)
    chain.add_argument("--output", type=Path, required=True)
    chain_review = subcommands.add_parser(
        "chain-review", help="record researcher approval of a frozen connection experiment"
    )
    chain_review.add_argument("chain", type=Path)
    chain_review.add_argument("--poc-review", type=Path, required=True)
    chain_review.add_argument("--plan", type=Path, required=True)
    chain_review.add_argument(
        "--decision", choices=("approve", "reject", "request_changes"), required=True
    )
    chain_review.add_argument("--reviewer", required=True)
    chain_review.add_argument("--rationale", required=True)
    chain_review.add_argument("--output", type=Path, required=True)
    chain_judge = subcommands.add_parser(
        "judge-chain", help="judge frozen connection observations without execution"
    )
    chain_judge.add_argument("chain", type=Path)
    chain_judge.add_argument("--review", type=Path, required=True)
    chain_judge.add_argument("--worker", type=Path, required=True)
    chain_judge.add_argument("--output", type=Path, required=True)
    impact_review = subcommands.add_parser(
        "impact-review", help="freeze researcher-reviewed staged impact measurements"
    )
    impact_source = impact_review.add_mutually_exclusive_group(required=True)
    impact_source.add_argument("--primitive", type=Path, help="validated judgment directory")
    impact_source.add_argument("--chain", type=Path, help="connected chain judgment directory")
    impact_review.add_argument("--plan", type=Path, required=True)
    impact_review.add_argument(
        "--decision", choices=("approve", "reject", "request_changes"), required=True
    )
    impact_review.add_argument("--reviewer", required=True)
    impact_review.add_argument("--rationale", required=True)
    impact_review.add_argument("--output", type=Path, required=True)
    impact_step = subcommands.add_parser(
        "impact-step", help="record one reviewed worker gate and advance its checkpoint"
    )
    impact_step.add_argument("review", type=Path)
    impact_step.add_argument("--worker", type=Path, required=True)
    impact_step.add_argument("--stage", required=True)
    impact_step.add_argument("--decision", choices=("approve", "retry", "reject"), required=True)
    impact_step.add_argument("--reviewer", required=True)
    impact_step.add_argument("--rationale", required=True)
    impact_step.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "doctor":
        print(json.dumps(doctor(), indent=2))
        return 0
    try:
        if arguments.command == "benchmark-attempts":
            from .benchmark import summarize_attempts

            result = summarize_attempts(arguments.run, arguments.output)
            print(
                json.dumps(
                    {
                        "report": str(arguments.output.resolve() / "attempts.json"),
                        "call_attempts": result["call_attempts"],
                        "failed_calls": result["failed_calls"],
                        "unknown_calls": result["unknown_calls"],
                        "citation_repair_outcomes": result["citation_repair_outcomes"],
                        "token_coverage": result["token_coverage"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "benchmark-summary":
            from .benchmark import summarize_benchmarks

            result = summarize_benchmarks(
                arguments.target, arguments.truth, arguments.report, arguments.output
            )
            print(
                json.dumps(
                    {
                        "summary": str(arguments.output.resolve() / "benchmark-summary.json"),
                        "measurement_kind": result["measurement_kind"],
                        "repeat_count": result["repeat_count"],
                        "complete_token_pairs": result["complete_token_pairs"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "benchmark-runs":
            from .benchmark import compare_runs

            result = compare_runs(
                arguments.target,
                arguments.truth,
                arguments.baseline,
                arguments.candidate,
                arguments.output,
            )
            print(
                json.dumps(
                    {
                        "report": str(arguments.output.resolve() / "benchmark.json"),
                        "measurement_kind": result["measurement_kind"],
                        "baseline": result["arms"]["baseline"]["label_counts"],
                        "candidate": result["arms"]["candidate"]["label_counts"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "benchmark-replay":
            from .benchmark import benchmark_replay

            result = benchmark_replay(
                arguments.target,
                arguments.truth,
                arguments.baseline_replay,
                arguments.candidate_replay,
                arguments.output,
                candidate_graph=arguments.candidate_graph,
                candidate_recon=arguments.candidate_recon,
                candidate_static=arguments.candidate_static,
                max_slices=arguments.max_slices,
                slice_bytes=arguments.slice_bytes,
                max_calls=arguments.max_calls,
                max_queries=arguments.max_queries,
                query_bytes=arguments.query_bytes,
            )
            print(
                json.dumps(
                    {
                        "report": str(arguments.output.resolve() / "benchmark.json"),
                        "measurement_kind": result["measurement_kind"],
                        "baseline": result["arms"]["baseline"]["label_counts"],
                        "candidate": result["arms"]["candidate"]["label_counts"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "impact-step":
            from .impact_steps import impact_step

            result = impact_step(
                arguments.review,
                arguments.worker,
                arguments.output,
                stage_id=arguments.stage,
                decision=arguments.decision,
                reviewer=arguments.reviewer,
                rationale=arguments.rationale,
            )
            print(
                json.dumps(
                    {
                        "checkpoint": str(arguments.output.resolve() / "impact-state.json"),
                        "status": result["status"],
                        "verdict": result["verdict"],
                        "next_stage_index": result["next_stage_index"],
                        "impact_validated": result["impact_validated"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "impact-review":
            from .impact import review_impact

            result = review_impact(
                "primitive" if arguments.primitive else "chain",
                arguments.primitive or arguments.chain,
                arguments.plan,
                arguments.output,
                decision=arguments.decision,
                reviewer=arguments.reviewer,
                rationale=arguments.rationale,
            )
            print(
                json.dumps(
                    {
                        "review": str(arguments.output.resolve() / "impact-review.json"),
                        "decision": result["decision"],
                        "stages": [item["id"] for item in result["stages"]],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "chain-review":
            from .chain_experiment import review_chain

            result = review_chain(
                arguments.chain,
                arguments.poc_review,
                arguments.plan,
                arguments.output,
                decision=arguments.decision,
                reviewer=arguments.reviewer,
                rationale=arguments.rationale,
            )
            print(
                json.dumps(
                    {
                        "review": str(arguments.output.resolve() / "chain-review.json"),
                        "decision": result["decision"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "judge-chain":
            from .chain_experiment import judge_chain

            result = judge_chain(
                arguments.chain, arguments.review, arguments.worker, arguments.output
            )
            print(
                json.dumps(
                    {
                        "judgment": str(arguments.output.resolve() / "chain-judgment.json"),
                        "status": result["status"],
                        "verdict": result["verdict"],
                        "connection_observed": result["connection_observed"],
                    },
                    indent=2,
                )
            )
            return 0 if result["status"] == "complete" else 1
        if arguments.command == "prepare-chain":
            from .chain import prepare_chain

            result = prepare_chain(
                arguments.first, arguments.second, arguments.spec, arguments.output
            )
            print(
                json.dumps(
                    {
                        "chain": str(arguments.output.resolve() / "chain.json"),
                        "status": result["status"],
                        "connection": result["connection"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command in {"prepare-matrix", "validate-matrix", "judge-matrix"}:
            from .matrix import judge_matrix, prepare_matrix, validate_matrix

            if arguments.command == "prepare-matrix":
                result = prepare_matrix(
                    arguments.target, arguments.run, arguments.spec, arguments.output
                )
                print(
                    json.dumps(
                        {"matrix": str(arguments.output.resolve()), "status": result["status"]},
                        indent=2,
                    )
                )
            elif arguments.command == "validate-matrix":
                result = validate_matrix(
                    arguments.matrix,
                    max_runs=arguments.max_runs,
                    docker=arguments.docker,
                    docker_host=arguments.docker_host,
                )
                print(
                    json.dumps(
                        {
                            "status": result["status"],
                            "run_attempts": result["run_attempts"],
                            "stop_reason": result["stop_reason"],
                        },
                        indent=2,
                    )
                )
                return 0 if result["status"] == "complete" else 1
            else:
                result = judge_matrix(arguments.matrix, arguments.output)
                print(
                    json.dumps(
                        {
                            "report": str(arguments.output.resolve() / "matrix-judgment.json"),
                            "coverage_complete": result["coverage_complete"],
                            "validated_cases": result["validated_cases"],
                        },
                        indent=2,
                    )
                )
            return 0
        if arguments.command == "poc-review":
            from .poc import review_poc

            receipt = review_poc(
                arguments.target,
                arguments.run,
                arguments.proposal,
                arguments.output,
                decision=arguments.decision,
                reviewer=arguments.reviewer,
                rationale=arguments.rationale,
            )
            print(
                json.dumps(
                    {
                        "review": str(arguments.output.resolve() / "review.json"),
                        "decision": receipt["decision"],
                        "identity_sha256": receipt["identity_sha256"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "poc":
            from .poc import propose_poc

            if arguments.codex and not arguments.model:
                raise ValueError("--codex requires an explicit --model")
            if arguments.replay and arguments.model:
                raise ValueError("--model is only used with --codex")
            agent = (
                ReplayAgent(arguments.replay)
                if arguments.replay
                else CodexAgent(arguments.model, arguments.timeout)
            )
            state = propose_poc(
                arguments.target,
                arguments.run,
                arguments.candidate,
                arguments.output,
                agent,
                input_bytes=arguments.input_bytes,
                support_paths=arguments.support_files,
                max_calls=arguments.max_calls,
                resume=arguments.resume,
            )
            print(
                json.dumps(
                    {
                        "proposal": str(arguments.output.resolve() / "proposal.json"),
                        "status": state["status"],
                        "call_attempts": state["call_attempts"],
                        "cache_hit": state["cache_hit"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "import-review":
            from .intake import import_review

            metrics = import_review(
                arguments.target,
                arguments.spec,
                arguments.output,
                graph_file=arguments.graph,
                static_file=arguments.static,
                input_bytes=arguments.input_bytes,
            )
            print(
                json.dumps(
                    {"report": str(arguments.output.resolve() / "report.md"), **metrics}, indent=2
                )
            )
            return 0
        if arguments.command == "judge":
            decision = judge(arguments.baseline, arguments.output, fixed=arguments.fixed)
            print(
                json.dumps(
                    {
                        "judgment": str(arguments.output.resolve() / "judgment.json"),
                        "status": decision["status"],
                        "verdict": decision["verdict"],
                        "validated_findings": decision["validated_findings"],
                        "promotion": decision["promotion"],
                    },
                    indent=2,
                )
            )
            return 0 if decision["status"] == "complete" else 1
        if arguments.command == "validate":
            result = validate(
                arguments.target,
                arguments.run,
                arguments.recipe,
                arguments.output,
                image=arguments.image,
                docker=arguments.docker,
                docker_host=arguments.docker_host,
                poc_review=arguments.poc_review,
                configuration_id=arguments.configuration,
            )
            print(
                json.dumps(
                    {
                        "result": str(arguments.output.resolve() / "result.json"),
                        "status": result["status"],
                        "execution_started": result["execution_started"],
                        "exit_code": result["exit_code"],
                        "cleanup": result["cleanup"],
                        "confirmed_findings": result["confirmed_findings"],
                    },
                    indent=2,
                )
            )
            return 0 if result["status"] == "completed" else 1
        if arguments.command == "graph":
            if arguments.graph_command == "build":
                result = build_graph(
                    arguments.target,
                    arguments.output,
                    database=arguments.compilation_database,
                    compiler=arguments.clang,
                    timeout=arguments.timeout,
                    language=arguments.language,
                    go=arguments.go,
                    node=arguments.node,
                )
                print(
                    json.dumps(
                        {
                            "graph": str(arguments.output.resolve() / "graph.json"),
                            "functions": len(result["functions"]),
                            "call_sites": len(result["calls"]),
                            "file_edges": len(result["file_calls"]),
                            "scope_edges": len(result["scope_calls"]),
                            "coverage": result["coverage"],
                        },
                        indent=2,
                    )
                )
            else:
                graph_data = read_graph(arguments.graph_file)
                result = (resolve if arguments.graph_command == "resolve" else reachable)(
                    graph_data, arguments.selector
                )
                if arguments.graph_command == "reachable" and arguments.files:
                    print("\n".join(result["files"]))
                    if result["unresolved_calls"] or result["parse_coverage"] == "partial":
                        print(
                            "note: partial parse/unresolved calls; see the full JSON query",
                            file=sys.stderr,
                        )
                else:
                    print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if arguments.command == "recon":
            if not arguments.spec:
                from .recon_proposal import propose_recon

                if arguments.codex and not arguments.model:
                    raise ValueError("--codex requires --model")
                if arguments.replay and arguments.model:
                    raise ValueError("--model is only used with --codex")
                agent = (
                    CodexAgent(arguments.model, arguments.timeout)
                    if arguments.codex
                    else ReplayAgent(arguments.replay)
                )
                state = propose_recon(
                    arguments.target,
                    arguments.graph,
                    arguments.static,
                    arguments.output,
                    agent,
                    input_bytes=arguments.input_bytes,
                    max_calls=arguments.max_calls,
                    resume=arguments.resume,
                )
                print(
                    json.dumps(
                        {
                            "output": str(arguments.output.resolve()),
                            "status": state["status"],
                            "hypotheses": state["proposed_hypotheses"],
                            "call_attempts": state["call_attempts"],
                            "cache_hit": state["cache_hit"],
                        },
                        indent=2,
                    )
                )
                return 0
            if arguments.static or arguments.model or arguments.resume:
                raise ValueError("--static/--model/--resume are used with recon proposals")
            result = build_recon(
                arguments.target, arguments.graph, arguments.spec, arguments.output
            )
            print(
                json.dumps(
                    {
                        "recon": str(arguments.output.resolve() / "recon.json"),
                        "hypotheses": len(result["hypotheses"]),
                        "identity_sha256": result["identity_sha256"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.command == "static":
            result = build_static(
                arguments.target,
                arguments.graph,
                arguments.rules,
                arguments.output,
                timeout=arguments.timeout,
            )
            print(
                json.dumps(
                    {
                        "static": str(arguments.output.resolve() / "static.json"),
                        "observations": len(result["observations"]),
                        "taint_results": len(result["taint_results"]),
                        "gaps": len(result["gaps"]),
                        "coverage": result["coverage"],
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.max_slices < 1:
            raise ValueError("max slices must be positive")
        if arguments.command == "plan":
            if (
                not 1 <= arguments.max_calls <= MAX_AGENT_CALLS
                or not 0 <= arguments.max_queries <= 32
                or not 1024 <= arguments.query_bytes <= 64 * 1024
            ):
                raise ValueError("invalid agent call or query budget")
            target = arguments.target.resolve()
            sources, skipped = index_target(target)
            slices, unsliced, _ = prepare_review(
                target,
                sources,
                arguments.slice_bytes,
                arguments.graph,
                arguments.recon,
                arguments.static,
            )
            selected = slices[: arguments.max_slices]
            print(
                json.dumps(
                    {
                        "indexed_files": len(sources),
                        "total_slices": len(slices),
                        "selected_slices": [slice_summary(s) for s in selected],
                        "base_agent_calls_if_candidates": len(selected) * 2,
                        "max_agent_calls_possible": min(
                            arguments.max_calls,
                            len(selected)
                            * (2 + arguments.max_queries + int(arguments.static is not None))
                            * (2 if arguments.repair_citations else 1),
                        ),
                        "max_citation_repairs_per_call": int(arguments.repair_citations),
                        "configured_call_cap": arguments.max_calls,
                        "max_queries_per_slice": arguments.max_queries,
                        "query_bytes_per_slice": arguments.query_bytes,
                        "skipped": skipped + unsliced,
                    },
                    indent=2,
                )
            )
            return 0
        if arguments.codex and not arguments.model:
            raise ValueError("--codex requires --model; select an available model explicitly")
        if arguments.replay and arguments.model:
            raise ValueError("--model is only used with --codex")
        agent = (
            CodexAgent(arguments.model, arguments.timeout)
            if arguments.codex
            else ReplayAgent(arguments.replay)
        )
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        output = arguments.output or Path("runs") / stamp
        metrics = run_pipeline(
            arguments.target,
            output,
            agent,
            max_slices=arguments.max_slices,
            slice_bytes=arguments.slice_bytes,
            max_calls=arguments.max_calls,
            max_queries=arguments.max_queries,
            query_bytes=arguments.query_bytes,
            repair_citations=arguments.repair_citations,
            resume=arguments.resume,
            graph_file=arguments.graph,
            recon_file=arguments.recon,
            static_file=arguments.static,
        )
        print(json.dumps({"report": str(output.resolve() / "report.md"), **metrics}, indent=2))
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
