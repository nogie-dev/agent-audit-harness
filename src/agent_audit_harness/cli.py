import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from .agents import CodexAgent, ReplayAgent
from .graph import build_graph, reachable, read_graph, resolve
from .pipeline import index_target, prepare_review, run_pipeline, slice_summary
from .recon import build_recon


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
        "note": "Docker is optional until the isolated validation worker is implemented.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Call structure first, then bounded agent review")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("doctor", help="check local development prerequisites")
    graph = subcommands.add_parser("graph", help="extract/query compiler-backed call structure")
    graph_commands = graph.add_subparsers(dest="graph_command", required=True)
    graph_build = graph_commands.add_parser("build", help="extract C/C++, Go or Solidity structure")
    graph_build.add_argument("target", type=Path)
    graph_build.add_argument("--output", type=Path, required=True)
    graph_build.add_argument("--compilation-database", type=Path)
    graph_build.add_argument("--clang", default="clang", help="trusted local Clang executable")
    graph_build.add_argument("--go", default="go", help="trusted local Go executable")
    graph_build.add_argument("--node", default="node", help="trusted Node.js for pinned solc")
    graph_build.add_argument(
        "--language", choices=("auto", "c_cpp", "go", "solidity"), default="auto"
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
    recon = subcommands.add_parser(
        "recon", help="bind research hypotheses to graph/source evidence"
    )
    recon.add_argument("target", type=Path)
    recon.add_argument("--graph", type=Path, required=True)
    recon.add_argument("--spec", type=Path, required=True)
    recon.add_argument("--output", type=Path, required=True)
    run = subcommands.add_parser("run", help="run analysis and independent triage")
    for command in (plan, run):
        command.add_argument("target", type=Path)
        command.add_argument("--max-slices", type=int, default=8)
        command.add_argument("--slice-bytes", type=int, default=16_000)
        command.add_argument("--graph", type=Path, help="v2 graph for relationship-based input")
        command.add_argument(
            "--recon", type=Path, help="source-backed recon artifact; requires --graph"
        )
    provider = run.add_mutually_exclusive_group(required=True)
    provider.add_argument("--replay", type=Path, help="directory of recorded JSON responses")
    provider.add_argument(
        "--codex", action="store_true", help="invoke Codex; sends slices to the model"
    )
    run.add_argument("--model", help="explicit model for Codex; recorded in run identity")
    run.add_argument("--output", type=Path)
    run.add_argument("--max-calls", type=int, default=16)
    run.add_argument("--timeout", type=int, default=180, help="seconds per Codex call")
    run.add_argument("--resume", action="store_true", help="reuse valid completed calls")
    arguments = parser.parse_args(argv)
    if arguments.command == "doctor":
        print(json.dumps(doctor(), indent=2))
        return 0
    try:
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
        if arguments.max_slices < 1:
            raise ValueError("max slices must be positive")
        if arguments.command == "plan":
            sources, skipped = index_target(arguments.target)
            slices, unsliced, _ = prepare_review(
                arguments.target, sources, arguments.slice_bytes, arguments.graph, arguments.recon
            )
            selected = slices[: arguments.max_slices]
            print(
                json.dumps(
                    {
                        "indexed_files": len(sources),
                        "total_slices": len(slices),
                        "selected_slices": [slice_summary(s) for s in selected],
                        "max_agent_calls_needed": len(selected) * 2,
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
            resume=arguments.resume,
            graph_file=arguments.graph,
            recon_file=arguments.recon,
        )
        print(json.dumps({"report": str(output.resolve() / "report.md"), **metrics}, indent=2))
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
