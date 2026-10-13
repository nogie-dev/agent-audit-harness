"""Rebuild the offline, deliberately empty-baseline model-evaluation rehearsal."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from time import monotonic

from agent_audit_harness.benchmark import benchmark_replay, call_profile, compare_runs
from agent_audit_harness.graph import build_graph
from agent_audit_harness.pipeline import index_target, make_slices
from agent_audit_harness.recon import build_recon

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "go": ("go-review", "go-review-plan.json", "go-review-benchmark-truth.json", "go-review"),
    "python": (
        "static",
        "python-benchmark-plan.json",
        "python-benchmark-truth.json",
        "python-benchmark",
    ),
    "solidity": (
        "solidity-benchmark",
        "solidity-benchmark-plan.json",
        "solidity-benchmark-truth.json",
        "solidity-benchmark",
    ),
}
CALL_CAPS = {"go": 15, "python": 6, "solidity": 6}
PROSPECTIVE_CASES = {
    language: (
        f"model-eval-prospective-{language}",
        f"model-eval-prospective-{language}-plan.json",
        f"model-eval-prospective-{language}-truth.json",
        None,
    )
    for language in CASES
}
PROSPECTIVE_CALL_CAPS = {"go": 18, "python": 12, "solidity": 12}


def preflight(output: Path, languages: tuple[str, ...], suite: str = "original") -> dict:
    output = output.resolve()
    if not output.is_relative_to(ROOT / "runs") or (output.exists() and any(output.iterdir())):
        raise ValueError("preflight output must be an empty directory under runs/")
    output.mkdir(parents=True, exist_ok=True)
    results = {}
    cases = CASES if suite == "original" else PROSPECTIVE_CASES
    caps = CALL_CAPS if suite == "original" else PROSPECTIVE_CALL_CAPS
    for language in languages:
        example, plan, truth, replay_name = cases[language]
        directory = output / language
        target = directory / "target"
        shutil.copytree(ROOT / "examples" / f"{example}-target", target)
        frozen_plan = directory / "plan.json"
        frozen_truth = directory / "truth.json"
        shutil.copyfile(ROOT / "examples" / plan, frozen_plan)
        shutil.copyfile(ROOT / "examples" / truth, frozen_truth)
        graph_file = directory / "graph/graph.json"
        started = monotonic()
        build_graph(target, graph_file.parent, language=language)
        graph_seconds = round(monotonic() - started, 3)
        recon_file = directory / "recon/recon.json"
        started = monotonic()
        build_recon(target, graph_file, frozen_plan, recon_file.parent)
        recon_seconds = round(monotonic() - started, 3)
        baseline = directory / "empty-lexical-replay"
        baseline.mkdir()
        started = monotonic()
        lexical_slices = make_slices(index_target(target)[0], 16_000)[0]
        lexical_seconds = round(monotonic() - started, 3)
        for source_slice in lexical_slices:
            (baseline / f"{source_slice['id']}.analysis.json").write_text(
                '{"candidates": []}\n', encoding="utf-8"
            )
        replay = directory / "rehearsal"
        benchmark_replay(
            target,
            frozen_truth,
            baseline,
            ROOT / "examples" / f"{replay_name}-replay" if replay_name else baseline,
            replay,
            candidate_graph=graph_file,
            candidate_recon=recon_file,
            max_slices=8,
            slice_bytes=16_000,
            max_calls=caps[language],
            max_queries=1,
            query_bytes=16_000,
        )
        comparison = compare_runs(
            target,
            frozen_truth,
            replay / "baseline",
            replay / "candidate",
            directory / "comparison",
        )
        if any(arm["label_counts"]["uncovered_labels"] for arm in comparison["arms"].values()):
            raise ValueError(f"{language} benchmark labels are outside supplied source")
        results[language] = {
            "comparison": str(directory / "comparison/benchmark.json"),
            "max_calls_per_run": caps[language],
            "preparation_seconds": {
                "lexical_index_slice": lexical_seconds,
                "graph": graph_seconds,
                "recon": recon_seconds,
            },
            "tool_sha256": json.loads((replay / "baseline/manifest.json").read_text())["identity"][
                "query_tool_sha256"
            ],
            "plan_sha256": hashlib.sha256(frozen_plan.read_bytes()).hexdigest(),
            "truth_sha256": comparison["truth_sha256"],
            "label_counts": {
                arm: comparison["arms"][arm]["label_counts"] for arm in ("baseline", "candidate")
            },
            "prompt_bytes": {
                arm: sum(stage["prompt_bytes"] for stage in call_profile(replay / arm).values())
                for arm in ("baseline", "candidate")
            },
        }
    summary = {
        "measurement_kind": "offline_replay_preflight",
        "suite": suite,
        "baseline_reply": "deliberately_empty_candidates",
        "candidate_reply": (
            "deliberately_empty_candidates" if suite == "prospective" else "recorded"
        ),
        "preparation_timing": (
            "single local wall-clock sample; excludes source copy and dependency setup"
        ),
        "results": results,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if suite == "prospective":
        tool_hashes = {item["tool_sha256"] for item in results.values()}
        if len(tool_hashes) != 1:
            raise ValueError("prospective inputs have different tool identities")
        inputs = {}
        for language in languages:
            directory = output / language
            comparison = json.loads((directory / "comparison/benchmark.json").read_text())
            graph_path = directory / "graph/graph.json"
            recon_path = directory / "recon/recon.json"
            inputs[language] = {
                "target": str(directory / "target"),
                "source_index": comparison["arms"]["baseline"]["source_index"],
                "graph": str(graph_path),
                "graph_sha256": hashlib.sha256(graph_path.read_bytes()).hexdigest(),
                "recon": str(recon_path),
                "recon_sha256": hashlib.sha256(recon_path.read_bytes()).hexdigest(),
                "plan": str(directory / "plan.json"),
                "plan_sha256": results[language]["plan_sha256"],
                "truth": str(directory / "truth.json"),
                "truth_sha256": results[language]["truth_sha256"],
                "max_calls_per_run": caps[language],
            }
        order = [
            {"language": language, "repeat": repeat, "arm": arm}
            for repeat in (1, 2)
            for language in languages
            for arm in (("baseline", "candidate") if repeat == 1 else ("candidate", "baseline"))
        ]
        protocol = {
            "approval_status": "not_requested",
            "execution_status": "not_started",
            "model": "gpt-6-luna",
            "tool_sha256": tool_hashes.pop(),
            "max_runs": len(order),
            "max_call_attempts": sum(caps[item["language"]] for item in order),
            "limits_per_run": {
                "max_slices": 8,
                "slice_bytes": 16_000,
                "max_queries_per_slice": 1,
                "query_bytes_per_slice": 16_000,
                "timeout_seconds_per_call": 180,
                "repair_citations": True,
            },
            "comparison_policy": (
                "Same frozen source and limits within each pair; compare complete pairs only; "
                "retain failed and unknown attempts and token coverage; no resume or replacement."
            ),
            "inputs": inputs,
            "order": order,
        }
        (output / "protocol.json").write_text(
            json.dumps(protocol, indent=2) + "\n", encoding="utf-8"
        )
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--language", choices=(*CASES, "all"), default="all")
    parser.add_argument("--suite", choices=("original", "prospective"), default="original")
    options = parser.parse_args()
    selected = tuple(CASES) if options.language == "all" else (options.language,)
    print(json.dumps(preflight(options.output, selected, options.suite), indent=2))
