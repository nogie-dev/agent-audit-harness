"""Offline replay comparison measures orchestration and labeled candidate handling."""

import json
import shutil
from pathlib import Path

import pytest

from agent_audit_harness import benchmark as benchmark_module
from agent_audit_harness.agents import ReplayAgent, Reply
from agent_audit_harness.benchmark import (
    benchmark_replay,
    call_profile,
    compare_runs,
    summarize_attempts,
    summarize_benchmarks,
)
from agent_audit_harness.cli import main
from agent_audit_harness.graph import build_graph
from agent_audit_harness.pipeline import digest, index_target, make_slices, run_pipeline
from agent_audit_harness.recon import build_recon

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples/demo-target"
REPLAY = ROOT / "examples/replay"
TRUTH = ROOT / "examples/benchmark-truth.json"
ALTERNATE_TRUTH = ROOT / "examples/benchmark-truth-alternate.json"
REPAIR_REPLAY = ROOT / "examples/citation-repair-replay"


def read(path):
    return json.loads(path.read_text())


def test_source_backed_root_cause_can_match_label_without_relabeling_candidate():
    case = {
        "path": "runner/execute.go",
        "line": 6,
        "quote": "exec.Command(program)",
        "cwe": "CWE-78",
        "source_sha256": "trusted-source",
    }
    finding = {
        "path": "web/handlers.go",
        "line": 10,
        "cwe": "CWE-78",
        "root_cause": {
            "evidence": {
                "path": "runner/execute.go",
                "line": 6,
                "quote": "_ = exec.Command(program).Run()",
                "source_sha256": "trusted-source",
            }
        },
    }
    assert benchmark_module.root_cause_matches_case(finding, case)
    finding["root_cause"]["evidence"]["source_sha256"] = "other-source"
    assert not benchmark_module.root_cause_matches_case(finding, case)
    finding["root_cause"]["evidence"]["source_sha256"] = "trusted-source"
    finding["root_cause"]["evidence"]["quote"] = "unrelated expression"
    assert not benchmark_module.root_cause_matches_case(finding, case)


def test_location_diagnostics_separate_cwe_location_and_verdict():
    case = {
        "path": "runner/execute.go",
        "line": 6,
        "quote": "exec.Command(program)",
        "cwe": "CWE-73",
        "source_sha256": "trusted-source",
    }
    findings = [
        {
            "id": "go-request",
            "path": "web/handlers.go",
            "line": 10,
            "cwe": "CWE-22",
            "verdict": "needs_validation",
            "root_cause": {
                "evidence": {
                    "path": case["path"],
                    "line": case["line"],
                    "quote": "_ = exec.Command(program).Run()",
                    "source_sha256": case["source_sha256"],
                }
            },
        },
        {
            "id": "rejected-location",
            "path": case["path"],
            "line": case["line"],
            "cwe": "CWE-22",
            "verdict": "rejected",
        },
        {
            "id": "wrong-evidence",
            "path": "web/handlers.go",
            "line": 10,
            "cwe": "CWE-73",
            "verdict": "uncertain",
            "root_cause": {
                "evidence": {
                    "path": case["path"],
                    "line": case["line"],
                    "quote": case["quote"],
                    "source_sha256": "other",
                }
            },
        },
    ]
    result = benchmark_module.location_diagnostics(findings, [case])
    assert result["representative_location"] == [
        {
            "candidate_id": "rejected-location",
            "verdict": "rejected",
            "reported_cwe": "CWE-22",
            "expected_cwes": ["CWE-73"],
        }
    ]
    assert result["root_cause_location"] == [
        {
            "candidate_id": "go-request",
            "verdict": "needs_validation",
            "reported_cwe": "CWE-22",
            "expected_cwes": ["CWE-73"],
        }
    ]
    assert not benchmark_module.root_cause_matches_case(findings[0], case)


def test_attempt_report_includes_failed_validation_cost_and_rejects_tampered_usage(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "manifest.json").write_text(
        json.dumps(
            {"status": "failed", "identity": {"agent": {"provider": "codex"}}, "call_attempts": 2}
        )
    )
    first = run / "calls/s0001.analysis/attempt-0001"
    second = run / "calls/s0002.analysis/attempt-0002"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    for attempt in (first, second):
        (attempt / "prompt.txt").write_text("fixed input")
    usage = {"input_tokens": 10, "cached_input_tokens": 2, "output_tokens": 3}
    (first / "events.jsonl").write_text(json.dumps({"type": "turn.completed", "usage": usage}))
    (first / "raw-response.json").write_text('{"candidates": []}')
    (first.parent / "reply.json").write_text(
        json.dumps(
            {
                "data": {"candidates": []},
                "reply_sha256": digest({"candidates": []}),
                "elapsed_seconds": 2.0,
                "usage": usage,
            }
        )
    )
    (second / "events.jsonl").write_text(json.dumps({"type": "turn.completed", "usage": usage}))
    (second / "failure.json").write_text(
        json.dumps(
            {
                "type": "CitationError",
                "elapsed_seconds": 3.0,
                "citation_code": "triage_column_mismatch",
            }
        )
    )
    report = summarize_attempts(run, tmp_path / "report")
    assert report["call_attempts"] == 2 and report["failed_calls"] == 1
    assert report["citation_failure_counts"] == {"triage_column_mismatch": 1}
    assert report["attempts"][1]["citation_code"] == "triage_column_mismatch"
    assert report["recorded_call_seconds"] == 5.0
    assert report["reported_token_usage"]["input_tokens"] == 20
    assert report["token_coverage"]["input_tokens"] == {
        "reported_attempts": 2,
        "total_attempts": 2,
    }
    assert read(tmp_path / "report/attempts.json") == report
    assert main(["benchmark-attempts", str(run), "--output", str(tmp_path / "via-cli")]) == 0
    assert read(tmp_path / "via-cli/attempts.json")["reported_token_usage"]["input_tokens"] == 20
    (first / "events.jsonl").write_text(json.dumps({"type": "turn.completed", "usage": None}))
    with pytest.raises(ValueError, match="reply differs"):
        summarize_attempts(run, tmp_path / "tampered")
    with pytest.raises(ValueError, match="outside the run"):
        summarize_attempts(run, run / "nested-output")
    (first / "events.jsonl").write_text(json.dumps({"type": "turn.completed", "usage": usage}))
    (second / "failure.json").write_text(
        json.dumps({"type": "CitationError", "elapsed_seconds": 3.0, "citation_code": "unknown"})
    )
    with pytest.raises(ValueError, match="citation code"):
        summarize_attempts(run, tmp_path / "invalid-code")


def test_attempt_report_keeps_missing_usage_unknown(tmp_path):
    run = tmp_path / "run"
    attempt = run / "calls/s0001.analysis/attempt-0001"
    attempt.mkdir(parents=True)
    (run / "manifest.json").write_text(
        json.dumps(
            {"status": "failed", "identity": {"agent": {"provider": "codex"}}, "call_attempts": 1}
        )
    )
    (attempt / "prompt.txt").write_text("fixed input")
    (attempt / "events.jsonl").write_text(json.dumps({"type": "turn.failed"}))
    (attempt / "failure.json").write_text(
        json.dumps({"type": "RuntimeError", "elapsed_seconds": 0.4})
    )
    report = summarize_attempts(run, tmp_path / "report")
    assert report["reported_token_usage"] == {
        "input_tokens": None,
        "cached_input_tokens": None,
        "output_tokens": None,
    }
    assert report["token_coverage"]["input_tokens"]["reported_attempts"] == 0
    (attempt / "failure.json").unlink()
    manifest = read(run / "manifest.json")
    manifest["status"] = "running"
    (run / "manifest.json").write_text(json.dumps(manifest))
    unknown = summarize_attempts(run, tmp_path / "unknown")
    assert unknown["unknown_calls"] == 1
    assert unknown["elapsed_coverage"] == {"recorded_attempts": 0, "total_attempts": 1}
    (attempt / "events.jsonl").write_text("not-json")
    with pytest.raises(ValueError):
        summarize_attempts(run, tmp_path / "invalid")


def test_attempt_report_does_not_assign_later_reply_to_unfinished_attempt(tmp_path):
    run = tmp_path / "run"
    call = run / "calls/s0001.analysis"
    usage = {"input_tokens": 10, "output_tokens": 2}
    for number in (1, 2):
        attempt = call / f"attempt-{number:04d}"
        attempt.mkdir(parents=True)
        (attempt / "prompt.txt").write_text("same call")
        (attempt / "events.jsonl").write_text(
            json.dumps({"type": "turn.completed", "usage": usage})
        )
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "status": "running",
                "identity": {"agent": {"provider": "codex"}},
                "call_attempts": 2,
            }
        )
    )
    (call / "attempt-0002/raw-response.json").write_text('{"candidates": []}')
    (call / "reply.json").write_text(
        json.dumps(
            {
                "attempt": 2,
                "data": {"candidates": []},
                "reply_sha256": digest({"candidates": []}),
                "usage": usage,
                "elapsed_seconds": 0.5,
            }
        )
    )
    report = summarize_attempts(run, tmp_path / "report")
    assert report["completed_calls"] == 1 and report["unknown_calls"] == 1
    assert report["attempts"][0]["elapsed_seconds"] is None
    assert report["reported_token_usage"]["input_tokens"] == 20


def test_call_profile_counts_utf8_bytes_and_rejects_changed_prompt(tmp_path):
    class EmptyReply:
        identity = {"provider": "replay"}

        def call(self, *args):
            return Reply({"candidates": []})

    target, run = tmp_path / "target", tmp_path / "run"
    target.mkdir()
    (target / "entry.py").write_text("# Korean source: 입력\n")
    run_pipeline(target, run, EmptyReply())
    directory = run / "calls/s0001.analysis"
    attempt = directory / "attempt-0001"
    prompt = (directory / "prompt.txt").read_text()
    assert len(prompt.encode()) > len(prompt)
    assert call_profile(run)["analysis"] == {
        "calls": 1,
        "prompt_bytes": len(prompt.encode("utf-8")),
        "recorded_call_seconds": read(directory / "reply.json")["elapsed_seconds"],
    }
    (attempt / "prompt.txt").write_text("different")
    with pytest.raises(ValueError, match="prompt evidence changed"):
        call_profile(run)


def test_repaired_run_comparison_includes_failed_attempt_cost_and_checks_both_prompts(tmp_path):
    class OfflineRepairStub:
        identity = {"provider": "codex", "model": "offline-repair", "cli_version": "fixture"}

        def __init__(self):
            self.recorded = ReplayAgent(REPAIR_REPLAY)

        def call(self, stage, slice_id, prompt, schema, directory):
            data = self.recorded.call(stage, slice_id, prompt, schema, directory).data
            usage = {"input_tokens": 10, "cached_input_tokens": 0, "output_tokens": 5}
            (directory / "events.jsonl").write_text(
                json.dumps({"type": "turn.completed", "usage": usage})
            )
            return Reply(data, usage)

    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    for output in (baseline, candidate):
        run_pipeline(TARGET, output, OfflineRepairStub(), max_slices=1, repair_citations=True)
    report = compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")
    for arm in report["arms"].values():
        assert arm["metrics"]["reported_token_usage"]["input_tokens"] == 20
        assert arm["attempt_reported_token_usage"]["input_tokens"] == 30
        assert arm["failed_call_attempts"] == 1
        assert arm["token_coverage"]["input_tokens"] == {"reported_calls": 3, "total_calls": 3}
    assert report["comparison"]["reported_token_delta"] == {"input_tokens": 0, "output_tokens": 0}
    profile = call_profile(candidate)
    assert profile["analysis"]["calls"] == 2
    assert profile["analysis"]["prompt_bytes"] == sum(
        len(path.read_bytes())
        for path in (candidate / "calls/s0001.analysis").glob("attempt-*/prompt.txt")
    )
    attempts = summarize_attempts(candidate, tmp_path / "attempts")
    assert attempts["call_attempts"] == 3 and attempts["failed_calls"] == 1
    assert attempts["citation_repair_outcomes"] == {"citation_corrected": 1}
    assert report["arms"]["candidate"]["citation_repair_outcomes"] == {"citation_corrected": 1}
    assert attempts["reported_token_usage"]["input_tokens"] == 30
    assert attempts["recorded_call_seconds"] == report["arms"]["candidate"]["recorded_call_seconds"]
    second = tmp_path / "second"
    for arm in ("baseline", "candidate"):
        run_pipeline(TARGET, second / arm, OfflineRepairStub(), max_slices=1, repair_citations=True)
    compare_runs(TARGET, TRUTH, second / "baseline", second / "candidate", second / "comparison")
    summary = summarize_benchmarks(
        TARGET, TRUTH, [tmp_path / "comparison", second / "comparison"], tmp_path / "summary"
    )
    assert summary["repeat_count"] == 2
    assert summary["per_pair_profiles"][0]["candidate"]["analysis"]["calls"] == 2
    assert summary["reported_token_delta"]["input_tokens"]["values"] == [0, 0]
    repaired_prompt = candidate / "calls/s0001.analysis/attempt-0002/prompt.txt"
    original = repaired_prompt.read_bytes()
    repaired_prompt.write_text("altered repair context")
    with pytest.raises(ValueError, match="prompt evidence changed"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "changed-prompt")
    repaired_prompt.write_bytes(original)
    rejected = candidate / "calls/s0001.analysis/attempt-0001/raw-response.json"
    data = read(rejected)
    data["candidates"][0]["reasoning"] = "changed rejected reply"
    rejected.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="repair rejection changed"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "changed-rejection")


@pytest.mark.parametrize("state", ["failed", "pending", "unknown", "withdrawn"])
def test_attempt_report_keeps_repair_failure_pending_unknown_and_withdrawal_separate(
    tmp_path, state
):
    class OfflineRepair:
        identity = {"provider": "codex", "model": "offline"}

        def call(self, stage, slice_id, prompt, schema, directory):
            usage = {"input_tokens": 10, "output_tokens": 2}
            (directory / "events.jsonl").write_text(
                json.dumps({"type": "turn.completed", "usage": usage})
            )
            if state == "withdrawn" and slice_id.endswith(".r0001"):
                return Reply({"candidates": []}, usage)
            return Reply(read(REPAIR_REPLAY / "s0001.analysis.json"), usage)

    run = tmp_path / "run"
    if state == "withdrawn":
        run_pipeline(TARGET, run, OfflineRepair(), max_slices=1, repair_citations=True)
    else:
        with pytest.raises(ValueError):
            run_pipeline(
                TARGET,
                run,
                OfflineRepair(),
                max_slices=1,
                max_calls=1 if state == "pending" else 3,
                repair_citations=True,
            )
    if state == "unknown":
        (run / "calls/s0001.analysis/attempt-0002/failure.json").unlink()
    report = summarize_attempts(run, tmp_path / "report")
    outcome = "candidates_withdrawn" if state == "withdrawn" else state
    assert report["citation_repair_outcomes"] == {outcome: 1}
    assert report["unknown_calls"] == int(state == "unknown")
    assert report["reported_token_usage"]["input_tokens"] == (10 if state == "pending" else 20)


def test_repair_feedback_and_outcome_are_bound_to_original_attempts(tmp_path):
    run_pipeline(
        TARGET, tmp_path / "run", ReplayAgent(REPAIR_REPLAY), max_slices=1, repair_citations=True
    )
    run = tmp_path / "run"
    call = run / "calls/s0001.analysis"
    reply_path = call / "reply.json"
    reply = read(reply_path)
    reply_path.write_text(json.dumps({**reply, "citation_repair_outcome": "candidates_withdrawn"}))
    with pytest.raises(ValueError, match="outcome"):
        benchmark_module.attempt_report(run, require_codex=False)
    reply_path.write_text(json.dumps(reply))
    repair_path = call / "citation-repair.json"
    repair = read(repair_path)
    repair["citation_details"]["source_context"]["text"] = "invented source"
    repair_path.write_text(json.dumps(repair))
    with pytest.raises(ValueError, match="rejection changed"):
        benchmark_module.attempt_report(run, require_codex=False)


def test_benchmark_replay_records_same_snapshot_budget_labels_and_unknown_tokens(tmp_path):
    output = tmp_path / "comparison"
    assert (
        main(
            [
                "benchmark-replay",
                str(TARGET),
                "--truth",
                str(TRUTH),
                "--baseline-replay",
                str(REPLAY),
                "--candidate-replay",
                str(REPLAY),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    report = read(output / "benchmark.json")
    state = read(output / "benchmark-state.json")
    assert state["status"] == "complete"
    assert report["measurement_kind"] == "offline_replay_orchestration"
    assert report["arms"]["baseline"]["source_index"] == report["arms"]["candidate"]["source_index"]
    assert (
        report["arms"]["baseline"]["label_counts"]
        == report["arms"]["candidate"]["label_counts"]
        == {
            "positive_retained": 1,
            "positive_missed": 0,
            "negative_flagged": 0,
            "negative_clear": 1,
            "uncovered_labels": 0,
        }
    )
    for arm in report["arms"].values():
        assert arm["metrics"]["call_attempts"] == 4
        assert arm["metrics"]["reported_token_usage"] is None
        assert arm["elapsed_seconds"] >= 0
        assert len(arm["artifact_sha256"]) == 4
    assert set(report["comparison"]["label_count_delta"].values()) == {0}
    assert report["comparison"]["reported_token_delta"] is None


def test_benchmark_counts_false_alarm_and_missed_positive_without_claiming_model_accuracy(tmp_path):
    alternate = tmp_path / "alternate-replay"
    alternate.mkdir()
    for file in REPLAY.glob("*.json"):
        (alternate / file.name).write_bytes(file.read_bytes())
    noisy = read(alternate / "s0001.triage.json")
    noisy["groups"][0]["decisions"][0]["verdict"] = "needs_validation"
    (alternate / "s0001.triage.json").write_text(json.dumps(noisy))
    (alternate / "s0002.analysis.json").write_text('{"candidates": []}')
    (alternate / "s0002.triage.json").write_text('{"groups": []}')
    report = benchmark_replay(TARGET, TRUTH, REPLAY, alternate, tmp_path / "comparison")
    assert report["arms"]["baseline"]["label_counts"]["positive_retained"] == 1
    assert report["arms"]["candidate"]["label_counts"]["positive_missed"] == 1
    assert report["arms"]["candidate"]["label_counts"]["negative_flagged"] == 1
    assert report["arms"]["candidate"]["metrics"]["reported_token_usage"] is None
    assert report["comparison"]["label_count_delta"]["positive_missed"] == 1
    assert report["comparison"]["label_count_delta"]["negative_flagged"] == 1


def test_false_truth_quote_fails_before_any_run(tmp_path):
    false_truth = tmp_path / "truth.json"
    truth = read(TRUTH)
    truth["cases"][0]["quote"] = "a fabricated guard"
    false_truth.write_text(json.dumps(truth))
    output = tmp_path / "comparison"
    with pytest.raises(ValueError, match="source-backed anchors"):
        benchmark_replay(TARGET, false_truth, REPLAY, REPLAY, output)
    assert not output.exists()


def test_predeclared_alternate_location_matches_same_source_backed_case(tmp_path):
    report = benchmark_replay(TARGET, ALTERNATE_TRUTH, REPLAY, REPLAY, tmp_path / "comparison")
    for arm in report["arms"].values():
        assert arm["label_counts"]["positive_retained"] == 1
        assert arm["label_counts"]["positive_missed"] == 0
        assert arm["labeled_cases"][1]["retained_candidate_ids"]
    assert report["truth_sha256"] != benchmark_module.checked_truth(TARGET, TRUTH)[3]


def test_predeclared_negative_alternate_counts_a_false_alarm(tmp_path):
    replay = tmp_path / "replay"
    replay.mkdir()
    for source in REPLAY.glob("*.json"):
        (replay / source.name).write_bytes(source.read_bytes())
    analysis = read(replay / "s0001.analysis.json")
    analysis["candidates"][0].update(line=5, quote="char buf[16];")
    (replay / "s0001.analysis.json").write_text(json.dumps(analysis))
    triage = read(replay / "s0001.triage.json")
    triage["groups"][0]["decisions"][0]["candidate_id"] = (
        "f-" + digest(["bounded.c", 5, "CWE-787"])[:16]
    )
    triage["groups"][0]["decisions"][0]["verdict"] = "needs_validation"
    (replay / "s0001.triage.json").write_text(json.dumps(triage))
    report = benchmark_replay(TARGET, ALTERNATE_TRUTH, REPLAY, replay, tmp_path / "comparison")
    assert report["arms"]["candidate"]["label_counts"]["negative_flagged"] == 1
    assert report["arms"]["candidate"]["unlabeled_candidate_count"] == 0


@pytest.mark.parametrize("change", ["fabricated_quote", "duplicate_location"])
def test_alternate_location_requires_original_source_and_unique_anchor(tmp_path, change):
    truth = read(ALTERNATE_TRUTH)
    alternate = truth["cases"][1]["accepted_locations"][0]
    if change == "fabricated_quote":
        alternate["quote"] = "a guard that does not exist"
    else:
        alternate.update(path="parser.c", line=5, quote="char buf[16];")
    path = tmp_path / "truth.json"
    path.write_text(json.dumps(truth))
    output = tmp_path / "comparison"
    with pytest.raises(ValueError, match="source-backed anchors"):
        benchmark_replay(TARGET, path, REPLAY, REPLAY, output)
    assert not output.exists()


def test_truth_inside_target_is_not_a_researcher_label_artifact(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    for source in TARGET.iterdir():
        (target / source.name).write_bytes(source.read_bytes())
    internal = target / "truth.json"
    internal.write_bytes(TRUTH.read_bytes())
    with pytest.raises(ValueError, match="boundary"):
        benchmark_replay(target, internal, REPLAY, REPLAY, tmp_path / "comparison")


def test_failure_preserves_first_run_and_records_incomplete_comparison(tmp_path):
    incomplete = tmp_path / "incomplete-replay"
    incomplete.mkdir()
    (incomplete / "s0001.analysis.json").write_bytes((REPLAY / "s0001.analysis.json").read_bytes())
    output = tmp_path / "comparison"
    with pytest.raises(ValueError, match="missing replay response"):
        benchmark_replay(TARGET, TRUTH, REPLAY, incomplete, output)
    assert read(output / "benchmark-state.json")["status"] == "failed"
    assert read(output / "baseline/manifest.json")["status"] == "complete"
    assert read(output / "candidate/manifest.json")["status"] == "failed"
    assert not (output / "benchmark.json").exists()


def test_source_drift_between_arms_rejects_comparison(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    for source in TARGET.iterdir():
        (target / source.name).write_bytes(source.read_bytes())
    run = benchmark_module.run_pipeline
    calls = 0

    def drift_after_baseline(*args, **kwargs):
        nonlocal calls
        result = run(*args, **kwargs)
        calls += 1
        if calls == 1:
            with (target / "parser.c").open("a") as stream:
                stream.write("/* changed between arms */\n")
        return result

    monkeypatch.setattr(benchmark_module, "run_pipeline", drift_after_baseline)
    output = tmp_path / "comparison"
    with pytest.raises(ValueError, match="source snapshot changed"):
        benchmark_replay(target, TRUTH, REPLAY, REPLAY, output)
    assert read(output / "benchmark-state.json")["status"] == "failed"
    assert not (output / "benchmark.json").exists()


@pytest.mark.skipif(shutil.which("go") is None, reason="Go not installed")
def test_go_graph_candidate_and_lexical_baseline_share_source_and_budget(tmp_path):
    target = ROOT / "examples/go-review-target"
    graph_dir, recon_dir = tmp_path / "graph", tmp_path / "recon"
    build_graph(target, graph_dir, language="go")
    build_recon(target, graph_dir / "graph.json", ROOT / "examples/go-review-plan.json", recon_dir)
    baseline = tmp_path / "empty-lexical-replay"
    baseline.mkdir()
    slices, _ = make_slices(index_target(target)[0], 16_000)
    for source_slice in slices:
        (baseline / f"{source_slice['id']}.analysis.json").write_text('{"candidates": []}')
    report = benchmark_replay(
        target,
        ROOT / "examples/go-review-benchmark-truth.json",
        baseline,
        ROOT / "examples/go-review-replay",
        tmp_path / "comparison",
        candidate_graph=graph_dir / "graph.json",
        candidate_recon=recon_dir / "recon.json",
    )
    assert report["arms"]["baseline"]["label_counts"]["positive_missed"] == 1
    assert report["arms"]["candidate"]["label_counts"]["positive_retained"] == 1
    assert report["arms"]["candidate"]["label_counts"]["negative_clear"] == 1
    assert report["arms"]["baseline"]["source_index"] == report["arms"]["candidate"]["source_index"]
    assert report["arms"]["candidate"]["coverage"]["input_mode"] == "graph_hypotheses"
    prompt = (tmp_path / "comparison/candidate/calls/s0001.analysis/prompt.txt").read_text()
    packet = json.loads(prompt.split("UNTRUSTED_INPUT_JSON:\n", 1)[1])
    fragments = packet["source_slice"]["fragments"]
    source_index = report["arms"]["candidate"]["source_index"]
    line_counts = {item["path"]: item["lines"] for item in source_index}
    assert packet["source_line_counts"] == {
        path: line_counts[path] for path in {part["path"] for part in fragments}
    }
    lexical = call_profile(tmp_path / "comparison/baseline")
    graph = call_profile(tmp_path / "comparison/candidate")
    assert sum(item["prompt_bytes"] for item in lexical.values()) != sum(
        item["prompt_bytes"] for item in graph.values()
    )


def test_python_graph_benchmark_covers_source_and_constant_control(tmp_path):
    target = ROOT / "examples/static-target"
    graph_dir, recon_dir = tmp_path / "graph", tmp_path / "recon"
    build_graph(target, graph_dir, language="python")
    build_recon(
        target,
        graph_dir / "graph.json",
        ROOT / "examples/python-benchmark-plan.json",
        recon_dir,
    )
    baseline = tmp_path / "empty-lexical-replay"
    baseline.mkdir()
    slices, _ = make_slices(index_target(target)[0], 16_000)
    for source_slice in slices:
        (baseline / f"{source_slice['id']}.analysis.json").write_text('{"candidates": []}')
    report = benchmark_replay(
        target,
        ROOT / "examples/python-benchmark-truth.json",
        baseline,
        ROOT / "examples/python-benchmark-replay",
        tmp_path / "comparison",
        candidate_graph=graph_dir / "graph.json",
        candidate_recon=recon_dir / "recon.json",
    )
    assert report["measurement_kind"] == "offline_replay_orchestration"
    assert report["arms"]["baseline"]["label_counts"]["positive_missed"] == 1
    assert report["arms"]["candidate"]["label_counts"] == {
        "positive_retained": 1,
        "positive_missed": 0,
        "negative_flagged": 0,
        "negative_clear": 1,
        "uncovered_labels": 0,
    }
    assert report["arms"]["baseline"]["source_index"] == report["arms"]["candidate"]["source_index"]


@pytest.mark.skipif(
    shutil.which("node") is None
    or not (ROOT / ".cache/solidity-extractor/node_modules/solc/soljson.js").is_file(),
    reason="Node/pinned solc unavailable; run make setup-solidity",
)
def test_solidity_benchmark_distinguishes_cross_file_guard_from_public_release(tmp_path):
    target = ROOT / "examples/solidity-benchmark-target"
    graph_dir, recon_dir = tmp_path / "graph", tmp_path / "recon"
    graph = build_graph(target, graph_dir, language="solidity")
    functions = {item["qualified_name"]: item for item in graph["functions"]}
    release_a = functions["Vault.sol:Vault.releaseA"]
    release_b = functions["Vault.sol:Vault.releaseB"]
    guard = functions["Authority.sol:Authority.ownerOnly"]
    modifier_calls = [call for call in graph["calls"] if call["dispatch"] == "modifier"]
    assert not any(call["caller"] == release_a["id"] for call in modifier_calls)
    assert any(
        call["caller"] == release_b["id"] and call["callee"] == guard["id"]
        for call in modifier_calls
    )
    flow = release_b["metadata"]["modifier_flow"]
    assert flow["body_execution"]["min"] == 1
    branch = next(
        node
        for node in flow["nodes"]
        if node["kind"] == "branch" and node.get("guard") == "require"
    )
    targets = {node["id"]: node["kind"] for node in flow["nodes"]}
    assert {
        (edge["kind"], targets[edge["to"]])
        for edge in flow["edges"]
        if edge["from"] == branch["id"]
    } == {
        ("true", "placeholder"),
        ("false", "revert"),
    }
    build_recon(
        target,
        graph_dir / "graph.json",
        ROOT / "examples/solidity-benchmark-plan.json",
        recon_dir,
    )
    baseline = tmp_path / "empty-lexical-replay"
    baseline.mkdir()
    slices, _ = make_slices(index_target(target)[0], 16_000)
    for source_slice in slices:
        (baseline / f"{source_slice['id']}.analysis.json").write_text('{"candidates": []}')
    report = benchmark_replay(
        target,
        ROOT / "examples/solidity-benchmark-truth.json",
        baseline,
        ROOT / "examples/solidity-benchmark-replay",
        tmp_path / "comparison",
        candidate_graph=graph_dir / "graph.json",
        candidate_recon=recon_dir / "recon.json",
    )
    assert report["measurement_kind"] == "offline_replay_orchestration"
    assert report["arms"]["candidate"]["label_counts"] == {
        "positive_retained": 1,
        "positive_missed": 0,
        "negative_flagged": 0,
        "negative_clear": 1,
        "uncovered_labels": 0,
    }
    assert report["arms"]["baseline"]["label_counts"]["positive_missed"] == 1
    prompt = (tmp_path / "comparison/candidate/calls/s0002.analysis/prompt.txt").read_text()
    packet = json.loads(prompt.split("UNTRUSTED_INPUT_JSON:\n", 1)[1])
    assert packet["source_slice"]["modifier_flows"][0]["flow"] == flow


def test_completed_replay_runs_compare_without_another_call(tmp_path):
    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, ReplayAgent(REPLAY))
    run_pipeline(TARGET, candidate, ReplayAgent(REPLAY))
    assert (
        main(
            [
                "benchmark-runs",
                str(TARGET),
                "--truth",
                str(TRUTH),
                "--baseline",
                str(baseline),
                "--candidate",
                str(candidate),
                "--output",
                str(tmp_path / "comparison"),
            ]
        )
        == 0
    )
    report = read(tmp_path / "comparison/benchmark.json")
    assert report["measurement_kind"] == "offline_replay_artifacts"
    assert "root_cause_candidate_ids" in report["arms"]["baseline"]["labeled_cases"][0]
    assert report["arms"]["baseline"]["elapsed_seconds"] is None
    assert report["arms"]["baseline"]["recorded_call_seconds"] >= 0
    assert report["arms"]["baseline"]["token_coverage"]["input_tokens"] == {
        "reported_calls": 0,
        "total_calls": 4,
    }
    assert not report["arms"]["baseline"]["complete_input_output_tokens"]


def test_declared_model_artifacts_preserve_partial_token_coverage(tmp_path):
    class OfflineModelStub:
        identity = {"provider": "codex", "model": "offline-stub", "cli_version": "fixture"}

        def __init__(self):
            self.recorded = ReplayAgent(REPLAY)

        def call(self, stage, slice_id, prompt, schema, directory):
            reply = self.recorded.call(stage, slice_id, prompt, schema, directory)
            usage = (
                None
                if slice_id == "s0002" and stage == "triage"
                else {"input_tokens": 10, "cached_input_tokens": 0, "output_tokens": 5}
            )
            return Reply(reply.data, usage)

    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, OfflineModelStub())
    run_pipeline(TARGET, candidate, OfflineModelStub())
    report = compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")
    assert report["measurement_kind"] == "declared_codex_artifacts"
    for arm in report["arms"].values():
        assert arm["metrics"]["reported_token_usage"] == {
            "input_tokens": 30,
            "cached_input_tokens": 0,
            "output_tokens": 15,
        }
        assert arm["token_coverage"]["input_tokens"] == {
            "reported_calls": 3,
            "total_calls": 4,
        }
        assert not arm["complete_input_output_tokens"]
    raw_path = candidate / "calls/s0001.analysis/attempt-0001/raw-response.json"
    raw = read(raw_path)
    raw["requests"] = None
    raw["model_proposals"] = None
    raw_path.write_text(json.dumps(raw))
    compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "nullable-response")
    raw["requests"] = [{"operation": "resolve", "selector": "fake", "reason": "fake"}]
    raw_path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="original agent response"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "altered-response")
    raw["requests"] = None
    raw_path.write_text(json.dumps(raw))
    manifest_path = candidate / "manifest.json"
    manifest = read(manifest_path)
    manifest["identity"]["agent"]["model"] = "another-model"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="model or budget"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "different-model")


def test_completed_report_calculates_token_delta_only_for_complete_usage(tmp_path):
    class OfflineUsageStub:
        identity = {"provider": "codex", "model": "offline-stub", "cli_version": "fixture"}

        def __init__(self, input_tokens, output_tokens):
            self.recorded = ReplayAgent(REPLAY)
            self.input_tokens = input_tokens
            self.output_tokens = output_tokens

        def call(self, stage, slice_id, prompt, schema, directory):
            data = self.recorded.call(stage, slice_id, prompt, schema, directory).data
            return Reply(
                data,
                {
                    "input_tokens": self.input_tokens,
                    "cached_input_tokens": 0,
                    "output_tokens": self.output_tokens,
                },
            )

    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, OfflineUsageStub(10, 5))
    run_pipeline(TARGET, candidate, OfflineUsageStub(12, 6))
    report = compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")
    assert report["comparison"]["reported_token_delta"] == {
        "input_tokens": 8,
        "output_tokens": 4,
    }
    assert report["comparison"]["duration_basis"] == "recorded_call_seconds"


def test_completed_run_comparison_rejects_budget_or_model_mismatch(tmp_path):
    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, ReplayAgent(REPLAY), max_calls=4)
    run_pipeline(TARGET, candidate, ReplayAgent(REPLAY), max_calls=5)
    with pytest.raises(ValueError, match="target, source, provider, model or budget"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")
    assert not (tmp_path / "comparison").exists()
    manifest = read(candidate / "manifest.json")
    manifest["max_calls"] = 4
    manifest["identity"]["query_tool_sha256"] = "different-renderer"
    (candidate / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="target, source, provider, model or budget"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")
    manifest["identity"]["query_tool_sha256"] = read(baseline / "manifest.json")["identity"][
        "query_tool_sha256"
    ]
    manifest["identity"]["agent"] = {"provider": "codex", "model": "different"}
    (candidate / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="target, source, provider, model or budget"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")


def test_completed_run_comparison_rejects_changed_current_source(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    for source in TARGET.iterdir():
        (target / source.name).write_bytes(source.read_bytes())
    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(target, baseline, ReplayAgent(REPLAY))
    run_pipeline(target, candidate, ReplayAgent(REPLAY))
    with (target / "parser.c").open("a") as stream:
        stream.write("/* changed after both reviews */\n")
    with pytest.raises(ValueError, match="source, provider, model or budget"):
        compare_runs(target, TRUTH, baseline, candidate, tmp_path / "comparison")
    assert not (tmp_path / "comparison").exists()


def test_completed_run_cannot_supply_its_own_truth_labels(tmp_path):
    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, ReplayAgent(REPLAY))
    run_pipeline(TARGET, candidate, ReplayAgent(REPLAY))
    internal_truth = baseline / "truth.json"
    internal_truth.write_bytes(TRUTH.read_bytes())
    with pytest.raises(ValueError, match="boundary"):
        compare_runs(TARGET, internal_truth, baseline, candidate, tmp_path / "comparison")


def test_completed_run_comparison_rejects_tampered_call_and_partial_resume(tmp_path):
    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, ReplayAgent(REPLAY))
    run_pipeline(TARGET, candidate, ReplayAgent(REPLAY))
    reply_path = candidate / "calls/s0001.analysis/reply.json"
    reply = read(reply_path)
    reply["data"]["candidates"] = []
    reply_path.write_text(json.dumps(reply))
    with pytest.raises(ValueError, match="call record is invalid"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")
    reply_path.write_text(json.dumps(read(baseline / "calls/s0001.analysis/reply.json")))
    metrics_path = candidate / "metrics.json"
    metrics = read(metrics_path)
    metrics["cache_hits"] = 1
    metrics_path.write_text(json.dumps(metrics))
    with pytest.raises(ValueError, match="fresh complete call records"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")


def test_completed_run_comparison_binds_reply_and_prompt_to_original_attempt(tmp_path):
    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, ReplayAgent(REPLAY))
    run_pipeline(TARGET, candidate, ReplayAgent(REPLAY))
    reply_path = candidate / "calls/s0001.analysis/reply.json"
    original = reply_path.read_bytes()
    reply = read(reply_path)
    reply["data"]["candidates"] = []
    reply["reply_sha256"] = digest(reply["data"])
    reply_path.write_text(json.dumps(reply))
    with pytest.raises(ValueError, match="original agent response"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "changed-reply")
    reply_path.write_bytes(original)
    prompt = candidate / "calls/s0001.analysis/prompt.txt"
    with prompt.open("a") as stream:
        stream.write("changed after the call\n")
    with pytest.raises(ValueError, match="original agent prompt"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "changed-prompt")


def test_completed_run_comparison_rejects_changed_findings_or_malformed_metrics(tmp_path):
    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, ReplayAgent(REPLAY))
    run_pipeline(TARGET, candidate, ReplayAgent(REPLAY))
    findings_path = candidate / "findings.json"
    findings = read(findings_path)
    findings[0]["source_sha256"] = "0" * 64
    findings_path.write_text(json.dumps(findings))
    with pytest.raises(ValueError, match="findings differ"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")
    findings_path.write_text((baseline / "findings.json").read_text())
    metrics_path = candidate / "metrics.json"
    metrics = read(metrics_path)
    del metrics["unique_candidates"]
    metrics_path.write_text(json.dumps(metrics))
    with pytest.raises(ValueError, match="artifact is malformed"):
        compare_runs(TARGET, TRUTH, baseline, candidate, tmp_path / "comparison")


def test_repeated_pair_summary_rechecks_runs_and_preserves_unknown_tokens(tmp_path, monkeypatch):
    reports = []
    for number in range(2):
        directory = tmp_path / f"pair-{number}"
        baseline, candidate = directory / "baseline", directory / "candidate"
        run_pipeline(TARGET, baseline, ReplayAgent(REPLAY))
        run_pipeline(TARGET, candidate, ReplayAgent(REPLAY))
        report_dir = directory / "comparison"
        compare_runs(TARGET, TRUTH, baseline, candidate, report_dir)
        reports.append(report_dir)

    def no_model_or_replay_call(*args, **kwargs):
        pytest.fail("benchmark summary must only read existing artifacts")

    monkeypatch.setattr(benchmark_module, "run_pipeline", no_model_or_replay_call)
    output = tmp_path / "summary"
    with pytest.raises(ValueError, match="2..16"):
        summarize_benchmarks(TARGET, TRUTH, reports[:1], output)
    assert (
        main(
            [
                "benchmark-summary",
                str(TARGET),
                "--truth",
                str(TRUTH),
                "--report",
                str(reports[0]),
                "--report",
                str(reports[1]),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    summary = read(output / "benchmark-summary.json")
    assert summary["repeat_count"] == 2
    assert summary["measurement_kind"] == "repeated_offline_replay_artifacts"
    assert summary["complete_token_pairs"] == 0
    assert summary["reported_token_delta"] is None
    assert summary["label_count_delta"]["positive_retained"]["values"] == [0, 0]
    assert summary["call_attempt_delta"]["median"] == 0
    assert summary["review_queue_size"]["baseline"]["values"] == [1, 1]
    assert summary["review_queue_delta"]["values"] == [0, 0]
    assert summary["prompt_byte_delta"]["values"] == [0, 0]
    assert summary["per_pair_profiles"][0]["baseline"]["analysis"]["calls"] == 2
    assert summary["per_pair_profiles"][0]["baseline"]["analysis"]["prompt_bytes"] > 0
    assert summary["stage_delta"]["triage"]["prompt_bytes"]["values"] == [0, 0]
    assert summary["case_variation"][0]["status_counts"]["candidate"] == {"negative_clear": 2}
    assert summary["case_variation"][0]["root_cause_evidence_counts"]["candidate"] == {"absent": 2}
    assert summary["case_variation"][1]["root_cause_evidence_counts"]["candidate"] == {"cited": 2}
    legacy_path = reports[0] / "benchmark.json"
    legacy = read(legacy_path)
    del legacy["comparison"]
    for arm in legacy["arms"].values():
        for label in arm["labeled_cases"]:
            del label["diagnostics"]
    legacy["identity_sha256"] = digest(
        {key: value for key, value in legacy.items() if key != "identity_sha256"}
    )
    legacy_path.write_text(json.dumps(legacy))
    restored = summarize_benchmarks(TARGET, TRUTH, reports, tmp_path / "legacy-summary")
    assert restored["repeat_count"] == 2
    assert restored["pairs"][0]["identity_sha256"] == legacy["identity_sha256"]


def test_repeated_summary_rejects_reused_runs_and_changed_report(tmp_path):
    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    run_pipeline(TARGET, baseline, ReplayAgent(REPLAY))
    run_pipeline(TARGET, candidate, ReplayAgent(REPLAY))
    first, copied = tmp_path / "first", tmp_path / "copied"
    compare_runs(TARGET, TRUTH, baseline, candidate, first)
    copied.mkdir()
    (copied / "benchmark.json").write_bytes((first / "benchmark.json").read_bytes())
    with pytest.raises(ValueError, match="reuses a run"):
        summarize_benchmarks(TARGET, TRUTH, [first, copied], tmp_path / "summary")
    altered = read(copied / "benchmark.json")
    altered["comparison"]["label_count_delta"]["positive_retained"] = 1
    (copied / "benchmark.json").write_text(json.dumps(altered))
    with pytest.raises(ValueError, match="evidence changed"):
        summarize_benchmarks(TARGET, TRUTH, [copied, first], tmp_path / "summary")
    reply_path = baseline / "calls/s0001.analysis/reply.json"
    reply = read(reply_path)
    reply["data"]["candidates"] = []
    reply_path.write_text(json.dumps(reply))
    with pytest.raises(ValueError, match="call record is invalid"):
        summarize_benchmarks(TARGET, TRUTH, [first, copied], tmp_path / "summary")
    assert not (tmp_path / "summary").exists()


def test_repeated_summary_rejects_changed_prompt_after_pair_review(tmp_path):
    reports = []
    for number in range(2):
        directory = tmp_path / f"pair-{number}"
        baseline, candidate = directory / "baseline", directory / "candidate"
        run_pipeline(TARGET, baseline, ReplayAgent(REPLAY))
        run_pipeline(TARGET, candidate, ReplayAgent(REPLAY))
        report_dir = directory / "comparison"
        compare_runs(TARGET, TRUTH, baseline, candidate, report_dir)
        reports.append(report_dir)
    prompt = tmp_path / "pair-1/candidate/calls/s0001.analysis/prompt.txt"
    with prompt.open("a") as stream:
        stream.write("changed after pair review\n")
    with pytest.raises(ValueError, match="prompt evidence changed"):
        summarize_benchmarks(TARGET, TRUTH, reports, tmp_path / "summary")
    assert not (tmp_path / "summary").exists()


def test_repeated_summary_rejects_different_budget_across_pairs(tmp_path):
    reports = []
    for number, limit in enumerate((4, 5)):
        directory = tmp_path / f"pair-{number}"
        baseline, candidate = directory / "baseline", directory / "candidate"
        run_pipeline(TARGET, baseline, ReplayAgent(REPLAY), max_calls=limit)
        run_pipeline(TARGET, candidate, ReplayAgent(REPLAY), max_calls=limit)
        report_dir = directory / "comparison"
        compare_runs(TARGET, TRUTH, baseline, candidate, report_dir)
        reports.append(report_dir)
    with pytest.raises(ValueError, match="repeats differ"):
        summarize_benchmarks(TARGET, TRUTH, reports, tmp_path / "summary")


def test_repeated_summary_reports_token_distribution_only_when_all_pairs_complete(tmp_path):
    class OfflineUsageStub:
        identity = {"provider": "codex", "model": "offline-stub", "cli_version": "fixture"}

        def __init__(self, input_tokens, missing=False):
            self.recorded = ReplayAgent(REPLAY)
            self.input_tokens = input_tokens
            self.missing = missing

        def call(self, stage, slice_id, prompt, schema, directory):
            data = self.recorded.call(stage, slice_id, prompt, schema, directory).data
            usage = (
                None
                if self.missing and slice_id == "s0002" and stage == "triage"
                else {"input_tokens": self.input_tokens, "output_tokens": 5}
            )
            return Reply(data, usage)

    reports = []
    for number, candidate_tokens in enumerate((12, 14)):
        directory = tmp_path / f"pair-{number}"
        baseline, candidate = directory / "baseline", directory / "candidate"
        run_pipeline(TARGET, baseline, OfflineUsageStub(10))
        run_pipeline(TARGET, candidate, OfflineUsageStub(candidate_tokens))
        report_dir = directory / "comparison"
        compare_runs(TARGET, TRUTH, baseline, candidate, report_dir)
        reports.append(report_dir)
    summary = summarize_benchmarks(TARGET, TRUTH, reports, tmp_path / "summary")
    assert summary["measurement_kind"] == "repeated_declared_codex_artifacts"
    assert summary["complete_token_pairs"] == 2
    assert summary["reported_token_delta"]["input_tokens"]["values"] == [8, 16]
    assert summary["reported_token_delta"]["input_tokens"]["median"] == 12
    third = tmp_path / "pair-2"
    run_pipeline(TARGET, third / "baseline", OfflineUsageStub(10))
    run_pipeline(TARGET, third / "candidate", OfflineUsageStub(16, missing=True))
    compare_runs(TARGET, TRUTH, third / "baseline", third / "candidate", third / "comparison")
    mixed = summarize_benchmarks(
        TARGET, TRUTH, [*reports, third / "comparison"], tmp_path / "mixed-summary"
    )
    assert mixed["complete_token_pairs"] == 2
    assert mixed["reported_token_delta"] is None
