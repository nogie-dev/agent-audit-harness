import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent, Reply
from agent_audit_harness.graph import build_graph
from agent_audit_harness.investigation import answer_requests
from agent_audit_harness.judgment import candidate_issues
from agent_audit_harness.pipeline import encode, index_target, run_pipeline, validate_evidence
from agent_audit_harness.recon import build_recon

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples/demo-target"


def read(path):
    return json.loads(path.read_text())


def source_request(path="parser.c", first=1, last=8):
    return {
        "operation": "source",
        "path": path,
        "first_line": first,
        "last_line": last,
        "reason": "Read the missing function before making a hypothesis.",
    }


def history(queries=4, byte_limit=16000):
    return {
        "responses": [],
        "budget": {"remaining_queries": queries, "remaining_bytes": byte_limit},
    }


class RecordedInvestigation:
    identity = {"provider": "replay", "case": "source-query"}

    def __init__(self, requests=None, final=None):
        self.requests = requests if requests is not None else [source_request()]
        self.final = (
            final if final is not None else read(ROOT / "examples/replay/s0002.analysis.json")
        )
        self.calls = []

    def call(self, stage, call_id, prompt, schema, directory):
        self.calls.append((stage, call_id, json.loads(prompt.split("UNTRUSTED_INPUT_JSON:\n")[1])))
        if stage == "triage":
            return Reply(read(ROOT / "examples/replay/s0002.triage.json"))
        if call_id == "s0001":
            return Reply({"candidates": [], "requests": self.requests})
        return Reply(self.final)


def test_additional_file_source_reaches_analysis_and_triage_without_target_execution(tmp_path):
    agent = RecordedInvestigation()
    output = tmp_path / "review"
    result = run_pipeline(DEMO, output, agent, max_slices=1)
    assert result["call_attempts"] == 3 and result["investigation_queries"] == 1
    assert [call[:2] for call in agent.calls] == [
        ("analysis", "s0001"),
        ("analysis", "s0001.q0001"),
        ("triage", "s0001"),
    ]
    assert agent.calls[0][2]["source_slice"]["path"] == "bounded.c"
    for _, _, payload in agent.calls[1:]:
        fragments = payload["investigation"]["responses"][0]["data"]["fragments"]
        assert fragments[0]["path"] == "parser.c"
        assert fragments[0]["text"] == (DEMO / "parser.c").read_text()
    candidate = read(output / "findings.json")[0]
    assert candidate["path"] == "parser.c" and candidate["verdict"] == "needs_validation"
    assert (
        candidate["source_sha256"]
        == agent.calls[-1][2]["investigation"]["responses"][0]["data"]["fragments"][0][
            "source_sha256"
        ]
    )
    assert result["confirmed_findings"] == 0 and result["validation_executions"] == 0
    assert read(output / "coverage.json")["reviewed_lines"] == 18


def test_call_budget_resume_reuses_queries_and_all_completed_replies(tmp_path, monkeypatch):
    output = tmp_path / "review"
    agent = RecordedInvestigation()
    with pytest.raises(ValueError, match="agent call budget"):
        run_pipeline(DEMO, output, agent, max_slices=1, max_calls=1)
    assert (output / "queries/s0001.q0001.json").exists()
    assert read(output / "investigations/s0001.json")["responses"][0]["status"] == "provided"
    resumed = run_pipeline(DEMO, output, agent, max_slices=1, max_calls=3, resume=True)
    assert resumed["cache_hits"] == resumed["query_cache_hits"] == 1

    def forbidden(*args, **kwargs):
        pytest.fail("resume repeated a model call or an evidence query")

    agent.call = forbidden
    monkeypatch.setattr("agent_audit_harness.investigation.answer_requests", forbidden)
    again = run_pipeline(DEMO, output, agent, max_slices=1, max_calls=3, resume=True)
    assert again["cache_hits"] == 3 and again["query_cache_hits"] == 1


def test_query_cache_tampering_and_changed_limits_are_rejected(tmp_path):
    output = tmp_path / "review"
    agent = RecordedInvestigation()
    run_pipeline(DEMO, output, agent, max_slices=1)
    with pytest.raises(ValueError, match="inputs changed"):
        run_pipeline(DEMO, output, agent, max_slices=1, query_bytes=20000, resume=True)
    path = output / "queries/s0001.q0001.json"
    record = read(path)
    record["data"]["responses"][0]["data"]["fragments"][0]["text"] = "invented source"
    path.write_text(encode(record))
    with pytest.raises(ValueError, match="cached query checksum"):
        run_pipeline(DEMO, output, agent, max_slices=1, resume=True)
    assert read(output / "manifest.json")["status"] == "failed"
    assert not (output / "findings.json").exists()


def test_query_failure_gaps_survive_triage_and_become_promotion_issues(tmp_path):
    requests = [source_request(), source_request("../outside.c")]
    output = tmp_path / "review"
    result = run_pipeline(DEMO, output, RecordedInvestigation(requests), max_slices=1)
    assert result["investigation_gap_count"] == 1
    failed = read(output / "investigations/s0001.json")["responses"][1]
    assert failed["status"] == "unavailable" and failed["reason"] == "source_not_indexed"
    candidate = read(output / "findings.json")[0]
    assert candidate["input_gaps"]["investigation_gap_ids"] == [failed["id"]]
    issue = next(i for i in candidate_issues(candidate) if i["kind"] == "investigation_gap_ids")
    assert issue["detail"] == failed["id"]
    assert read(output / "coverage.json")["investigations"][0]["gap_ids"] == [failed["id"]]


def test_query_count_and_byte_omissions_are_explicit(tmp_path):
    requests = [source_request(), source_request("bounded.c", 1, 10)]
    output = tmp_path / "count"
    result = run_pipeline(
        DEMO, output, RecordedInvestigation(requests), max_slices=1, max_queries=1
    )
    assert result["investigation_queries"] == 1 and result["investigation_gap_count"] == 1
    assert (
        read(output / "investigations/s0001.json")["responses"][1]["reason"]
        == "query_count_budget_exhausted"
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "large.py").write_text("# 한글 " + "x" * 2000 + "\n")
    output = tmp_path / "bytes"
    agent = RecordedInvestigation([source_request("large.py", 1, 1)], {"candidates": []})
    result = run_pipeline(target, output, agent, query_bytes=1024)
    omitted = read(output / "investigations/s0001.json")["responses"][0]
    assert omitted["reason"] == "query_byte_budget_exhausted" and omitted["data"] is None
    assert omitted["required_bytes"] > 1024 and result["investigation_payload_bytes"] == 0
    assert result["investigation_gap_count"] == 1


def test_unavailable_evidence_cannot_support_a_candidate(tmp_path):
    agent = RecordedInvestigation([source_request(last=999)])
    output = tmp_path / "review"
    with pytest.raises(ValueError, match="outside its source slice"):
        run_pipeline(DEMO, output, agent, max_slices=1)
    assert (
        read(output / "investigations/s0001.json")["responses"][0]["reason"]
        == "invalid_source_range"
    )
    assert not (output / "calls/s0001.q0001.analysis/reply.json").exists()
    assert (output / "calls/s0001.q0001.analysis/attempt-0002/failure.json").exists()


def test_query_payload_limit_counts_cumulative_utf8_bytes(tmp_path):
    for path in ("a.py", "b.py"):
        (tmp_path / path).write_text("# " + "한" * 400 + "\n")
    sources, _ = index_target(tmp_path)
    requests = [source_request(path, 1, 1) for path in ("a.py", "b.py")]
    result = answer_requests(None, sources, requests, history(byte_limit=2048), "s0001")
    first, second = result["responses"]
    assert first["status"] == "provided" and second["reason"] == "query_byte_budget_exhausted"
    assert first["payload_bytes"] > len(encode(first["data"]))
    assert result["budget"]["remaining_bytes"] == 2048 - first["payload_bytes"]
    assert first["payload_bytes"] + second["required_bytes"] > 2048


@pytest.mark.parametrize("invalid", ["shell", "mixed", "repeat", "disabled"])
def test_invalid_or_exhausted_requests_fail_without_running_commands(tmp_path, invalid):
    agent = RecordedInvestigation()
    if invalid == "shell":
        agent.requests = [{"operation": "shell", "command": "touch /host-marker", "reason": "run"}]
    elif invalid == "mixed":
        agent.final = {**agent.final, "requests": [source_request()]}
    elif invalid == "repeat":
        agent.final = {"candidates": [], "requests": [source_request()]}
    output = tmp_path / "review"
    with pytest.raises(ValueError):
        run_pipeline(
            DEMO, output, agent, max_slices=1, max_queries=0 if invalid == "disabled" else 1
        )
    assert read(output / "manifest.json")["status"] == "failed"
    assert not (output / "findings.json").exists()
    assert list(output.glob("calls/*/attempt-*/failure.json"))


def test_timeout_keeps_query_evidence_and_each_retry_attempt(tmp_path):
    agent = RecordedInvestigation()
    original_call = agent.call

    def timeout(stage, call_id, *args):
        if call_id == "s0001.q0001":
            raise subprocess.TimeoutExpired(["offline-fixture"], 1)
        return original_call(stage, call_id, *args)

    agent.call = timeout
    output = tmp_path / "review"
    with pytest.raises(subprocess.TimeoutExpired):
        run_pipeline(DEMO, output, agent, max_slices=1)
    assert (
        read(output / "calls/s0001.q0001.analysis/attempt-0002/failure.json")["type"]
        == "TimeoutExpired"
    )
    assert read(output / "investigations/s0001.json")["responses"][0]["status"] == "provided"
    agent.call = original_call
    result = run_pipeline(DEMO, output, agent, max_slices=1, resume=True)
    assert result["call_attempts"] == 4 and result["query_cache_hits"] == 1
    assert (output / "calls/s0001.q0001.analysis/attempt-0003/raw-response.json").exists()
    assert (output / "calls/s0001.q0001.analysis/attempt-0002/failure.json").exists()


def test_queries_use_indexed_snapshots_and_never_import_or_read_other_files(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    sentinel = tmp_path / "executed"
    (target / "target.py").write_text(f"open({str(sentinel)!r}, 'w').write('executed')\n# 한글\r\n")
    (target / ".env").write_text("SYNTHETIC_SECRET=hidden")
    (target / "link.py").symlink_to(target / ".env")
    sources, _ = index_target(target)
    (target / "target.py").write_text("changed on disk")
    requests = [
        source_request(path, 1, 2) for path in ("target.py", ".env", "link.py", "../outside.py")
    ]
    result = answer_requests(None, sources, requests, history(), "s0001")
    assert "# 한글\r\n" in result["responses"][0]["data"]["fragments"][0]["text"]
    assert all(r["reason"] == "source_not_indexed" for r in result["responses"][1:])
    assert not sentinel.exists() and "SYNTHETIC_SECRET" not in encode(result)


def test_overlap_allows_a_quote_returned_in_a_larger_fragment():
    fragments = [
        {"path": "a.py", "first_line": 1, "last_line": 1, "text": "first\n"},
        {"path": "a.py", "first_line": 1, "last_line": 2, "text": "first\nsecond\n"},
    ]
    assert (
        validate_evidence({"path": "a.py", "line": 1, "quote": "first\nsecond"}, fragments)
        is fragments[1]
    )


@pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain required")
def test_typed_graph_queries_keep_cross_package_calls_and_unresolved_boundaries(tmp_path):
    target = ROOT / "examples/go-review-target"
    graph = build_graph(target, tmp_path / "graph", language="go")
    sources, _ = index_target(target)
    dynamic = next(
        f
        for f in graph["functions"]
        if f["qualified_name"] == "audit.example/review/service.Dynamic"
    )
    requests = [
        {
            "operation": "resolve",
            "selector": "runner/execute.go",
            "reason": "Find callers and definition.",
        },
        {
            "operation": "reachable",
            "selector": "audit.example/review/service.Dynamic",
            "reason": "Check dispatch gaps.",
        },
        {"operation": "resolve", "selector": "Raw", "reason": "Check an ambiguous short name."},
        source_request(dynamic["path"], dynamic["line"], dynamic["end_line"]),
    ]
    result = answer_requests(graph, sources, requests, history(byte_limit=65536), "s0001")
    first, second, ambiguous, source = result["responses"]
    assert first["status"] == second["status"] == "provided"
    assert {c["path"] for c in first["data"]["structure"]["incoming_calls"]} == {"service/flow.go"}
    assert {f["path"] for f in first["data"]["fragments"]} >= {
        "runner/execute.go",
        "service/flow.go",
    }
    unknown = second["data"]["structure"]["unresolved_calls"]
    assert len(unknown) == 2 and all(c["callee"] is None for c in unknown)
    assert len(second["data"]["structure"]["functions"]) == 1
    assert ambiguous["status"] == "unavailable"
    assert ambiguous["reason"] == "selector_missing_or_ambiguous" and ambiguous["data"] is None
    assert source["status"] == "provided"
    assert set(source["data"]["input_gaps"]["unresolved_call_ids"]) == {c["id"] for c in unknown}


@pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain required")
def test_graph_replay_demo_exposes_new_launcher_source_and_retains_query_gap(tmp_path):
    target = ROOT / "examples/go-http-target"
    build_graph(target, tmp_path / "graph", language="go")
    build_recon(
        target,
        tmp_path / "graph/graph.json",
        ROOT / "examples/go-http-plan.json",
        tmp_path / "recon",
    )
    output = tmp_path / "review"
    result = run_pipeline(
        target,
        output,
        ReplayAgent(ROOT / "examples/investigation-replay"),
        graph_file=tmp_path / "graph/graph.json",
        recon_file=tmp_path / "recon/recon.json",
        query_bytes=48000,
    )
    initial = read(output / "slices.json")[0]
    assert "cmd/server/main.go" not in {f["path"] for f in initial["fragments"]}
    responses = read(output / "investigations/s0001.json")["responses"]
    assert [r["status"] for r in responses] == ["provided", "provided", "provided", "unavailable"]
    assert any(
        f["path"] == "cmd/server/main.go" for r in responses[:3] for f in r["data"]["fragments"]
    )
    finding = read(output / "findings.json")[0]
    assert finding["verdict"] == "uncertain" and len(finding["input_gaps"]["external_call_ids"]) > 2
    assert finding["input_gaps"]["investigation_gap_ids"] == [responses[3]["id"]]
    assert result["call_attempts"] == 3 and result["investigation_queries"] == 4
    limited = tmp_path / "limited"
    run_pipeline(
        target,
        limited,
        ReplayAgent(ROOT / "examples/investigation-replay"),
        graph_file=tmp_path / "graph/graph.json",
        recon_file=tmp_path / "recon/recon.json",
        query_bytes=24000,
    )
    limited_responses = read(limited / "investigations/s0001.json")["responses"]
    assert limited_responses[2]["status"] == "omitted" and limited_responses[2]["data"] is None
    assert read(limited / "findings.json")[0]["input_gaps"]["investigation_gap_ids"] == [
        r["id"] for r in limited_responses if r["status"] != "provided"
    ]
