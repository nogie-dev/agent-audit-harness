import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent, Reply
from agent_audit_harness.graph import build_graph
from agent_audit_harness.judgment import candidate_issues
from agent_audit_harness.model_analysis import compile_models, model_context
from agent_audit_harness.pipeline import digest, encode, index_target, run_pipeline
from agent_audit_harness.recon import build_recon, make_graph_slices
from agent_audit_harness.static_analysis import DEFAULT_RULES, build_static, validate_static

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache/semgrep"


def read(path):
    return json.loads(path.read_text())


@pytest.fixture(scope="module", params=["python", "go"])
def case(request, tmp_path_factory):
    if not (CACHE / "semgrep-core").is_file():
        pytest.skip("run make setup-static")
    language = request.param
    if language == "go" and shutil.which("go") is None:
        pytest.skip("Go toolchain required")
    suffix = "-go" if language == "go" else ""
    root = tmp_path_factory.mktemp("model-" + language)
    target = root / "target"
    shutil.copytree(ROOT / f"examples/model{suffix}-target", target)
    sentinel = root / "target-executed"
    if language == "python":
        (target / "trap.py").write_text(
            f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n"
        )
    graph = build_graph(target, root / "graph", language=language)
    recon = build_recon(
        target,
        root / "graph/graph.json",
        ROOT / f"examples/model{suffix}-plan.json",
        root / "recon",
    )
    before = build_static(
        target, root / "graph/graph.json", DEFAULT_RULES, root / "first", cache=CACHE
    )
    sources, _ = index_target(target)
    slices = make_graph_slices(graph, recon, sources, 16000, before)[0]
    replay = ROOT / f"examples/model{suffix}-replay"
    assert not sentinel.exists()
    return {
        "language": language,
        "root": root,
        "target": target,
        "graph": graph,
        "recon": recon,
        "before": before,
        "sources": sources,
        "slice": slices[0],
        "replay": replay,
        "sentinel": sentinel,
    }


def run(case, output, agent=None, **kwargs):
    return run_pipeline(
        case["target"],
        output,
        agent or ReplayAgent(case["replay"]),
        graph_file=case["root"] / "graph/graph.json",
        recon_file=case["root"] / "recon/recon.json",
        static_file=case["root"] / "first/static.json",
        **kwargs,
    )


def proposal(case):
    return read(case["replay"] / "s0001.q0001.analysis.json")["model_proposals"][0]


def test_real_two_pass_wrappers_negative_control_unknown_binding_and_resume(
    case, tmp_path, monkeypatch
):
    output = tmp_path / "review"
    original = (case["root"] / "first/static.json").read_bytes()
    metrics = run(case, output)
    stage = read(output / "models/s0001/result.json")["data"]
    after = read(output / stage["after_ref"])
    assert case["before"]["taint_results"] == []
    assert len(after["taint_results"]) == (3 if case["language"] == "python" else 2)
    assert all(t["trace_status"] == "partial" and t["source"] for t in after["taint_results"])
    constant = next(f for f in case["graph"]["functions"] if f["name"].lower() == "constant")
    assert not any(t["sink"]["function_id"] == constant["id"] for t in after["taint_results"])
    unknown = next(f for f in case["graph"]["functions"] if f["name"].lower() == "unknown")
    assert any(t["sink"]["function_id"] == unknown["id"] for t in after["taint_results"])
    if case["language"] == "python":
        shadowed = next(f for f in case["graph"]["functions"] if f["name"] == "shadowed")
        assert any(
            g["reason"] == "model_endpoint_binding_unverified"
            and g["function_id"] == shadowed["id"]
            for g in after["gaps"]
        )
    assert (case["root"] / "first/static.json").read_bytes() == original
    assert read(output / "static.json") == case["before"]
    assert read(output / "graph.json") == case["graph"]
    for key in ("core_sha256", "runtime_sha256", "adapter_sha256", "normalizer_sha256"):
        assert after["engine"][key] == case["before"]["engine"][key]
    candidate = read(output / "findings.json")[0]
    assert candidate["verdict"] == "uncertain" and candidate["input_gaps"]["model_static_gap_ids"]
    assert candidate["input_gaps"]["static_gap_ids"]
    assert candidate["input_gaps"]["model_gap_ids"]
    assert {i["kind"] for i in candidate_issues(candidate)} >= {
        "model_gap_ids",
        "model_static_gap_ids",
        "static_gap_ids",
    }
    assert metrics["model_second_passes"] == 1 and metrics["model_cache_hits"] == 0
    assert metrics["call_attempts"] == 4 and metrics["confirmed_findings"] == 0
    payload = json.loads(
        (output / "calls/s0001.m0001.analysis/prompt.txt")
        .read_text()
        .split("UNTRUSTED_INPUT_JSON:\n")[1]
    )
    packet = payload["model_analysis"]["result"]
    assert payload["model_analysis"]["remaining_passes"] == 0
    assert packet["before_sha256"] != packet["after_sha256"]
    assert packet["payload_bytes"] <= packet["byte_limit"] == 16000
    assert packet["data"]["static_analysis"]["taint_results"]
    assert "omissions" not in packet
    saved_context = read(output / packet["omissions_ref"])
    assert saved_context["omissions"]
    assert saved_context["data"] == packet["data"]

    def forbidden(*args, **kwargs):
        pytest.fail("resume repeated an engine or agent invocation")

    agent = ReplayAgent(case["replay"])
    agent.call = forbidden
    monkeypatch.setattr("agent_audit_harness.model_analysis.build_static", forbidden)
    resumed = run(case, output, agent, resume=True)
    assert resumed["cache_hits"] == 4 and resumed["model_cache_hits"] == 1
    assert read(output / "findings.json")[0] == candidate
    assert not case["sentinel"].exists()


class DirectModelAgent(ReplayAgent):
    def __init__(self, case, data=None, repeat=False):
        super().__init__(case["replay"])
        self.data = data or read(case["replay"] / "s0001.q0001.analysis.json")
        self.final = read(case["replay"] / "s0001.m0001.analysis.json")
        self.repeat = repeat

    def call(self, stage, call_id, prompt, schema, directory):
        if stage == "triage":
            return super().call(stage, call_id, prompt, schema, directory)
        return Reply(self.data if call_id == "s0001" or self.repeat else self.final)


@pytest.mark.parametrize(
    "change",
    ["pattern", "false_quote", "wrong_column", "wrong_function", "mixed", "duplicate", "count"],
)
def test_untrusted_model_contract_fails_before_second_engine(case, tmp_path, monkeypatch, change):
    data = {"candidates": [], "model_proposals": [proposal(case)]}
    model = data["model_proposals"][0]
    if change == "pattern":
        model["source_patterns"] = ["run_arbitrary(...)"]
    elif change == "false_quote":
        model["source"]["evidence"]["quote"] = "invented input source"
    elif change == "wrong_column":
        model["source"]["evidence"]["column"] += 1
    elif change == "wrong_function":
        model["source"]["function_id"] = model["sink"]["function_id"]
    elif change == "mixed":
        data["candidates"] = read(case["replay"] / "s0001.m0001.analysis.json")["candidates"]
    elif change == "duplicate":
        data["model_proposals"].append(copy.deepcopy(model))
    else:
        data["model_proposals"] *= 5

    def forbidden(*args, **kwargs):
        pytest.fail("invalid model reached the analyzer")

    monkeypatch.setattr("agent_audit_harness.model_analysis.build_static", forbidden)
    output = tmp_path / "review"
    with pytest.raises(ValueError):
        run(case, output, DirectModelAgent(case, data))
    assert read(output / "manifest.json")["status"] == "failed"
    assert (output / "calls/s0001.analysis/attempt-0001/raw-response.json").exists()
    assert (output / "calls/s0001.analysis/attempt-0001/failure.json").exists()
    assert not (output / "findings.json").exists()


def test_second_model_request_is_rejected_without_replacing_first_pass(case, tmp_path):
    output = tmp_path / "review"
    with pytest.raises(ValueError, match="remaining second pass"):
        run(case, output, DirectModelAgent(case, repeat=True))
    assert (output / "models/s0001/attempt-0001/analysis/static.json").exists()
    assert read(output / "static.json") == case["before"]
    assert not (output / "findings.json").exists()


def test_timeout_keeps_proposals_and_first_pass_then_resume_retries_and_caches(
    case, tmp_path, monkeypatch
):
    import agent_audit_harness.model_analysis as models

    actual = models.build_static

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(["trusted-semgrep-core"], 30)

    monkeypatch.setattr(models, "build_static", timeout)
    output = tmp_path / "review"
    with pytest.raises(subprocess.TimeoutExpired):
        run(case, output)
    failed = output / "models/s0001/attempt-0001/failure.json"
    assert read(failed)["type"] == "TimeoutExpired"
    assert read(output / "models/s0001/plan.json")["models"][0]["status"] == "declared"
    assert read(output / "static.json") == case["before"]
    assert not (output / "models/s0001/result.json").exists()
    monkeypatch.setattr(models, "build_static", actual)
    metrics = run(case, output, resume=True)
    assert metrics["cache_hits"] == 2 and metrics["model_second_passes"] == 1
    assert read(failed)["type"] == "TimeoutExpired"
    assert (output / "models/s0001/attempt-0002/analysis/analyzer-output.json").exists()


@pytest.mark.parametrize("change", ["plan", "raw", "rules", "checkpoint"])
def test_cached_model_evidence_tampering_is_rejected(case, tmp_path, change):
    output = tmp_path / "review"
    run(case, output)
    stage = output / "models/s0001"
    if change == "plan":
        path = stage / "plan.json"
        data = read(path)
        data["models"][0]["assumptions"].append("tampered model")
        path.write_text(encode(data))
    elif change == "raw":
        path = output / read(stage / "result.json")["data"]["after_ref"]
        (path.parent / "analyzer-output.json").write_text("{}")
    elif change == "rules":
        (stage / "attempt-0001/rules.json").write_text("{}")
    else:
        path = stage / "result.json"
        data = read(path)
        data["data"]["before_sha256"] = "0" * 64
        data["reply_sha256"] = digest(data["data"])
        path.write_text(encode(data))
    with pytest.raises(ValueError, match="cached model"):
        run(case, output, resume=True)
    assert not (output / "findings.json").exists()


def test_source_backed_model_gaps_and_bounded_context(case, tmp_path, monkeypatch):
    data = {"candidates": [], "model_proposals": [proposal(case)]}
    data["model_proposals"][0]["source"]["function_id"] = "not-a-known-function"

    def forbidden(*args, **kwargs):
        pytest.fail("unavailable model ran the engine")

    monkeypatch.setattr("agent_audit_harness.model_analysis.build_static", forbidden)
    output = tmp_path / "review"
    metrics = run(case, output, DirectModelAgent(case, data))
    assert metrics["model_second_passes"] == 0
    stage = read(output / "models/s0001/result.json")["data"]
    assert stage["after_ref"] is None
    candidate = read(output / "findings.json")[0]
    assert candidate["input_gaps"]["model_gap_ids"]
    plan = compile_models(
        [proposal(case)], case["graph"], case["sources"], case["slice"], case["before"]
    )
    result = {
        "plan": plan,
        "before_sha256": case["before"]["identity_sha256"],
        "after_sha256": None,
        "after_ref": None,
    }
    packet = model_context(
        result, None, case["slice"], case["recon"]["hypotheses"][0], case["graph"], 1024
    )
    assert packet["status"] == "omitted" and packet["data"] is None
    assert any(g["reason"] == "model_context_byte_budget_exhausted" for g in packet["gaps"])


def test_missing_static_input_rejects_model_actions(case, tmp_path):
    with pytest.raises(ValueError, match="--static"):
        run_pipeline(
            case["target"],
            tmp_path / "review",
            DirectModelAgent(case),
            graph_file=case["root"] / "graph/graph.json",
            recon_file=case["root"] / "recon/recon.json",
        )


def test_resealed_binding_change_cannot_omit_model_binding_gaps(case, tmp_path):
    output = tmp_path / "review"
    run(case, output)
    after = read(output / read(output / "models/s0001/result.json")["data"]["after_ref"])
    custom = next(r for r in after["rule_spec"]["rules"] if "call_models" in r)
    custom["call_models"]["source"] = custom["call_models"]["sink"]
    after["rules_sha256"] = digest(after["rule_spec"])
    after["identity_sha256"] = digest({k: v for k, v in after.items() if k != "identity_sha256"})
    with pytest.raises(ValueError, match="binding gaps"):
        validate_static(after, case["graph"], case["sources"])


def test_call_budget_after_second_pass_resumes_without_reanalysis(case, tmp_path, monkeypatch):
    output = tmp_path / "review"
    with pytest.raises(ValueError, match="agent call budget"):
        run(case, output, max_calls=2)
    assert (output / "models/s0001/result.json").exists()

    def forbidden(*args, **kwargs):
        pytest.fail("resume reran the second pass")

    monkeypatch.setattr("agent_audit_harness.model_analysis.build_static", forbidden)
    metrics = run(case, output, max_calls=4, resume=True)
    assert metrics["cache_hits"] == 2 and metrics["model_cache_hits"] == 1
    assert metrics["call_attempts"] == 4
    with pytest.raises(ValueError, match="inputs changed"):
        run(case, output, max_calls=4, slice_bytes=20000, resume=True)


@pytest.mark.parametrize("key", ["core_sha256", "normalizer_sha256"])
def test_first_engine_identity_mismatch_fails_before_any_native_invocation(
    case, tmp_path, monkeypatch, key
):
    poisoned = copy.deepcopy(case["before"])
    poisoned["engine"][key] = "0" * 64
    poisoned["identity_sha256"] = digest(
        {k: v for k, v in poisoned.items() if k != "identity_sha256"}
    )
    first = tmp_path / "first.json"
    first.write_text(encode(poisoned))

    def forbidden(*args, **kwargs):
        pytest.fail("changed engine reached a native invocation")

    monkeypatch.setattr("agent_audit_harness.analyzers.semgrep.run_tool", forbidden)
    output = tmp_path / "review"
    with pytest.raises(ValueError, match="differs from the first"):
        run_pipeline(
            case["target"],
            output,
            DirectModelAgent(case),
            graph_file=case["root"] / "graph/graph.json",
            recon_file=case["root"] / "recon/recon.json",
            static_file=first,
        )
    assert (output / "models/s0001/attempt-0001/failure.json").exists()
    assert read(output / "static.json") == poisoned


def test_queries_after_models_preserve_earlier_context_omissions(case, tmp_path):
    class LaterQuery(ReplayAgent):
        def call(self, stage, call_id, prompt, schema, directory):
            if call_id == "s0001" and stage == "analysis":
                data = read(case["replay"] / "s0001.analysis.json")
                data["requests"] = data["requests"][:1]
                return Reply(data)
            if call_id == "s0001.m0001" and stage == "analysis":
                return Reply(
                    {
                        "candidates": [],
                        "requests": [
                            {
                                "operation": "source",
                                "path": "entry.py"
                                if case["language"] == "python"
                                else "client/entry.go",
                                "first_line": 1,
                                "last_line": 22 if case["language"] == "python" else 21,
                                "reason": "Inspect the shadowed callback and missing source quote.",
                            }
                        ],
                    }
                )
            if call_id == "s0001.q0002":
                return super().call(stage, "s0001.m0001", prompt, schema, directory)
            return super().call(stage, call_id, prompt, schema, directory)

    output = tmp_path / "review"
    metrics = run(case, output, LaterQuery(case["replay"]), query_bytes=32000)
    assert metrics["model_second_passes"] == 1 and metrics["call_attempts"] == 5
    original = read(output / "models/s0001/contexts/s0001.m0001.analysis.json")
    later = read(output / "models/s0001/contexts/s0001.q0002.analysis.json")
    omitted = [
        g for g in original["gaps"] if g["reason"] == "model_context_static_source_not_supplied"
    ]
    assert omitted
    candidate = read(output / "findings.json")[0]
    assert all(g["id"] in candidate["input_gaps"]["model_gap_ids"] for g in omitted)
    assert len(later["data"]["static_analysis"]["taint_results"]) >= len(
        original["data"]["static_analysis"]["taint_results"]
    )


def test_unsupported_call_spellings_remain_model_gaps(case, tmp_path):
    target = tmp_path / "target"
    shutil.copytree(case["target"], target)
    if case["language"] == "python":
        for path in (target / "readers.py", target / "entry.py"):
            path.write_text(path.read_text().replace("read_field", "읽기"))
    else:
        path = target / "protocol/read.go"
        path.write_text(path.read_text().replace("ReadField()", "ReadField[T any]()"))
        path = target / "client/entry.go"
        path.write_text(path.read_text().replace("ReadField()", "ReadField[byte]()"))
    graph = build_graph(target, tmp_path / "graph", language=case["language"])
    sources, _ = index_target(target)
    fragments = [
        {
            "path": s.path,
            "first_line": 1,
            "last_line": len(s.text.splitlines()),
            "text": s.text,
            "source_sha256": s.sha256,
        }
        for s in sources
    ]
    data = proposal(case)
    source = next(f for f in graph["functions"] if f["name"] in {"읽기", "ReadField"})
    data["source"]["function_id"] = source["id"]
    if case["language"] == "go":
        data["source"]["evidence"]["quote"] = (
            'func ReadField[T any]() string { return os.Getenv("AUDIT_REQUEST") }'
        )
    plan = compile_models([data], graph, sources, {"fragments": fragments}, case["before"])
    assert plan["models"][0]["status"] == "unavailable"
    assert any(g["reason"] == "model_call_spelling_unsupported" for g in plan["gaps"])
    assert plan["rule_spec"] == case["before"]["rule_spec"]


def test_spelling_budget_and_model_gap_identity_use_actual_source_graph(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(ROOT / "examples/model-target", target)
    imports = "".join(f"import readers as r{i}\n" for i in range(9))
    calls = "".join(f"    value_{i} = r{i}.read_field()\n" for i in range(9))
    (target / "entry.py").write_text(
        imports
        + "from writers import send_command\n\ndef entry():\n"
        + calls
        + "    send_command(value_0)\n"
    )
    graph = build_graph(target, tmp_path / "graph", language="python")
    sources, _ = index_target(target)
    evidence = {
        "fragments": [
            {
                "path": s.path,
                "first_line": 1,
                "last_line": len(s.text.splitlines()),
                "text": s.text,
                "source_sha256": s.sha256,
            }
            for s in sources
        ]
    }
    data = read(ROOT / "examples/model-replay/s0001.q0001.analysis.json")["model_proposals"]
    before = {"rule_spec": read(DEFAULT_RULES)}
    plan = compile_models(data, graph, sources, evidence, before)
    assert len(plan["models"][0]["patterns"]["source"]) == 8
    assert any(g["reason"] == "model_spelling_budget_exhausted" for g in plan["gaps"])
    changed = copy.deepcopy(data)
    changed[0]["assumptions"].append("A different declared trust boundary")
    updated = compile_models(changed, graph, sources, evidence, before)
    assert plan["models"][0]["gap_ids"] != updated["models"][0]["gap_ids"]
