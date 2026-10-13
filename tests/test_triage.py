import copy
import json
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent, Reply
from agent_audit_harness.pipeline import (
    Source,
    candidates_for_slice,
    digest,
    encode,
    make_slices,
    run_pipeline,
)
from agent_audit_harness.triage import apply_triage, checked_evidence, cluster_findings

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def case():
    text = (
        "def execute(value):\n    shell(value)\n\nexecute(first)\n"
        'if second == "date":\n    execute(second)\n'
    )
    source = Source("entry.py", text, digest(text))
    source_slice = make_slices([source], 16000)[0][0]
    analysis = {
        "candidates": [
            {
                "path": source.path,
                "line": line,
                "cwe": "CWE-78",
                "title": "Unrestricted execution",
                "reasoning": "Investigate the shared executor boundary.",
                "quote": quote,
                "validation_plan": "Check binding and exposure in an isolated worker.",
            }
            for line, quote in ((4, "execute(first)"), (6, "execute(second)"))
        ]
    }
    candidates = candidates_for_slice(analysis, source_slice)
    point = {"path": source.path, "line": 2, "column": 5, "quote": "shell(value)"}
    cause = {
        "invariant": "input-must-not-select-shell-command",
        "description": "The shared executor has no local shell control.",
        "evidence": point,
        "fix": {
            "strategy": "fixed-argv-without-shell",
            "description": "Use a fixed executable without shell interpretation.",
            "evidence": point,
        },
    }
    data = {
        "groups": [
            {
                "root_cause": cause,
                "decisions": [
                    {
                        "candidate_id": candidate["id"],
                        "verdict": "needs_validation",
                        "rationale": "A shared executor needs validation.",
                        "counterevidence": [],
                        "unresolved": [
                            {"claim": "Runtime binding is not supplied.", "evidence": None}
                        ],
                    }
                    for candidate in candidates
                ],
            }
        ]
    }
    return source_slice, analysis, candidates, data


def test_shared_control_and_fix_group_members_without_erasing_evidence(case):
    source_slice, _, candidates, data = case
    candidates[1]["cwe"] = "CWE-88"  # A cause can span different issue labels.
    data["groups"][0]["decisions"][1].update(
        verdict="rejected",
        counterevidence=[
            {
                "claim": "Second path restricts the command to date.",
                "evidence": {
                    "path": "entry.py",
                    "line": 5,
                    "column": 1,
                    "quote": 'if second == "date":\n    execute(second)',
                },
            }
        ],
    )
    findings = apply_triage(candidates, data, source_slice)
    findings[1]["root_cause"] = copy.deepcopy(findings[1]["root_cause"])
    findings[1]["root_cause"]["description"] = (
        "A differently worded hypothesis of the same control."
    )
    findings[1]["root_cause"]["fix"]["description"] = (
        "Apply the same repair at the shared executor."
    )
    original = copy.deepcopy(findings)
    clusters = cluster_findings(findings)
    assert len(clusters) == 1 and clusters[0]["status"] == "mixed"
    assert clusters[0]["verdict_counts"] == {"needs_validation": 1, "rejected": 1}
    assert clusters[0]["counterevidence_candidate_ids"] == [candidates[1]["id"]]
    assert len(clusters[0]["unresolved_candidate_ids"]) == 2
    assert clusters[0]["root_cause"]["evidence"]["source_sha256"] == source_slice["source_sha256"]
    for finding, before in zip(findings, original, strict=True):
        assert {k: v for k, v in finding.items() if k != "cluster_id"} == before
    assert cluster_findings(list(reversed(findings))) == clusters


@pytest.mark.parametrize(
    "difference", ["control", "invariant", "repair_location", "repair_strategy", "snapshot"]
)
def test_same_cwe_does_not_merge_distinct_causes_or_repairs(case, difference):
    source_slice, _, candidates, data = case
    first = apply_triage(candidates, data, source_slice)
    other = first[1]["root_cause"] = copy.deepcopy(first[1]["root_cause"])
    point = checked_evidence(
        {"path": "entry.py", "line": 4, "column": 1, "quote": "execute(first)"}, source_slice
    )
    if difference == "control":
        other["evidence"] = point
    elif difference == "invariant":
        other["invariant"] = "argument-must-be-validated"
    elif difference == "repair_location":
        other["fix"]["evidence"] = point
    elif difference == "repair_strategy":
        other["fix"]["strategy"] = "allowlist-shell-input"
    else:
        other["evidence"]["source_sha256"] = "f" * 64
    assert len(cluster_findings(first)) == 2


def test_unknown_causes_stay_separate_and_all_rejected_uncertain_members_survive(case):
    source_slice, _, candidates, data = case
    first, second = data["groups"][0]["decisions"]
    second.update(
        verdict="rejected",
        counterevidence=[
            {
                "claim": "Second path restricts execution.",
                "evidence": {
                    "path": "entry.py",
                    "line": 5,
                    "column": 1,
                    "quote": 'if second == "date":\n    execute(second)',
                },
            }
        ],
    )
    first["verdict"] = "uncertain"
    data["groups"] = [{"root_cause": None, "decisions": [d]} for d in (first, second)]
    findings = apply_triage(candidates, data, source_slice)
    clusters = cluster_findings(findings)
    assert len(clusters) == 2
    assert {c["status"] for c in clusters} == {"rejected", "uncertain"}
    assert all(c["grouping_basis"] == "unresolved_singleton" for c in clusters)
    assert all(f["unresolved"][0]["evidence"] is None for f in findings)
    data["groups"] = [{"root_cause": None, "decisions": [first, second]}]
    with pytest.raises(ValueError, match="singleton"):
        apply_triage(candidates, data, source_slice)


@pytest.mark.parametrize(
    "verdict,field", [("rejected", "counterevidence"), ("uncertain", "unresolved")]
)
def test_verdict_requires_its_own_disproof_or_missing_evidence(case, verdict, field):
    source_slice, _, candidates, data = case
    data["groups"][0]["decisions"][0].update(verdict=verdict, **{field: []})
    with pytest.raises(ValueError, match="requires"):
        apply_triage(candidates, data, source_slice)


@pytest.mark.parametrize("field", ["cause", "fix", "counterevidence", "unresolved"])
@pytest.mark.parametrize(
    "change", [{"path": "../outside.py"}, {"line": 3}, {"column": 6}, {"quote": "invented()"}]
)
def test_every_triage_citation_is_checked_inside_supplied_source(case, field, change):
    source_slice, _, candidates, data = case
    group = data["groups"][0]
    if field == "cause":
        point = group["root_cause"]["evidence"]
    elif field == "fix":
        point = group["root_cause"]["fix"]["evidence"]
    else:
        group["decisions"][0][field] = [
            {
                "claim": "Check this boundary.",
                "evidence": copy.deepcopy(group["root_cause"]["evidence"]),
            }
        ]
        point = group["decisions"][0][field][0]["evidence"]
    point.update(change)
    with pytest.raises(ValueError):
        apply_triage(candidates, data, source_slice)


@pytest.mark.parametrize(
    "bad",
    [
        "missing",
        "duplicate",
        "unknown",
        "extra",
        "confirmed",
        "null_counterevidence",
        "old_contract",
    ],
)
def test_closed_contract_and_exact_candidate_ownership(case, bad):
    source_slice, _, candidates, data = case
    group = data["groups"][0]
    if bad == "missing":
        group["decisions"].pop()
    elif bad == "duplicate":
        data["groups"].append(copy.deepcopy(group))
    elif bad == "unknown":
        group["decisions"][0]["candidate_id"] = "f-0000000000000000"
    elif bad == "extra":
        group["root_cause"]["evidence"]["source_sha256"] = "0" * 64
    elif bad == "confirmed":
        group["decisions"][0]["verdict"] = "confirmed"
    elif bad == "null_counterevidence":
        group["decisions"][0]["counterevidence"] = [{"claim": "Trust me.", "evidence": None}]
    else:
        data = {"decisions": group["decisions"]}
    with pytest.raises(ValueError):
        apply_triage(candidates, data, source_slice)


def test_byte_columns_distinguish_same_line_controls_and_utf8_crlf():
    text = '값 = "x"; shell(a); shell(b)\r\n'
    source_slice = {
        "id": "s0001",
        "path": "entry.py",
        "text": text,
        "first_line": 1,
        "last_line": 1,
        "source_sha256": digest(text),
    }
    for quote in ("shell(a)", "shell(b)"):
        column = text.encode().index(quote.encode()) + 1
        assert (
            checked_evidence(
                {"path": "entry.py", "line": 1, "column": column, "quote": quote}, source_slice
            )["column"]
            == column
        )
    with pytest.raises(ValueError, match="byte column"):
        checked_evidence(
            {
                "path": "entry.py",
                "line": 1,
                "column": text.index("shell(a)") + 1,
                "quote": "shell(a)",
            },
            source_slice,
        )
    with pytest.raises(ValueError, match="byte column"):
        checked_evidence({"path": "entry.py", "line": 1, "column": 2, "quote": "값"}, source_slice)


def test_model_cannot_erase_harness_gap_inventory(case):
    source_slice, _, candidates, data = case
    source_slice.update(
        calls=[
            {"id": "unknown-call", "status": "unresolved"},
            {"id": "external-call", "status": "external"},
        ],
        omitted_counts={"functions": 2, "calls": 1},
        static_analysis={"gaps": [{"id": "static-gap"}]},
        modifier_flows=[
            {"function_id": "modifier-owner", "flow": {"gaps": [{"reason": "opaque"}]}}
        ],
    )
    for decision in data["groups"][0]["decisions"]:
        decision["unresolved"] = []
    findings = apply_triage(candidates, data, source_slice)
    for f in findings:
        assert f["unresolved"] == []
        assert f["input_gaps"] == {
            "coverage_ref": "coverage.json",
            "unresolved_call_ids": ["unknown-call"],
            "external_call_ids": ["external-call"],
            "unlinked_annotation_ids": [],
            "omitted_counts": {"functions": 2, "calls": 1},
            "static_gap_ids": ["static-gap"],
            "modifier_gap_function_ids": ["modifier-owner"],
        }


def test_bad_triage_evidence_fails_before_cache_and_resume_removes_stale_clusters(tmp_path):
    target = ROOT / "examples/demo-target"
    replay = ReplayAgent(ROOT / "examples/replay")
    output = tmp_path / "run"
    run_pipeline(target, output, replay)
    path = output / "calls/s0001.triage/reply.json"
    record = json.loads(path.read_text())
    record["data"]["groups"][0]["decisions"][0]["counterevidence"][0]["evidence"]["column"] += 1
    record["reply_sha256"] = digest(record["data"])
    path.write_text(encode(record))
    (path.parent / f"attempt-{record['attempt']:04d}/raw-response.json").write_text(
        encode(record["data"])
    )
    with pytest.raises(ValueError, match="byte column"):
        run_pipeline(target, output, replay, resume=True)
    assert not (output / "clusters.json").exists()
    assert json.loads((output / "manifest.json").read_text())["status"] == "failed"
    path.unlink()
    original_call = replay.call

    def bad_reply(stage, *args):
        reply = original_call(stage, *args)
        if stage == "triage":
            return Reply(record["data"])
        return reply

    replay.call = bad_reply
    with pytest.raises(ValueError, match="byte column"):
        run_pipeline(target, output, replay, resume=True)
    assert not path.exists()


def test_multi_candidate_group_survives_pipeline_queue_and_resume(case, tmp_path):
    source_slice, analysis, _, data = case
    target = tmp_path / "target"
    target.mkdir()
    (target / "entry.py").write_text(source_slice["text"])
    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    (replay_dir / "s0001.analysis.json").write_text(encode(analysis))
    (replay_dir / "s0001.triage.json").write_text(encode(data))
    output = tmp_path / "run"
    agent = ReplayAgent(replay_dir)
    result = run_pipeline(target, output, agent)
    assert result["unique_candidates"] == 2 and result["cluster_count"] == 1
    findings = json.loads((output / "findings.json").read_text())
    assert len({f["cluster_id"] for f in findings}) == 1
    assert json.loads((output / "validation-queue.json").read_text()) == findings
    before = (output / "clusters.json").read_bytes()
    agent.call = lambda *args: pytest.fail("resume must reuse both replies")
    assert run_pipeline(target, output, agent, resume=True)["cache_hits"] == 2
    assert (output / "clusters.json").read_bytes() == before
