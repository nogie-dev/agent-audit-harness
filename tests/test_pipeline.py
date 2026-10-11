import copy
import json
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent, Reply
from agent_audit_harness.pipeline import (
    RESOURCES,
    apply_triage,
    candidates_for_slice,
    index_target,
    make_slices,
    report_text,
    run_lock,
    run_pipeline,
    validate_shape,
)

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo-target"
REPLAY = ROOT / "examples" / "replay"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_replay_end_to_end_and_resume_do_not_repeat_calls(tmp_path):
    output = tmp_path / "run"
    agent = ReplayAgent(REPLAY)
    first = run_pipeline(DEMO, output, agent)
    assert first["call_attempts"] == 4
    assert first["verdict_counts"] == {"rejected": 1, "needs_validation": 1}
    assert first["confirmed_findings"] == 0
    assert first["reported_token_usage"] is None
    queue = read(output / "validation-queue.json")
    assert len(queue) == 1 and queue[0]["path"] == "parser.c"
    assert "Replay fixture demonstration" in (output / "report.md").read_text()
    assert read(output / "manifest.json")["status"] == "complete"

    def no_call(*args):
        pytest.fail("resume invoked the agent instead of using a completed call")

    agent.call = no_call
    resumed = run_pipeline(DEMO, output, agent, resume=True)
    assert resumed["call_attempts"] == 4 and resumed["cache_hits"] == 4
    assert (output / "manifest.json").stat().st_mode & 0o777 == 0o600


def test_budget_failure_checkpoints_and_resume_can_raise_budget(tmp_path):
    output = tmp_path / "run"
    with pytest.raises(ValueError, match="budget exhausted"):
        run_pipeline(DEMO, output, ReplayAgent(REPLAY), max_calls=1)
    state = read(output / "manifest.json")
    assert state["status"] == "failed" and state["call_attempts"] == 1
    assert (output / "calls" / "s0001.analysis" / "reply.json").exists()
    assert not (output / "report.md").exists()
    result = run_pipeline(DEMO, output, ReplayAgent(REPLAY), max_calls=4, resume=True)
    assert result["call_attempts"] == 4 and result["cache_hits"] == 1


def test_resume_refuses_changed_source_or_fixture(tmp_path):
    target = tmp_path / "source"
    target.mkdir()
    for source in DEMO.iterdir():
        (target / source.name).write_bytes(source.read_bytes())
    output = tmp_path / "run"
    run_pipeline(target, output, ReplayAgent(REPLAY))
    (target / "parser.c").write_text("int changed;\n")
    with pytest.raises(ValueError, match="inputs changed"):
        run_pipeline(target, output, ReplayAgent(REPLAY), resume=True)


def test_index_skips_symlinks_secrets_binary_and_records_gaps(tmp_path):
    target = tmp_path / "source"
    target.mkdir()
    (target / "ok.c").write_text("int ok;\n")
    (target / ".env").write_text("SECRET=do-not-include\n")
    (target / "binary.c").write_bytes(b"\x00binary")
    outside = tmp_path / "outside.c"
    outside.write_text("outside-secret\n")
    (target / "link.c").symlink_to(outside)
    (target / "external").symlink_to(tmp_path, target_is_directory=True)
    sources, skipped = index_target(target)
    assert [source.path for source in sources] == ["ok.c"]
    assert {item["path"] for item in skipped} == {".env", "binary.c", "link.c", "external"}


def test_slicing_bounds_utf8_bytes_preserves_lines_and_is_deterministic(tmp_path):
    (tmp_path / "source.c").write_text("// 한글 abc\n" * 250, encoding="utf-8")
    sources, _ = index_target(tmp_path)
    slices, skipped = make_slices(sources, 1024)
    assert not skipped and len(slices) > 1
    assert all(len(source_slice["text"].encode()) <= 1024 for source_slice in slices)
    assert "".join(source_slice["text"] for source_slice in slices) == sources[0].text
    assert slices[0]["first_line"] == 1 and slices[-1]["last_line"] == 250
    assert make_slices(sources, 1024)[0] == slices


def test_oversized_line_is_an_explicit_coverage_gap(tmp_path):
    (tmp_path / "source.c").write_text("x" * 2048)
    sources, _ = index_target(tmp_path)
    slices, skipped = make_slices(sources, 1024)
    assert not slices and skipped[0]["reason"] == "line_exceeds_slice_budget"


@pytest.mark.parametrize(
    "change",
    [
        {"path": "../outside.c"},
        {"line": 1},
        {"line": 999},
        {"quote": "invented code"},
        {"quote": " "},
    ],
)
def test_candidate_must_cite_real_evidence_inside_slice(change):
    sources, _ = index_target(DEMO)
    source_slice = make_slices(sources, 16000)[0][0]
    data = read(REPLAY / "s0001.analysis.json")
    data["candidates"][0].update(change)
    with pytest.raises(ValueError):
        candidates_for_slice(data, source_slice)


def test_exact_occurrences_deduplicate_and_triage_requires_complete_known_ids():
    source_slice = make_slices(index_target(DEMO)[0], 16000)[0][0]
    data = read(REPLAY / "s0001.analysis.json")
    data["candidates"].append(copy.deepcopy(data["candidates"][0]))
    candidates = candidates_for_slice(data, source_slice)
    assert len(candidates) == 1
    triage = read(REPLAY / "s0001.triage.json")
    assert apply_triage(candidates, triage)[0]["verdict"] == "rejected"
    for invalid in (
        {"decisions": []},
        {"decisions": triage["decisions"] * 2},
        {"decisions": [{**triage["decisions"][0], "candidate_id": "f-0000000000000000"}]},
    ):
        with pytest.raises(ValueError, match="exactly one"):
            apply_triage(candidates, invalid)


def test_confirmed_verdict_is_not_part_of_agent_contract():
    data = read(REPLAY / "s0001.triage.json")
    data["decisions"][0]["verdict"] = "confirmed"
    with pytest.raises(ValueError, match="invalid triage"):
        validate_shape("triage", data, read(RESOURCES / "schemas" / "triage.json"))


def test_partial_coverage_is_visible_and_zero_candidates_skip_triage(tmp_path):
    class NoCandidates:
        identity = {"provider": "replay"}

        def call(self, stage, *args):
            assert stage == "analysis"
            return Reply({"candidates": []})

    result = run_pipeline(DEMO, tmp_path / "run", NoCandidates(), max_slices=1)
    assert result["call_attempts"] == 1
    coverage = read(tmp_path / "run" / "coverage.json")
    assert coverage["selected_slices"] == 1 and coverage["total_slices"] == 2
    assert coverage["remaining_slices"][0]["path"] == "parser.c"


def test_corrupt_cache_is_rejected(tmp_path):
    output = tmp_path / "run"
    run_pipeline(DEMO, output, ReplayAgent(REPLAY))
    path = output / "calls" / "s0001.analysis" / "reply.json"
    record = read(path)
    record["data"]["candidates"][0]["title"] = "modified"
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="checksum mismatch"):
        run_pipeline(DEMO, output, ReplayAgent(REPLAY), resume=True)
    assert read(output / "manifest.json")["status"] == "failed"
    assert not (output / "report.md").exists()


def test_run_lock_target_boundary_and_existing_data_are_preserved(tmp_path):
    output = tmp_path / "run"
    with run_lock(output), pytest.raises(ValueError, match="locked"):
        run_pipeline(DEMO, output, ReplayAgent(REPLAY))
    assert not (output / ".lock").exists()
    with pytest.raises(ValueError, match="outside the target"):
        run_pipeline(tmp_path, tmp_path / "nested", ReplayAgent(REPLAY))
    (output / "existing.txt").write_text("keep")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        run_pipeline(DEMO, output, ReplayAgent(REPLAY))
    assert (output / "existing.txt").read_text() == "keep"


def test_report_escapes_untrusted_html_and_image_markup(tmp_path):
    output = tmp_path / "run"
    run_pipeline(DEMO, output, ReplayAgent(REPLAY))
    findings = read(output / "findings.json")
    findings[0]["title"] = '<img src="https://example.invalid/track">'
    findings[0]["reasoning"] = "![image](https://example.invalid/track)"
    report = report_text(
        findings, read(output / "coverage.json"), read(output / "metrics.json"), True
    )
    assert "<img" not in report and "![image]" not in report
    assert "&lt;img" in report


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        (
            {"input_tokens": "unknown", "output_tokens": 5},
            {"input_tokens": None, "cached_input_tokens": None, "output_tokens": 5},
        ),
        (
            {"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0},
            {"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0},
        ),
    ],
)
def test_unknown_usage_fields_are_not_reported_as_zero(tmp_path, usage, expected):
    class PartialUsage:
        identity = {"provider": "replay"}

        def call(self, stage, *args):
            return Reply({"candidates": []}, usage)

    metrics = run_pipeline(DEMO, tmp_path / "run", PartialUsage(), max_slices=1)
    assert metrics["reported_token_usage"] == expected
