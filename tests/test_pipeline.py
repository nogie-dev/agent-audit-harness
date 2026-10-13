import copy
import json
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent, Reply
from agent_audit_harness.pipeline import (
    RESOURCES,
    CitationError,
    apply_triage,
    candidates_for_slice,
    citation_repair_outcome,
    digest,
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
REPAIR_REPLAY = ROOT / "examples" / "citation-repair-replay"


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
    assert first["cluster_count"] == 2
    rejected = next(f for f in read(output / "findings.json") if f["verdict"] == "rejected")
    assert rejected["counterevidence"][0]["evidence"]["source_sha256"] == rejected["source_sha256"]
    queue = read(output / "validation-queue.json")
    assert len(queue) == 1 and queue[0]["path"] == "parser.c"
    assert "Replay fixture demonstration" in (output / "report.md").read_text()
    assert read(output / "manifest.json")["status"] == "complete"
    prompt = (output / "calls/s0001.analysis/prompt.txt").read_text()
    packet_text = prompt.split("UNTRUSTED_INPUT_JSON:\n", 1)[1]
    packet = json.loads(packet_text)
    assert packet["source_slice"] == read(output / "slices.json")[0]
    assert packet["source_line_counts"] == {
        item["path"]: item["lines"]
        for item in read(output / "index.json")
        if item["path"] == packet["source_slice"]["path"]
    }
    assert len(packet_text.encode()) < len(
        json.dumps(packet, ensure_ascii=False, indent=2).encode()
    )

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


def test_programmatic_call_budget_has_same_bound_as_attempt_reporting(tmp_path):
    with pytest.raises(ValueError, match="max calls must be 1..128"):
        run_pipeline(DEMO, tmp_path / "run", ReplayAgent(REPLAY), max_calls=129)


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


@pytest.mark.parametrize(
    ("stage_to_break", "code", "attempt_number"),
    [
        ("analysis", "candidate_quote_mismatch", 1),
        ("triage", "triage_column_mismatch", 2),
    ],
)
def test_failed_call_records_citation_code_without_discarding_raw_reply(
    tmp_path, stage_to_break, code, attempt_number
):
    class InvalidCitationAgent:
        identity = {"provider": "replay"}

        def call(self, stage, slice_id, prompt, schema, directory):
            data = read(REPLAY / f"{slice_id}.{stage}.json")
            if stage == stage_to_break == "analysis":
                data["candidates"][0]["quote"] = "absent source quote"
            if stage == stage_to_break == "triage":
                data["groups"][0]["decisions"][0]["counterevidence"][0]["evidence"]["column"] = 1
            return Reply(data)

    output = tmp_path / "run"
    with pytest.raises(CitationError) as error:
        run_pipeline(DEMO, output, InvalidCitationAgent(), max_slices=1)
    assert error.value.code == code
    attempt = output / f"calls/s0001.{stage_to_break}/attempt-{attempt_number:04d}"
    assert read(attempt / "failure.json")["citation_code"] == code
    assert (attempt / "raw-response.json").is_file()
    assert read(output / "manifest.json")["status"] == "failed"


def test_citation_repair_preserves_rejection_and_reuses_only_checked_result(tmp_path):
    output = tmp_path / "run"
    agent = ReplayAgent(REPAIR_REPLAY)
    result = run_pipeline(DEMO, output, agent, max_slices=1, repair_citations=True)
    assert result["call_attempts"] == 3 and result["citation_repairs"] == 1
    assert result["failed_call_attempts"] == 1 and result["verdict_counts"] == {"rejected": 1}
    call = output / "calls/s0001.analysis"
    assert read(call / "attempt-0001/failure.json")["citation_code"] == "candidate_quote_mismatch"
    assert read(call / "attempt-0001/raw-response.json")["candidates"][0]["line"] == 6
    assert read(call / "attempt-0002/raw-response.json")["candidates"][0]["line"] == 8
    feedback = json.loads(
        (call / "attempt-0002/prompt.txt").read_text().split("UNTRUSTED_CITATION_REPAIR_JSON:\n")[1]
    )
    assert feedback["rejected_reply"] == read(call / "attempt-0001/raw-response.json")
    assert feedback["citation_details"]["field"] == "/candidates/0/quote"
    assert feedback["citation_details"]["source_context"]["first_line"] == 5
    assert result["citation_repair_outcomes"] == {"citation_corrected": 1}
    assert read(call / "reply.json")["attempt"] == 2

    def no_call(*args):
        pytest.fail("completed citation repair must not be invoked again")

    agent.call = no_call
    resumed = run_pipeline(DEMO, output, agent, max_slices=1, repair_citations=True, resume=True)
    assert resumed["call_attempts"] == 3 and resumed["cache_hits"] == 2
    changed = read(call / "attempt-0001/raw-response.json")
    changed["candidates"][0]["reasoning"] = "changed after rejection"
    (call / "attempt-0001/raw-response.json").write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="original rejection changed"):
        run_pipeline(DEMO, output, agent, max_slices=1, repair_citations=True, resume=True)


def test_one_repair_receives_all_invalid_citations_and_exact_matches(tmp_path):
    class MultipleInvalidCitations:
        identity = {"provider": "replay"}

        def call(self, stage, slice_id, prompt, schema, directory):
            data = read(REPAIR_REPLAY / f"{slice_id}.{stage}.json")
            if stage == "analysis":
                data["candidates"].append(copy.deepcopy(data["candidates"][0]))
                if slice_id.endswith(".r0001"):
                    feedback = json.loads(prompt.split("UNTRUSTED_CITATION_REPAIR_JSON:\n")[1])[
                        "citation_details"
                    ]
                    assert [item["field"] for item in feedback["errors"]] == [
                        "/candidates/0/quote",
                        "/candidates/1/quote",
                    ]
                    assert all(
                        item["exact_quote_matches"]
                        == [{"path": "bounded.c", "line": 8, "column": 5}]
                        for item in feedback["errors"]
                    )
            return Reply(data)

    result = run_pipeline(
        DEMO,
        tmp_path / "run",
        MultipleInvalidCitations(),
        max_slices=1,
        repair_citations=True,
    )
    assert result["call_attempts"] == 3
    assert result["citation_repair_outcomes"] == {"citation_corrected": 1}
    assert result["unique_candidates"] == 1


def test_citation_repair_resumes_after_call_cap_without_repeating_initial_call(tmp_path):
    output = tmp_path / "run"
    agent = ReplayAgent(REPAIR_REPLAY)
    with pytest.raises(ValueError, match="budget exhausted"):
        run_pipeline(DEMO, output, agent, max_slices=1, max_calls=1, repair_citations=True)
    checkpoint = read(output / "calls/s0001.analysis/citation-repair.json")
    assert checkpoint["failed_attempt"] == 1 and checkpoint["repair_attempt"] is None
    recorded_call = agent.call

    def only_repair(stage, slice_id, *args):
        assert stage != "analysis" or slice_id == "s0001.r0001"
        return recorded_call(stage, slice_id, *args)

    agent.call = only_repair
    result = run_pipeline(
        DEMO, output, agent, max_slices=1, max_calls=3, repair_citations=True, resume=True
    )
    assert result["call_attempts"] == 3 and result["citation_repairs"] == 1


def test_failed_citation_repair_is_bounded_across_resume(tmp_path):
    class StillInvalid:
        identity = {"provider": "replay"}

        def call(self, *args):
            return Reply(read(REPAIR_REPLAY / "s0001.analysis.json"))

    output = tmp_path / "run"
    agent = StillInvalid()
    with pytest.raises(CitationError):
        run_pipeline(DEMO, output, agent, max_slices=1, repair_citations=True)
    assert read(output / "manifest.json")["call_attempts"] == 2
    with pytest.raises(ValueError, match="already attempted"):
        run_pipeline(DEMO, output, agent, max_slices=1, repair_citations=True, resume=True)
    assert read(output / "manifest.json")["call_attempts"] == 2


@pytest.mark.parametrize("failure_kind", ["transport", "schema", "raw"])
def test_citation_repair_does_not_retry_other_failures(tmp_path, failure_kind):
    class OtherFailure:
        identity = {"provider": "replay"}

        def call(self, stage, slice_id, prompt, schema, directory):
            if failure_kind == "transport":
                raise RuntimeError("transport failure")
            if failure_kind == "schema":
                return Reply({})
            (directory / "raw-response.json").write_text("{}")
            return Reply(read(REPAIR_REPLAY / "s0001.analysis.json"))

    output = tmp_path / "run"
    with pytest.raises((ValueError, RuntimeError)):
        run_pipeline(DEMO, output, OtherFailure(), max_slices=1, repair_citations=True)
    assert read(output / "manifest.json")["call_attempts"] == 1
    assert not list(output.glob("calls/*/citation-repair.json"))


def test_triage_byte_column_repair_uses_same_source_and_candidate_ids(tmp_path):
    class TriageRepair:
        identity = {"provider": "replay"}

        def call(self, stage, slice_id, prompt, schema, directory):
            data = read(REPLAY / f"{slice_id.removesuffix('.r0001')}.{stage}.json")
            if stage == "triage" and not slice_id.endswith(".r0001"):
                data["groups"][0]["decisions"][0]["counterevidence"][0]["evidence"]["column"] = 1
            if slice_id.endswith(".r0001"):
                assert "triage_column_mismatch" in prompt
            return Reply(data)

    output = tmp_path / "run"
    result = run_pipeline(DEMO, output, TriageRepair(), max_slices=1, repair_citations=True)
    assert result["citation_repairs"] == 1 and result["call_attempts"] == 3
    assert read(output / "calls/s0001.triage/reply.json")["attempt"] == 3
    assert read(output / "findings.json")[0]["verdict"] == "rejected"


@pytest.mark.parametrize(
    "case",
    read(REPLAY.parent / "citation-failure-cases.json")["cases"],
    ids=lambda case: case["id"],
)
def test_saved_multilanguage_failures_identify_field_and_supplied_source(case):
    with pytest.raises(CitationError) as raised:
        if case["stage"] == "analysis":
            candidates_for_slice(case["rejected_reply"], case["source_slice"])
        else:
            apply_triage(case["candidates"], case["rejected_reply"], case["source_slice"])
    error = raised.value
    assert error.code == case["expected_code"]
    assert error.details["field"] == case["expected_field"]
    assert (
        error.details["first_matching_byte_column"] == case["expected_first_matching_byte_column"]
    )
    context = error.details["source_context"]
    assert error.details["context_status"] == "provided"
    assert context["first_line"] <= error.details["line"] <= context["last_line"]
    assert context["last_line"] - context["first_line"] < 3
    assert len(context["text"].encode()) <= 4096
    original = next(
        f
        for f in case["source_slice"]["fragments"]
        if f["path"] == context["path"]
        and f["first_line"] <= context["first_line"] <= context["last_line"] <= f["last_line"]
    )
    assert context["source_sha256"] == original["source_sha256"]
    start = context["first_line"] - original["first_line"]
    count = context["last_line"] - context["first_line"] + 1
    assert context["text"] == "".join(
        original["text"].splitlines(keepends=True)[start : start + count]
    )


def test_citation_feedback_uses_utf8_columns_and_never_reads_outside_slice(tmp_path):
    from agent_audit_harness.triage import checked_evidence

    frame = {
        "id": "s0001",
        "path": "entry.py",
        "first_line": 20,
        "last_line": 21,
        "text": '값 = "x"; shell(a)\r\n# keep original\r\n',
        "source_sha256": digest("fixture"),
    }
    with pytest.raises(CitationError) as raised:
        checked_evidence({"path": "entry.py", "line": 20, "column": 10, "quote": "shell(a)"}, frame)
    assert raised.value.details["first_matching_byte_column"] == 12
    assert "\r\n" in raised.value.details["source_context"]["text"]
    outside = tmp_path / "outside.py"
    outside.write_text("SYNTHETIC_SECRET\n")
    with pytest.raises(CitationError) as raised:
        candidates_for_slice(
            {"candidates": [{"path": str(outside), "line": 1, "quote": "SYNTHETIC_SECRET"}]}, frame
        )
    assert raised.value.details["context_status"] == "outside_supplied_fragments"
    assert raised.value.details["field"] == "/candidates/0/path"
    assert raised.value.details["source_context"] is None
    assert "SYNTHETIC_SECRET" not in json.dumps(raised.value.details)
    frame.update(text="x" * 4097 + "\n", last_line=20)
    with pytest.raises(CitationError) as raised:
        candidates_for_slice(
            {"candidates": [{"path": "entry.py", "line": 20, "quote": "absent"}]}, frame
        )
    assert raised.value.details["context_status"] == "omitted_byte_budget"
    assert raised.value.details["source_context"] is None


def test_triage_citation_feedback_reports_every_invalid_byte_column():
    source_slice = make_slices(index_target(DEMO)[0], 16000)[0][0]
    candidates = candidates_for_slice(read(REPLAY / "s0001.analysis.json"), source_slice)
    triage = read(REPLAY / "s0001.triage.json")
    evidence = triage["groups"][0]["decisions"][0]["counterevidence"]
    evidence[:] = [
        {
            "claim": f"The copy call is proposed evidence {number}.",
            "evidence": {
                "path": "bounded.c",
                "line": 8,
                "column": 1,
                "quote": "memcpy(buf, data, length);",
            },
        }
        for number in range(9)
    ]
    with pytest.raises(CitationError) as raised:
        apply_triage(candidates, triage, source_slice)
    details = raised.value.details
    assert [item["field"] for item in details["errors"]] == [
        f"/groups/0/decisions/0/counterevidence/{number}/evidence/column" for number in range(8)
    ]
    assert all(item["exact_quote_matches"][0]["column"] == 5 for item in details["errors"])
    assert details["omitted_error_count"] == 1


def test_citation_feedback_preserves_low_level_fragments_without_hashes():
    from agent_audit_harness.pipeline import validate_evidence

    fragments = [{"path": "x.py", "first_line": 10, "last_line": 10, "text": "actual\n"}]
    with pytest.raises(CitationError) as raised:
        validate_evidence({"path": "x.py", "line": 10, "quote": "absent"}, fragments)
    assert raised.value.details["source_context"]["text"] == "actual\n"
    assert raised.value.details["source_context"]["source_sha256"] is None
    with pytest.raises(CitationError) as raised:
        validate_evidence({"path": "x.py", "line": 11, "quote": "actual"}, fragments)
    assert raised.value.details["field"] == "/evidence/line"
    assert raised.value.details["source_context"] is None


@pytest.mark.parametrize(
    "change,outcome", [("withdraw", "candidates_withdrawn"), ("reasoning", "reply_revised")]
)
def test_repair_does_not_count_withdrawal_or_changed_reasoning_as_citation_only(
    tmp_path, change, outcome
):
    class ChangedRepair:
        identity = {"provider": "replay"}

        def call(self, stage, slice_id, prompt, schema, directory):
            data = ReplayAgent(REPAIR_REPLAY).call(stage, slice_id, prompt, schema, directory).data
            if slice_id.endswith(".r0001"):
                if change == "withdraw":
                    data = {"candidates": []}
                else:
                    data["candidates"][0]["reasoning"] = (
                        "Revised hypothesis after checking the source."
                    )
            return Reply(data)

    result = run_pipeline(
        DEMO, tmp_path / "run", ChangedRepair(), max_slices=1, repair_citations=True
    )
    assert result["citation_repair_outcomes"] == {outcome: 1}
    assert result["unique_candidates"] == (0 if change == "withdraw" else 1)
    assert "Candidate withdrawal" in (tmp_path / "run/report.md").read_text()


def test_repair_outcome_keeps_triage_judgment_changes_separate():
    before = {
        "groups": [
            {
                "root_cause": {
                    "evidence": {"path": "x.py", "line": 1, "column": 3, "quote": "code"}
                },
                "decisions": [{"candidate_id": "known", "verdict": "uncertain"}],
            }
        ]
    }
    after = copy.deepcopy(before)
    after["groups"][0]["root_cause"]["evidence"]["column"] = 1
    assert citation_repair_outcome(before, after) == "citation_corrected"
    after["groups"][0]["decisions"][0]["verdict"] = "needs_validation"
    assert citation_repair_outcome(before, after) == "reply_revised"


def test_resume_recomputes_feedback_even_if_two_saved_copies_are_changed(tmp_path):
    output = tmp_path / "run"
    agent = ReplayAgent(REPAIR_REPLAY)
    run_pipeline(DEMO, output, agent, max_slices=1, repair_citations=True)
    call = output / "calls/s0001.analysis"
    for path in (call / "citation-repair.json", call / "attempt-0001/failure.json"):
        record = read(path)
        record["citation_details"]["source_context"]["text"] = "fabricated context"
        path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="rejection changed"):
        run_pipeline(DEMO, output, agent, max_slices=1, repair_citations=True, resume=True)
    assert read(output / "manifest.json")["call_attempts"] == 3


def test_exact_occurrences_deduplicate_and_triage_requires_complete_known_ids():
    source_slice = make_slices(index_target(DEMO)[0], 16000)[0][0]
    data = read(REPLAY / "s0001.analysis.json")
    data["candidates"].append(copy.deepcopy(data["candidates"][0]))
    candidates = candidates_for_slice(data, source_slice)
    assert len(candidates) == 1
    triage = read(REPLAY / "s0001.triage.json")
    assert apply_triage(candidates, triage, source_slice)[0]["verdict"] == "rejected"
    for invalid in (
        {"groups": []},
        {"groups": triage["groups"] * 2},
        {
            "groups": [
                {
                    **triage["groups"][0],
                    "decisions": [
                        {
                            **triage["groups"][0]["decisions"][0],
                            "candidate_id": "f-0000000000000000",
                        }
                    ],
                }
            ]
        },
    ):
        with pytest.raises(ValueError, match="exactly one"):
            apply_triage(candidates, invalid, source_slice)


def test_confirmed_verdict_is_not_part_of_agent_contract():
    data = read(REPLAY / "s0001.triage.json")
    data["groups"][0]["decisions"][0]["verdict"] = "confirmed"
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
    findings[0]["counterevidence"][0]["claim"] = '<img src="https://example.invalid/track">'
    findings[0]["counterevidence"][0]["evidence"]["quote"] = (
        "![image](https://example.invalid/track)"
    )
    clusters = read(output / "clusters.json")
    next(c for c in clusters if c["root_cause"])["root_cause"]["fix"]["description"] = (
        "![image](https://example.invalid/track)"
    )
    report = report_text(
        findings, read(output / "coverage.json"), read(output / "metrics.json"), True, clusters
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
