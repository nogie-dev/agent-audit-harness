import copy
import hashlib
import json
from pathlib import Path

import pytest
from test_validation import IMAGE
from test_validation import engine as shared_engine

from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.cli import main
from agent_audit_harness.judgment import candidate_issues, judge
from agent_audit_harness.pipeline import digest, encode, run_pipeline
from agent_audit_harness.validation import validate

ROOT = Path(__file__).resolve().parents[1]
ENTRY = "TARGET guest stdout ENTRY request-handler\n"
CONTROL = (
    "TARGET admin stdout ENTRY request-handler\nTARGET admin stdout DATA private-record\n"
    "CONTROL admin passed\n"
)
POSITIVE = (
    ENTRY
    + "TARGET guest stdout DATA private-record\n"
    + CONTROL
    + "ORACLE unauthorized-read\nCHECK complete\n"
)
NEGATIVE = (
    ENTRY + "TARGET guest stdout DENIED\n" + CONTROL + "ORACLE access-denied\nCHECK complete\n"
)


def read(path):
    return json.loads(path.read_text())


@pytest.fixture
def engine(monkeypatch):
    return shared_engine.__wrapped__(monkeypatch)


@pytest.fixture
def scenario(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    for source in (ROOT / "examples/judgment-target").iterdir():
        (target / source.name).write_bytes(source.read_bytes())
    review = tmp_path / "review"
    run_pipeline(target, review, ReplayAgent(ROOT / "examples/judgment-replay"))
    return target, review, tmp_path


def execute(scenario, engine, *, fixed=False, modify=None, stdout=None, name=None):
    target, review, root = scenario
    kind = "fixed" if fixed else "baseline"
    recipe = read(ROOT / f"examples/judgment-{kind}-recipe.json")
    if modify:
        modify(recipe)
    name = name or kind
    recipe_file = root / f"{name}-recipe.json"
    recipe_file.write_text(encode(recipe))
    output = root / name
    engine.stdout = stdout if stdout is not None else (NEGATIVE if fixed else POSITIVE)
    result = validate(target, review, recipe_file, output, image=IMAGE)
    assert result["cleanup"]["status"] in {"removed", "not_created", "failed"}
    return output, result


def assessment(scenario, baseline, fixed=None):
    return judge(baseline, scenario[2] / "judgment", fixed=fixed)


def reseal(directory, mutate):
    """Offline contract cases only; does not fabricate an actual Docker execution."""
    result = read(directory / "result.json")
    mutate(result)
    for evidence in result["evidence"]:
        data = (directory / evidence["path"]).read_bytes()
        evidence.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    result["identity_sha256"] = digest({k: v for k, v in result.items() if k != "identity_sha256"})
    (directory / "result.json").write_text(encode(result))


def test_full_gates_promote_and_preserve_candidate_issues_and_source_changes(scenario, engine):
    baseline, original = execute(scenario, engine)
    fixed, updated = execute(scenario, engine, fixed=True)
    before = {p: p.read_bytes() for p in scenario[0].iterdir()}
    decision = assessment(scenario, baseline, fixed)
    assert decision["status"] == "complete" and decision["verdict"] == "validated"
    assert decision["promotion"]["eligible"] and decision["validated_findings"] == 1
    assert not decision["promotion"]["blockers"]
    assert decision["promotion"]["requirements"] == {
        "reproduction": True,
        "entrypoint": True,
        "fix_comparison": True,
    }
    assert all(i["resolved"] and i["detail"]["evidence"] is None for i in decision["issues"])
    assert decision["candidate"] == read(baseline / "candidate.json")
    assert decision["candidate"]["verdict"] == "uncertain" and decision["candidate"]["unresolved"]
    assert original["confirmed_findings"] == updated["confirmed_findings"] == 0
    assert read(scenario[1] / "findings.json")[0]["verdict"] == "uncertain"
    assert before == {p: p.read_bytes() for p in scenario[0].iterdir()}
    assert (fixed / "reviewed-input/app.sh").read_bytes() == before[scenario[0] / "app.sh"]
    assert (fixed / "input/app.sh").read_bytes() != before[scenario[0] / "app.sh"]
    assert "content" not in decision["comparison"]["changes"][0]
    assert decision["identity_sha256"] == digest(
        {k: v for k, v in decision.items() if k != "identity_sha256"}
    )
    assert decision["runs"]["baseline"]["observations"]["reproduced"]["lines"] == [6]


def test_exit_zero_without_an_oracle_is_execution_only(scenario, engine):
    baseline, _ = execute(scenario, engine, modify=lambda r: r.pop("oracle"))
    decision = assessment(scenario, baseline)
    assert decision["verdict"] == "execution_only" and not decision["promotion"]["eligible"]
    assert len(decision["issues"]) == 2 and not any(i["resolved"] for i in decision["issues"])


@pytest.mark.parametrize(
    "stdout,verdict",
    [
        ("all tests passed\nCHECK complete\n", "execution_only"),
        ("ORACLE unauthorized-read\n", "inconclusive"),
        (POSITIVE + "ORACLE access-denied\n", "inconclusive"),
        (POSITIVE + "ORACLE unauthorized-read\n", "inconclusive"),
        (POSITIVE.replace("CHECK complete\n", "CHECK complete"), "inconclusive"),
        (
            POSITIVE.replace(
                "ORACLE unauthorized-read\n", "some ORACLE unauthorized-read suffix\n"
            ),
            "execution_only",
        ),
        ("CHECK complete\nORACLE unauthorized-read\n", "inconclusive"),
    ],
)
def test_success_and_partial_conflicting_or_out_of_order_logs_do_not_promote(
    scenario, engine, stdout, verdict
):
    baseline, _ = execute(scenario, engine, stdout=stdout)
    decision = assessment(scenario, baseline)
    assert decision["verdict"] == verdict and not decision["promotion"]["eligible"]


@pytest.mark.parametrize(
    "kind,stdout",
    [
        ("direct_call", POSITIVE),
        ("entrypoint", POSITIVE.replace(ENTRY, "")),
        ("entrypoint", POSITIVE.replace(ENTRY, "") + ENTRY),
        ("entrypoint", ENTRY + POSITIVE),
    ],
)
def test_direct_call_missing_or_late_runtime_entrypoint_never_promotes(
    scenario, engine, kind, stdout
):
    def modify(recipe):
        recipe["oracle"]["entrypoint"].update(kind=kind)

    baseline, _ = execute(scenario, engine, modify=modify, stdout=stdout)
    fixed, _ = execute(scenario, engine, fixed=True, modify=modify)
    decision = assessment(scenario, baseline, fixed)
    assert decision["runs"]["baseline"]["outcome"] == "reproduced"
    assert not decision["runs"]["baseline"]["entrypoint_reached"]
    assert not decision["promotion"]["eligible"]
    assert "actual_entrypoint_not_observed" in decision["promotion"]["blockers"]


def test_reproduction_without_fix_preserves_the_unresolved_comparison(scenario, engine):
    baseline, _ = execute(scenario, engine)
    decision = assessment(scenario, baseline)
    assert decision["verdict"] == "inconclusive"
    assert decision["runs"]["baseline"]["outcome"] == "reproduced"
    assert sum(i["resolved"] for i in decision["issues"]) == 1
    assert "fixed_run_missing" in decision["promotion"]["blockers"]


def test_fixed_case_that_still_reproduces_does_not_promote(scenario, engine):
    baseline, _ = execute(scenario, engine)
    fixed, _ = execute(scenario, engine, fixed=True, stdout=POSITIVE)
    decision = assessment(scenario, baseline, fixed)
    assert not decision["comparison"]["fix_verified"] and decision["verdict"] == "inconclusive"


@pytest.mark.parametrize(
    "change", ["command", "image", "limits", "oracle", "review", "worker", "engine", "no_change"]
)
def test_non_equivalent_comparisons_are_inconclusive(scenario, engine, change):
    baseline, _ = execute(scenario, engine)

    def modify(recipe):
        if change == "command":
            recipe["command"].append("different-input")
        elif change == "limits":
            recipe["limits"]["timeout_seconds"] = 11
        elif change == "oracle":
            recipe["oracle"]["description"] = "changed oracle"
        elif change == "no_change":
            recipe.pop("replacements")

    fixed, _ = execute(scenario, engine, fixed=True, modify=modify)

    def mutation(result):
        if change == "image":
            result["identity"]["image"] = result["image"] = "sha256:" + "b" * 64
        elif change in {"review", "worker"}:
            result["identity"][change + "_sha256"] = "b" * 64
        elif change == "engine":
            result["engine"]["version"] = "other"

    if change in {"image", "review", "worker", "engine"}:
        if change == "image":
            policy = read(fixed / "policy.json")
            policy["image"] = "sha256:" + "b" * 64
            (fixed / "policy.json").write_text(encode(policy))
        reseal(fixed, mutation)
    decision = assessment(scenario, baseline, fixed)
    assert decision["verdict"] == "inconclusive" and not decision["promotion"]["eligible"]


@pytest.mark.parametrize("fixed", [False, True])
@pytest.mark.parametrize(
    "failure", ["timeout", "output_limit", "oom", "unexpected_exit", "cleanup"]
)
def test_operational_failures_are_not_reproduction_or_a_successful_fix(
    scenario, engine, fixed, failure
):
    if fixed:
        baseline, _ = execute(scenario, engine)
    if failure in {"timeout", "output_limit"}:
        engine.reason = failure
    if failure == "oom":
        engine.oom = True
        engine.exit_code = 137
    if failure == "unexpected_exit":
        engine.exit_code = 23
    if failure == "cleanup":
        engine.fail_stage = "cleanup"
    output, _ = execute(scenario, engine, fixed=fixed)
    decision = assessment(scenario, baseline if fixed else output, output if fixed else None)
    assert decision["verdict"] == "inconclusive" and not decision["promotion"]["eligible"]


def test_declared_test_failure_can_reproduce_with_complete_oracle_evidence(scenario, engine):
    def modify(recipe):
        recipe["oracle"]["expected_exit_codes"] = [0, 23]

    engine.exit_code = 23
    baseline, _ = execute(scenario, engine, modify=modify)
    engine.exit_code = 0
    fixed, _ = execute(scenario, engine, fixed=True, modify=modify)
    assert assessment(scenario, baseline, fixed)["verdict"] == "validated"


def test_negative_case_does_not_reject_the_original_candidate(scenario, engine):
    baseline, _ = execute(scenario, engine, stdout=NEGATIVE)
    decision = assessment(scenario, baseline)
    assert decision["verdict"] == "not_reproduced" and not decision["promotion"]["eligible"]
    assert decision["candidate"]["verdict"] == "uncertain" and decision["candidate"]["unresolved"]


@pytest.mark.parametrize(
    "kind",
    [
        "unresolved",
        "counterevidence",
        "gap",
        "static_gap_ids",
        "model_gap_ids",
        "model_static_gap_ids",
        "recon_gap_ids",
        "import_gap_ids",
        "modifier_gap_function_ids",
        "omitted",
    ],
)
def test_unaddressed_evidence_blocks_promotion_and_is_preserved(scenario, engine, kind):
    findings = read(scenario[1] / "findings.json")
    candidate = findings[0]
    if kind in {"unresolved", "counterevidence"}:
        candidate[kind].append(
            {"claim": "Deployment input is not covered by this test.", "evidence": None}
        )
        if kind == "counterevidence":
            candidate[kind][-1]["evidence"] = {
                "path": "app.sh",
                "line": 2,
                "column": 1,
                "quote": "serve_request() {",
                "source_sha256": candidate["source_sha256"],
            }
    elif kind == "gap":
        candidate["input_gaps"]["unresolved_call_ids"] = ["call-unresolved"]
    elif kind.endswith("_ids"):
        candidate["input_gaps"][kind] = ["query-function-limit"]
    else:
        candidate["input_gaps"]["omitted_counts"] = {"functions": 2}
    for file in ("findings.json", "validation-queue.json"):
        (scenario[1] / file).write_text(encode(findings))
    baseline, _ = execute(scenario, engine)
    fixed, _ = execute(scenario, engine, fixed=True)
    decision = assessment(scenario, baseline, fixed)
    assert decision["comparison"]["fix_verified"]
    assert decision["verdict"] == "inconclusive" and not decision["promotion"]["eligible"]
    assert decision["candidate"] == candidate
    assert len(decision["issues"]) == 3
    assert sum(not i["resolved"] for i in decision["issues"]) == 1


@pytest.mark.parametrize(
    "change",
    [
        "harness",
        "before_hash",
        "after_hash",
        "unreviewed",
        "duplicate",
        "source_quote",
        "entry_quote",
        "invocation",
        "unknown_issue",
        "duplicate_issue",
        "marker_collision",
        "inline_command",
    ],
)
def test_invalid_oracles_and_replacements_fail_before_execution(scenario, engine, change):
    def modify(recipe):
        replacement = recipe["replacements"][0]
        if change == "harness":
            probe = (scenario[0] / "probe.sh").read_bytes()
            recipe["replacements"].append(
                {
                    "path": "probe.sh",
                    "before_sha256": hashlib.sha256(probe).hexdigest(),
                    "after_sha256": hashlib.sha256(probe + b"# changed\n").hexdigest(),
                    "content": (probe + b"# changed\n").decode(),
                }
            )
        elif change in {"before_hash", "after_hash"}:
            replacement[change.replace("hash", "sha256")] = "b" * 64
        elif change == "unreviewed":
            replacement["path"] = "missing.sh"
        elif change == "duplicate":
            recipe["replacements"].append(copy.deepcopy(replacement))
        elif change == "source_quote":
            recipe["oracle"]["source"]["quote"] = "invented quote"
        elif change == "entry_quote":
            recipe["oracle"]["entrypoint"]["source"]["quote"] = "invented entry"
        elif change == "invocation":
            recipe["oracle"]["entrypoint"]["invocation"]["path"] = "app.sh"
        elif change == "unknown_issue":
            recipe["oracle"]["resolutions"][0]["issue_id"] = "vi-" + "b" * 16
        elif change == "duplicate_issue":
            recipe["oracle"]["resolutions"].append(
                copy.deepcopy(recipe["oracle"]["resolutions"][0])
            )
        elif change == "marker_collision":
            recipe["oracle"]["not_reproduced"] = copy.deepcopy(recipe["oracle"]["reproduced"])
        else:
            recipe["command"] = ["/bin/sh", "-c", "printf spoofed-evidence"]

    output, result = execute(scenario, engine, fixed=True, modify=modify)
    assert result["status"] == "worker_failed" and not result["execution_attempted"]
    assert not engine.calls and read(output / "result.json")["failure"]


@pytest.mark.parametrize(
    "path",
    [
        "result.json",
        "recipe.json",
        "candidate.json",
        "source-manifest.json",
        "input/app.sh",
        "logs/execute.stdout.log",
        "state.json",
        "policy.json",
    ],
)
def test_corrupt_evidence_is_never_promoted(scenario, engine, path):
    baseline, _ = execute(scenario, engine)
    (baseline / path).chmod(0o644)
    (baseline / path).write_bytes((baseline / path).read_bytes() + b" ")
    if path == "result.json":
        result = read(baseline / path)
        result["exit_code"] = 9
        (baseline / path).write_text(encode(result))
    decision = assessment(scenario, baseline)
    assert decision["status"] == "failed" and decision["verdict"] == "inconclusive"
    assert decision["failure"] and not decision["promotion"]["eligible"]


def test_symlink_evidence_and_unfinished_controller_result_are_rejected(scenario, engine):
    baseline, _ = execute(scenario, engine)
    original = scenario[2] / "outside"
    original.write_bytes((baseline / "logs/execute.stdout.log").read_bytes())
    (baseline / "logs/execute.stdout.log").unlink()
    (baseline / "logs/execute.stdout.log").symlink_to(original)
    assert assessment(scenario, baseline)["status"] == "failed"
    result = read(baseline / "result.json")
    result.pop("identity_sha256")
    (baseline / "result.json").write_text(encode(result))
    decision = judge(baseline, scenario[2] / "unfinished")
    assert decision["status"] == "failed" and not decision["promotion"]["eligible"]


def test_invalid_fixed_evidence_keeps_baseline_claims(scenario, engine):
    baseline, _ = execute(scenario, engine)
    fixed, _ = execute(scenario, engine, fixed=True)
    (fixed / "state.json").write_text("{}")
    decision = assessment(scenario, baseline, fixed)
    assert decision["status"] == "failed" and decision["candidate"]["unresolved"]
    assert len(decision["issues"]) == 2 and not any(i["resolved"] for i in decision["issues"])


def test_judgment_cli_and_output_boundaries(scenario, engine, capsys):
    baseline, _ = execute(scenario, engine)
    fixed, _ = execute(scenario, engine, fixed=True)
    output = scenario[2] / "judgment"
    assert main(["judge", str(baseline), "--fixed", str(fixed), "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "validated"
    for forbidden in (baseline / "output", fixed / "output", scenario[0] / "output", output):
        with pytest.raises(ValueError):
            judge(baseline, forbidden, fixed=fixed)
    assert not (scenario[0] / "output").exists()


def test_issue_ids_are_stable_and_zero_omissions_are_not_issues():
    candidate = {
        "unresolved": [{"claim": "unknown", "evidence": None}],
        "input_gaps": {
            "coverage_ref": "coverage.json",
            "static_gap_ids": ["g1"],
            "omitted_counts": {"functions": 0},
        },
    }
    first = candidate_issues(candidate)
    assert first == candidate_issues(copy.deepcopy(candidate)) and len(first) == 2


def test_direct_reproduction_is_a_separate_verdict_even_without_open_issues(scenario, engine):
    candidate = read(scenario[1] / "findings.json")[0]
    candidate.update(verdict="needs_validation", unresolved=[])
    for file in ("findings.json", "validation-queue.json"):
        (scenario[1] / file).write_text(encode([candidate]))

    def modify(recipe):
        recipe["oracle"]["resolutions"] = []
        recipe["oracle"]["entrypoint"]["kind"] = "direct_call"

    baseline, _ = execute(scenario, engine, modify=modify)
    decision = assessment(scenario, baseline)
    assert decision["verdict"] == "reproduced" and not decision["promotion"]["eligible"]
    assert not decision["runs"]["baseline"]["entrypoint_reached"]


def test_order_between_different_streams_is_not_assumed(scenario, engine):
    engine.stderr = "ENTRY request-handler\n"

    def modify(recipe):
        recipe["oracle"]["entrypoint"]["observation"]["stream"] = "stderr"

    baseline, _ = execute(scenario, engine, modify=modify)
    fixed, _ = execute(scenario, engine, fixed=True, modify=modify)
    assert not assessment(scenario, baseline, fixed)["promotion"]["eligible"]


def test_untrusted_resolved_boolean_is_rejected_before_execution(scenario, engine):
    def modify(recipe):
        recipe["oracle"]["resolutions"][0]["resolved"] = True

    _, result = execute(scenario, engine, modify=modify)
    assert result["status"] == "worker_failed" and not engine.calls


def test_preparation_failure_without_candidate_remains_inconclusive(scenario):
    target, review, root = scenario
    output = root / "baseline"
    result = validate(
        target, review, ROOT / "examples/judgment-baseline-recipe.json", output, image="invalid"
    )
    decision = assessment(scenario, output)
    assert decision["status"] == "complete" and decision["verdict"] == "inconclusive"
    assert decision["candidate"] is None and not decision["promotion"]["eligible"]
    assert decision["runs"]["baseline"]["worker_failure"] == result["failure"]


def test_counterevidence_is_retained_after_an_evidenced_resolution(scenario, engine):
    candidate = read(scenario[1] / "findings.json")[0]
    candidate["counterevidence"] = [
        {
            "claim": "The public dispatcher might not be used.",
            "evidence": {
                "path": "app.sh",
                "line": 7,
                "column": 1,
                "quote": 'serve_request "$1"',
                "source_sha256": candidate["source_sha256"],
            },
        }
    ]
    for file in ("findings.json", "validation-queue.json"):
        (scenario[1] / file).write_text(encode([candidate]))
    issue = next(i for i in candidate_issues(candidate) if i["kind"] == "counterevidence")

    def modify(recipe):
        recipe["oracle"]["resolutions"].append(
            {
                "issue_id": issue["id"],
                "requirement": "entrypoint",
                "rationale": (
                    "The unchanged CLI probe invokes the public dispatcher "
                    "and observes entry before outcome."
                ),
            }
        )

    baseline, _ = execute(scenario, engine, modify=modify)
    fixed, _ = execute(scenario, engine, fixed=True, modify=modify)
    decision = assessment(scenario, baseline, fixed)
    assert decision["verdict"] == "validated"
    retained = next(i for i in decision["issues"] if i["id"] == issue["id"])
    assert retained["resolved"] and retained["detail"] == candidate["counterevidence"][0]
    assert retained["evidence_refs"] == [{"run": "baseline", "observation": "entrypoint"}]


@pytest.mark.parametrize(
    "field,value",
    [
        ("Running", True),
        ("Error", "runtime failure"),
        ("Status", "created"),
        ("StartedAt", "0001-01-01T00:00:00Z"),
    ],
)
def test_inconsistent_terminal_state_does_not_promote(scenario, engine, field, value):
    baseline, _ = execute(scenario, engine)
    state = read(baseline / "state.json")
    state[field] = value
    (baseline / "state.json").write_text(encode(state))
    reseal(baseline, lambda r: None)
    assert assessment(scenario, baseline)["verdict"] == "inconclusive"


def test_malformed_result_is_recorded_as_invalid_evidence(scenario):
    baseline = scenario[2] / "baseline"
    baseline.mkdir()
    (baseline / "result.json").write_text("[]")
    decision = assessment(scenario, baseline)
    assert decision["status"] == "failed" and not decision["promotion"]["eligible"]
