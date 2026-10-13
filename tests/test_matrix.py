"""Build cases use recorded Docker responses; no target is compiled or executed here."""

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_validation import IMAGE
from test_validation import engine as shared_engine

from agent_audit_harness import matrix
from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.cli import main
from agent_audit_harness.intake import import_review
from agent_audit_harness.judgment import judge
from agent_audit_harness.matrix import judge_matrix, prepare_matrix, validate_matrix
from agent_audit_harness.pipeline import digest, encode, index_target
from agent_audit_harness.poc import propose_poc, review_poc
from agent_audit_harness.validation import validate

ROOT = Path(__file__).resolve().parents[1]
CID = "f-7d72725d4bf39b4b"


def read(path):
    return json.loads(path.read_text())


def write(path, data):
    path.write_text(encode(data))


@pytest.fixture
def scenario(tmp_path, request):
    target, review, proposal, approved, output = [
        tmp_path / n for n in ("target", "review", "proposal", "approved", "matrix")
    ]
    shutil.copytree(ROOT / "examples/matrix-target", target)
    support = getattr(request, "param", None) == "support"
    if support:
        (target / "support.c").write_text("int support(void) { return 1; }\n")
    import_spec = ROOT / "examples/matrix-candidate-import.json"
    if support:
        changed = read(import_spec)
        changed["source_index_sha256"] = digest([s.metadata() for s in index_target(target)[0]])
        import_spec = tmp_path / "candidate-import.json"
        write(import_spec, changed)
    import_review(target, import_spec, review)
    replay = ROOT / "examples/matrix-replay"
    if support:
        replay = tmp_path / "replay"
        replay.mkdir()
        response = read(ROOT / "examples/matrix-replay/p0001.poc.json")
        response["recipe"]["oracle"]["resolutions"] = []
        write(replay / "p0001.poc.json", response)
    agent = ReplayAgent(replay)
    propose_poc(
        target, review, CID, proposal, agent, support_paths=("support.c",) if support else ()
    )
    receipt = review_poc(
        target,
        review,
        proposal,
        approved,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Synthetic build contract review; not an actual approval or execution.",
    )
    recipe = read(approved / "recipe.json")
    fixed = {**recipe, "replacements": [read(ROOT / "examples/matrix-fix.json")]}
    fixed_file, spec_file = tmp_path / "fixed-recipe.json", tmp_path / "matrix-spec.json"
    write(fixed_file, fixed)
    spec = {
        "schema_version": 1,
        "poc_review": "approved",
        "poc_review_sha256": receipt["identity_sha256"],
        "recipe_sha256": digest(recipe),
        "fixed_recipe": "fixed-recipe.json",
        "fixed_recipe_sha256": digest(fixed),
        "cases": [{"id": "release", "image": IMAGE}, {"id": "guarded", "image": IMAGE}],
    }
    write(spec_file, spec)
    return target, review, approved, spec_file, output


def transcript(case, fixed=False):
    setting = (
        "optimization=enabled guard=0" if case == "release" else "optimization=disabled guard=1"
    )
    config = "CONFIG " + setting + "\n"
    private = case == "release" and not fixed
    guest = (
        config + "ENTRY request-handler\n" + ("DATA private-record\n" if private else "DENIED\n")
    )
    admin = config + "ENTRY request-handler\nDATA private-record\n"
    text = ""
    for name, value in (("guest", guest), ("admin", admin)):
        text += f"TARGET {name} bytes " + base64.b64encode(value.encode()).decode() + "\n"
        text += "".join(f"TARGET {name} stdout {line}\n" for line in value.splitlines())
    return (
        text
        + "CONTROL admin passed\n"
        + ("ORACLE unauthorized-read\n" if private else "ORACLE access-denied\n")
        + "CHECK complete\n"
    )


@pytest.fixture
def engine(monkeypatch):
    base = shared_engine.__wrapped__(monkeypatch)
    base.mutate_output = lambda text, case, phase: text

    def run(command, cwd, environment, prefix, timeout, byte_limit):
        if prefix.name == "execute":
            identity = read(prefix.parents[1] / "result.json")["identity"]
            case = identity["configuration_id"]
            phase = prefix.parents[1].name
            base.stdout = base.mutate_output(transcript(case, phase == "fixed"), case, phase)
        return base(command, cwd, environment, prefix, timeout, byte_limit)

    monkeypatch.setattr("agent_audit_harness.validation.bounded_process", run)
    return base


def prepared(scenario):
    target, review, _, spec, output = scenario
    prepare_matrix(target, review, spec, output)
    return output


@pytest.mark.parametrize("scenario", ["support"], indirect=True)
def test_matrix_rechecks_source_bound_support_files(scenario):
    output = prepared(scenario)
    proposal = read(output / "poc-review/proposal.json")
    assert proposal["context"]["support_paths"] == ["support.c"]
    execution = validate_matrix(output, max_runs=0)
    assert execution["run_attempts"] == 0


def test_matrix_freezes_approved_inputs_and_preserves_missing_cases_without_processes(
    scenario, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("preparation/judgment must not start a process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    output = prepared(scenario)
    assert read(output / "matrix-input.json") == read(scenario[3])
    assert read(output / "recipe.json") == read(scenario[2] / "recipe.json")
    report = judge_matrix(output, output.parent / "report")
    assert not report["coverage_complete"] and not report["validated_cases"]
    assert len(report["cases"]) == 2 and all(c["status"] == "missing" for c in report["cases"])
    assert report["candidate"]["verdict"] == "uncertain" and report["cases"][0]["issues"]
    assert not (output / "execution.json").exists()


def test_two_build_cases_use_same_harness_and_fix_but_independent_gates(scenario, engine):
    output = prepared(scenario)
    target_before = (scenario[0] / "app.c").read_bytes()
    execution = validate_matrix(output)
    report = judge_matrix(output, output.parent / "report")
    assert execution["status"] == "complete" and execution["run_attempts"] == 4
    assert report["coverage_complete"] and report["validated_cases"] == ["release"]
    release, guarded = report["cases"]
    assert release["verdict"] == "validated" and guarded["verdict"] == "not_reproduced"
    assert release["judgment"]["promotion"]["requirements"]["configuration"]
    for issue in release["judgment"]["issues"]:
        for ref in issue["evidence_refs"]:
            assert release["judgment"]["runs"][ref["run"]]["observations"][ref["observation"]][
                "unique"
            ]
    assert any(not i["resolved"] for i in guarded["judgment"]["issues"])
    assert report["candidate"]["verdict"] == "uncertain"
    harnesses = [p.read_bytes() for p in output.glob("cases/*/*/input/poc/probe.sh")]
    assert len(harnesses) == 4 and all(h == harnesses[0] for h in harnesses)
    creates = [c[1] for c in engine.calls if c[0] == "create"]
    assert [c[-1] for c in creates] == ["release", "release", "guarded", "guarded"]
    assert all(c[c.index("--network") + 1] == "none" for c in creates)
    assert (scenario[0] / "app.c").read_bytes() == target_before


@pytest.mark.parametrize(
    "case", ["missing", "wrong", "duplicate", "after_outcome", "control_failed", "spoofed_request"]
)
def test_setting_labels_mismatch_or_failed_controls_block_only_that_case(scenario, engine, case):
    def mutate(text, selected, phase):
        if selected != "release":
            return text
        line = "TARGET guest stdout CONFIG optimization=enabled guard=0\n"
        if case == "missing":
            return text.replace(line, "")
        if case == "wrong":
            return text.replace(line, "TARGET guest stdout CONFIG optimization=disabled guard=1\n")
        if case == "duplicate":
            return text.replace(line, line * 2)
        if case == "after_outcome":
            return text.replace(line, "").replace("CHECK complete\n", line + "CHECK complete\n")
        if case == "control_failed":
            return text.replace("ORACLE unauthorized-read\n", "").replace(
                "CONTROL admin passed", "CONTROL admin failed"
            )
        return text.replace(line, "REQUESTED " + line)

    engine.mutate_output = mutate
    output = prepared(scenario)
    validate_matrix(output)
    report = judge_matrix(output, output.parent / "report")
    assert not report["validated_cases"] and not report["coverage_complete"]
    assert report["cases"][1]["judgment"]["runs"]["baseline"]["configuration"]["applied"]
    assert not report["cases"][0]["judgment"]["promotion"]["eligible"]


@pytest.mark.parametrize("budget", [0, 1, 3])
def test_partial_run_budget_preserves_every_case_and_never_restarts(scenario, engine, budget):
    output = prepared(scenario)
    execution = validate_matrix(output, max_runs=budget)
    assert execution["status"] == "partial" and execution["run_attempts"] == budget
    assert len([c for c in engine.calls if c[0] == "execute"]) == budget
    report = judge_matrix(output, output.parent / "report")
    assert len(report["cases"]) == 2 and not report["coverage_complete"]
    assert any(c["status"] == "missing" for c in report["cases"])
    assert report["validated_cases"] == (["release"] if budget == 3 else [])
    with pytest.raises(ValueError, match="already started"):
        validate_matrix(output)


@pytest.mark.parametrize("failure", ["timeout", "process", "cleanup", "policy", "unknown_state"])
def test_worker_failures_keep_raw_issues_and_cleanup_failure_stops_remaining_runs(
    scenario, engine, failure
):
    if failure == "timeout":
        engine.reason = "timeout"
    elif failure == "process":
        engine.exit_code = 1
    elif failure == "cleanup":
        engine.fail_stage = "cleanup"
    elif failure == "unknown_state":
        engine.fail_stage = "state"
    else:
        engine.policy_change = lambda p: p["host"].update(NetworkMode="host")
    output = prepared(scenario)
    execution = validate_matrix(output)
    report = judge_matrix(output, output.parent / "report")
    assert not report["validated_cases"] and not report["coverage_complete"]
    assert all(c["issues"] for c in report["cases"])
    assert (output / "cases/release/baseline/result.json").exists()
    if failure in {"cleanup", "unknown_state"}:
        assert (
            execution["run_attempts"] == 1
            and execution["stop_reason"] == "cleanup_or_execution_unknown"
        )
        assert all(c["status"] == "missing" for c in report["cases"])
    elif failure == "policy":
        assert not any(c[0] == "execute" for c in engine.calls)
    else:
        assert report["cases"][0]["judgment"]["issues"]


@pytest.mark.parametrize(
    "change",
    [
        "duplicate",
        "missing",
        "unknown",
        "image",
        "review_hash",
        "recipe_hash",
        "fixed_hash",
        "command",
        "observation",
        "extra_field",
    ],
)
def test_invalid_matrix_specs_preserve_raw_failure_and_never_call_docker(scenario, engine, change):
    spec = read(scenario[3])
    if change == "duplicate":
        spec["cases"].append(spec["cases"][0].copy())
    elif change == "missing":
        spec["cases"].pop()
    elif change == "unknown":
        spec["cases"][0]["id"] = "undeclared"
    elif change == "image":
        spec["cases"][0]["image"] = "debian:latest"
    elif change in {"review_hash", "recipe_hash", "fixed_hash"}:
        spec[
            {
                "review_hash": "poc_review_sha256",
                "recipe_hash": "recipe_sha256",
                "fixed_hash": "fixed_recipe_sha256",
            }[change]
        ] = "0" * 64
    elif change in {"command", "observation"}:
        fixed = read(scenario[3].parent / "fixed-recipe.json")
        if change == "command":
            fixed["command"].append("unreviewed")
        else:
            fixed["configurations"][0]["observation"]["line"] = "applied because the model said so"
        write(scenario[3].parent / "fixed-recipe.json", fixed)
        spec["fixed_recipe_sha256"] = digest(fixed)
    else:
        spec["validated"] = True
    write(scenario[3], spec)
    with pytest.raises(ValueError):
        prepared(scenario)
    assert read(scenario[4] / "manifest.json")["status"] == "failed"
    assert (scenario[4] / "matrix-input.json").read_bytes() == scenario[3].read_bytes()
    assert not engine.calls


@pytest.mark.parametrize("change", ["source", "recipe", "receipt", "provider_tool"])
def test_changes_after_preparation_stop_before_docker(scenario, engine, monkeypatch, change):
    output = prepared(scenario)
    if change == "source":
        with (scenario[0] / "app.c").open("a") as stream:
            stream.write("\n/* changed */\n")
    elif change == "recipe":
        write(output / "fixed-recipe.json", {})
    elif change == "receipt":
        receipt = read(output / "poc-review/review.json")
        receipt["decision"] = "request_changes"
        write(output / "poc-review/review.json", receipt)
    else:
        monkeypatch.setattr(matrix, "tool_identity", lambda: {"different": "tool"})
    with pytest.raises(ValueError):
        validate_matrix(output)
    assert not engine.calls and not (output / "cases").exists()


def test_judgment_never_compares_different_selected_configurations(scenario, engine):
    output = prepared(scenario)
    validate_matrix(output)
    decision = judge(
        output / "cases/release/baseline",
        output.parent / "mixed",
        fixed=output / "cases/guarded/fixed",
    )
    assert not decision["comparison"]["comparable"] and not decision["promotion"]["eligible"]


@pytest.mark.parametrize("file", ["input/poc/probe.sh", "poc-review.json", "result.json"])
def test_worker_artifact_changes_are_isolated_in_case_report(scenario, engine, file):
    output = prepared(scenario)
    validate_matrix(output)
    path = output / "cases/release/baseline" / file
    if file.endswith(".sh"):
        path.chmod(0o644)
    path.write_text("{}")
    report = judge_matrix(output, output.parent / "report")
    assert report["cases"][0]["status"] == "invalid" and not report["validated_cases"]
    assert report["cases"][1]["status"] == "judged"


def test_configuration_selection_is_mandatory_and_reviewed(scenario, engine):
    approved = scenario[2]
    for selected in (None, "unknown"):
        result = validate(
            scenario[0],
            scenario[1],
            approved / "recipe.json",
            approved.parent / (selected or "missing"),
            image=IMAGE,
            poc_review=approved,
            configuration_id=selected,
        )
        assert result["status"] == "worker_failed" and not result["execution_attempted"]
    assert not engine.calls


def test_matrix_cli_prepare_bounded_validation_and_nonexecuting_judgment(scenario, engine, capsys):
    target, review, _, spec, output = scenario
    assert (
        main(
            [
                "prepare-matrix",
                str(target),
                "--run",
                str(review),
                "--spec",
                str(spec),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert main(["validate-matrix", str(output), "--max-runs", "0"]) == 1
    assert not engine.calls
    report = output.parent / "cli-report"
    assert main(["judge-matrix", str(output), "--output", str(report)]) == 0
    assert not read(report / "matrix-judgment.json")["coverage_complete"]
    assert '"run_attempts": 0' in capsys.readouterr().out


def test_input_change_between_workers_records_terminal_failure_and_stops(
    scenario, engine, monkeypatch
):
    output = prepared(scenario)
    original = matrix.validate

    def change_after_worker(*args, **kwargs):
        result = original(*args, **kwargs)
        write(output / "fixed-recipe.json", {})
        return result

    monkeypatch.setattr(matrix, "validate", change_after_worker)
    execution = validate_matrix(output)
    assert execution["status"] == "partial" and execution["run_attempts"] == 1
    assert execution["stop_reason"] == "matrix_inputs_changed"
    assert read(output / "execution.json")["status"] == "partial"
    assert len([c for c in engine.calls if c[0] == "execute"]) == 1


def test_controller_interruption_retains_all_declared_cases_without_restart(scenario, monkeypatch):
    output = prepared(scenario)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(matrix, "validate", interrupted)
    with pytest.raises(KeyboardInterrupt):
        validate_matrix(output)
    execution = read(output / "execution.json")
    assert execution["status"] == "interrupted" and execution["run_attempts"] == 1
    assert len(execution["cases"]) == 2
    report = judge_matrix(output, output.parent / "report")
    assert all(c["status"] == "missing" for c in report["cases"])
    assert not report["validated_cases"]


@pytest.mark.skipif(
    not os.environ.get("AUDIT_MATRIX_VALIDATION_IMAGE"),
    reason="explicit prepared C-compiler image required",
)
def test_real_isolated_compiler_matrix(scenario):
    spec = read(scenario[3])
    for case in spec["cases"]:
        case["image"] = os.environ["AUDIT_MATRIX_VALIDATION_IMAGE"]
    write(scenario[3], spec)
    output = prepared(scenario)
    execution = validate_matrix(output)
    report = judge_matrix(output, output.parent / "report")
    assert execution["status"] == "complete" and report["coverage_complete"]
    assert report["validated_cases"] == ["release"]
