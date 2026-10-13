"""Stage receipts gate synthetic worker evidence; no target runs on the host."""

import json

import pytest
from test_validation import IMAGE

from agent_audit_harness.cli import main
from agent_audit_harness.impact import review_impact
from agent_audit_harness.impact_steps import impact_step
from agent_audit_harness.pipeline import digest, encode
from agent_audit_harness.validation import validate

pytest_plugins = ["test_impact_review"]


def read(path):
    return json.loads(path.read_text())


@pytest.fixture
def approved(reviewed):
    judgment, plan, root = reviewed
    directory = root / "approved-impact-plan"
    review_impact(
        "primitive",
        judgment,
        plan,
        directory,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Approve synthetic stage measurements.",
    )
    return directory, root


def stage_output(stage, *, outcome=None):
    entry = "admin" if stage == "control" else "guest"
    result = (
        outcome
        or {
            "setup": "ORACLE setup-ready",
            "primitive": "ORACLE primitive-read",
            "control": "ORACLE control-authorized",
            "impact": "ORACLE impact-private-record",
        }[stage]
    )
    return f"TARGET {entry} stdout ENTRY request-handler\n{result}\nCHECK complete\n"


def worker(approved, engine, stage, *, stdout=None, reason=None, name=None):
    directory, root = approved
    poc = directory / "stages" / stage / "poc-review"
    engine.stdout = stdout if stdout is not None else stage_output(stage)
    engine.reason = reason
    output = root / (name or f"worker-impact-{stage}")
    result = validate(
        root / "target",
        root / "review",
        poc / "recipe.json",
        output,
        image=IMAGE,
        poc_review=poc,
    )
    return output, result


def advance(approved, worker_dir, stage, *, decision="approve", output=None):
    directory, root = approved
    return impact_step(
        directory,
        worker_dir,
        output or root / "impact-checkpoint",
        stage_id=stage,
        decision=decision,
        reviewer="offline-fixture",
        rationale="Review synthetic gate evidence.",
    )


def test_all_four_reviewed_gates_required_for_bounded_impact(approved, engine):
    directory, root = approved
    for index, stage in enumerate(("setup", "primitive", "control", "impact"), 1):
        run, _ = worker(approved, engine, stage)
        if stage == "setup":
            assert (
                main(
                    [
                        "impact-step",
                        str(directory),
                        "--worker",
                        str(run),
                        "--stage",
                        stage,
                        "--decision",
                        "approve",
                        "--reviewer",
                        "offline-fixture",
                        "--rationale",
                        "Synthetic gate review.",
                        "--output",
                        str(root / "impact-checkpoint"),
                    ]
                )
                == 0
            )
            state = read(root / "impact-checkpoint/impact-state.json")
        else:
            state = advance(approved, run, stage)
        assert state["next_stage_index"] == index
        assert len(state["stage_results"]) == index
        assert state["impact_validated"] is (index == 4)
    assert state["status"] == "complete" and state["verdict"] == "impact_observed"
    assert state["attempts"][2]["assessment"]["evaluation"]["outcome"] == "not_reproduced"
    assert state["attempts"][3]["assessment"]["evaluation"]["entrypoint_reached"]
    assert state["identity_sha256"] == digest(
        {key: value for key, value in state.items() if key != "identity_sha256"}
    )


@pytest.mark.parametrize("failure", ["wrong_worker", "timeout", "negative", "tamper"])
def test_failed_gate_is_retained_and_explicit_new_attempt_can_resume(approved, engine, failure):
    directory, root = approved
    stage = "setup"
    if failure == "wrong_worker":
        bad, _ = worker(approved, engine, "primitive", name="wrong-stage-worker")
    else:
        stdout = stage_output(stage)
        if failure == "negative":
            stdout = stdout.replace("ORACLE setup-ready", "ORACLE setup-negative")
        bad, _ = worker(
            approved,
            engine,
            stage,
            stdout=stdout,
            reason="timeout" if failure == "timeout" else None,
            name="failed-stage-worker",
        )
        if failure == "tamper":
            with (bad / "logs/execute.stdout.log").open("a") as stream:
                stream.write("changed\n")
    paused = advance(approved, bad, stage, decision="approve")
    assert paused["status"] == "paused" and paused["next_stage_index"] == 0
    assert not paused["impact_validated"] and paused["attempts"][0]["assessment"]["blockers"]
    good, _ = worker(approved, engine, stage, name="retried-stage-worker")
    resumed = advance(approved, good, stage)
    assert resumed["status"] == "ready" and resumed["next_stage_index"] == 1
    assert len(resumed["attempts"]) == 2 and len(resumed["stage_results"]) == 1
    assert resumed["attempts"][0]["assessment"]["worker"] == str(bad)


def test_wrong_order_duplicate_and_stopped_checkpoint_do_not_advance(approved, engine):
    _, root = approved
    run, _ = worker(approved, engine, "setup")
    with pytest.raises(ValueError, match="out of order"):
        advance(approved, run, "primitive")
    state = advance(approved, run, "setup", decision="retry")
    assert state["status"] == "paused" and state["next_stage_index"] == 0
    with pytest.raises(ValueError, match="already submitted"):
        advance(approved, run, "setup")
    next_run, _ = worker(approved, engine, "setup", name="second-setup-worker")
    stopped = advance(approved, next_run, "setup", decision="reject")
    assert stopped["status"] == "stopped" and not stopped["impact_validated"]
    with pytest.raises(ValueError, match="terminal"):
        advance(approved, root / "third-worker", "setup")


def test_control_negative_observation_is_required_before_impact(approved, engine):
    _, root = approved
    for stage in ("setup", "primitive"):
        run, _ = worker(approved, engine, stage)
        advance(approved, run, stage)
    wrong, _ = worker(
        approved,
        engine,
        "control",
        stdout=stage_output("control", outcome="ORACLE control-denied"),
        name="wrong-control-worker",
    )
    paused = advance(approved, wrong, "control")
    assert paused["status"] == "paused" and paused["next_stage_index"] == 2
    assert not paused["attempts"][-1]["assessment"]["gate_pass"]
    proper, _ = worker(approved, engine, "control", name="proper-control-worker")
    advanced = advance(approved, proper, "control")
    assert advanced["next_stage_index"] == 3 and not advanced["impact_validated"]
    assert len(advanced["attempts"]) == 4


def test_attempt_budget_preserves_every_failed_worker(approved, engine):
    _, root = approved
    for number in range(3):
        run, _ = worker(approved, engine, "setup", reason="timeout", name=f"timeout-{number}")
        state = advance(approved, run, "setup", decision="retry")
        assert state["status"] == "paused" and len(state["attempts"]) == number + 1
    extra, _ = worker(approved, engine, "setup", name="extra-worker")
    with pytest.raises(ValueError, match="budget"):
        advance(approved, extra, "setup")
    assert len(read(root / "impact-checkpoint/impact-state.json")["attempts"]) == 3


def test_changed_prior_worker_or_resealed_checkpoint_blocks_resume(approved, engine):
    _, root = approved
    run, _ = worker(approved, engine, "setup")
    advance(approved, run, "setup")
    state_path = root / "impact-checkpoint/impact-state.json"
    state = read(state_path)
    state["attempts"][0]["assessment"]["gate_pass"] = False
    state["identity_sha256"] = digest(
        {key: value for key, value in state.items() if key != "identity_sha256"}
    )
    state_path.write_text(encode(state))
    next_run, _ = worker(approved, engine, "primitive")
    with pytest.raises(ValueError, match="evidence changed"):
        advance(approved, next_run, "primitive")


def test_changed_raw_worker_evidence_blocks_resume(approved, engine):
    _, root = approved
    run, _ = worker(approved, engine, "setup")
    advance(approved, run, "setup")
    with (run / "logs/execute.stdout.log").open("a") as stream:
        stream.write("changed after approval\n")
    next_run, _ = worker(approved, engine, "primitive")
    with pytest.raises(ValueError, match="evidence changed"):
        advance(approved, next_run, "primitive")
    assert len(read(root / "impact-checkpoint/impact-state.json")["attempts"]) == 1


def test_resealed_checkpoint_cannot_exceed_stage_budget_or_reuse_worker(approved, engine):
    _, root = approved
    run, _ = worker(approved, engine, "setup")
    advance(approved, run, "setup", decision="retry")
    state_path = root / "impact-checkpoint/impact-state.json"
    state = read(state_path)
    state["attempts"] *= 4
    state["identity_sha256"] = digest(
        {key: value for key, value in state.items() if key != "identity_sha256"}
    )
    state_path.write_text(encode(state))
    next_run, _ = worker(approved, engine, "setup", name="another-setup-worker")
    with pytest.raises(ValueError, match="budget or worker reuse"):
        advance(approved, next_run, "setup")


def test_checkpoint_cannot_mutate_original_worker_or_poc_review(approved, engine):
    directory, root = approved
    run, _ = worker(approved, engine, "setup")
    for forbidden in (
        root / "baseline" / "checkpoint",
        root / "approved-setup" / "checkpoint",
    ):
        with pytest.raises(ValueError, match="boundary"):
            impact_step(
                directory,
                run,
                forbidden,
                stage_id="setup",
                decision="approve",
                reviewer="offline-fixture",
                rationale="Must preserve original artifacts.",
            )
        assert not forbidden.exists()


@pytest.mark.parametrize("resolve", [False, True])
def test_open_issues_survive_successful_steps_until_mapped_gate_passes(reviewed, engine, resolve):
    judgment, plan_file, root = reviewed
    plan = read(plan_file)
    plan["unresolved"] = ["Synthetic deployment reachability is unverified."]
    plan["counterevidence"] = [
        {
            "claim": "The normal admin path may be distinct.",
            "source": {"path": "app.sh", "line": 3, "column": 5, "quote": "role=$1"},
        }
    ]
    if resolve:
        plan["resolutions"] = [
            {
                "kind": kind,
                "index": 0,
                "stage_id": "impact",
                "rationale": "Synthetic impact stage is the declared resolution gate.",
            }
            for kind in ("unresolved", "counterevidence")
        ]
    plan_file.write_text(encode(plan))
    review_dir = root / "issue-impact-review"
    review_impact(
        "primitive",
        judgment,
        plan_file,
        review_dir,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Retain impact-specific issues.",
    )
    context = review_dir, root
    for stage in ("setup", "primitive", "control", "impact"):
        run, _ = worker(context, engine, stage, name=f"issue-worker-{stage}")
        state = advance(context, run, stage, output=root / "issue-checkpoint")
    assert state["status"] == "complete"
    assert state["impact_validated"] is resolve
    assert state["verdict"] == ("impact_observed" if resolve else "observed_with_open_issues")
    assert all(
        item["resolved"] is resolve for values in state["issues"].values() for item in values
    )
