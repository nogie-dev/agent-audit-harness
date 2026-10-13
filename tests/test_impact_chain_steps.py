"""A connected chain still needs every distinct reviewed impact gate."""

from test_validation import IMAGE

from agent_audit_harness.impact import review_impact
from agent_audit_harness.impact_steps import impact_step
from agent_audit_harness.validation import validate

pytest_plugins = ["test_impact_chain_review"]


def test_connected_chain_advances_only_after_reviewed_stage_measurements(chain_plan, experiment):
    connected, plan, root = chain_plan
    target, source_review, _, _, _, _, _, engine = experiment
    review_dir = root / "chain-impact-gates"
    receipt = review_impact(
        "chain",
        connected,
        plan,
        review_dir,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Synthetic chain impact gates.",
    )
    assert receipt["input"]["kind"] == "chain"
    for stage in ("setup", "primitive", "control", "impact"):
        poc = review_dir / "stages" / stage / "poc-review"
        marker = "control-authorized" if stage == "control" else stage + "-positive"
        engine.stdout = (
            f"TARGET second stdout ENTRY request-handler\nORACLE {marker}\nCHECK complete\n"
        )
        worker_dir = root / f"chain-impact-worker-{stage}"
        result = validate(
            target,
            source_review,
            poc / "recipe.json",
            worker_dir,
            image=IMAGE,
            poc_review=poc,
        )
        assert result["status"] == "completed"
        state = impact_step(
            review_dir,
            worker_dir,
            root / "chain-impact-checkpoint",
            stage_id=stage,
            decision="approve",
            reviewer="offline-fixture",
            rationale="Observe synthetic chain property.",
        )
        assert state["attempts"][-1]["assessment"]["gate_pass"]
    assert state["impact_validated"] and state["verdict"] == "impact_observed"
