"""Impact plans are frozen source-backed experiments, never host commands."""

import hashlib
import json
from pathlib import Path

import pytest
from test_judgment import execute
from test_poc import SuppliedAgent

from agent_audit_harness.cli import main
from agent_audit_harness.impact import review_impact
from agent_audit_harness.judgment import judge
from agent_audit_harness.pipeline import digest, encode
from agent_audit_harness.poc import propose_poc, review_poc

pytest_plugins = ["test_judgment"]
ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text())


def stage_reply(data, stage, _):
    recipe = data["recipe"]
    oracle = recipe["oracle"]
    oracle["resolutions"] = []
    recipe["purpose"] = f"Synthetic impact measurement: {stage}"
    if stage == "control":
        script = (ROOT / "examples/impact-control-probe.sh").read_text()
        harness = "poc/impact-control-probe.sh"
        oracle["harness_path"] = harness
        oracle["entrypoint"]["invocation"] = {
            "path": harness,
            "line": 2,
            "column": 1,
            "quote": "/bin/sh /input/app.sh admin > /work/admin.stdout",
        }
        oracle["entrypoint"]["observation"]["line"] = "TARGET admin stdout ENTRY request-handler"
        oracle["reproduced"]["line"] = "ORACLE control-denied"
        oracle["not_reproduced"]["line"] = "ORACLE control-authorized"
    else:
        harness = "poc/probe.sh"
        script = recipe["attachments"][0]["content"]
        marker = {
            "setup": "setup-ready",
            "primitive": "primitive-read",
            "impact": "impact-private-record",
        }[stage]
        script = script.replace("ORACLE unauthorized-read", "ORACLE " + marker)
        script = script.replace("ORACLE access-denied", "ORACLE " + stage + "-negative")
        oracle["reproduced"]["line"] = "ORACLE " + marker
        oracle["not_reproduced"]["line"] = "ORACLE " + stage + "-negative"
    recipe["attachments"] = [
        {
            "path": harness,
            "content": script,
            "sha256": hashlib.sha256(script.encode()).hexdigest(),
        }
    ]
    recipe["command"] = ["/bin/sh", "/input/" + harness]


@pytest.fixture
def reviewed(scenario, engine):
    target, review, root = scenario
    baseline, _ = execute(scenario, engine)
    fixed, _ = execute(scenario, engine, fixed=True)
    judgment = root / "validated-primitive"
    assert judge(baseline, judgment, fixed=fixed)["verdict"] == "validated"
    plan = read(ROOT / "examples/impact-plan.json")
    candidate = read(review / "findings.json")[0]
    for stage in plan["stages"]:
        stage_id = stage["id"]
        proposal = root / f"proposal-{stage_id}"
        propose_poc(
            target,
            review,
            candidate["id"],
            proposal,
            SuppliedAgent(
                lambda data, directory, name=stage_id: stage_reply(data, name, directory)
            ),
        )
        approved = root / f"approved-{stage_id}"
        review_poc(
            target,
            review,
            proposal,
            approved,
            decision="approve",
            reviewer="offline-fixture",
            rationale="Synthetic stage contract only.",
        )
        stage["poc_review"] = str(approved)
    plan_file = root / "impact-plan.json"
    plan_file.write_text(encode(plan))
    return judgment, plan_file, root


def test_review_freezes_distinct_approved_gates_without_execution(reviewed):
    judgment, plan, root = reviewed
    destination = root / "impact-review"
    assert (
        main(
            [
                "impact-review",
                "--primitive",
                str(judgment),
                "--plan",
                str(plan),
                "--decision",
                "approve",
                "--reviewer",
                "offline-fixture",
                "--rationale",
                "Review synthetic stage properties.",
                "--output",
                str(destination),
            ]
        )
        == 0
    )
    receipt = read(destination / "impact-review.json")
    assert receipt["status"] == "reviewed" and receipt["decision"] == "approve"
    assert receipt["input"]["kind"] == "primitive"
    assert [stage["kind"] for stage in receipt["stages"]] == [
        "setup",
        "primitive",
        "control",
        "impact",
    ]
    assert len({stage["recipe_sha256"] for stage in receipt["stages"]}) == 4
    assert receipt["property_proof"]["source_sha256"]
    assert all(stage["source_proofs"]["harness_observation"] for stage in receipt["stages"])
    assert not any(
        (destination / "stages" / stage["id"] / "worker").exists() for stage in receipt["stages"]
    )


@pytest.mark.parametrize(
    "change", ["order", "source", "marker", "duplicate", "rejected", "resolution"]
)
def test_review_rejects_unsupported_impact_contract(reviewed, change):
    judgment, plan_file, root = reviewed
    plan = read(plan_file)
    if change == "order":
        plan["stages"][1], plan["stages"][2] = plan["stages"][2], plan["stages"][1]
    elif change == "source":
        plan["security_property"]["source"]["quote"] = "invented source"
    elif change == "marker":
        plan["stages"][-1]["harness_observation"]["quote"] = "printf 'invented'"
    elif change == "duplicate":
        plan["stages"][-1]["poc_review"] = plan["stages"][0]["poc_review"]
    elif change == "resolution":
        plan["resolutions"] = [
            {
                "kind": "unresolved",
                "index": 0,
                "stage_id": "impact",
                "rationale": "No such unresolved claim.",
            }
        ]
    else:
        approved = Path(plan["stages"][0]["poc_review"])
        receipt = read(approved / "review.json")
        receipt["decision"] = "reject"
        receipt["identity_sha256"] = digest(
            {key: value for key, value in receipt.items() if key != "identity_sha256"}
        )
        (approved / "review.json").write_text(encode(receipt))
    plan_file.write_text(encode(plan))
    destination = root / f"invalid-impact-{change}"
    with pytest.raises(ValueError):
        review_impact(
            "primitive",
            judgment,
            plan_file,
            destination,
            decision="approve",
            reviewer="offline-fixture",
            rationale="Invalid fixture.",
        )
    assert not destination.exists()


def test_uncertain_input_cannot_become_an_impact_plan(reviewed):
    judgment, plan, root = reviewed
    saved = read(judgment / "judgment.json")
    saved["promotion"]["eligible"] = False
    saved["identity_sha256"] = digest(
        {key: value for key, value in saved.items() if key != "identity_sha256"}
    )
    (judgment / "judgment.json").write_text(encode(saved))
    with pytest.raises(ValueError):
        review_impact(
            "primitive",
            judgment,
            plan,
            root / "invalid-base",
            decision="approve",
            reviewer="offline-fixture",
            rationale="Invalid primitive.",
        )
