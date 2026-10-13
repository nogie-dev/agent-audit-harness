"""A connected chain can enter impact planning without becoming impact evidence."""

import hashlib
import json
from pathlib import Path

import pytest
from test_chain_experiment import ChainAgent, worker

from agent_audit_harness.agents import Reply
from agent_audit_harness.chain_experiment import judge_chain
from agent_audit_harness.impact import review_impact
from agent_audit_harness.pipeline import digest, encode
from agent_audit_harness.poc import propose_poc, review_poc

pytest_plugins = ["test_chain_experiment"]
ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text())


class StageAgent(ChainAgent):
    def __init__(self, candidate, stage):
        super().__init__(candidate)
        self.stage = stage

    def call(self, stage, slice_id, prompt, schema, directory):
        data = super().call(stage, slice_id, prompt, schema, directory).data
        recipe = data["recipe"]
        oracle = recipe["oracle"]
        recipe["purpose"] = "Synthetic chain impact stage: " + self.stage
        positive = "ORACLE " + self.stage + "-positive"
        negative = "ORACLE " + self.stage + "-negative"
        if self.stage == "control":
            positive, negative = "ORACLE control-authorized", "ORACLE control-negative"
        script = recipe["attachments"][0]["content"]
        script = script.replace("ORACLE chain-state-accepted", positive)
        script = script.replace("ORACLE chain-state-denied", negative)
        recipe["attachments"][0]["content"] = script
        recipe["attachments"][0]["sha256"] = hashlib.sha256(script.encode()).hexdigest()
        oracle["reproduced"]["line"] = negative if self.stage == "control" else positive
        oracle["not_reproduced"]["line"] = positive if self.stage == "control" else negative
        oracle["resolutions"] = []
        return Reply(data)


@pytest.fixture
def chain_plan(experiment):
    target, review, chain, _, _, chain_review, root, _ = experiment
    run, _ = worker(experiment)
    connected = root / "connected-base"
    assert judge_chain(chain, chain_review, run, connected)["verdict"] == "connected"
    candidate = next(
        item
        for item in read(review / "findings.json")
        if item["id"] == read(chain / "chain.json")["hypothesis"]["sequence"][1]
    )
    plan = read(ROOT / "examples/impact-plan.json")
    for stage in plan["stages"]:
        name = stage["id"]
        proposal = root / f"chain-stage-{name}"
        propose_poc(target, review, candidate["id"], proposal, StageAgent(candidate, name))
        approved = root / f"chain-approved-{name}"
        review_poc(
            target,
            review,
            proposal,
            approved,
            decision="approve",
            reviewer="offline-fixture",
            rationale="Synthetic chain stage.",
        )
        stage["poc_review"] = str(approved)
        stage["harness_observation"] = {
            "path": "poc/chain-probe.sh",
            "line": 18,
            "column": 5,
            "quote": "printf 'ORACLE "
            + ("control-authorized" if name == "control" else name + "-positive")
            + "\\n'",
        }
    plan_file = root / "chain-impact-plan.json"
    plan_file.write_text(encode(plan))
    return connected, plan_file, root


def test_connected_chain_is_reviewed_without_automatic_impact_promotion(chain_plan):
    connected, plan, root = chain_plan
    receipt = review_impact(
        "chain",
        connected,
        plan,
        root / "chain-impact-review",
        decision="approve",
        reviewer="offline-fixture",
        rationale="Stage gates remain unexecuted.",
    )
    assert receipt["input"]["kind"] == "chain"
    assert receipt["decision"] == "approve" and len(receipt["stages"]) == 4
    assert not receipt.get("impact_validated", False)


def test_nonconnected_chain_cannot_enter_impact_review(chain_plan):
    connected, plan, root = chain_plan
    saved = read(connected / "chain-judgment.json")
    saved["verdict"] = "observed_with_open_issues"
    saved["identity_sha256"] = digest(
        {key: value for key, value in saved.items() if key != "identity_sha256"}
    )
    (connected / "chain-judgment.json").write_text(encode(saved))
    with pytest.raises(ValueError):
        review_impact(
            "chain",
            connected,
            plan,
            root / "nonconnected-review",
            decision="approve",
            reviewer="offline-fixture",
            rationale="Reject unconnected input.",
        )
