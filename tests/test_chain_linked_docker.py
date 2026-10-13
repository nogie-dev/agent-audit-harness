"""Two separate synthetic flaws form a real isolated token-to-redemption chain."""

import base64
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from test_chain_experiment import ChainAgent

from agent_audit_harness.agents import Reply
from agent_audit_harness.chain import prepare_chain
from agent_audit_harness.chain_experiment import judge_chain, review_chain
from agent_audit_harness.impact import review_impact
from agent_audit_harness.impact_steps import impact_step
from agent_audit_harness.intake import import_review
from agent_audit_harness.judgment import candidate_issues, judge
from agent_audit_harness.pipeline import digest, encode, index_target
from agent_audit_harness.poc import propose_poc, review_poc
from agent_audit_harness.validation import validate

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("AUDIT_VALIDATION_IMAGE")
DOCKER_HOST = os.environ.get("AUDIT_VALIDATION_DOCKER_HOST")
pytestmark = pytest.mark.skipif(not IMAGE, reason="set AUDIT_VALIDATION_IMAGE to a local image ID")


def citation(line, quote, column=1, path="app.sh"):
    return {"path": path, "line": line, "column": column, "quote": quote}


class LinkedChainAgent(ChainAgent):
    def __init__(self, candidate, source_sha256):
        super().__init__(candidate)
        self.source_sha256 = source_sha256

    def call(self, stage, slice_id, prompt, schema, directory):
        data = super().call(stage, slice_id, prompt, schema, directory).data
        recipe = data["recipe"]
        script = (ROOT / "examples/chain-linked-probe.sh").read_text()
        recipe["attachments"][0].update(
            content=script, sha256=hashlib.sha256(script.encode()).hexdigest()
        )
        recipe["inputs"] = [{"path": "app.sh", "sha256": self.source_sha256}]
        oracle = recipe["oracle"]
        data["evidence"]["column"] = 13
        oracle["source"] = data["evidence"]
        oracle["description"] = "Guest leak output is used for a separate guest redemption request."
        oracle["entrypoint"]["source"] = citation(15, "printf 'ENTRY redeem\\n'", 9)
        oracle["entrypoint"]["invocation"] = citation(
            15,
            '/bin/sh /input/app.sh redeem guest "$state" > /work/second.stdout',
            path="poc/chain-probe.sh",
        )
        oracle["entrypoint"]["observation"]["line"] = "TARGET second stdout ENTRY redeem"
        oracle["reproduced"]["line"] = "ORACLE chain-accepted"
        oracle["not_reproduced"]["line"] = "ORACLE chain-denied"
        return Reply(data)


class LinkedImpactAgent(LinkedChainAgent):
    def __init__(self, candidate, source_sha256, stage):
        super().__init__(candidate, source_sha256)
        self.stage = stage

    def call(self, stage, slice_id, prompt, schema, directory):
        data = super().call(stage, slice_id, prompt, schema, directory).data
        recipe = data["recipe"]
        script = (ROOT / f"examples/chain-linked-{self.stage}.sh").read_text()
        recipe["attachments"][0].update(
            content=script, sha256=hashlib.sha256(script.encode()).hexdigest()
        )
        recipe["purpose"] = "Measure synthetic chain impact stage " + self.stage
        oracle = recipe["oracle"]
        entry = oracle["entrypoint"]
        route = "redeem" if self.stage == "control" else "leak"
        entry["source"] = citation(
            15 if self.stage == "control" else 6,
            "printf 'ENTRY " + route + "\\n'",
            9,
        )
        invocation = {
            "setup": "leak admin",
            "primitive": "leak guest",
            "control": "redeem admin bridge-key",
        }[self.stage]
        entry["invocation"] = citation(
            2,
            "/bin/sh /input/app.sh "
            + invocation
            + " > /work/"
            + ("guest.stdout" if self.stage == "primitive" else "admin.stdout"),
            path="poc/chain-probe.sh",
        )
        actor = "guest" if self.stage == "primitive" else "admin"
        entry["observation"]["line"] = "TARGET " + actor + " stdout ENTRY " + route
        outcome = {
            "setup": ("setup-ready", "setup-failed"),
            "primitive": ("primitive-leaked", "primitive-denied"),
            "control": ("control-failed", "control-authorized"),
        }[self.stage]
        oracle["reproduced"]["line"] = "ORACLE " + outcome[0]
        oracle["not_reproduced"]["line"] = "ORACLE " + outcome[1]
        return Reply(data)


@pytest.fixture(scope="module")
def linked_chain(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("linked-chain")
    target = tmp_path / "target"
    shutil.copytree(ROOT / "examples/chain-linked-target", target)
    sources, _ = index_target(target)
    app_sha256 = next(item.sha256 for item in sources if item.path == "app.sh")
    claims = [
        (10, "Guest token disclosure", "printf 'TOKEN bridge-key\\n'"),
        (21, "Guest token redemption", "printf 'SECRET vault-record\\n'"),
    ]
    candidates = [
        {
            "path": "app.sh",
            "line": line,
            "cwe": "CWE-862",
            "title": title,
            "reasoning": "A separate guest branch lacks an authorization check.",
            "quote": quote,
            "validation_plan": "Use an unchanged entrypoint probe and compare a focused fix.",
        }
        for line, title, quote in claims
    ]
    ids = ["f-" + digest(["app.sh", item["line"], item["cwe"]])[:16] for item in candidates]
    assert (
        ids == json.loads((ROOT / "examples/chain-linked-hypothesis.json").read_text())["sequence"]
    )
    spec = {
        "schema_version": 1,
        "source_index_sha256": digest([item.metadata() for item in sources]),
        "fragments": [{"path": "app.sh", "first_line": 1, "last_line": 25, "sha256": app_sha256}],
        "analysis": {"candidates": candidates},
        "triage": {
            "groups": [
                {
                    "root_cause": None,
                    "decisions": [
                        {
                            "candidate_id": candidate_id,
                            "verdict": "needs_validation",
                            "rationale": "Separate source branch needs runtime and fix evidence.",
                            "counterevidence": [],
                            "unresolved": [],
                        }
                    ],
                }
                for candidate_id in ids
            ]
        },
        "gaps": [],
    }
    spec_file = tmp_path / "import.json"
    spec_file.write_text(encode(spec))
    review = tmp_path / "review"
    import_review(target, spec_file, review)
    findings = {item["id"]: item for item in json.loads((review / "findings.json").read_text())}
    original = (target / "app.sh").read_text()
    judgments = []
    for index, candidate_id in enumerate(ids):
        candidate = findings[candidate_id]
        probe = ("leak-probe.sh", "redeem-probe.sh")[index]
        label = ("leak", "redeem")[index]
        recipe = json.loads((ROOT / "examples/judgment-baseline-recipe.json").read_text())
        recipe["candidate_id"] = candidate_id
        recipe["command"] = ["/bin/sh", "/input/" + probe]
        recipe["inputs"] = [
            {"path": "app.sh", "sha256": app_sha256},
            {
                "path": probe,
                "sha256": hashlib.sha256((target / probe).read_bytes()).hexdigest(),
            },
        ]
        recipe["purpose"] = "Compare the separate synthetic " + label + " flaw."
        oracle = recipe["oracle"]
        oracle["description"] = "Guest request must be denied while admin remains authorized."
        oracle["source"] = citation(candidate["line"], candidate["quote"], 13)
        oracle["harness_path"] = probe
        oracle["entrypoint"]["description"] = "Invoke the normal CLI request dispatcher."
        oracle["entrypoint"]["source"] = citation(
            6 if index == 0 else 15,
            "printf 'ENTRY " + label + "\\n'",
            9,
        )
        oracle["entrypoint"]["invocation"] = citation(
            2,
            "/bin/sh /input/app.sh "
            + ("leak guest" if index == 0 else "redeem guest bridge-key")
            + " > /work/guest.stdout",
            path=probe,
        )
        oracle["entrypoint"]["observation"]["line"] = "TARGET guest stdout ENTRY " + label
        oracle["reproduced"]["line"] = "ORACLE " + label + "-accepted"
        oracle["not_reproduced"]["line"] = "ORACLE " + label + "-denied"
        oracle["resolutions"] = [
            {
                "issue_id": issue["id"],
                "requirement": "entrypoint",
                "rationale": "The unchanged probe observes the CLI entrypoint in both runs.",
            }
            for issue in candidate_issues(candidate)
        ]
        workers = []
        for fixed in (False, True):
            run_recipe = json.loads(encode(recipe))
            if fixed:
                lines = original.splitlines(keepends=True)
                assert lines[candidate["line"] - 1].strip() == candidate["quote"]
                lines[candidate["line"] - 1] = "            printf 'DENIED\\n'\n"
                changed = "".join(lines)
                run_recipe["replacements"] = [
                    {
                        "path": "app.sh",
                        "before_sha256": app_sha256,
                        "after_sha256": hashlib.sha256(changed.encode()).hexdigest(),
                        "content": changed,
                    }
                ]
            recipe_file = tmp_path / f"{label}-{'fixed' if fixed else 'baseline'}.json"
            recipe_file.write_text(encode(run_recipe))
            output = tmp_path / f"{label}-{'fixed' if fixed else 'baseline'}"
            result = validate(
                target, review, recipe_file, output, image=IMAGE, docker_host=DOCKER_HOST
            )
            assert result["status"] == "completed" and result["cleanup"]["status"] == "removed"
            workers.append(output)
        judgment = tmp_path / (label + "-judgment")
        decision = judge(workers[0], judgment, fixed=workers[1])
        assert decision["verdict"] == "validated" and decision["promotion"]["eligible"]
        assert decision["runs"]["baseline"]["outcome"] == "reproduced"
        assert decision["runs"]["fixed"]["outcome"] == "not_reproduced"
        judgments.append(judgment)
    chain = tmp_path / "chain"
    prepare_chain(*judgments, ROOT / "examples/chain-linked-hypothesis.json", chain)
    second = findings[ids[1]]
    proposal = tmp_path / "chain-poc-proposal"
    propose_poc(target, review, second["id"], proposal, LinkedChainAgent(second, app_sha256))
    approved = tmp_path / "chain-poc-approved"
    review_poc(
        target,
        review,
        proposal,
        approved,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Synthetic two-primitive chain experiment.",
    )
    chain_review = tmp_path / "chain-review"
    review_chain(
        chain,
        approved,
        ROOT / "examples/chain-linked-experiment.json",
        chain_review,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Synthetic bounded transfer and wrong-state control.",
    )
    combined = tmp_path / "combined"
    result = validate(
        target,
        review,
        chain_review / "poc-review/recipe.json",
        combined,
        image=IMAGE,
        docker_host=DOCKER_HOST,
        poc_review=chain_review / "poc-review",
    )
    assert result["status"] == "completed" and result["cleanup"]["status"] == "removed"
    decision = judge_chain(chain, chain_review, combined, tmp_path / "chain-judgment")
    assert decision["status"] == "complete" and decision["verdict"] == "connected"
    assert decision["connection_observed"] and not decision["impact_validated"]
    assert not decision["blockers"]
    assert decision["observations"]["control_denied"]["lines"]
    assert all(item["resolved"] for item in decision["issues"]["unresolved"])
    assert all(item["resolved"] for item in decision["issues"]["prerequisites"])
    return target, review, tmp_path / "chain-judgment", approved, second, app_sha256, tmp_path


def test_real_independent_primitives_connect_with_wrong_state_control(linked_chain):
    _, _, judgment, _, _, _, _ = linked_chain
    decision = json.loads((judgment / "chain-judgment.json").read_text())
    assert decision["verdict"] == "connected" and not decision["impact_validated"]


def test_real_chain_impact_stages_measure_guest_record_and_controls(linked_chain):
    target, review, judgment, chain_poc, candidate, app_sha256, root = linked_chain
    plan = json.loads((ROOT / "examples/chain-linked-impact-plan.json").read_text())
    for stage in plan["stages"]:
        name = stage["id"]
        if name == "impact":
            stage["poc_review"] = str(chain_poc)
            continue
        proposal = root / f"impact-{name}-proposal"
        propose_poc(
            target,
            review,
            candidate["id"],
            proposal,
            LinkedImpactAgent(candidate, app_sha256, name),
        )
        approved = root / f"impact-{name}-approved"
        review_poc(
            target,
            review,
            proposal,
            approved,
            decision="approve",
            reviewer="offline-fixture",
            rationale="Synthetic measured impact stage: " + name,
        )
        stage["poc_review"] = str(approved)
    plan_file = root / "impact-plan.json"
    plan_file.write_text(encode(plan))
    impact_review = root / "impact-review"
    receipt = review_impact(
        "chain",
        judgment,
        plan_file,
        impact_review,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Measure the synthetic guest record disclosure and controls.",
    )
    assert receipt["decision"] == "approve"
    checkpoint = root / "impact-checkpoint"
    for stage in plan["stages"]:
        name = stage["id"]
        poc = impact_review / "stages" / name / "poc-review"
        worker = root / ("impact-worker-" + name)
        result = validate(
            target,
            review,
            poc / "recipe.json",
            worker,
            image=IMAGE,
            docker_host=DOCKER_HOST,
            poc_review=poc,
        )
        assert result["status"] == "completed" and result["cleanup"]["status"] == "removed"
        if name == "setup":
            with pytest.raises(ValueError, match="out of order"):
                impact_step(
                    impact_review,
                    worker,
                    checkpoint,
                    stage_id="impact",
                    decision="approve",
                    reviewer="offline-fixture",
                    rationale="Attempt to skip prerequisite stages.",
                )
        state = impact_step(
            impact_review,
            worker,
            checkpoint,
            stage_id=name,
            decision="approve",
            reviewer="offline-fixture",
            rationale="Synthetic source-bound observation for " + name,
        )
        assert state["attempts"][-1]["assessment"]["gate_pass"]
    assert state["status"] == "complete" and state["verdict"] == "impact_observed"
    assert state["impact_validated"] and len(state["stage_results"]) == 4
    assert [item["assessment"]["evaluation"]["outcome"] for item in state["attempts"]] == [
        "reproduced",
        "reproduced",
        "not_reproduced",
        "reproduced",
    ]
    log = (root / "impact-worker-impact/logs/execute.stdout.log").read_text()
    encoded = [
        line.removeprefix("TARGET second bytes ")
        for line in log.splitlines()
        if line.startswith("TARGET second bytes ")
    ]
    assert len(encoded) == 1
    assert base64.b64decode(encoded[0], validate=True) == b"ENTRY redeem\nSECRET vault-record\n"
