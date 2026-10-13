"""Synthetic worker logs verify the chain contract, not real vulnerability impact."""

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from test_validation import engine as shared_engine

from agent_audit_harness.agents import Reply
from agent_audit_harness.chain import prepare_chain
from agent_audit_harness.chain_experiment import judge_chain, review_chain
from agent_audit_harness.cli import main
from agent_audit_harness.pipeline import digest, encode
from agent_audit_harness.poc import propose_poc, review_poc
from agent_audit_harness.validation import validate

ROOT = Path(__file__).resolve().parents[1]
pytest_plugins = ["test_chain"]


def read(path):
    return json.loads(path.read_text())


class ChainAgent:
    identity = {"provider": "offline-chain-fixture"}

    def __init__(self, candidate):
        self.candidate = candidate

    def call(self, stage, slice_id, prompt, schema, directory):
        assert (stage, slice_id) == ("poc", "p0001")
        data = read(ROOT / "examples/poc-replay/p0001.poc.json")
        evidence = {key: self.candidate[key] for key in ("path", "line", "quote")}
        evidence["column"] = 5
        data["candidate_id"] = self.candidate["id"]
        data["evidence"] = evidence
        recipe = data["recipe"]
        recipe["candidate_id"] = self.candidate["id"]
        script = (ROOT / "examples/chain-probe.sh").read_text()
        recipe["attachments"] = [
            {
                "path": "poc/chain-probe.sh",
                "content": script,
                "sha256": hashlib.sha256(script.encode()).hexdigest(),
            }
        ]
        recipe["command"] = ["/bin/sh", "/input/poc/chain-probe.sh"]
        oracle = recipe["oracle"]
        oracle["description"] = "Synthetic first response is passed into a later CLI request."
        oracle["source"] = evidence
        oracle["harness_path"] = "poc/chain-probe.sh"
        oracle["entrypoint"]["invocation"] = {
            "path": "poc/chain-probe.sh",
            "line": 15,
            "column": 1,
            "quote": '/bin/sh /input/app.sh "$state" > /work/second.stdout',
        }
        oracle["entrypoint"]["observation"]["line"] = "TARGET second stdout ENTRY request-handler"
        oracle["reproduced"]["line"] = "ORACLE chain-state-accepted"
        oracle["not_reproduced"]["line"] = "ORACLE chain-state-denied"
        oracle["resolutions"] = []
        recipe["purpose"] = "Synthetic reviewed connection experiment."
        data["requirements"] = ["Prepared isolated image with sh, sed, cmp and base64."]
        return Reply(data)


@pytest.fixture
def engine(monkeypatch):
    return shared_engine.__wrapped__(monkeypatch)


def build_experiment(prepared, engine=None):
    target, judgments, chain_spec, root = prepared
    chain_dir = root / "chain"
    prepare_chain(*judgments, chain_spec, chain_dir)
    candidate = next(
        item
        for item in read(root / "review/findings.json")
        if item["id"] == read(chain_spec)["sequence"][1]
    )
    proposal = root / "chain-poc-proposal"
    propose_poc(target, root / "review", candidate["id"], proposal, ChainAgent(candidate))
    approved = root / "chain-poc-approved"
    review_poc(
        target,
        root / "review",
        proposal,
        approved,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Synthetic experiment contract only.",
    )
    plan = root / "chain-experiment.json"
    plan.write_bytes((ROOT / "examples/chain-experiment.json").read_bytes())
    chain_review = root / "chain-review"
    receipt = review_chain(
        chain_dir,
        approved,
        plan,
        chain_review,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Approve synthetic transfer markers only.",
    )
    assert receipt["decision"] == "approve"
    return target, root / "review", chain_dir, approved, plan, chain_review, root, engine


@pytest.fixture
def experiment(prepared, engine):
    return build_experiment(prepared, engine)


def output(value="private-record"):
    encoded = base64.b64encode(value.encode()).decode()
    return (
        "TARGET first stdout ENTRY request-handler\n"
        f"CHAIN producer base64 {encoded}\n"
        f"CHAIN consumer base64 {encoded}\n"
        "TARGET second stdout ENTRY request-handler\n"
        "ORACLE chain-state-accepted\nCHAIN control denied\nCHECK complete\n"
    )


def worker(experiment, *, stdout=None, fail_stage=None, reason=None, name="chain-worker"):
    target, review, _, _, _, chain_review, root, engine = experiment
    engine.stdout = stdout if stdout is not None else output()
    engine.fail_stage = fail_stage
    engine.reason = reason
    path = root / name
    result = validate(
        target,
        review,
        chain_review / "poc-review/recipe.json",
        path,
        image="sha256:" + "a" * 64,
        poc_review=chain_review / "poc-review",
    )
    return path, result


def test_reviewed_worker_observation_is_distinct_from_individual_and_impact(experiment):
    _, _, chain_dir, _, _, chain_review, root, _ = experiment
    run, result = worker(experiment)
    assert result["status"] == "completed"
    destination = root / "chain-judgment"
    assert (
        main(
            [
                "judge-chain",
                str(chain_dir),
                "--review",
                str(chain_review),
                "--worker",
                str(run),
                "--output",
                str(destination),
            ]
        )
        == 0
    )
    decision = read(destination / "chain-judgment.json")
    assert decision["status"] == "complete" and decision["verdict"] == "connected"
    assert decision["connection_observed"] and not decision["impact_validated"]
    assert len(decision["individual_primitives"]) == 2
    assert decision["issues"]["unresolved"][0]["resolved"]
    assert decision["issues"]["prerequisites"][0]["resolved"]
    assert decision["observations"]["producer"]["matches"][0]["bytes"] == 14
    assert decision["identity_sha256"] == digest(
        {key: value for key, value in decision.items() if key != "identity_sha256"}
    )


@pytest.mark.parametrize(
    "case", ["order", "state", "missing", "duplicate", "negative", "control", "timeout", "failure"]
)
def test_incomplete_or_conflicting_connection_never_promotes(experiment, case):
    _, _, chain_dir, _, _, chain_review, root, engine = experiment
    stdout = output()
    if case == "order":
        lines = stdout.splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        stdout = "\n".join(lines) + "\n"
    elif case == "state":
        stdout = stdout.replace(
            "CHAIN consumer base64 " + base64.b64encode(b"private-record").decode(),
            "CHAIN consumer base64 " + base64.b64encode(b"wrong-state").decode(),
        )
    elif case == "missing":
        stdout = (
            "\n".join(line for line in stdout.splitlines() if not line.startswith("CHAIN producer"))
            + "\n"
        )
    elif case == "duplicate":
        stdout = stdout.replace("CHAIN producer base64 ", "CHAIN producer base64 ", 1)
        stdout = stdout.replace(
            "CHAIN consumer base64 ",
            "CHAIN producer base64 cHJpdmF0ZS1yZWNvcmQ=\nCHAIN consumer base64 ",
        )
    elif case == "negative":
        stdout = stdout.replace("ORACLE chain-state-accepted", "ORACLE chain-state-denied")
    elif case == "control":
        stdout = stdout.replace("CHAIN control denied", "CHAIN control accepted")
    run, result = worker(
        experiment,
        stdout=stdout,
        fail_stage="execute" if case == "failure" else None,
        reason="timeout" if case == "timeout" else None,
    )
    decision = judge_chain(chain_dir, chain_review, run, root / f"judgment-{case}")
    assert decision["status"] == "complete"
    assert not decision["connection_observed"] and decision["verdict"] != "connected"
    if case == "control":
        assert "state_dependence_unverified" in decision["blockers"]
    assert decision["worker"]["result_sha256"] == result["identity_sha256"]


def test_unapproved_review_and_changed_experiment_are_rejected(experiment):
    _, _, chain_dir, approved, plan, chain_review, root, _ = experiment
    run, _ = worker(experiment)
    rejected = root / "rejected-chain-review"
    review_chain(
        chain_dir,
        approved,
        plan,
        rejected,
        decision="reject",
        reviewer="offline-fixture",
        rationale="Synthetic rejection.",
    )
    denied = judge_chain(chain_dir, rejected, run, root / "rejected-judgment")
    assert denied["status"] == "failed" and not denied["connection_observed"]
    changed = read(chain_review / "experiment-input.json")
    changed["observations"]["producer_prefix"]["prefix"] = "CHANGED "
    (chain_review / "experiment-input.json").write_text(encode(changed))
    altered = judge_chain(chain_dir, chain_review, run, root / "altered-judgment")
    assert altered["status"] == "failed" and not altered["connection_observed"]


def test_unresolved_counterevidence_is_preserved_even_if_transfer_is_observed(experiment):
    _, _, chain_dir, _, _, chain_review, root, _ = experiment
    run, _ = worker(experiment)
    plan = read(chain_review / "experiment-input.json")
    plan["resolve_unresolved"] = []
    alternative = root / "unresolved-plan.json"
    alternative.write_text(encode(plan))
    review_chain(
        chain_dir,
        experiment[3],
        alternative,
        root / "unresolved-review",
        decision="approve",
        reviewer="offline-fixture",
        rationale="Retain unresolved gap.",
    )
    # The worker is bound to the same approved PoC, while the separate chain review retains the gap.
    decision = judge_chain(chain_dir, root / "unresolved-review", run, root / "unresolved-judgment")
    assert decision["status"] == "complete"
    assert decision["connection_observed"] and decision["verdict"] == "observed_with_open_issues"
    assert not decision["issues"]["unresolved"][0]["resolved"]

    original = read(chain_dir / "chain.json")
    spec = read(chain_dir / "hypothesis-input.json")
    spec["counterevidence"].append(
        {
            "claim": "The second request may ignore the transferred state.",
            "at": "second",
            "source": {
                "path": "app.sh",
                "line": 5,
                "column": 5,
                "quote": "printf 'DATA private-record\\n'",
            },
        }
    )
    counter_spec = root / "counter-chain.json"
    counter_spec.write_text(encode(spec))
    counter_chain = root / "counter-chain"
    prepare_chain(
        *(Path(item["judgment"]) for item in original["individual_primitives"]),
        counter_spec,
        counter_chain,
    )
    counter_review = root / "counter-review"
    review_chain(
        counter_chain,
        experiment[3],
        experiment[4],
        counter_review,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Retain counterevidence.",
    )
    counter = judge_chain(counter_chain, counter_review, run, root / "counter-judgment")
    assert counter["status"] == "complete"
    assert counter["connection_observed"] and counter["verdict"] == "observed_with_open_issues"
    assert counter["issues"]["counterevidence"] == spec["counterevidence"]


def test_review_rejects_unquoted_harness_claim_before_worker(experiment):
    _, _, chain_dir, approved, plan_file, _, root, _ = experiment
    plan = read(plan_file)
    plan["harness"]["capture"]["quote"] = "state=$(invented command)"
    invalid = root / "invalid-experiment.json"
    invalid.write_text(encode(plan))
    destination = root / "invalid-review"
    with pytest.raises(ValueError, match="quote"):
        review_chain(
            chain_dir,
            approved,
            invalid,
            destination,
            decision="approve",
            reviewer="offline-fixture",
            rationale="No source proof.",
        )
    assert not destination.exists()


def test_worker_raw_evidence_tamper_is_not_a_connection(experiment):
    _, _, chain_dir, _, _, chain_review, root, _ = experiment
    run, _ = worker(experiment)
    with (run / "logs/execute.stdout.log").open("a") as stream:
        stream.write("CHAIN producer base64 ZmFrZQ==\n")
    decision = judge_chain(chain_dir, chain_review, run, root / "tampered-judgment")
    assert decision["status"] == "failed" and not decision["connection_observed"]


@pytest.mark.skipif(
    not os.environ.get("AUDIT_VALIDATION_IMAGE"),
    reason="set AUDIT_VALIDATION_IMAGE to a prepared local image ID",
)
def test_real_worker_rejects_state_independent_chain(tmp_path):
    from test_chain import build_prepared

    image = os.environ["AUDIT_VALIDATION_IMAGE"]
    docker_host = os.environ.get("AUDIT_VALIDATION_DOCKER_HOST")
    reviewed = build_experiment(build_prepared(tmp_path, image=image, docker_host=docker_host))
    target, review, chain, _, _, chain_review, root, _ = reviewed
    run = root / "real-chain-worker"
    result = validate(
        target,
        review,
        chain_review / "poc-review/recipe.json",
        run,
        image=image,
        docker_host=docker_host,
        poc_review=chain_review / "poc-review",
    )
    assert result["status"] == "completed" and result["cleanup"]["status"] == "removed"
    assert "CHAIN control accepted\n" in (run / "logs/execute.stdout.log").read_text()
    decision = judge_chain(chain, chain_review, run, root / "real-chain-judgment")
    assert decision["status"] == "complete" and decision["verdict"] == "not_observed"
    assert not decision["connection_observed"]
    assert decision["observations"]["control_denied"]["lines"] == []
    assert "state_dependence_unverified" in decision["blockers"]
