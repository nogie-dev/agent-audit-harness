"""Offline contract checks; FakeDocker responses do not prove real target behavior."""

import copy
import json
import shutil
from pathlib import Path

import pytest
from test_judgment import NEGATIVE, POSITIVE
from test_validation import IMAGE
from test_validation import engine as shared_engine

import agent_audit_harness.chain as chain_module
from agent_audit_harness.chain import prepare_chain
from agent_audit_harness.cli import main
from agent_audit_harness.intake import import_review
from agent_audit_harness.judgment import candidate_issues, judge
from agent_audit_harness.pipeline import digest, encode
from agent_audit_harness.validation import validate

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text())


@pytest.fixture
def engine(monkeypatch):
    return shared_engine.__wrapped__(monkeypatch)


def build_prepared(tmp_path, engine=None, *, image=IMAGE, docker_host=None):
    target = tmp_path / "target"
    shutil.copytree(ROOT / "examples/judgment-target", target)
    import_spec = read(ROOT / "examples/candidate-import.json")
    other = {
        "cwe": "CWE-862",
        "line": 3,
        "path": "app.sh",
        "quote": "role=$1",
        "reasoning": "Synthetic second primitive for chain contract checks.",
        "title": "Synthetic request-role input",
        "validation_plan": "Compare the same frozen synthetic request probe before and after.",
    }
    other_id = "f-" + digest(["app.sh", 3, "CWE-862"])[:16]
    assert other_id == read(ROOT / "examples/chain-hypothesis.json")["sequence"][1]
    import_spec["analysis"]["candidates"].append(other)
    import_spec["triage"]["groups"].append(
        {
            "root_cause": None,
            "decisions": [
                {
                    "candidate_id": other_id,
                    "verdict": "needs_validation",
                    "rationale": "Synthetic independent candidate; runtime evidence required.",
                    "counterevidence": [],
                    "unresolved": [],
                }
            ],
        }
    )
    spec_path = tmp_path / "import.json"
    spec_path.write_text(encode(import_spec))
    review = tmp_path / "review"
    import_review(target, spec_path, review)
    decisions = []
    for index, candidate in enumerate(read(review / "findings.json")):
        recipes = []
        for fixed in (False, True):
            recipe = read(
                ROOT / f"examples/judgment-{'fixed' if fixed else 'baseline'}-recipe.json"
            )
            recipe["candidate_id"] = candidate["id"]
            recipe["oracle"]["source"] = {
                "path": "app.sh",
                "line": candidate["line"],
                "column": 5,
                "quote": candidate["quote"],
            }
            recipe["oracle"]["resolutions"] = [
                {
                    "issue_id": issue["id"],
                    "requirement": "fix_comparison",
                    "rationale": "Synthetic fixture: resolve only after comparison.",
                }
                for issue in candidate_issues(candidate)
            ]
            recipe_path = tmp_path / f"{index}-{'fixed' if fixed else 'baseline'}.json"
            recipe_path.write_text(encode(recipe))
            output = tmp_path / f"worker-{index}-{'fixed' if fixed else 'baseline'}"
            if engine is not None:
                engine.stdout = NEGATIVE if fixed else POSITIVE
            result = validate(
                target, review, recipe_path, output, image=image, docker_host=docker_host
            )
            assert result["status"] == "completed"
            recipes.append(output)
        decision_dir = tmp_path / f"judgment-{index}"
        decision = judge(recipes[0], decision_dir, fixed=recipes[1])
        assert decision["verdict"] == "validated"
        decisions.append(decision_dir)
    spec = tmp_path / "chain-spec.json"
    spec.write_bytes((ROOT / "examples/chain-hypothesis.json").read_bytes())
    return target, decisions, spec, tmp_path


@pytest.fixture
def prepared(tmp_path, engine):
    return build_prepared(tmp_path, engine)


def test_validated_inputs_make_only_a_source_backed_hypothesis(prepared):
    _, decisions, spec, root = prepared
    output = root / "chain"
    assert (
        main(
            [
                "prepare-chain",
                str(decisions[0]),
                str(decisions[1]),
                "--spec",
                str(spec),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    chain = read(output / "chain.json")
    assert chain["status"] == "hypothesis" and chain["connection"] == "unobserved"
    assert [p["candidate_id"] for p in chain["individual_primitives"]] == read(spec)["sequence"]
    assert chain["source_proofs"]["producer"]["source_sha256"]
    assert chain["source_proofs"]["prerequisites"] == [None]
    assert chain["hypothesis"]["unresolved"] and not chain.get("impact_validated", False)
    assert chain["identity_sha256"] == digest(
        {key: value for key, value in chain.items() if key != "identity_sha256"}
    )


@pytest.mark.parametrize(
    "change",
    ["order", "quote", "missing_gap", "unknown_source", "not_validated", "tamper_worker"],
)
def test_chain_rejects_unverified_inputs_without_losing_failure(prepared, change):
    _, decisions, spec, root = prepared
    data = read(spec)
    if change == "order":
        data["sequence"].reverse()
    elif change == "quote":
        data["state"]["consumer"]["quote"] = "not source text"
    elif change == "missing_gap":
        data["unresolved"] = []
    elif change == "unknown_source":
        data["state"]["consumer"]["path"] = "missing.sh"
    elif change == "not_validated":
        decision = read(decisions[1] / "judgment.json")
        decision["promotion"]["eligible"] = False
        decision["identity_sha256"] = digest(
            {key: value for key, value in decision.items() if key != "identity_sha256"}
        )
        (decisions[1] / "judgment.json").write_text(encode(decision))
    else:
        original = read(decisions[0] / "judgment.json")
        worker = Path(original["inputs"]["baseline"])
        result = read(worker / "result.json")
        result["exit_code"] = 9
        result["identity_sha256"] = digest(
            {key: value for key, value in result.items() if key != "identity_sha256"}
        )
        (worker / "result.json").write_text(encode(result))
    spec.write_text(encode(data))
    output = root / "rejected-chain"
    with pytest.raises((ValueError, KeyError)):
        prepare_chain(*decisions, spec, output)
    assert read(output / "chain.json")["status"] == "failed"


def test_output_inside_target_is_rejected_before_creation(prepared):
    target, decisions, spec, _ = prepared
    with pytest.raises(ValueError, match="outside the target"):
        prepare_chain(*decisions, spec, target / "chain")
    assert not (target / "chain").exists()


def test_same_configuration_id_with_different_settings_is_rejected(prepared, monkeypatch):
    _, decisions, spec, root = prepared
    original = chain_module.verified_primitive

    def configured(path, scratch):
        saved, run = original(path, scratch)
        run = copy.deepcopy(run)
        run["result"]["identity"]["configuration_id"] = "release"
        run["recipe"]["configurations"] = [
            {"id": "release", "settings": {"optimization": "on" if path == decisions[0] else "off"}}
        ]
        return saved, run

    monkeypatch.setattr(chain_module, "verified_primitive", configured)
    with pytest.raises(ValueError, match="configuration"):
        prepare_chain(*decisions, spec, root / "mismatched-config")
