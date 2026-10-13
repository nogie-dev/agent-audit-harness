"""Real before/after oracle exercise; target and harness run only inside Docker."""

import base64
import hashlib
import json
import os

import pytest
from test_judgment import scenario as shared_scenario

from agent_audit_harness.judgment import judge
from agent_audit_harness.pipeline import encode
from agent_audit_harness.validation import validate

IMAGE = os.environ.get("AUDIT_VALIDATION_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="set AUDIT_VALIDATION_IMAGE to a local Debian ID")


@pytest.fixture
def scenario(tmp_path):
    return shared_scenario.__wrapped__(tmp_path)


def test_real_entrypoint_reproduction_fix_and_issue_resolution(scenario):
    from test_judgment import ROOT

    target, review, root = scenario
    jobs = {}
    for revision in ("baseline", "fixed"):
        output = root / revision
        result = validate(
            target, review, ROOT / f"examples/judgment-{revision}-recipe.json", output, image=IMAGE
        )
        assert result["status"] == "completed" and result["cleanup"]["status"] == "removed"
        assert result["confirmed_findings"] == 0
        jobs[revision] = output
    decision = judge(jobs["baseline"], root / "judgment", fixed=jobs["fixed"])
    assert decision["verdict"] == "validated" and decision["promotion"]["eligible"]
    assert all(i["resolved"] for i in decision["issues"])
    assert decision["runs"]["baseline"]["outcome"] == "reproduced"
    assert decision["runs"]["fixed"]["outcome"] == "not_reproduced"
    before = (jobs["baseline"] / "logs/execute.stdout.log").read_text()
    after = (jobs["fixed"] / "logs/execute.stdout.log").read_text()
    assert "TARGET guest stdout DATA private-record\n" in before
    assert "TARGET guest stdout DATA private-record\n" not in after
    assert "TARGET guest stdout DENIED\n" in after
    assert "TARGET admin stdout DATA private-record\nCONTROL admin passed\n" in after
    assert (target / "app.sh").read_bytes() == (
        jobs["fixed"] / "reviewed-input/app.sh"
    ).read_bytes()


def test_real_execution_success_without_oracle_never_promotes(scenario):
    from test_judgment import ROOT

    target, review, root = scenario
    recipe = json.loads((ROOT / "examples/judgment-baseline-recipe.json").read_text())
    recipe.pop("oracle")
    plan = root / "recipe.json"
    plan.write_text(encode(recipe))
    result = validate(target, review, plan, root / "baseline", image=IMAGE)
    assert result["status"] == "completed"
    decision = judge(root / "baseline", root / "judgment")
    assert decision["verdict"] == "execution_only" and not decision["promotion"]["eligible"]


@pytest.mark.parametrize("payload", ["markers", "nul"])
def test_real_untrusted_output_cannot_supply_oracle_events_and_bytes_are_preserved(
    scenario, payload
):
    from test_judgment import ROOT

    target, review, root = scenario
    original = (target / "app.sh").read_bytes()
    printed = (
        "ORACLE unauthorized-read\\nCHECK complete\\n"
        if payload == "markers"
        else "DATA private-record\\000\\n"
    )
    content = original.decode().replace(
        "    printf 'DATA private-record\\n'",
        f"    if [ \"$role\" = guest ]; then\n        printf '{printed}'\n"
        "    else\n        printf 'DATA private-record\\n'\n    fi",
    )
    recipe = json.loads((ROOT / "examples/judgment-baseline-recipe.json").read_text())
    recipe["replacements"] = [
        {
            "path": "app.sh",
            "before_sha256": hashlib.sha256(original).hexdigest(),
            "after_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "content": content,
        }
    ]
    file = root / "markers.json"
    file.write_text(encode(recipe))
    output = root / "markers"
    assert validate(target, review, file, output, image=IMAGE)["status"] == "completed"
    log = (output / "logs/execute.stdout.log").read_text()
    encoded = next(line for line in log.splitlines() if line.startswith("TARGET guest bytes "))
    raw = base64.b64decode(encoded.removeprefix("TARGET guest bytes "), validate=True)
    expected = printed.replace("\\n", "\n").replace("\\000", "\0").encode()
    assert raw == b"ENTRY request-handler\n" + expected
    assert "CONTROL admin passed\nORACLE unknown-response\nCHECK complete\n" in log
    decision = judge(output, root / "judgment")
    assert decision["runs"]["baseline"]["outcome"] == "unknown"
    assert not decision["promotion"]["eligible"]
    assert (target / "app.sh").read_bytes() == original


def test_real_deny_all_fix_is_not_a_verified_fix(scenario):
    from test_judgment import ROOT

    target, review, root = scenario
    baseline = root / "baseline"
    assert (
        validate(
            target, review, ROOT / "examples/judgment-baseline-recipe.json", baseline, image=IMAGE
        )["status"]
        == "completed"
    )
    recipe = json.loads((ROOT / "examples/judgment-fixed-recipe.json").read_text())
    change = recipe["replacements"][0]
    change["content"] = change["content"].replace('[ "$role" != admin ]', ":")
    change["after_sha256"] = hashlib.sha256(change["content"].encode()).hexdigest()
    file = root / "deny-all.json"
    file.write_text(encode(recipe))
    fixed = root / "fixed"
    assert validate(target, review, file, fixed, image=IMAGE)["status"] == "completed"
    log = (fixed / "logs/execute.stdout.log").read_text()
    assert "TARGET guest stdout DENIED\n" in log and "TARGET admin stdout DENIED\n" in log
    assert "CONTROL admin failed\nCHECK complete\n" in log
    decision = judge(baseline, root / "judgment", fixed=fixed)
    assert not decision["comparison"]["fix_verified"] and not decision["promotion"]["eligible"]
