"""The file-selection fixture connects reviewed structure to an isolated HTTP comparison."""

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.graph import build_graph, reachable
from agent_audit_harness.judgment import candidate_issues, judge
from agent_audit_harness.pipeline import run_pipeline
from agent_audit_harness.recon import build_recon
from agent_audit_harness.validation import prepare_inputs, validate

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples/go-file-selection-target"
IMAGE = os.environ.get("AUDIT_GO_VALIDATION_IMAGE")
DOCKER_HOST = os.environ.get("AUDIT_GO_DOCKER_HOST")
pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain is required")


def read(path):
    return json.loads(path.read_text())


@pytest.fixture
def scenario(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(TARGET, target)
    graph_dir = tmp_path / "graph"
    graph = build_graph(target, graph_dir, language="go")
    recon = build_recon(
        target,
        graph_dir / "graph.json",
        ROOT / "examples/go-file-selection-plan.json",
        tmp_path / "recon",
    )
    review = tmp_path / "review"
    run_pipeline(
        target,
        review,
        ReplayAgent(ROOT / "examples/go-file-selection-replay"),
        graph_file=graph_dir / "graph.json",
        recon_file=tmp_path / "recon/recon.json",
    )
    return target, graph, recon, review


def test_reviewed_file_selection_and_only_declared_replacement(scenario, tmp_path):
    target, graph, recon, review = scenario
    candidate = read(review / "findings.json")[0]
    assert candidate["path"] == "storage/files.go" and candidate["line"] == 6
    assert candidate["cwe"] == "CWE-73" and candidate["verdict"] == "uncertain"
    assert recon["hypotheses"][0]["id"] == "request-selected-export"
    calls = reachable(graph, "audit.example/exporter/web.Download")["calls"]
    assert {c["callee_name"] for c in calls if c["status"] == "resolved"} >= {
        "audit.example/exporter/relay.Fetch",
        "audit.example/exporter/storage.Open",
    }
    notice_calls = reachable(graph, "audit.example/exporter/storage.ReadNotice")["calls"]
    assert {c["callee_name"] for c in notice_calls} == {"os.ReadFile"}

    original = hashlib.sha256((target / "storage/files.go").read_bytes()).hexdigest()
    baseline = read(ROOT / "examples/go-file-selection-baseline-recipe.json")
    fixed = read(ROOT / "examples/go-file-selection-fixed-recipe.json")
    assert baseline["candidate_id"] == candidate["id"]
    assert {r["issue_id"] for r in baseline["oracle"]["resolutions"]} == {
        issue["id"] for issue in candidate_issues(candidate)
    }
    assert baseline["oracle"] == fixed["oracle"]
    assert baseline["inputs"] == fixed["inputs"]
    assert baseline["command"] == fixed["command"]
    for name, recipe in (("baseline", baseline), ("fixed", fixed)):
        _, _, _, manifest = prepare_inputs(target, review, recipe, tmp_path / name)
        changed = [m["path"] for m in manifest if m["reviewed_sha256"] != m["executed_sha256"]]
        assert changed == (["storage/files.go"] if name == "fixed" else [])
    assert hashlib.sha256((target / "storage/files.go").read_bytes()).hexdigest() == original


def test_changed_supplied_probe_is_rejected_before_execution(scenario, tmp_path):
    target, _, _, review = scenario
    (target / "probe.sh").write_text((target / "probe.sh").read_text() + "\n# stale\n")
    with pytest.raises(ValueError, match="validation input does not match"):
        prepare_inputs(
            target,
            review,
            read(ROOT / "examples/go-file-selection-baseline-recipe.json"),
            tmp_path / "snapshot",
        )
    assert not (tmp_path / "snapshot").exists()


@pytest.mark.skipif(
    not IMAGE, reason="set AUDIT_GO_VALIDATION_IMAGE to a prepared local Go image ID"
)
def test_real_file_selection_before_after_and_constant_control(scenario, tmp_path):
    target, _, _, review = scenario
    jobs = {}
    for revision in ("baseline", "fixed"):
        output = tmp_path / revision
        result = validate(
            target,
            review,
            ROOT / f"examples/go-file-selection-{revision}-recipe.json",
            output,
            image=IMAGE,
            docker_host=DOCKER_HOST,
        )
        assert result["status"] == "completed" and result["cleanup"]["status"] == "removed"
        assert read(output / "policy.json")["host"]["NetworkMode"] == "none"
        jobs[revision] = output
    before = (jobs["baseline"] / "logs/execute.stdout.log").read_text()
    after = (jobs["fixed"] / "logs/execute.stdout.log").read_text()
    assert 'HTTP private status 200 body "DATA private-record\\n"' in before
    assert 'HTTP private status 404 body "unavailable\\n"' in after
    for log in (before, after):
        assert 'HTTP public status 200 body "DATA public-record\\n"' in log
        assert 'HTTP notice status 200 body "DATA public-notice\\n"' in log
        assert 'TARGET private stdout "ENTRY HTTP /download"' in log
        assert "CONTROL passed\n" in log
    decision = judge(jobs["baseline"], tmp_path / "judgment", fixed=jobs["fixed"])
    assert decision["verdict"] == "validated" and decision["promotion"]["eligible"]
