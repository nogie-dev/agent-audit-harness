"""The held-out Go fixture has frozen, source-backed positive and negative labels."""

import shutil
from pathlib import Path

import pytest

from agent_audit_harness.benchmark import checked_truth
from agent_audit_harness.graph import build_graph, reachable
from agent_audit_harness.recon import build_recon

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples/go-eval-holdout-target"
pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain is required")


def test_go_holdout_labels_and_cross_package_structure(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(TARGET, target)
    labels, _, _, _ = checked_truth(target, ROOT / "examples/go-eval-holdout-truth.json")
    assert [(case["id"], case["expected"], case["path"], case["line"]) for case in labels] == [
        ("env-command-construction", "positive", "runner/runner.go", 6),
        ("fixed-shell-control", "negative", "runner/runner.go", 10),
    ]
    graph_dir = tmp_path / "graph"
    graph = build_graph(target, graph_dir, language="go")
    recon = build_recon(
        target,
        graph_dir / "graph.json",
        ROOT / "examples/go-eval-holdout-plan.json",
        tmp_path / "recon",
    )
    assert {h["id"] for h in recon["hypotheses"]} == {
        "env-command-construction",
        "fixed-shell-control",
    }
    calls = reachable(graph, "audit.example/commandcase/entry.Run")["calls"]
    assert {call["callee_name"] for call in calls if call["status"] == "resolved"} >= {
        "audit.example/commandcase/dispatch.Start",
        "audit.example/commandcase/runner.Build",
    }
    assert 'exec.Command("sh", "-c", value)' in (target / "runner/runner.go").read_text()
    assert 'exec.Command("sh", "-c", "echo ready")' in (target / "runner/runner.go").read_text()
