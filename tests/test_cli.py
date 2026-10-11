import json
from pathlib import Path

from agent_audit_harness.cli import main

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo-target"


def test_plan_has_scope_and_budget_but_no_source_text(capsys):
    assert main(["plan", str(DEMO), "--max-slices", "1"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["max_agent_calls_needed"] == 2
    assert "text" not in result["selected_slices"][0]


def test_codex_requires_explicit_model_before_any_call(capsys):
    assert main(["run", str(DEMO), "--codex"]) == 1
    assert "requires --model" in capsys.readouterr().err


def test_invalid_budget_returns_cli_error(capsys):
    assert main(["plan", str(DEMO), "--max-slices", "0"]) == 1
    assert "must be positive" in capsys.readouterr().err
