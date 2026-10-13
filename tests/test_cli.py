import json
from pathlib import Path

from agent_audit_harness.cli import main

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo-target"


def test_plan_has_scope_and_budget_but_no_source_text(capsys):
    assert main(["plan", str(DEMO), "--max-slices", "1"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["base_agent_calls_if_candidates"] == 2
    assert result["max_agent_calls_possible"] == 6
    assert result["configured_call_cap"] == 16
    assert main(["plan", str(DEMO), "--max-slices", "1", "--max-queries", "0"]) == 0
    assert json.loads(capsys.readouterr().out)["max_agent_calls_possible"] == 2
    assert "text" not in result["selected_slices"][0]
    assert (
        main(["plan", str(DEMO), "--max-slices", "1", "--repair-citations", "--max-calls", "7"])
        == 0
    )
    repaired = json.loads(capsys.readouterr().out)
    assert repaired["max_citation_repairs_per_call"] == 1
    assert repaired["max_agent_calls_possible"] == 7


def test_codex_requires_explicit_model_before_any_call(capsys):
    assert main(["run", str(DEMO), "--codex"]) == 1
    assert "requires --model" in capsys.readouterr().err


def test_invalid_budget_returns_cli_error(capsys):
    assert main(["plan", str(DEMO), "--max-slices", "0"]) == 1
    assert "must be positive" in capsys.readouterr().err
    assert main(["plan", str(DEMO), "--max-queries", "-1"]) == 1
    assert "invalid agent call or query budget" in capsys.readouterr().err
    assert main(["plan", str(DEMO), "--max-calls", "129"]) == 1
    assert "invalid agent call or query budget" in capsys.readouterr().err


def test_run_can_enable_bounded_citation_repair_with_offline_fixture(tmp_path, capsys):
    fixture = DEMO.parent / "citation-repair-replay"
    assert (
        main(
            [
                "run",
                str(DEMO),
                "--replay",
                str(fixture),
                "--max-slices",
                "1",
                "--repair-citations",
                "--output",
                str(tmp_path / "run"),
            ]
        )
        == 0
    )
    metrics = json.loads(capsys.readouterr().out)
    assert metrics["call_attempts"] == 3 and metrics["citation_repairs"] == 1
