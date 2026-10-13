"""The evaluation rehearsal must be reproducible without model calls."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples/model_eval_preflight.py"


def test_python_preflight_rebuilds_evidence_and_rejects_output_reuse():
    (ROOT / "runs").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / "runs", prefix="preflight-test-") as name:
        output = Path(name)
        command = [sys.executable, str(SCRIPT), "--language", "python", "--output", name]
        first = subprocess.run(command, capture_output=True, text=True, timeout=60)
        assert first.returncode == 0, first.stderr
        summary = json.loads((output / "summary.json").read_text())
        result = summary["results"]["python"]
        assert summary["baseline_reply"] == "deliberately_empty_candidates"
        assert result["max_calls_per_run"] == 6
        assert set(result["preparation_seconds"]) == {"lexical_index_slice", "graph", "recon"}
        assert all(value >= 0 for value in result["preparation_seconds"].values())
        assert result["label_counts"]["candidate"]["uncovered_labels"] == 0
        assert result["prompt_bytes"]["candidate"] > result["prompt_bytes"]["baseline"]
        assert Path(result["comparison"]).is_file()
        assert (
            result["truth_sha256"]
            == json.loads((output / "python/comparison/benchmark.json").read_text())["truth_sha256"]
        )
        assert (output / "python/plan.json").is_file()
        assert (output / "python/truth.json").is_file()
        second = subprocess.run(command, capture_output=True, text=True, timeout=60)
        assert second.returncode != 0
        assert "must be an empty directory" in second.stderr
        assert json.loads((output / "summary.json").read_text()) == summary


def test_prospective_preflight_freezes_new_sources_truth_and_repair_budget():
    (ROOT / "runs").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / "runs", prefix="prospective-test-") as name:
        output = Path(name)
        command = [sys.executable, str(SCRIPT), "--suite", "prospective", "--output", name]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stderr
        summary = json.loads((output / "summary.json").read_text())
        protocol = json.loads((output / "protocol.json").read_text())
        assert summary["suite"] == "prospective"
        assert summary["candidate_reply"] == "deliberately_empty_candidates"
        assert protocol["approval_status"] == "not_requested"
        assert protocol["execution_status"] == "not_started"
        assert protocol["max_runs"] == 12
        assert protocol["max_call_attempts"] == 168
        assert protocol["model"] == "gpt-6-luna"
        caps = {
            language: item["max_calls_per_run"] for language, item in summary["results"].items()
        }
        assert caps == {
            "go": 18,
            "python": 12,
            "solidity": 12,
        }
        for language, item in summary["results"].items():
            assert all(counts["uncovered_labels"] == 0 for counts in item["label_counts"].values())
            slices = [
                len(json.loads((output / language / "rehearsal" / arm / "slices.json").read_text()))
                for arm in ("baseline", "candidate")
            ]
            assert item["max_calls_per_run"] >= max(slices) * 6
            assert Path(item["comparison"]).is_file()
            assert (output / language / "plan.json").is_file()
            assert (output / language / "truth.json").is_file()
            truth = json.loads((output / language / "truth.json").read_text())
            assert {case["expected"] for case in truth["cases"]} == {"positive", "negative"}
            assert all(case["accepted_locations"] for case in truth["cases"])
            if language == "solidity":
                assert all(
                    {case["cwe"], *(item["cwe"] for item in case["accepted_locations"])}
                    == {"CWE-284", "CWE-862"}
                    for case in truth["cases"]
                )
            assert (
                item["truth_sha256"]
                == json.loads(Path(item["comparison"]).read_text())["truth_sha256"]
            )
            frozen = protocol["inputs"][language]
            assert frozen["truth_sha256"] == item["truth_sha256"]
            assert frozen["plan_sha256"] == item["plan_sha256"]
            assert (
                frozen["graph_sha256"]
                == hashlib.sha256(Path(frozen["graph"]).read_bytes()).hexdigest()
            )
        graphs = {
            language: json.loads((output / language / "graph/graph.json").read_text())
            for language in summary["results"]
        }
        for language, source, target in (
            (
                "go",
                "audit.example/preview/web.Selected",
                "audit.example/preview/store.ReadSelected",
            ),
            ("python", "api.selected", "reader.read_selected"),
            ("solidity", "Vault.sol:Vault.setPayoutByOwner", "Access.sol:Access.onlyOwner"),
        ):
            graph = graphs[language]
            ids = {item["qualified_name"]: item["id"] for item in graph["functions"]}
            assert any(
                call["caller"] == ids[source]
                and call["callee"] == ids[target]
                and call["status"] == "resolved"
                for call in graph["calls"]
            )
        second = subprocess.run(command, capture_output=True, text=True, timeout=90)
        assert second.returncode != 0
        assert "must be an empty directory" in second.stderr
