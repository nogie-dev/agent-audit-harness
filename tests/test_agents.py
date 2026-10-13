import json
from pathlib import Path

import pytest

from agent_audit_harness.agents import CODEX_CONFIG, CodexAgent, strip_optional_nulls

ROOT = Path(__file__).resolve().parents[1]

FAKE_CODEX = """#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
if "--version" in sys.argv:
    print("codex test-fixture")
    raise SystemExit(0)
if "features" in sys.argv and "list" in sys.argv:
    for argument in sys.argv:
        if argument.startswith("features."):
            key, value = argument.split("=", 1)
            if os.environ.get("AUDIT_FAKE_FORCED_FEATURE") == key:
                value = "true"
            print(key.removeprefix("features.") + " stable " + value)
    raise SystemExit(0)
destination = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
prompt = sys.stdin.read()
(destination.parent / "capture.json").write_text(json.dumps({
    "argv": sys.argv[1:], "cwd": os.getcwd(), "prompt": prompt,
    "extra_secret_present": "AUDIT_TEST_SECRET" in os.environ,
}))
if "sleep-fixture" in sys.argv:
    time.sleep(20)
if "fail-fixture" in sys.argv:
    raise SystemExit(3)
if "noisy-fixture" in sys.argv:
    sys.stdout.write("x" * 2048)
    sys.stdout.flush()
    time.sleep(20)
destination.write_text(json.dumps(
    {"candidates": [], "requests": None, "model_proposals": None}
    if "nullable-fixture" in sys.argv else {"candidates": []}
))
print(json.dumps({"type": "turn.completed", "usage": {
    "input_tokens": 100, "cached_input_tokens": 20, "output_tokens": 10,
}}))
"""


def fake_codex(tmp_path, monkeypatch, model="fixture", timeout=10):
    executable = tmp_path / "codex"
    executable.write_text(FAKE_CODEX)
    executable.chmod(0o700)
    monkeypatch.setattr("agent_audit_harness.agents.shutil.which", lambda _: str(executable))
    return CodexAgent(model, timeout)


def test_codex_adapter_uses_stdin_isolated_cwd_strict_config_and_restricted_tools(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("AUDIT_TEST_SECRET", "should-not-be-inherited")
    agent = fake_codex(tmp_path, monkeypatch)
    directory = tmp_path / "call"
    directory.mkdir()
    reply = agent.call("analysis", "s0001", "untrusted evidence", {"type": "object"}, directory)
    assert reply.data == {"candidates": []}
    assert reply.usage["input_tokens"] == 100
    capture = json.loads((directory / "capture.json").read_text())
    assert capture["prompt"] == "untrusted evidence" and capture["argv"][-1] == "-"
    assert not capture["extra_secret_present"]
    assert capture["cwd"] != str(directory) and not Path(capture["cwd"]).exists()
    assert "--ignore-user-config" in capture["argv"] and "--strict-config" in capture["argv"]
    assert capture["argv"][capture["argv"].index("--sandbox") + 1] == "read-only"
    for key, value in CODEX_CONFIG.items():
        assert f"{key}={json.dumps(value)}" in capture["argv"]
    assert "--dangerously-bypass-approvals-and-sandbox" not in capture["argv"]


def test_codex_strict_schema_preserves_optional_contract_and_raw_reply(tmp_path, monkeypatch):
    agent = fake_codex(tmp_path, monkeypatch, "nullable-fixture")
    directory = tmp_path / "call"
    directory.mkdir()
    schema = json.loads((ROOT / "src/agent_audit_harness/schemas/analysis.json").read_text())
    reply = agent.call("analysis", "s0001", "input", schema, directory)
    sent = json.loads((directory / "schema.json").read_text())
    assert set(sent["required"]) == set(sent["properties"])
    assert sent["properties"]["model_proposals"]["anyOf"][1] == {"type": "null"}
    assert sent["properties"]["requests"]["anyOf"][0]["items"]["anyOf"][1]["properties"][
        "operation"
    ] == {"const": "source", "type": "string"}
    assert set(schema["required"]) == {"candidates"}
    assert json.loads((directory / "raw-response.json").read_text())["requests"] is None
    assert reply.data == {"candidates": []}
    required_null = {"properties": {"root_cause": {}}, "required": ["root_cause"]}
    assert strip_optional_nulls({"root_cause": None}, required_null) == {"root_cause": None}


def test_failed_codex_call_cannot_reuse_old_raw_reply(tmp_path, monkeypatch):
    agent = fake_codex(tmp_path, monkeypatch, "fail-fixture")
    directory = tmp_path / "call"
    directory.mkdir()
    (directory / "raw-response.json").write_text('{"candidates": []}')
    with pytest.raises(RuntimeError, match="exited 3"):
        agent.call("analysis", "s0001", "input", {}, directory)
    assert not (directory / "raw-response.json").exists()


def test_timeout_kills_process_group(tmp_path, monkeypatch):
    import subprocess

    agent = fake_codex(tmp_path, monkeypatch, "sleep-fixture", timeout=1)
    directory = tmp_path / "call"
    directory.mkdir()
    with pytest.raises(subprocess.TimeoutExpired):
        agent.call("analysis", "s0001", "input", {}, directory)
    assert not (directory / "raw-response.json").exists()


def test_codex_log_limit_kills_process_group(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_audit_harness.agents.MAX_CODEX_LOG_BYTES", 1024)
    agent = fake_codex(tmp_path, monkeypatch, "noisy-fixture")
    directory = tmp_path / "call"
    directory.mkdir()
    with pytest.raises(ValueError, match="logs exceed 8 MiB"):
        agent.call("analysis", "s0001", "input", {}, directory)
    assert (directory / "events.jsonl").stat().st_size > 1024
    assert not (directory / "raw-response.json").exists()


def test_replay_agent_bounds_file_count_size_total_and_symlinks(tmp_path, monkeypatch):
    from agent_audit_harness.agents import ReplayAgent

    replay = tmp_path / "replay"
    replay.mkdir()
    (replay / "a.json").write_text("{}")
    (replay / "b.json").write_text("{}")
    monkeypatch.setattr("agent_audit_harness.agents.MAX_REPLAY_FILES", 1)
    with pytest.raises(ValueError, match="exceeds 1 JSON files"):
        ReplayAgent(replay)

    monkeypatch.setattr("agent_audit_harness.agents.MAX_REPLAY_FILES", 128)
    monkeypatch.setattr("agent_audit_harness.agents.MAX_REPLAY_RESPONSE_BYTES", 1)
    with pytest.raises(ValueError, match="response exceeds 128 KiB"):
        ReplayAgent(replay)

    monkeypatch.setattr("agent_audit_harness.agents.MAX_REPLAY_RESPONSE_BYTES", 128 * 1024)
    monkeypatch.setattr("agent_audit_harness.agents.MAX_REPLAY_TOTAL_BYTES", 3)
    with pytest.raises(ValueError, match="responses exceed 8 MiB total"):
        ReplayAgent(replay)

    monkeypatch.setattr("agent_audit_harness.agents.MAX_REPLAY_TOTAL_BYTES", 8 * 1024 * 1024)
    (replay / "a.json").unlink()
    (replay / "b.json").unlink()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (replay / "linked.json").symlink_to(outside)
    with pytest.raises(ValueError, match="cannot read regular replay response"):
        ReplayAgent(replay)


def test_ignored_restriction_fails_before_a_model_call(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_FAKE_FORCED_FEATURE", "features.shell_tool")
    with pytest.raises(ValueError, match="refusing model invocation"):
        fake_codex(tmp_path, monkeypatch)
    assert not list(tmp_path.glob("**/capture.json"))
