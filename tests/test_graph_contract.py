import json
import sys

import pytest

from agent_audit_harness.extractors.process import run_tool
from agent_audit_harness.graph import reachable, read_graph, resolve
from agent_audit_harness.pipeline import digest


def test_legacy_v1_graph_queries_and_checksum_remain_supported(tmp_path):
    graph = {
        "schema_version": 1,
        "functions": [
            {
                "id": "entry",
                "name": "entry",
                "qualified_name": "entry",
                "path": "entry.c",
                "signature": "void ()",
                "line": 1,
                "end_line": 1,
            }
        ],
        "calls": [
            {
                "id": "callback",
                "caller": "entry",
                "callee": None,
                "callee_name": "callback",
                "path": "entry.c",
                "line": 1,
                "column": 20,
                "status": "indirect",
            }
        ],
        "coverage": {"status": "parsed", "configuration_verified": False},
    }
    graph["identity_sha256"] = digest(graph)
    path = tmp_path / "graph-v1.json"
    path.write_text(json.dumps(graph))
    loaded = read_graph(path)
    assert resolve(loaded, "entry.c")["outgoing_calls"] == graph["calls"]
    assert reachable(loaded, "entry")["unresolved_calls"][0]["status"] == "indirect"
    assert loaded == graph  # Reader preserves the legacy artifact and identity.
    graph["functions"][0]["name"] = "changed"
    path.write_text(json.dumps(graph))
    with pytest.raises(ValueError, match="checksum mismatch"):
        read_graph(path)


def test_trusted_tool_output_limit_and_exit_error(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_audit_harness.extractors.process.MAX_TOOL_BYTES", 256)
    with pytest.raises(ValueError, match="output exceeds"):
        run_tool("fixture", [sys.executable, "-c", "print('x'*1000)"], tmp_path, {}, 2)
    with pytest.raises(ValueError, match="failed.*fixture error"):
        run_tool(
            "fixture",
            [sys.executable, "-c", "import sys; sys.exit('fixture error')"],
            tmp_path,
            {},
            2,
        )


@pytest.mark.parametrize("terminated", [True, False])
def test_signal_denial_preserves_limit_only_after_confirmed_termination(
    tmp_path, monkeypatch, terminated
):
    import subprocess

    class Process:
        pid = 123
        returncode = None
        waits = []

        def poll(self):
            return None

        def wait(self, timeout=None):
            self.waits.append(timeout)
            if not terminated:
                raise subprocess.TimeoutExpired("fixture", timeout)
            self.returncode = 0
            return 0

    process = Process()

    def spawn(*args, **kwargs):
        kwargs["stdout"].write(b"x" * 1000)
        kwargs["stdout"].flush()
        return process

    def denied(*args):
        raise PermissionError("fixture group signal denied")

    monkeypatch.setattr("agent_audit_harness.extractors.process.MAX_TOOL_BYTES", 256)
    monkeypatch.setattr("agent_audit_harness.extractors.process.subprocess.Popen", spawn)
    monkeypatch.setattr("agent_audit_harness.extractors.process.os.killpg", denied)
    if terminated:
        with pytest.raises(ValueError, match="output exceeds"):
            run_tool("fixture", ["unused"], tmp_path, {}, 2)
        assert process.waits == [0.1, None]
    else:
        with pytest.raises(PermissionError, match="signal denied"):
            run_tool("fixture", ["unused"], tmp_path, {}, 2)
        assert process.waits == [0.1]
