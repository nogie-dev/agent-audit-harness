"""Opt-in real Docker tests with a prepared immutable Debian image; no pulls."""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.pipeline import encode, run_pipeline
from agent_audit_harness.validation import validate

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("AUDIT_VALIDATION_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="set AUDIT_VALIDATION_IMAGE to a local Debian ID")


@pytest.fixture
def job(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    source = ROOT / "examples/validation-target/check.sh"
    (target / "check.sh").write_bytes(source.read_bytes())
    review = tmp_path / "review"
    run_pipeline(target, review, ReplayAgent(ROOT / "examples/validation-replay"))
    recipe = tmp_path / "recipe.json"
    recipe.write_bytes((ROOT / "examples/validation-recipe.json").read_bytes())
    return target, review, recipe, tmp_path / "validation"


def execute(job, command, *, timeout=10, output_bytes=1048576):
    recipe = json.loads(job[2].read_text())
    recipe["command"] = command
    recipe["limits"].update(timeout_seconds=timeout, output_bytes=output_bytes)
    job[2].write_text(encode(recipe))
    result = validate(*job, image=IMAGE)
    assert result["cleanup"]["status"] == "removed", result
    assert result["confirmed_findings"] == 0
    # Inspect only this worker's random name, never unrelated user containers.
    probe = subprocess.run(
        [
            shutil.which("docker"),
            "--config",
            str(job[3] / "docker-config"),
            "--host",
            result["docker_host"],
            "container",
            "inspect",
            result["container_name"],
        ],
        capture_output=True,
        timeout=10,
        env={"PATH": os.defpath, "HOME": str(job[3] / "docker-config")},
    )
    assert probe.returncode != 0
    for item in result["evidence"]:
        data = (job[3] / item["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"] and len(data) == item["bytes"]
    return result


def test_real_containment_credentials_readonly_network_and_cgroup_limits(job, monkeypatch):
    monkeypatch.setenv("AUDIT_TEST_CREDENTIAL", "synthetic-host-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-host-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-host-secret")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/synthetic-host-agent.sock")
    monkeypatch.setenv("HTTP_PROXY", "http://synthetic-host-proxy.invalid")
    private = job[0].parent / "private-host-token"
    private.write_text("synthetic-host-secret")
    result = execute(
        job,
        [
            "/bin/sh",
            "-c",
            (
                f"test ! -e {shlex.quote(str(private))} && /bin/sh /input/check.sh && "
                "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max"
            ),
        ],
    )
    assert result["status"] == "completed" and result["execution_started"]
    stdout = (job[3] / "logs/execute.stdout.log").read_text()
    assert "CONTAINMENT_CHECKS_PASSED" in stdout
    assert "134217728\n32\n50000 100000\n" in stdout
    assert "synthetic-host-secret" not in stdout
    assert not (job[0] / "host-write-probe").exists()
    policy = json.loads((job[3] / "policy.json").read_text())
    assert policy["host"]["NetworkMode"] == "none" and policy["mounts"][0]["RW"] is False


def test_real_nonzero_exit_keeps_failure_evidence(job):
    result = execute(job, ["/bin/sh", "-c", "printf 'failure evidence\\n' >&2; exit 23"])
    assert result["status"] == "process_failed" and result["exit_code"] == 23
    assert "failure evidence" in (job[3] / "logs/execute.stderr.log").read_text()


def test_real_timeout_kills_container_and_its_child(job):
    result = execute(
        job, ["/bin/sh", "-c", "printf 'before timeout\\n'; sleep 20 & wait"], timeout=1
    )
    assert result["status"] == "timeout" and result["exit_code"] == 137
    assert "before timeout" in (job[3] / "logs/execute.stdout.log").read_text()
    assert json.loads((job[3] / "state.json").read_text())["Running"] is False


def test_real_output_limit_retains_bounded_prefix(job):
    result = execute(job, ["/bin/sh", "-c", "yes evidence"], output_bytes=1024)
    assert result["status"] == "output_limit"
    assert (job[3] / "logs/execute.stdout.log").stat().st_size == 1024
    assert json.loads((job[3] / "state.json").read_text())["Running"] is False


def test_real_memory_limit_records_oom_kill(job):
    result = execute(job, ["/usr/bin/awk", 'BEGIN { s="x"; while (1) {s=s s} }'])
    assert result["status"] == "process_failed" and result["exit_code"] == 137
    assert result["oom_killed"] is True


def test_real_scratch_space_is_bounded(job):
    result = execute(job, ["/bin/dd", "if=/dev/zero", "of=/work/fill", "bs=1M", "count=40"])
    assert result["status"] == "process_failed"
    assert "No space left" in (job[3] / "logs/execute.stderr.log").read_text()


def test_real_process_limit_blocks_forking(job):
    result = execute(
        job,
        ["/bin/sh", "-c", "i=0; while [ $i -lt 100 ]; do sleep 20 & i=$((i+1)); done; wait"],
        timeout=2,
    )
    assert result["status"] == "process_failed"
    stderr = (job[3] / "logs/execute.stderr.log").read_text().lower()
    assert "fork" in stderr or "resource temporarily unavailable" in stderr


def test_real_external_connection_is_blocked(job):
    result = execute(
        job,
        [
            "/bin/bash",
            "-c",
            (
                "if exec 3<>/dev/tcp/1.1.1.1/443; then exit 21; "
                "else printf 'NETWORK_CONNECTION_BLOCKED\\n'; fi"
            ),
        ],
    )
    assert result["status"] == "completed"
    assert "NETWORK_CONNECTION_BLOCKED" in (job[3] / "logs/execute.stdout.log").read_text()
    assert "Network is unreachable" in (job[3] / "logs/execute.stderr.log").read_text()


def test_disposal_timer_removes_container_after_controller_sigkill(job):
    recipe = json.loads(job[2].read_text())
    recipe["command"] = ["/bin/sh", "-c", "printf 'orphan started\\n'; sleep 60"]
    recipe["limits"]["timeout_seconds"] = 1
    job[2].write_text(encode(recipe))
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agent_audit_harness",
            "validate",
            str(job[0]),
            "--run",
            str(job[1]),
            "--recipe",
            str(job[2]),
            "--image",
            IMAGE,
            "--docker",
            shutil.which("docker"),
            "--output",
            str(job[3]),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath},
    )
    try:
        stdout = job[3] / "logs/execute.stdout.log"
        deadline = time.monotonic() + 5
        while not stdout.exists() or b"orphan started" not in stdout.read_bytes():
            assert process.poll() is None
            assert time.monotonic() < deadline, "worker did not start"
            time.sleep(0.02)
        process.kill()
        process.wait(timeout=5)
        timer = job[3] / "watchdog.json"
        deadline = time.monotonic() + 5
        while json.loads(timer.read_text())["status"] == "armed":
            assert time.monotonic() < deadline, "disposal timer did not remove orphan"
            time.sleep(0.02)
        record = json.loads(timer.read_text())
        assert record["status"] == "removed" and record["exit_code"] == 0
        pending = json.loads((job[3] / "result.json").read_text())
        assert pending["execution_attempted"] and pending["execution_started"] is None
        probe = subprocess.run(
            [
                shutil.which("docker"),
                "--config",
                str(job[3] / "docker-config"),
                "--host",
                pending["docker_host"],
                "container",
                "inspect",
                pending["container_name"],
            ],
            capture_output=True,
            timeout=10,
            env={"PATH": os.defpath},
        )
        assert probe.returncode != 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
