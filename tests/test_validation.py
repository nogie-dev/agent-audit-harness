import copy
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.cli import main
from agent_audit_harness.pipeline import digest, encode, run_pipeline
from agent_audit_harness.validation import bounded_process, execution_command, validate

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:" + "a" * 64
TARGET = ROOT / "examples/validation-target"
REPLAY = ROOT / "examples/validation-replay"


def read(path):
    return json.loads(path.read_text())


@pytest.fixture
def job(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    for file in TARGET.iterdir():
        (target / file.name).write_bytes(file.read_bytes())
    review = tmp_path / "review"
    run_pipeline(target, review, ReplayAgent(REPLAY))
    recipe = tmp_path / "recipe.json"
    recipe.write_bytes((ROOT / "examples/validation-recipe.json").read_bytes())
    return target, review, recipe, tmp_path / "validation"


class FakeDocker:
    """Docker control responses only; never executes a target or a recipe."""

    def __init__(self):
        self.calls = []
        self.fail_stage = None
        self.control_reason = None
        self.reason = None
        self.exit_code = 0
        self.oom = False
        self.policy_change = lambda p: None
        self.info = {
            "os": "linux",
            "security": ["name=seccomp,profile=builtin"],
            "memory_limit": True,
            "pids_limit": True,
            "cpu_quota": True,
            "version": "fixture",
        }
        self.volumes = None
        self.started_at = "2026-10-12T00:00:00Z"
        self.stdout = "fixture validation stdout\n"
        self.stderr = "fixture validation stderr\n"

    def __call__(self, command, cwd, environment, prefix, timeout, byte_limit):
        stage = prefix.name
        self.calls.append((stage, command, environment.copy(), timeout, byte_limit))
        output = ""
        errors = ""
        code, reason = 0, None
        if stage == self.fail_stage:
            code, errors = 1, "fixture daemon failure\n"
            reason = self.control_reason
        elif stage == "engine":
            output = encode(self.info)
        elif stage == "image":
            output = encode(
                {"id": IMAGE, "os": "linux", "architecture": "fixture", "volumes": self.volumes}
            )
        elif stage == "policy":
            policy = read(ROOT / "examples/validation-policy.json")
            snapshot = str(prefix.parents[1] / "input")
            policy["mounts"][0]["Source"] = snapshot
            policy["host"]["Mounts"][0]["Source"] = snapshot
            recipe = read(prefix.parents[1] / "recipe.json")
            selected = (
                read(prefix.parents[1] / "result.json").get("identity", {}).get("configuration_id")
            )
            policy["command"] = policy["command"][:6] + execution_command(recipe, selected)
            self.policy_change(policy)
            output = encode(policy)
        elif stage == "execute":
            code, reason = self.exit_code, self.reason
            output = self.stdout
            errors = self.stderr
        elif stage == "state":
            output = encode(
                {
                    "Running": False,
                    "ExitCode": self.exit_code,
                    "OOMKilled": self.oom,
                    "Error": "",
                    "StartedAt": self.started_at,
                }
            )
        Path(str(prefix) + ".stdout.log").write_text(output)
        Path(str(prefix) + ".stderr.log").write_text(errors)
        return code, reason


@pytest.fixture
def engine(monkeypatch):
    engine = FakeDocker()
    monkeypatch.setattr("agent_audit_harness.validation.bounded_process", engine)
    monkeypatch.setattr("agent_audit_harness.validation.shutil.which", lambda _: "/trusted/docker")

    class Watchdog:
        pid = 123

        def terminate(self):
            pass

        def wait(self, timeout):
            return 0

        def poll(self):
            return None

    def armed(command, **kwargs):
        (Path(command[6]) / "watchdog.json").write_text(encode({"status": "armed"}))
        return Watchdog()

    monkeypatch.setattr("agent_audit_harness.validation.subprocess.Popen", armed)
    return engine


def test_worker_binds_only_snapshot_clears_credentials_and_preserves_evidence(
    job, engine, monkeypatch
):
    target, review, recipe_file, output = job
    for key in (
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "HTTP_PROXY",
        "DOCKER_HOST",
        "DOCKER_AUTH_CONFIG",
    ):
        monkeypatch.setenv(key, "synthetic-credential")
    original_review = {p.name: p.read_bytes() for p in review.glob("*.json")}
    recipe = read(recipe_file)
    recipe["command"] += ["$(touch /host-sentinel); `touch /another-host-sentinel`", "--privileged"]
    recipe_file.write_text(encode(recipe))
    result = validate(target, review, recipe_file, output, image=IMAGE)
    assert result["status"] == "completed" and result["exit_code"] == 0
    assert result["execution_started"] and result["execution_attempted"]
    assert result["confirmed_findings"] == 0 and result["cleanup"]["status"] == "removed"
    assert read(output / "candidate.json")["unresolved"]
    assert {p.name: p.read_bytes() for p in review.glob("*.json")} == original_review
    for stage, command, environment, _, _ in engine.calls:
        assert command[0] == "/trusted/docker" and command[1] == "--config"
        assert set(environment) == {"PATH", "HOME", "DOCKER_CONFIG"}
        assert environment["HOME"] == str(output / "docker-config")
        if stage != "create":
            assert not any("host-sentinel" in arg for arg in command)
    create = next(c[1] for c in engine.calls if c[0] == "create")
    assert create[create.index("--pull") + 1] == "never"
    assert create[create.index("--network") + 1] == "none"
    assert create[create.index("--entrypoint") + 1] == "/usr/bin/env"
    assert create[create.index(IMAGE) + 1 :] == ["-i", *read(output / "policy.json")["command"][1:]]
    mount = create[create.index("--mount") + 1]
    assert str(output / "input") in mount and str(target) not in mount and "readonly" in mount
    assert (output / "input/check.sh").read_bytes() == (target / "check.sh").read_bytes()
    assert (output / "input/check.sh").stat().st_mode & 0o777 == 0o444
    stored = read(output / "result.json")
    assert stored == result
    assert result["identity_sha256"] == digest(
        {k: v for k, v in result.items() if k != "identity_sha256"}
    )
    for item in result["evidence"]:
        data = (output / item["path"]).read_bytes()
        assert len(data) == item["bytes"] and hashlib.sha256(data).hexdigest() == item["sha256"]


@pytest.mark.parametrize(
    "mutation",
    [
        {"NetworkMode": "host"},
        {"ReadonlyRootfs": False},
        {"Privileged": True},
        {"CapDrop": []},
        {"CapAdd": ["SYS_ADMIN"]},
        {"SecurityOpt": []},
        {"SecurityOpt": ["no-new-privileges=true", "seccomp=unconfined"]},
        {"PidMode": "host"},
        {"UsernsMode": "host"},
        {"UTSMode": "host"},
        {"IpcMode": "host"},
        {"Memory": 0},
        {"MemorySwap": -1},
        {"NanoCpus": 0},
        {"PidsLimit": -1},
        {"Tmpfs": {}},
        {"Ulimits": []},
        {"Devices": [{"PathOnHost": "/dev/sda"}]},
        {"LogConfig": {"Type": "json-file"}},
        {"ShmSize": 0},
    ],
)
def test_ignored_isolation_option_prevents_execution_and_removes_container(job, engine, mutation):
    engine.policy_change = lambda p: p["host"].update(mutation)
    result = validate(*job, image=IMAGE)
    assert result["status"] == "worker_failed" and result["failure"]["stage"] == "policy"
    assert result["execution_started"] is False and result["execution_attempted"] is False
    assert "execute" not in [c[0] for c in engine.calls]
    assert result["cleanup"]["status"] == "removed"


@pytest.mark.parametrize(
    "change", ["writable", "extra_mount", "wrong_source", "root", "entrypoint", "command"]
)
def test_mount_user_and_entrypoint_cannot_be_replaced(job, engine, change):
    def mutate(p):
        if change == "writable":
            p["mounts"][0]["RW"] = True
        elif change == "extra_mount":
            p["mounts"].append({"Source": "/home", "RW": False})
        elif change == "wrong_source":
            p["mounts"][0]["Source"] = str(job[0])
        elif change == "root":
            p["user"] = "0:0"
        elif change == "entrypoint":
            p["entrypoint"] = ["/host-secret-loader"]
        else:
            p["command"] = ["/bin/sh"]

    engine.policy_change = mutate
    result = validate(*job, image=IMAGE)
    assert not result["execution_attempted"] and result["cleanup"]["status"] == "removed"


@pytest.mark.parametrize(
    "mode,status,exit_code,oom",
    [
        ("failure", "process_failed", 7, False),
        ("timeout", "timeout", 137, False),
        ("output", "output_limit", 137, False),
        ("oom", "process_failed", 137, True),
    ],
)
def test_failures_keep_logs_exit_state_source_and_cleanup(
    job, engine, mode, status, exit_code, oom
):
    engine.exit_code, engine.oom = exit_code, oom
    if mode in {"timeout", "output"}:
        engine.reason = status
    result = validate(*job, image=IMAGE)
    assert result["status"] == status and result["exit_code"] == exit_code
    assert result["oom_killed"] is oom and result["cleanup"]["status"] == "removed"
    assert (job[3] / "logs/execute.stderr.log").read_text() == "fixture validation stderr\n"
    assert read(job[3] / "state.json")["ExitCode"] == exit_code
    assert result["failure"]["stage"] == "execute" and result["confirmed_findings"] == 0
    if engine.reason:
        assert "kill" in [c[0] for c in engine.calls]


@pytest.mark.parametrize("phase", ["create", "policy", "execute", "state", "cleanup"])
def test_control_failure_records_phase_and_cleanup(job, engine, phase):
    engine.fail_stage = phase
    result = validate(*job, image=IMAGE)
    assert result["status"] == "worker_failed" and result["failure"]["stage"] == phase
    assert result["cleanup"]["status"] == ("failed" if phase == "cleanup" else "removed")
    assert read(job[3] / "result.json") == result
    assert "cleanup" in [c[0] for c in engine.calls]


@pytest.mark.parametrize(
    "gap", ["seccomp", "memory_limit", "pids_limit", "cpu_quota", "image_volumes"]
)
def test_missing_engine_limits_or_implicit_image_volumes_fail_closed(job, engine, gap):
    if gap == "seccomp":
        engine.info["security"] = []
    elif gap == "image_volumes":
        engine.volumes = {"/credential-volume": {}}
    else:
        engine.info[gap] = False
    result = validate(*job, image=IMAGE)
    assert result["status"] == "worker_failed" and not result["execution_attempted"]
    assert result["cleanup"]["status"] == "not_created"


@pytest.mark.parametrize(
    "change",
    [
        "unknown_id",
        "source_changed",
        "recipe_hash",
        "duplicate",
        "unsafe_path",
        "extra_option",
        "relative_command",
        "nul",
        "rejected",
        "incomplete",
        "queue_tamper",
    ],
)
def test_invalid_recipe_review_and_source_fail_before_docker(job, engine, change):
    target, review, recipe_file, output = job
    recipe = read(recipe_file)
    if change == "unknown_id":
        recipe["candidate_id"] = "f-0000000000000000"
    elif change == "source_changed":
        (target / "check.sh").write_text("changed\n")
    elif change == "recipe_hash":
        recipe["inputs"][0]["sha256"] = "0" * 64
    elif change == "duplicate":
        recipe["inputs"] *= 2
    elif change == "unsafe_path":
        recipe["inputs"][0]["path"] = "../outside.sh"
    elif change == "extra_option":
        recipe["network"] = "host"
    elif change == "relative_command":
        recipe["command"][0] = "sh"
    elif change == "nul":
        recipe["command"].append("bad\0argument")
    elif change == "rejected":
        findings = read(review / "findings.json")
        findings[0]["verdict"] = "rejected"
        (review / "findings.json").write_text(encode(findings))
        (review / "validation-queue.json").write_text("[]")
    elif change == "incomplete":
        manifest = read(review / "manifest.json")
        manifest["status"] = "failed"
        (review / "manifest.json").write_text(encode(manifest))
    else:
        (review / "validation-queue.json").write_text("[]")
    recipe_file.write_text(encode(recipe))
    result = validate(*job, image=IMAGE)
    assert result["status"] == "worker_failed" and result["failure"]["stage"] == "prepare"
    assert not engine.calls and result["cleanup"]["status"] == "not_created"


def test_source_symlink_parent_symlink_fifo_and_credentials_are_not_copied(job, engine):
    target, _, recipe_file, _ = job
    outside = target.parent / "outside"
    outside.mkdir()
    (outside / "data.sh").write_text("synthetic credential\n")
    (target / "link").symlink_to(outside, target_is_directory=True)
    (target / "linked.sh").symlink_to(outside / "data.sh")
    os.mkfifo(target / "fifo.sh")
    recipe = read(recipe_file)
    for index, relative in enumerate(
        ("link/data.sh", "linked.sh", "fifo.sh", ".env", "credentials.json")
    ):
        changed = copy.deepcopy(recipe)
        changed["inputs"].append({"path": relative, "sha256": "0" * 64})
        recipe_file.write_text(encode(changed))
        result = validate(*job[:3], job[3].parent / f"blocked-{index}", image=IMAGE)
        assert result["status"] == "worker_failed" and not engine.calls


def test_no_docker_and_remote_socket_have_no_host_fallback(job, engine, monkeypatch):
    monkeypatch.setattr("agent_audit_harness.validation.shutil.which", lambda _: None)
    assert validate(*job, image=IMAGE)["execution_attempted"] is False
    assert not engine.calls
    monkeypatch.setattr("agent_audit_harness.validation.shutil.which", lambda _: "/trusted/docker")
    result = validate(
        *job[:3], job[3].parent / "remote", image=IMAGE, docker_host="tcp://remote:2375"
    )
    assert result["status"] == "worker_failed" and not engine.calls


def test_nonempty_output_and_target_review_boundaries_preserve_data(job, engine):
    output = job[3]
    output.mkdir()
    (output / "keep").write_text("existing")
    with pytest.raises(ValueError, match="nonempty"):
        validate(*job, image=IMAGE)
    assert (output / "keep").read_text() == "existing" and not engine.calls
    for forbidden in (job[0] / "results", job[1] / "results"):
        with pytest.raises(ValueError, match="outside"):
            validate(*job[:3], forbidden, image=IMAGE)
        assert not forbidden.exists()


def test_worker_does_not_claim_execution_without_observed_start(job, engine):
    engine.started_at = "0001-01-01T00:00:00Z"
    result = validate(*job, image=IMAGE)
    assert result["execution_attempted"] and result["execution_started"] is False
    assert result["status"] == "worker_failed"


def test_bounded_process_keeps_failure_logs_and_caps_output(tmp_path):
    code, reason = bounded_process(
        [
            sys.executable,
            "-I",
            "-c",
            'import sys; print("out"); print("err",file=sys.stderr); sys.exit(7)',
        ],
        tmp_path,
        {"PATH": os.defpath},
        tmp_path / "failure",
        2,
        1024,
    )
    assert code == 7 and reason is None
    assert (tmp_path / "failure.stdout.log").read_text() == "out\n"
    assert (tmp_path / "failure.stderr.log").read_text() == "err\n"
    code, reason = bounded_process(
        [sys.executable, "-I", "-c", 'import os; os.write(1,b"x"*1000000)'],
        tmp_path,
        {"PATH": os.defpath},
        tmp_path / "output",
        2,
        1024,
    )
    assert reason == "output_limit" and (tmp_path / "output.stdout.log").stat().st_size == 1024


def test_bounded_process_timeout_preserves_partial_output(tmp_path):
    code, reason = bounded_process(
        [sys.executable, "-I", "-c", 'import time; print("before",flush=True); time.sleep(5)'],
        tmp_path,
        {"PATH": os.defpath},
        tmp_path / "timeout",
        0.1,
        1024,
    )
    assert code != 0 and reason == "timeout"
    assert (tmp_path / "timeout.stdout.log").read_text() == "before\n"


def test_validation_cli_returns_record_path_and_failure_code(job, engine, capsys):
    engine.exit_code = 9
    assert (
        main(
            [
                "validate",
                str(job[0]),
                "--run",
                str(job[1]),
                "--recipe",
                str(job[2]),
                "--image",
                IMAGE,
                "--output",
                str(job[3]),
            ]
        )
        == 1
    )
    result = json.loads(capsys.readouterr().out)
    assert result["exit_code"] == 9 and result["cleanup"]["status"] == "removed"


def test_control_timeout_is_recorded_without_executing_target(job, engine):
    engine.fail_stage = "policy"
    engine.control_reason = "timeout"
    result = validate(*job, image=IMAGE)
    assert result["status"] == "worker_failed" and not result["execution_attempted"]
    assert "timeout" in result["failure"]["detail"]
    assert result["cleanup"]["status"] == "removed"


@pytest.mark.parametrize(
    "field,value",
    [
        ("timeout_seconds", 0),
        ("cpus", 0),
        ("memory_mb", 4096),
        ("pids", -1),
        ("scratch_mb", 0),
        ("output_bytes", 1),
    ],
)
def test_recipe_cannot_remove_resource_limits(job, engine, field, value):
    recipe = read(job[2])
    recipe["limits"][field] = value
    job[2].write_text(encode(recipe))
    result = validate(*job, image=IMAGE)
    assert result["status"] == "worker_failed" and not engine.calls
    assert read(job[3] / "recipe.json") == recipe


def test_image_tags_are_rejected_without_pull_or_execution(job, engine):
    result = validate(*job, image="debian:latest")
    assert result["status"] == "worker_failed" and not engine.calls


def test_disposal_timer_failure_prevents_target_start(job, engine, monkeypatch):
    class FailedWatchdog:
        pid = 123

        def poll(self):
            return 1

        def terminate(self):
            pass

        def wait(self, timeout):
            return 1

    monkeypatch.setattr(
        "agent_audit_harness.validation.subprocess.Popen", lambda *a, **kw: FailedWatchdog()
    )
    result = validate(*job, image=IMAGE)
    assert result["status"] == "worker_failed" and not result["execution_attempted"]
    assert result["failure"]["stage"] == "watchdog"
    assert result["cleanup"]["status"] == "removed"
    assert "execute" not in [call[0] for call in engine.calls]


def test_interruption_keeps_pending_evidence_and_cleans_up(job, engine, monkeypatch):
    def interrupted(command, cwd, environment, prefix, timeout, byte_limit):
        if prefix.name == "execute":
            raise KeyboardInterrupt()
        return engine(command, cwd, environment, prefix, timeout, byte_limit)

    monkeypatch.setattr("agent_audit_harness.validation.bounded_process", interrupted)
    result = validate(*job, image=IMAGE)
    assert result["status"] == "interrupted" and result["execution_attempted"]
    assert result["execution_started"] is None and result["exit_code"] is None
    assert result["cleanup"]["status"] == "removed"
    assert read(job[3] / "watchdog.json")["status"] == "cancelled_after_cleanup"
    assert (job[3] / "candidate.json").exists() and (job[3] / "policy.json").exists()


@pytest.mark.parametrize("change", ["healthcheck", "working_dir", "started"])
def test_unexpected_image_behavior_is_rejected_before_execution(job, engine, change):
    def mutate(policy):
        if change == "healthcheck":
            policy["healthcheck"] = {"Test": ["CMD-SHELL", "load-credentials"]}
        elif change == "working_dir":
            policy["working_dir"] = "/"
        else:
            policy["state"].update(Status="running", Running=True)

    engine.policy_change = mutate
    result = validate(*job, image=IMAGE)
    assert result["status"] == "worker_failed" and not result["execution_attempted"]
