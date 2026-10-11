import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Reply:
    data: dict
    usage: dict | None = None


class ReplayAgent:
    """Recorded responses exercise orchestration without network or model charges."""

    def __init__(self, directory: Path):
        self.responses = {path.name: path.read_bytes() for path in sorted(directory.glob("*.json"))}
        if not self.responses:
            raise ValueError(f"no replay JSON files in {directory}")
        digest = hashlib.sha256()
        for name, content in self.responses.items():
            digest.update(name.encode() + b"\0" + content + b"\0")
        self.identity = {"provider": "replay", "fixture_sha256": digest.hexdigest()}

    def call(self, stage: str, slice_id: str, prompt: str, schema: dict, directory: Path) -> Reply:
        name = f"{slice_id}.{stage}.json"
        if name not in self.responses:
            raise ValueError(f"missing replay response: {name}")
        return Reply(json.loads(self.responses[name]))


# These restrictions apply to research calls, not to the agent developing this repository.
CODEX_CONFIG = {
    "approval_policy": "never",
    "web_search": "disabled",
    "project_doc_max_bytes": 0,
    "features.shell_tool": False,
    "features.shell_snapshot": False,
    "features.view_image": False,
    "features.apps": False,
    "features.plugins": False,
    "features.hooks": False,
    "features.multi_agent": False,
    "features.memories": False,
    "features.remote_plugin": False,
    "features.browser_use": False,
    "features.computer_use": False,
    "features.code_mode": False,
    "features.image_generation": False,
}


class CodexAgent:
    def __init__(self, model: str, timeout: int = 180):
        self.executable = shutil.which("codex")
        if not self.executable:
            raise ValueError("codex CLI not found; use --replay for offline development")
        if not model.strip() or timeout < 1:
            raise ValueError("a model and a positive timeout are required")
        self.model = model
        self.timeout = timeout
        version = subprocess.run(
            [self.executable, "--version"], capture_output=True, text=True, check=True, timeout=10
        ).stdout.strip()
        self.config_arguments = []
        for key, value in CODEX_CONFIG.items():
            self.config_arguments.extend(["--config", f"{key}={json.dumps(value)}"])
        feature_result = subprocess.run(
            [self.executable, *self.config_arguments, "features", "list"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        effective = {}
        for line in feature_result.stdout.splitlines():
            fields = line.split()
            if fields:
                effective[fields[0]] = fields[-1]
        for key in CODEX_CONFIG:
            if (
                key.startswith("features.")
                and effective.get(key.removeprefix("features.")) != "false"
            ):
                raise ValueError(f"Codex did not honor {key}=false; refusing model invocation")
        self.identity = {
            "provider": "codex",
            "model": model,
            "cli_version": version,
            "config": CODEX_CONFIG,
        }

    def call(self, stage: str, slice_id: str, prompt: str, schema: dict, directory: Path) -> Reply:
        schema_path = directory / "schema.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        response_path = directory / "raw-response.json"
        # An old partial reply must never stand in for a failed retry.
        response_path.unlink(missing_ok=True)
        command = [
            self.executable,
            "exec",
            "--strict-config",
            "--ignore-user-config",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--json",
            "--color",
            "never",
            "--model",
            self.model,
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(response_path),
        ]
        command.extend(self.config_arguments)
        command.append("-")
        allowed = {
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "CODEX_HOME",
            "OPENAI_API_KEY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
        }
        environment = {key: value for key, value in os.environ.items() if key in allowed}
        with (
            tempfile.TemporaryDirectory(prefix="audit-agent-") as workspace,
            (directory / "events.jsonl").open("w", encoding="utf-8") as events,
            (directory / "stderr.log").open("w", encoding="utf-8") as errors,
        ):
            process = subprocess.Popen(
                command,
                cwd=workspace,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=events,
                stderr=errors,
                text=True,
                start_new_session=True,
            )
            try:
                process.communicate(prompt, timeout=self.timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise
        if process.returncode:
            raise RuntimeError(f"codex exited {process.returncode}; see {directory / 'stderr.log'}")
        if not response_path.is_file() or response_path.stat().st_size > 128 * 1024:
            raise ValueError("codex response missing or exceeds 128 KiB")
        usage = None
        for line in (directory / "events.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("type") == "turn.completed":
                usage = event.get("usage")
        return Reply(json.loads(response_path.read_text(encoding="utf-8")), usage)
