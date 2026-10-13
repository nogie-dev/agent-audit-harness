import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from copy import deepcopy
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

MAX_REPLAY_FILES = 128
MAX_REPLAY_RESPONSE_BYTES = 128 * 1024
MAX_REPLAY_TOTAL_BYTES = 8 * 1024 * 1024
MAX_CODEX_LOG_BYTES = 8 * 1024 * 1024


@dataclass
class Reply:
    data: dict
    usage: dict | None = None


class ReplayAgent:
    """Recorded responses exercise orchestration without network or model charges."""

    def __init__(self, directory: Path):
        paths = list(islice(directory.glob("*.json"), MAX_REPLAY_FILES + 1))
        if len(paths) > MAX_REPLAY_FILES:
            raise ValueError(f"replay directory exceeds {MAX_REPLAY_FILES} JSON files")
        self.responses, total = {}, 0
        for path in sorted(paths):
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as error:
                raise ValueError(f"cannot read regular replay response: {path.name}") from error
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError(f"replay response is not a regular file: {path.name}")
                content = stream.read(MAX_REPLAY_RESPONSE_BYTES + 1)
            if len(content) > MAX_REPLAY_RESPONSE_BYTES:
                raise ValueError(f"replay response exceeds 128 KiB: {path.name}")
            total += len(content)
            if total > MAX_REPLAY_TOTAL_BYTES:
                raise ValueError("replay responses exceed 8 MiB total")
            self.responses[path.name] = content
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


def codex_output_schema(schema: dict) -> dict:
    """Make optional object fields nullable for Codex's strict JSON output."""
    result = deepcopy(schema)
    json_types = {
        str: "string",
        bool: "boolean",
        int: "integer",
        float: "number",
        type(None): "null",
    }

    def visit(node):
        if isinstance(node, list):
            for item in node:
                visit(item)
        elif isinstance(node, dict):
            if "type" not in node and "const" in node:
                node["type"] = json_types[type(node["const"])]
            if "type" not in node and "enum" in node and node["enum"]:
                kinds = {json_types[type(value)] for value in node["enum"]}
                if len(kinds) == 1:
                    node["type"] = kinds.pop()
            properties = node.get("properties")
            if isinstance(properties, dict):
                optional = properties.keys() - set(node.get("required", []))
                for name in optional:
                    properties[name] = {"anyOf": [properties[name], {"type": "null"}]}
                node["required"] = list(properties)
            for value in node.values():
                visit(value)

    visit(result)
    return result


def strip_optional_nulls(data, schema: dict, root: dict | None = None):
    """Restore omitted fields before validating against the original contract."""
    root = schema if root is None else root
    if "$ref" in schema:
        reference = schema["$ref"]
        if not reference.startswith("#/"):
            return data
        target = root
        for part in reference[2:].split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        return strip_optional_nulls(data, target, root)
    if isinstance(data, dict) and isinstance(schema.get("properties"), dict):
        properties = schema["properties"]
        required = set(schema.get("required", []))
        return {
            key: strip_optional_nulls(value, properties[key], root) if key in properties else value
            for key, value in data.items()
            if not (key in properties and key not in required and value is None)
        }
    if isinstance(data, list) and isinstance(schema.get("items"), dict):
        return [strip_optional_nulls(item, schema["items"], root) for item in data]
    return data


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
        schema_path.write_text(json.dumps(codex_output_schema(schema)), encoding="utf-8")
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
        event_path, error_path = directory / "events.jsonl", directory / "stderr.log"
        with tempfile.TemporaryDirectory(prefix="audit-agent-") as workspace:
            input_path = Path(workspace) / "prompt.txt"
            input_path.write_text(prompt, encoding="utf-8")
            with (
                input_path.open("r", encoding="utf-8") as input_stream,
                event_path.open("w", encoding="utf-8") as events,
                error_path.open("w", encoding="utf-8") as errors,
            ):
                process = subprocess.Popen(
                    command,
                    cwd=workspace,
                    env=environment,
                    stdin=input_stream,
                    stdout=events,
                    stderr=errors,
                    text=True,
                    start_new_session=True,
                )
                deadline = time.monotonic() + self.timeout
                try:
                    while process.poll() is None:
                        if time.monotonic() > deadline:
                            raise subprocess.TimeoutExpired(command, self.timeout)
                        if any(
                            path.stat().st_size > MAX_CODEX_LOG_BYTES
                            for path in (event_path, error_path)
                        ):
                            raise ValueError("codex logs exceed 8 MiB")
                        time.sleep(0.05)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
        if any(path.stat().st_size > MAX_CODEX_LOG_BYTES for path in (event_path, error_path)):
            raise ValueError("codex logs exceed 8 MiB")
        if process.returncode:
            raise RuntimeError(f"codex exited {process.returncode}; see {directory / 'stderr.log'}")
        if not response_path.is_file() or response_path.stat().st_size > 128 * 1024:
            raise ValueError("codex response missing or exceeds 128 KiB")
        usage = None
        for line in event_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("type") == "turn.completed":
                usage = event.get("usage")
        data = json.loads(response_path.read_text(encoding="utf-8"))
        return Reply(strip_optional_nulls(data, schema), usage)
