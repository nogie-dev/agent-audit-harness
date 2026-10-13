"""Bounded invocation of trusted analysis tools."""

import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

MAX_TOOL_BYTES = 64 * 1024 * 1024


def run_tool(
    name: str, command: list, cwd: Path, environment: dict, timeout: int
) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="audit-tool-") as scratch:
        output_path, log_path = Path(scratch) / "stdout", Path(scratch) / "stderr"
        with output_path.open("wb") as output, log_path.open("wb") as errors:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=environment,
                stdout=output,
                stderr=errors,
                start_new_session=True,
            )
            deadline = time.monotonic() + timeout
            try:
                while process.poll() is None:
                    if time.monotonic() > deadline:
                        raise ValueError(f"{name} timeout after {timeout}s")
                    if any(
                        path.stat().st_size > MAX_TOOL_BYTES for path in (output_path, log_path)
                    ):
                        raise ValueError(f"{name} output exceeds 64 MiB")
                    time.sleep(0.05)
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError as error:
                        try:
                            process.wait(timeout=0.1)
                        except subprocess.TimeoutExpired as timeout_error:
                            raise error from timeout_error
                    process.wait()
        with log_path.open("rb") as stream:
            diagnostics = stream.read(64_000).decode("utf-8", errors="replace")
        if process.returncode:
            raise ValueError(f"{name} failed ({process.returncode}): {diagnostics}")
        if any(path.stat().st_size > MAX_TOOL_BYTES for path in (output_path, log_path)):
            raise ValueError(f"{name} output exceeds 64 MiB")
        return output_path.read_text(encoding="utf-8"), diagnostics
