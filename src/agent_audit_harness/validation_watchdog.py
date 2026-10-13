"""Independent disposal timer; only removes the parent worker's container."""

import os
import re
import sys
import time
from pathlib import Path

from .pipeline import save_json
from .validation import bounded_process


def main():
    executable, socket, directory, name, seconds = sys.argv[1:]
    timeout = int(seconds)
    if (
        not Path(executable).is_absolute()
        or not socket.startswith("unix:///")
        or not re.fullmatch(r"audit-validation-[0-9a-f]{32}", name)
        or not 3 <= timeout <= 302
    ):
        raise ValueError("invalid trusted watchdog parameters")
    output = Path(directory)
    config = output / "docker-config"
    record = {"container_name": name, "deadline_seconds": timeout, "status": "armed"}
    save_json(output / "watchdog.json", record)
    time.sleep(timeout)
    record["status"] = "failed"
    try:
        code, reason = bounded_process(
            [
                executable,
                "--config",
                str(config),
                "--host",
                socket,
                "container",
                "rm",
                "--force",
                "--volumes",
                name,
            ],
            config,
            {"PATH": os.defpath, "HOME": str(config), "DOCKER_CONFIG": str(config)},
            output / "logs/watchdog",
            10,
            1024 * 1024,
        )
        record.update(
            status="removed" if code == 0 and not reason else "failed",
            exit_code=code,
            termination=reason,
        )
    except Exception as error:
        record["error_type"] = type(error).__name__
    save_json(output / "watchdog.json", record)


if __name__ == "__main__":
    main()
