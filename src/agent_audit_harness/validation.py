"""Explicit recipes execute only in disposable, policy-checked Docker containers."""

import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path, PurePosixPath

from .pipeline import (
    MAX_FILE_BYTES,
    MAX_SOURCE_BYTES,
    RESOURCES,
    digest,
    index_target,
    run_lock,
    save_json,
    source_lines,
    validate_evidence,
    validate_shape,
)

CONTROL_TIMEOUT = 10
CONTROL_BYTES = 1024 * 1024
CONTAINER_ENV = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/tmp",
    "TMPDIR=/tmp",
    "LANG=C",
    "AUDIT_WORKER=1",
]
INFO_FORMAT = (
    '{"os":{{json .OSType}},"security":{{json .SecurityOptions}},'
    '"memory_limit":{{json .MemoryLimit}},"pids_limit":{{json .PidsLimit}},'
    '"cpu_quota":{{json .CPUCfsQuota}},"version":{{json .ServerVersion}}}'
)
IMAGE_FORMAT = (
    '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},'
    '"volumes":{{json .Config.Volumes}}}'
)
INSPECT_FORMAT = (
    '{"image":{{json .Image}},"host":{{json .HostConfig}},'
    '"mounts":{{json .Mounts}},"state":{{json .State}},'
    '"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},'
    '"command":{{json .Config.Cmd}},"healthcheck":{{json .Config.Healthcheck}},'
    '"working_dir":{{json .Config.WorkingDir}}}'
)


def read_json(path):
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("validation document exceeds 8 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def input_path(relative):
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or str(path) != relative
        or "\\" in relative
        or "\0" in relative
        or any(part in {".", ".."} or part.startswith(".") for part in path.parts)
        or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}
        or path.name.lower() in {"credentials", "credentials.json", "id_rsa", "id_ed25519"}
    ):
        raise ValueError("unsafe or credential input path")
    return path


def read_regular(target, relative, limit=MAX_FILE_BYTES):
    path = input_path(relative)
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        source_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source_fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("validation input must be a regular file")
            data = stream.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError("validation file exceeds size limit")
    return data


def read_source(target, relative):
    data = read_regular(target, relative)
    if b"\0" in data:
        raise ValueError("validation input is binary")
    data.decode("utf-8")
    return data


def review_candidate(target, review, candidate_id):
    manifest = read_json(review / "manifest.json")
    if manifest["status"] != "complete" or manifest["identity"]["target"] != str(target):
        raise ValueError("validation requires a complete review of this target")
    findings = read_json(review / "findings.json")
    queue = read_json(review / "validation-queue.json")
    if queue != [f for f in findings if f["verdict"] != "rejected"]:
        raise ValueError("validation queue does not match review findings")
    matches = [f for f in queue if f["id"] == candidate_id]
    if len(matches) != 1:
        raise ValueError("recipe must reference exactly one queued candidate")
    candidate = matches[0]
    occurrence = [candidate["path"], candidate["line"], candidate["cwe"]]
    if "hypothesis_id" in candidate:
        occurrence.append(candidate["hypothesis_id"])
    indexed = {item["path"]: item["sha256"] for item in manifest["identity"]["source_index"]}
    config_hashes = {}
    if graph_hash := manifest["identity"].get("graph_sha256"):
        from .graph import MAX_GRAPH_BYTES, validate_graph

        graph = json.loads(read_regular(review, "graph.json", MAX_GRAPH_BYTES))
        validate_graph(graph)
        if (
            graph["schema_version"] != 2
            or graph["target"] != str(target)
            or graph["source_index"] != manifest["identity"]["source_index"]
            or graph["identity_sha256"] != graph_hash
            or digest({k: v for k, v in graph.items() if k != "identity_sha256"}) != graph_hash
        ):
            raise ValueError("validation graph does not match reviewed identity")
        for item in graph["input_config"]:
            path, checksum = item["path"], item["sha256"]
            if (
                path in config_hashes
                or indexed.get(path, checksum) != checksum
                or hashlib.sha256(read_source(target, path)).hexdigest() != checksum
            ):
                raise ValueError("validation configuration does not match reviewed graph")
            config_hashes[path] = checksum
    if (
        candidate["id"] != "f-" + digest(occurrence)[:16]
        or indexed.get(candidate["path"]) != candidate["source_sha256"]
    ):
        raise ValueError("candidate does not match reviewed source identity")
    return candidate, manifest, queue, config_hashes


def attachment_sources(recipe, existing):
    attachments = {}
    for item in recipe.get("attachments", []):
        path = input_path(item["path"])
        data = item["content"].encode("utf-8")
        if (
            not path.is_relative_to("poc")
            or len(path.parts) < 2
            or item["path"] in existing
            or item["path"] in attachments
            or b"\0" in data
            or len(data) > 65536
            or hashlib.sha256(data).hexdigest() != item["sha256"]
        ):
            raise ValueError("PoC attachment path/content/hash is invalid or collides with input")
        attachments[item["path"]] = data
    if sum(map(len, attachments.values())) > 128 * 1024:
        raise ValueError("PoC attachments exceed 128 KiB")
    return attachments


def prepare_inputs(target, review, recipe, destination, *, poc_review=None):
    schema = read_json(RESOURCES / "schemas/validation-recipe.json")
    validate_shape("validation recipe", recipe, schema)
    command = recipe["command"]
    if not command[0].startswith("/") or any("\0" in arg for arg in command):
        raise ValueError("container executable must be absolute and arguments must not contain NUL")
    candidate, manifest, queue, config_hashes = review_candidate(
        target, review, recipe["candidate_id"]
    )
    indexed = {item["path"]: item["sha256"] for item in manifest["identity"]["source_index"]}
    seen, total = {}, 0
    for item in recipe["inputs"]:
        if item["path"] in seen:
            raise ValueError("duplicate validation input")
        data = read_source(target, item["path"])
        checksum = hashlib.sha256(data).hexdigest()
        expected = indexed.get(item["path"], config_hashes.get(item["path"], checksum))
        if checksum != item["sha256"] or expected != checksum:
            raise ValueError("validation input does not match recipe/review source hash")
        total += len(data)
        if total > MAX_SOURCE_BYTES:
            raise ValueError("validation snapshot exceeds 32 MiB")
        seen[item["path"]] = data
    if candidate["path"] not in seen:
        raise ValueError("candidate source must be included in the recipe")
    text = seen[candidate["path"]].decode()
    validate_evidence(
        candidate,
        [
            {
                "path": candidate["path"],
                "first_line": 1,
                "last_line": len(source_lines(text)),
                "text": text,
                "source_sha256": candidate["source_sha256"],
            }
        ],
    )
    from .judgment import check_oracle

    issues = None
    if recipe.get("attachments") or "poc_review_sha256" in recipe or poc_review is not None:
        if poc_review is None or not recipe.get("attachments"):
            raise ValueError("PoC attachments require an explicit approved --poc-review")
        from .poc import poc_issues, verify_review

        receipt = json.loads(read_regular(poc_review, "review.json"))
        proposal = json.loads(read_regular(poc_review, "proposal.json"))
        current_sources, _ = index_target(target)
        if digest([s.metadata() for s in current_sources]) != receipt["source_index_sha256"]:
            raise ValueError("PoC source index changed after researcher review")
        verify_review(
            receipt,
            proposal,
            recipe,
            candidate,
            digest(manifest),
            digest(queue),
            digest(manifest["identity"]["source_index"]),
        )
        issues = poc_issues(proposal)
        seen.update(attachment_sources(recipe, set(indexed) | seen.keys() | config_hashes.keys()))
        save_json(destination.parent / "poc-review.json", receipt)
        save_json(destination.parent / "poc-proposal.json", proposal)

    executed = seen.copy()
    changes = {}
    for replacement in recipe.get("replacements", []):
        path = replacement["path"]
        if path in changes or path not in seen or path not in indexed:
            raise ValueError("replacement must uniquely reference a reviewed input")
        data = replacement["content"].encode("utf-8")
        if (
            hashlib.sha256(seen[path]).hexdigest() != replacement["before_sha256"]
            or hashlib.sha256(data).hexdigest() != replacement["after_sha256"]
            or data == seen[path]
            or len(data) > MAX_FILE_BYTES
            or b"\0" in data
        ):
            raise ValueError("replacement content/hash/size is invalid")
        changes[path] = replacement
        executed[path] = data
    if sum(map(len, executed.values())) > MAX_SOURCE_BYTES:
        raise ValueError("modified validation snapshot exceeds 32 MiB")
    check_oracle(recipe, candidate, seen, executed, issues=issues)
    destination.mkdir(mode=0o755)
    source_manifest = []
    for relative, data in seen.items():
        reviewed_artifact = "input/" + relative
        if relative in changes:
            reviewed_artifact = "reviewed-input/" + relative
            original = destination.parent / reviewed_artifact
            original.parent.mkdir(parents=True, exist_ok=True)
            original.write_bytes(data)
            original.chmod(0o444)
        file = destination / relative
        file.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        file.write_bytes(executed[relative])
        file.chmod(0o444)
        source_manifest.append(
            {
                "path": relative,
                "reviewed_sha256": hashlib.sha256(data).hexdigest(),
                "executed_sha256": hashlib.sha256(executed[relative]).hexdigest(),
                "reviewed_artifact": reviewed_artifact,
                "executed_artifact": "input/" + relative,
            }
        )
    return candidate, digest(manifest), digest(queue), source_manifest


def bounded_process(command, cwd, environment, prefix, timeout, byte_limit):
    streams = [Path(str(prefix) + suffix) for suffix in (".stdout.log", ".stderr.log")]
    reason = None
    with streams[0].open("wb") as output, streams[1].open("wb") as errors:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, (output, 0))
            selector.register(process.stderr, selectors.EVENT_READ, (errors, 1))
            sizes = [0, 0]
            try:
                while selector.get_map() or process.poll() is None:
                    if time.monotonic() >= deadline:
                        reason = "timeout"
                        break
                    for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                        chunk = os.read(key.fd, 16 * 1024)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        stream, index = key.data
                        stream.write(chunk[: max(0, byte_limit - sizes[index])])
                        stream.flush()
                        sizes[index] += len(chunk)
                        if sizes[index] > byte_limit:
                            reason = "output_limit"
                            break
                    if reason:
                        break
            finally:
                if process.poll() is None or reason:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                process.stdout.close()
                process.stderr.close()
    return process.returncode, reason


def execution_command(recipe, configuration_id=None):
    configurations = recipe.get("configurations", [])
    if configurations:
        ids = [c["id"] for c in configurations]
        if len(set(ids)) != len(ids) or configuration_id not in ids:
            raise ValueError("worker requires exactly one declared configuration ID")
        return [*recipe["command"], configuration_id]
    if configuration_id is not None:
        raise ValueError("worker configuration was not declared in the reviewed recipe")
    return recipe["command"]


def create_arguments(name, image, snapshot, recipe, configuration_id=None):
    limits = recipe["limits"]
    memory = limits["memory_mb"] * 1024 * 1024
    if "," in str(snapshot):
        raise ValueError("Docker bind input path must not contain commas")
    return [
        "container",
        "create",
        "--name",
        name,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--cpus",
        str(limits["cpus"]),
        "--memory",
        str(memory),
        "--memory-swap",
        str(memory),
        "--pids-limit",
        str(limits["pids"]),
        "--ulimit",
        "core=0:0",
        "--ulimit",
        "nofile=256:256",
        "--restart",
        "no",
        "--no-healthcheck",
        "--log-driver",
        "none",
        "--shm-size",
        "16m",
        "--tmpfs",
        f"/work:rw,exec,nosuid,nodev,size={limits['scratch_mb']}m,uid=65532,gid=65532,mode=700",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=1700",
        "--mount",
        f"type=bind,source={snapshot},target=/input,readonly,bind-propagation=rprivate",
        "--workdir",
        "/work",
        "--entrypoint",
        "/usr/bin/env",
        image,
        "-i",
        *CONTAINER_ENV,
        *execution_command(recipe, configuration_id),
    ]


def verify_policy(document, snapshot, image, recipe, configuration_id=None):
    host, limits = document["host"], recipe["limits"]
    memory = limits["memory_mb"] * 1024 * 1024
    checks = [
        document["image"] == image,
        document["user"] == "65532:65532",
        document["entrypoint"] == ["/usr/bin/env"],
        document["command"] == ["-i", *CONTAINER_ENV, *execution_command(recipe, configuration_id)],
        document["working_dir"] == "/work",
        document["healthcheck"]["Test"] == ["NONE"],
        document["state"]["Status"] == "created",
        document["state"]["Running"] is False,
        document["state"]["StartedAt"].startswith("0001-"),
        host["NetworkMode"] == "none",
        host["ReadonlyRootfs"] is True,
        host["Privileged"] is False,
        set(host["CapDrop"] or []) == {"ALL"},
        not host["CapAdd"],
        "no-new-privileges=true" in (host["SecurityOpt"] or []),
        not any("unconfined" in opt for opt in host["SecurityOpt"]),
        host["PidMode"] == "",
        host["UTSMode"] == "",
        host["UsernsMode"] != "host",
        host["IpcMode"] == "private",
        host["CgroupnsMode"] == "private",
        host["Memory"] == memory,
        host["MemorySwap"] == memory,
        host["NanoCpus"] == int(limits["cpus"] * 1e9),
        host["PidsLimit"] == limits["pids"],
        not host["OomKillDisable"],
        not host["Devices"],
        not host["DeviceRequests"],
        not host["PortBindings"],
        not host["PublishAllPorts"],
        not host["VolumesFrom"],
        host["RestartPolicy"]["Name"] == "no",
        host["LogConfig"]["Type"] == "none",
        host["ShmSize"] == 16 * 1024 * 1024,
        host["Tmpfs"]
        == {
            "/work": (
                f"rw,exec,nosuid,nodev,size={limits['scratch_mb']}m,uid=65532,gid=65532,mode=700"
            ),
            "/tmp": "rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=1700",
        },
        {u["Name"]: (u["Soft"], u["Hard"]) for u in host["Ulimits"]}
        == {
            "core": (0, 0),
            "nofile": (256, 256),
        },
        len(document["mounts"]) == 1,
    ]
    if len(document["mounts"]) == 1:
        mount = document["mounts"][0]
        checks.extend(
            [
                mount["Type"] == "bind",
                mount["Source"] == str(snapshot),
                mount["Destination"] == "/input",
                mount["RW"] is False,
                mount["Propagation"] == "rprivate",
            ]
        )
    if not all(checks):
        raise ValueError("Docker did not apply the required isolation policy; refusing execution")


def validate(
    target,
    review,
    recipe_file,
    output,
    *,
    image,
    docker="docker",
    docker_host=None,
    poc_review=None,
    configuration_id=None,
):
    target, review, output = target.resolve(), review.resolve(), output.resolve()
    if output.is_relative_to(target) or output.is_relative_to(review):
        raise ValueError("validation output must be outside target and review")
    if recipe_file.resolve().is_relative_to(target):
        raise ValueError("explicit validation recipe must be outside target")
    if poc_review is not None:
        poc_review = poc_review.resolve()
        if poc_review.is_relative_to(target):
            raise ValueError("PoC researcher review must be outside target")
    with run_lock(output):
        if any(p.name != ".lock" for p in output.iterdir()):
            raise ValueError("validation output is nonempty; use a new output directory")
        result = {
            "schema_version": 1,
            "status": "worker_failed",
            "stage": "prepare",
            "execution_started": False,
            "execution_attempted": False,
            "exit_code": None,
            "oom_killed": None,
            "confirmed_findings": 0,
            "cleanup": {"status": "not_created"},
            "failure": None,
            "target": str(target),
            "image": image,
        }
        name = "audit-validation-" + uuid.uuid4().hex
        result["container_name"] = name
        config = output / "docker-config"
        config.mkdir(mode=0o700)
        logs = output / "logs"
        logs.mkdir(mode=0o700)
        environment = {"PATH": os.defpath, "HOME": str(config), "DOCKER_CONFIG": str(config)}
        base = None
        created = False
        watchdog = None
        watchdog_log = None
        started = time.monotonic()

        def invoke(stage, arguments, *, timeout=CONTROL_TIMEOUT, byte_limit=CONTROL_BYTES):
            result["stage"] = stage
            save_json(output / "result.json", result)
            prefix = logs / stage
            code, reason = bounded_process(
                base + arguments, config, environment, prefix, timeout, byte_limit
            )
            if code or reason:
                raise RuntimeError(f"Docker {stage} failed ({reason or code}); see bounded logs")
            return (Path(str(prefix) + ".stdout.log")).read_text(encoding="utf-8")

        try:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
                raise ValueError("worker image must be a prepared immutable local sha256 ID")
            recipe = read_json(recipe_file)
            save_json(output / "recipe.json", recipe)
            execution_command(recipe, configuration_id)
            candidate, review_hash, queue_hash, sources = prepare_inputs(
                target, review, recipe, output / "input", poc_review=poc_review
            )
            save_json(output / "candidate.json", candidate)
            save_json(output / "source-manifest.json", sources)
            result["identity"] = {
                "recipe_sha256": digest(recipe),
                "review_sha256": review_hash,
                "queue_sha256": queue_hash,
                "candidate_id": candidate["id"],
                "source_manifest_sha256": digest(sources),
                "worker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "recipe_schema_sha256": hashlib.sha256(
                    (RESOURCES / "schemas/validation-recipe.json").read_bytes()
                ).hexdigest(),
                "image": image,
            }
            if configuration_id is not None:
                result["identity"]["configuration_id"] = configuration_id
            if poc_review is not None:
                result["identity"].update(
                    poc_review_sha256=recipe["poc_review_sha256"],
                    poc_proposal_sha256=read_json(output / "poc-proposal.json")["identity_sha256"],
                    source_index_sha256=digest(
                        read_json(review / "manifest.json")["identity"]["source_index"]
                    ),
                )
            executable = shutil.which(docker)
            if executable is None:
                raise ValueError("Docker executable unavailable; no host execution fallback")
            socket = docker_host or (
                "unix://"
                + str(
                    Path("/var/run/docker.sock")
                    if Path("/var/run/docker.sock").exists()
                    else Path.home() / ".docker/run/docker.sock"
                )
            )
            if not socket.startswith("unix:///") or "\0" in socket:
                raise ValueError("validation requires an explicit local Unix Docker socket")
            base = [executable, "--config", str(config), "--host", socket]
            result["docker_host"] = socket
            info = json.loads(invoke("engine", ["info", "--format", INFO_FORMAT]))
            if (
                info["os"] != "linux"
                or not all(info[k] is True for k in ("memory_limit", "pids_limit", "cpu_quota"))
                or not any(
                    opt.startswith("name=seccomp,profile=builtin") for opt in info["security"]
                )
            ):
                raise ValueError(
                    "Docker requires Linux, enforced resource limits and default seccomp"
                )
            metadata = json.loads(
                invoke("image", ["image", "inspect", image, "--format", IMAGE_FORMAT])
            )
            if metadata["id"] != image or metadata["os"] != "linux" or metadata["volumes"]:
                raise ValueError("worker image must be Linux with no implicit volumes")
            result["engine"] = info
            result["image_metadata"] = metadata
            snapshot = output / "input"
            created = True  # Even an interrupted create can leave a container with this name.
            create = create_arguments(name, image, snapshot, recipe, configuration_id)
            save_json(output / "create-arguments.json", create)
            invoke("create", create)
            policy = json.loads(
                invoke("policy", ["container", "inspect", name, "--format", INSPECT_FORMAT])
            )
            verify_policy(policy, snapshot, image, recipe, configuration_id)
            save_json(output / "policy.json", policy)
            result["stage"] = "watchdog"
            watchdog_log = (logs / "watchdog-process.log").open("wb")
            watchdog = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-m",
                    "agent_audit_harness.validation_watchdog",
                    executable,
                    socket,
                    str(output),
                    name,
                    str(recipe["limits"]["timeout_seconds"] + 2),
                ],
                cwd=config,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=watchdog_log,
                stderr=watchdog_log,
                start_new_session=True,
            )
            result["watchdog"] = {
                "pid": watchdog.pid,
                "record": "watchdog.json",
                "deadline_seconds": recipe["limits"]["timeout_seconds"] + 2,
                "code_sha256": hashlib.sha256(
                    (RESOURCES / "validation_watchdog.py").read_bytes()
                ).hexdigest(),
            }
            ready_deadline = time.monotonic() + 2
            while not (output / "watchdog.json").exists():
                if watchdog.poll() is not None or time.monotonic() >= ready_deadline:
                    raise RuntimeError("disposal timer failed to arm; target was not started")
                time.sleep(0.02)
            if read_json(output / "watchdog.json")["status"] != "armed":
                raise RuntimeError("disposal timer is not armed; target was not started")
            result.update(stage="execute", execution_attempted=True, execution_started=None)
            save_json(output / "result.json", result)
            code, reason = bounded_process(
                base + ["container", "start", "--attach", name],
                config,
                environment,
                logs / "execute",
                recipe["limits"]["timeout_seconds"],
                recipe["limits"]["output_bytes"],
            )
            if reason:
                result["status"] = reason
                try:
                    invoke("kill", ["container", "kill", name])
                except RuntimeError:
                    pass  # A deadline can race with natural exit; inspect the terminal state.
            state = json.loads(
                invoke("state", ["container", "inspect", name, "--format", "{{json .State}}"])
            )
            save_json(output / "state.json", state)
            result["execution_started"] = not state["StartedAt"].startswith("0001-")
            if not result["execution_started"] or state["Running"] or state["ExitCode"] < 0:
                raise ValueError("container did not reach an observed terminal state")
            result.update(exit_code=state["ExitCode"], oom_killed=state["OOMKilled"])
            if not reason:
                if code and state["ExitCode"] == 0:
                    result["stage"] = "execute"
                    raise RuntimeError("Docker attach failed; validation logs may be incomplete")
                result["status"] = (
                    "completed"
                    if code == 0
                    and state["ExitCode"] == 0
                    and not state["Error"]
                    and not state["OOMKilled"]
                    else "process_failed"
                )
            result["failure"] = (
                None
                if result["status"] == "completed"
                else {"type": result["status"], "stage": "execute"}
            )
        except (Exception, KeyboardInterrupt) as error:
            if result["status"] not in {"timeout", "output_limit"}:
                result["status"] = (
                    "interrupted" if isinstance(error, KeyboardInterrupt) else "worker_failed"
                )
            result["failure"] = {
                "type": type(error).__name__,
                "stage": result["stage"],
                "detail": str(error)[:2000],
            }
        finally:
            if created:
                try:
                    invoke("cleanup", ["container", "rm", "--force", "--volumes", name])
                    result["cleanup"] = {"status": "removed"}
                    if watchdog is not None:
                        watchdog.terminate()
                        watchdog.wait(timeout=5)
                        if (
                            not (output / "watchdog.json").exists()
                            or read_json(output / "watchdog.json")["status"] == "armed"
                        ):
                            save_json(
                                output / "watchdog.json", {"status": "cancelled_after_cleanup"}
                            )
                except (Exception, KeyboardInterrupt) as error:
                    result["cleanup"] = {
                        "status": "failed",
                        "error_type": type(error).__name__,
                        "detail": str(error)[:2000],
                    }
                    if result["status"] == "completed":
                        result["status"] = "worker_failed"
                        result["failure"] = {"type": "cleanup_failed", "stage": "cleanup"}
            if watchdog_log is not None:
                watchdog_log.close()
            result["elapsed_seconds"] = round(time.monotonic() - started, 3)
            result["evidence"] = [
                {
                    "path": p.relative_to(output).as_posix(),
                    "bytes": p.stat().st_size,
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                }
                for p in sorted(output.rglob("*"))
                if p.is_file()
                and p.name not in {"result.json", ".lock"}
                and not (result["cleanup"]["status"] == "failed" and p.name.startswith("watchdog"))
            ]
            result["identity_sha256"] = digest(result)
            save_json(output / "result.json", result)
        return result
