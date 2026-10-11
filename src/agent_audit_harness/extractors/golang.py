"""Go typed-AST extractor. Target modules are loaded from a filtered source snapshot."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..pipeline import IGNORED_DIRECTORIES
from .inputs import read_input
from .process import run_tool

HELPER = Path(__file__).parent / "go_helper"


def entry_registrations(graph: dict, function_id: str) -> list[dict]:
    """Typed callback registration facts; neither invocation nor network exposure."""
    apis = {"net/http.HandleFunc", "net/http.ServeMux.HandleFunc"}
    return [
        {"call_id": call["id"], "caller": call["caller"], "api": call["callee_name"]}
        for call in graph["calls"]
        if call["provenance"] == "go_types"
        and call["status"] == "external"
        and call["dispatch"] == "direct"
        and call["callee_name"] in apis
        and any(
            argument["index"] == 1
            and argument["status"] == "resolved"
            and argument["function"] == function_id
            for argument in call.get("function_arguments", [])
        )
    ]


def extract(
    target: Path, sources: list, *, compiler: str = "go", timeout: int = 30, cache: Path
) -> dict:
    executable = shutil.which(compiler)
    if not executable:
        raise ValueError("Go is required for Go graph extraction")
    selected = [source for source in sources if Path(source.path).suffix == ".go"]
    if not selected:
        raise ValueError("no Go source files")
    if any("\r" in source.text.replace("\r\n", "") for source in selected):
        raise ValueError("Go source requires LF/CRLF; bare CR line positions are unsupported")
    if not (target / "go.mod").is_file():
        raise ValueError("Go extraction requires one module with go.mod at the target root")
    # Nested modules/workspaces must not silently become packages of the root module.
    for directory, directories, filenames in os.walk(target, followlinks=False):
        directories[:] = [
            name
            for name in directories
            if not name.startswith(".")
            and name not in IGNORED_DIRECTORIES
            and not (Path(directory) / name).is_symlink()
        ]
        if "go.work" in filenames or (Path(directory) != target and "go.mod" in filenames):
            raise ValueError("Go workspaces/nested modules are unsupported; select a single module")
    configs = [read_input(target, "go.mod")]
    if (target / "go.sum").exists():
        configs.append(read_input(target, "go.sum"))
    environment = {
        key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "LANG") if key in os.environ
    }
    cache = cache.resolve()
    if cache.is_relative_to(target):
        raise ValueError("Go tool cache must be outside the target")
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    environment.update(
        GOENV="off",
        GOTOOLCHAIN="local",
        GOWORK="off",
        CGO_ENABLED="0",
        GOFLAGS="-mod=readonly",
        GOPACKAGESDRIVER="off",
        GOPROXY="off",
        GOSUMDB="off",
        GOCACHE=str(cache / "build"),
        GOMODCACHE=str(cache / "mod"),
    )
    version = subprocess.run(
        [executable, "version"],
        capture_output=True,
        text=True,
        env=environment,
        timeout=5,
        check=True,
    ).stdout.strip()
    if not version.startswith("go version go"):
        raise ValueError("Go extractor requires a trusted Go toolchain")
    helper_hash = hashlib.sha256()
    for filename in ("main.go", "go.mod", "go.sum"):
        helper_hash.update((HELPER / filename).read_bytes())
    with tempfile.TemporaryDirectory(prefix="audit-go-") as scratch:
        root, binary = Path(scratch) / "source", Path(scratch) / "extractor"
        root.mkdir(mode=0o700)
        tools = Path(scratch) / "tools"
        tools.mkdir()
        (tools / "go").symlink_to(Path(executable).absolute())
        environment["PATH"] = str(tools) + os.pathsep + environment.get("PATH", "")
        for source in selected + configs:
            path = root / source.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source.text, encoding="utf-8")
        # Only the packaged helper is compiled; analysis never runs target programs or scripts.
        build_environment = dict(environment)
        # Reuse installed, checksum-verified dependency archives without network access.
        global_environment = {
            key: value for key, value in environment.items() if key not in {"GOMODCACHE", "GOCACHE"}
        }
        global_cache = subprocess.run(
            [executable, "env", "GOMODCACHE"],
            capture_output=True,
            text=True,
            env=global_environment,
            timeout=5,
            check=True,
        ).stdout.strip()
        proxy = Path(global_cache) / "cache" / "download"
        if proxy.is_dir():
            build_environment["GOPROXY"] = proxy.as_uri()
        try:
            run_tool(
                "Go helper build",
                [executable, "build", "-mod=readonly", "-o", str(binary), "."],
                HELPER,
                build_environment,
                timeout,
            )
        except ValueError as error:
            raise ValueError(
                f"{error}; prepare pinned helper dependencies with make setup-go"
            ) from error
        output, _ = run_tool("Go analysis", [str(binary), str(root)], root, environment, timeout)
        result = json.loads(output)
    indexed = {source.path for source in selected}
    visited = {
        path for unit in result["units"] if unit["status"] == "parsed" for path in unit["files"]
    }
    skipped = [
        {"path": source.path, "reason": "unsupported_graph_language"}
        for source in sources
        if source.path not in indexed
    ]
    skipped += [
        {"path": path, "reason": "not_selected_by_go_build"}
        for path in sorted(indexed - visited)
        if not any(path in unit["files"] and unit["status"] == "failed" for unit in result["units"])
    ]
    failed = any(unit["status"] == "failed" for unit in result["units"])
    return {
        "engine": {
            "name": "go_packages",
            "version": version,
            "executable": executable,
            "helper_sha256": helper_hash.hexdigest(),
            "tools_version": "v0.30.0",
        },
        "functions": result["functions"],
        "calls": result["calls"],
        "contexts": result["contexts"],
        "input_config": [source.metadata() for source in configs],
        "coverage": {
            "status": "partial" if failed or skipped else "parsed",
            "units": result["units"],
            "skipped": skipped,
            "unvisited_sources": sorted(indexed - visited),
            "configuration_verified": not failed,
            "metadata": result["context"],
        },
        "limitations": [
            "interface and function-value calls remain unresolved; no points-to analysis",
            "single module, local toolchain/default build context; tests and cgo excluded",
            "dependencies must already be cached; analysis never downloads them",
            "package-level initializer calls and reflection are not modeled",
            "embedded assets and assembly are not copied into the source snapshot",
            "call reachability is not data flow or attacker reachability",
            "Go source positions require LF/CRLF; bare CR is rejected",
        ],
    }
