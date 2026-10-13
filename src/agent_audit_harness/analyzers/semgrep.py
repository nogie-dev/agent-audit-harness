"""Pinned Semgrep CE core over a filtered snapshot and generated local rules."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from ..extractors.process import run_tool
from ..pipeline import digest

VERSION = "1.180.0"
# shortcut: CE traces stay intra-function, add another adapter when cross-function proof is needed.
LANGUAGES = {"python": ".py", "go": ".go"}


def generated_rules(spec: dict, language: str) -> tuple[dict, dict]:
    rules, ids = [], {}
    for rule in spec["rules"]:
        if rule["language"] != language:
            continue
        base = {"languages": [language], "message": rule["id"], "severity": "WARNING"}
        for role in ("source", "sink", "sanitizer"):
            patterns = rule[f"{role}_patterns"]
            if patterns:
                rule_id = rule["id"] + "." + role
                rules.append(
                    {
                        **base,
                        "id": rule_id,
                        "pattern-either": [{"pattern": pattern} for pattern in patterns],
                    }
                )
                ids[rule_id] = (rule["id"], role)
        rule_id = rule["id"] + ".taint"
        taint = {
            **base,
            "id": rule_id,
            "mode": "taint",
            "pattern-sources": [{"pattern": p, "exact": True} for p in rule["source_patterns"]],
            "pattern-sinks": [{"pattern": p} for p in rule["sink_patterns"]],
        }
        if rule["sanitizer_patterns"]:
            taint["pattern-sanitizers"] = [
                {"pattern": p, "exact": True} for p in rule["sanitizer_patterns"]
            ]
        rules.append(taint)
        ids[rule_id] = (rule["id"], "taint")
    return {"rules": rules}, ids


def scan(
    target: Path,
    sources: list,
    spec: dict,
    language: str,
    cache: Path,
    timeout: int,
    *,
    expected_engine=None,
):
    config, ids = generated_rules(spec, language)
    selected = [source for source in sources if Path(source.path).suffix == LANGUAGES.get(language)]
    if not config["rules"] or not selected:
        raise ValueError(
            "static rules do not cover this graph language; first adapter supports Python/Go"
        )
    if len(selected) > 256:
        raise ValueError("static analysis exceeds 256 files; select a smaller subtree")
    cache = cache.resolve()
    if cache.is_relative_to(target):
        raise ValueError("static analyzer cache must be outside target")
    core, certificates = cache / "semgrep-core", cache / "ca.pem"
    if not core.is_file() or not certificates.is_file():
        raise ValueError("pinned Semgrep dependencies missing; run make setup-static")
    core_hash = hashlib.sha256(core.read_bytes()).hexdigest()
    runtime_files = [certificates, *sorted((cache / "libs").glob("*"))]
    runtime_hash = digest(
        {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime_files if p.is_file()}
    )
    identity = {
        "name": "semgrep_ce_core",
        "version": VERSION,
        "core_sha256": core_hash,
        "runtime_sha256": runtime_hash,
        "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "requirements_sha256": hashlib.sha256(
            Path(__file__).with_name("semgrep-requirements.txt").read_bytes()
        ).hexdigest(),
    }
    if expected_engine is not None and any(
        expected_engine.get(key) != value for key, value in identity.items()
    ):
        raise ValueError("second analysis engine differs from the first; rebuild static analysis")
    with tempfile.TemporaryDirectory(prefix="audit-static-") as scratch:
        root = Path(scratch)
        snapshot = root / "source"
        snapshot.mkdir()
        paths = {}
        for source in selected:
            path = snapshot / source.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source.text, encoding="utf-8")
            paths[str(path)] = source.path
        rules = root / "rules.json"
        rules.write_text(json.dumps(config), encoding="utf-8")
        targets = root / "targets.json"
        targets.write_text(
            json.dumps(
                [
                    "Targets",
                    [
                        [
                            "CodeTarget",
                            {
                                "path": {"fpath": path, "ppath": "/" + relative},
                                "analyzer": language,
                                "products": ["sast"],
                            },
                        ]
                        for path, relative in paths.items()
                    ],
                ]
            ),
            encoding="utf-8",
        )
        environment = {
            key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG") if key in os.environ
        }
        environment["SSL_CERT_FILE"] = str(certificates)
        version, _ = run_tool(
            "Semgrep version", [str(core), "-version"], root, environment, timeout
        )
        if not re.fullmatch(
            r"semgrep-core version: " + re.escape(VERSION) + r" \([0-9a-f]+\)", version.strip()
        ):
            raise ValueError(
                f"static analyzer requires pinned Semgrep {VERSION}; run make setup-static"
            )
        # Core JSON retains source/sink traces; the CLI renderer can omit them without login.
        raw, diagnostics = run_tool(
            "Semgrep analysis",
            [
                str(core),
                "-json_nodots",
                "-j",
                "1",
                "-rules",
                str(rules),
                "-targets",
                str(targets),
                "-timeout",
                str(min(timeout, 10)),
                "-timeout_threshold",
                "1",
                "-max_memory",
                "256",
                "-max_match_per_file",
                "2000",
            ],
            snapshot,
            environment,
            timeout,
        )
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get("version") != VERSION:
            raise ValueError("invalid Semgrep output/version")

        def relative_path(path):
            if path not in paths:
                raise ValueError("analyzer location is outside supplied source snapshot")
            return paths[path]

        def locations(value):
            if isinstance(value, dict):
                return {
                    key: relative_path(item) if key == "path" else locations(item)
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [locations(item) for item in value]
            return value

        try:
            normalized = {
                "results": [locations(item) for item in result["results"]],
                "scanned": sorted(relative_path(path) for path in result["paths"]["scanned"]),
                "diagnostics": [
                    json.dumps(item, sort_keys=True).replace(str(root), "<snapshot>")[:8000]
                    for item in [
                        *result["errors"],
                        *result.get("skipped_rules", []),
                        *result.get("time", {}).get("fixpoint_timeouts", []),
                    ]
                ],
            }
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("malformed Semgrep output") from error
        if diagnostics.strip():
            normalized["diagnostics"].append(diagnostics.replace(str(root), "<snapshot>")[:8000])
    if hashlib.sha256(core.read_bytes()).hexdigest() != core_hash:
        raise ValueError("analyzer changed during extraction")
    if (
        digest(
            {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in runtime_files
                if p.is_file()
            }
        )
        != runtime_hash
    ):
        raise ValueError("analyzer runtime changed during extraction")
    return (
        normalized,
        ids,
        {
            **identity,
            "scope": "intraprocedural",
            "generated_rules_sha256": digest(config),
            "target_execution": False,
            "remote_rules": False,
        },
    )
