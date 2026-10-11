import hashlib
import html
import json
import os
import re
import stat
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from . import __version__

RESOURCES = Path(__file__).parent
SOURCE_SUFFIXES = {
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".hh",
    ".hxx",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".sol",
    ".rs",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".swift",
    ".sh",
}
IGNORED_DIRECTORIES = {"node_modules", "vendor", "build", "dist", "runs", "targets"}
MAX_FILE_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_VISITED_FILES = 20_000


def encode(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def digest(value) -> str:
    return hashlib.sha256(encode(value).encode()).hexdigest()


def save_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as f:
        temporary = Path(f.name)
        try:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def save_json(path: Path, value):
    save_text(path, encode(value))


def source_lines(text: str) -> list[str]:
    # Unicode separators inside literals/comments are not physical source newlines.
    return re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", text)[:-1]


@dataclass(frozen=True)
class Source:
    path: str
    text: str
    sha256: str

    def metadata(self) -> dict:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "bytes": len(self.text.encode()),
            "lines": len(source_lines(self.text)),
        }


def index_target(target: Path) -> tuple[list[Source], list[dict]]:
    if not target.is_dir():
        raise ValueError(f"target is not a directory: {target}")
    target = target.resolve()
    sources, skipped = [], []
    visited = total_bytes = 0
    for directory, directories, filenames in os.walk(target, followlinks=False):
        retained = []
        for name in sorted(directories):
            child = Path(directory) / name
            if name.startswith(".") or name in IGNORED_DIRECTORIES or child.is_symlink():
                skipped.append(
                    {"path": child.relative_to(target).as_posix(), "reason": "directory"}
                )
            else:
                retained.append(name)
        directories[:] = retained
        for name in sorted(filenames):
            visited += 1
            if visited > MAX_VISITED_FILES:
                raise ValueError("target exceeds 20,000 visited files; select a smaller subtree")
            path = Path(directory) / name
            relative = path.relative_to(target).as_posix()
            reason = None
            if name.startswith(".") or path.suffix.lower() not in SOURCE_SUFFIXES:
                reason = "unsupported"
            elif path.is_symlink() or not path.resolve().is_relative_to(target):
                reason = "symlink"
            else:
                # shortcut: stable source tree required, seal snapshots before concurrent writes.
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        reason = "not_regular"
                        content = b""
                    else:
                        content = stream.read(MAX_FILE_BYTES + 1)
                if reason is None:
                    if len(content) > MAX_FILE_BYTES:
                        reason = "oversized"
                    elif not content or b"\0" in content:
                        reason = "empty_or_binary"
                    else:
                        try:
                            text = content.decode("utf-8")
                        except UnicodeDecodeError:
                            reason = "non_utf8"
                        else:
                            total_bytes += len(content)
                            if total_bytes > MAX_SOURCE_BYTES:
                                raise ValueError("source exceeds 32 MiB; select a smaller subtree")
                            sources.append(
                                Source(relative, text, hashlib.sha256(content).hexdigest())
                            )
            if reason:
                skipped.append({"path": relative, "reason": reason})
    if not sources:
        raise ValueError("target contains no supported readable UTF-8 source files")
    return sorted(sources, key=lambda s: s.path), skipped


def make_slices(sources: list[Source], byte_limit: int) -> tuple[list[dict], list[dict]]:
    if not 1024 <= byte_limit <= 64_000:
        raise ValueError("slice bytes must be between 1024 and 64000")
    slices, skipped = [], []
    for source in sources:
        lines = source_lines(source.text)
        if any(len(line.encode()) > byte_limit for line in lines):
            skipped.append({"path": source.path, "reason": "line_exceeds_slice_budget"})
            continue
        start, size, chunk = 1, 0, []
        for line_number, line in enumerate(lines, 1):
            if chunk and size + len(line.encode()) > byte_limit:
                slices.append(
                    {
                        "path": source.path,
                        "first_line": start,
                        "last_line": line_number - 1,
                        "text": "".join(chunk),
                        "source_sha256": source.sha256,
                    }
                )
                start, size, chunk = line_number, 0, []
            chunk.append(line)
            size += len(line.encode())
        if chunk:
            slices.append(
                {
                    "path": source.path,
                    "first_line": start,
                    "last_line": len(lines),
                    "text": "".join(chunk),
                    "source_sha256": source.sha256,
                }
            )
    for number, source_slice in enumerate(slices, 1):
        source_slice["id"] = f"s{number:04d}"
    return slices, skipped


def validate_shape(stage: str, data: dict, schema: dict):
    try:
        Draft202012Validator(schema).validate(data)
    except ValidationError as error:
        location = "/".join(str(item) for item in error.absolute_path)
        raise ValueError(f"invalid {stage} output at /{location}: {error.message}") from error


def validate_evidence(evidence: dict, fragments: list[dict]) -> dict:
    for fragment in fragments:
        if evidence["path"] != fragment["path"] or not (
            fragment["first_line"] <= evidence["line"] <= fragment["last_line"]
        ):
            continue
        lines = source_lines(fragment["text"])
        offset = evidence["line"] - fragment["first_line"]
        quote = evidence["quote"]
        position = "".join(lines[offset:]).find(quote)
        if not quote.strip() or not 0 <= position < len(lines[offset].rstrip("\r\n")):
            raise ValueError("candidate quote does not begin on the cited source line")
        return fragment
    raise ValueError("candidate path or line is outside its source slice")


def candidates_for_slice(data: dict, source_slice: dict) -> list[dict]:
    candidates = {}
    for candidate in data["candidates"]:
        fragment = validate_evidence(candidate, source_slice.get("fragments", [source_slice]))
        occurrence = [candidate["path"], candidate["line"], candidate["cwe"]]
        hypothesis = source_slice.get("hypothesis")
        if hypothesis:
            occurrence.append(hypothesis["id"])
        candidate_id = "f-" + digest(occurrence)[:16]
        candidates.setdefault(
            candidate_id,
            {
                **candidate,
                "id": candidate_id,
                "slice_id": source_slice["id"],
                "source_sha256": fragment["source_sha256"],
                **({"hypothesis_id": hypothesis["id"]} if hypothesis else {}),
            },
        )
    return list(candidates.values())


def apply_triage(candidates: list[dict], data: dict) -> list[dict]:
    decisions = data["decisions"]
    expected = {candidate["id"] for candidate in candidates}
    actual = [decision["candidate_id"] for decision in decisions]
    if set(actual) != expected or len(actual) != len(expected):
        raise ValueError("triage must return exactly one decision for each known candidate")
    by_id = {decision["candidate_id"]: decision for decision in decisions}
    return [
        {
            **candidate,
            "verdict": by_id[candidate["id"]]["verdict"],
            "triage_rationale": by_id[candidate["id"]]["rationale"],
        }
        for candidate in candidates
    ]


@contextmanager
def run_lock(output: Path):
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = output / ".lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise ValueError(
            f"run is locked: {lock}; check the owning process before removing it"
        ) from error
    with os.fdopen(fd, "w") as stream:
        stream.write(str(os.getpid()))
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def report_text(findings: list[dict], coverage: dict, metrics: dict, replay: bool) -> str:
    def plain(value: str) -> str:
        return re.sub(r"([\\`*_{}\[\]()#+!|])", r"\\\1", html.escape(value, quote=False))

    lines = [
        "# Source review report",
        "",
        "Replay fixture demonstration; no model or target execution."
        if replay
        else "Agent hypotheses only; no dynamic validation or confirmed vulnerabilities.",
        "",
        f"Reviewed slices: {coverage['selected_slices']}/{coverage['total_slices']}",
        f"Reviewed source lines: {coverage['reviewed_lines']}/{coverage['indexed_lines']}",
        f"Agent call attempts: {metrics['call_attempts']}; "
        f"cache hits this invocation: {metrics['cache_hits']}",
        "",
        "Coverage is a count of supplied source lines, not proof of semantic coverage.",
        "Skipped inputs and remaining slices are listed in coverage.json.",
        "",
    ]
    for finding in findings:
        lines.extend(
            [
                f"## {finding['id']} — {finding['verdict']}",
                "",
                f"{finding['cwe']} at {plain(finding['path'])}:{finding['line']}",
                "",
                plain(finding["title"]),
                "",
                *(
                    ["Research hypothesis: " + plain(finding["hypothesis_id"]), ""]
                    if "hypothesis_id" in finding
                    else []
                ),
                plain(finding["reasoning"]),
                "",
                "Evidence (untrusted source text):",
                "",
                *["> " + plain(line) for line in finding["quote"].splitlines()],
                "",
                "Triage: " + plain(finding["triage_rationale"]),
                "",
                "Proposed validation: " + plain(finding["validation_plan"]),
                "",
            ]
        )
    return "\n".join(lines)


def slice_summary(source_slice: dict) -> dict:
    if "fragments" not in source_slice:
        return {key: value for key, value in source_slice.items() if key != "text"}
    return {
        "id": source_slice["id"],
        "hypothesis_id": source_slice["hypothesis"]["id"],
        "fragments": [
            {key: value for key, value in part.items() if key != "text"}
            for part in source_slice["fragments"]
        ],
        "omitted_counts": source_slice["omitted_counts"],
        "input_bytes": len(encode(source_slice).encode()),
    }


def prepare_review(target, sources, slice_bytes, graph_file=None, recon_file=None):
    if (graph_file is None) != (recon_file is None):
        raise ValueError("--graph and --recon must be supplied together")
    if graph_file is None:
        slices, gaps = make_slices(sources, slice_bytes)
        return slices, gaps, {}
    from .recon import current_graph, make_graph_slices, read_recon

    graph = current_graph(target, graph_file, sources)
    recon = read_recon(recon_file, graph, sources)
    slices, gaps = make_graph_slices(graph, recon, sources, slice_bytes)
    return slices, gaps, {"graph": graph, "recon": recon}


def run_pipeline(
    target: Path,
    output: Path,
    agent,
    *,
    max_slices: int = 8,
    slice_bytes: int = 16_000,
    max_calls: int = 16,
    resume: bool = False,
    graph_file: Path | None = None,
    recon_file: Path | None = None,
) -> dict:
    if max_slices < 1 or max_calls < 1:
        raise ValueError("max slices and max calls must be positive")
    target, output = target.resolve(), output.resolve()
    if output.is_relative_to(target):
        raise ValueError("output must be outside the target directory")
    sources, skipped = index_target(target)
    slices, unsliced, artifacts = prepare_review(
        target, sources, slice_bytes, graph_file, recon_file
    )
    selected = slices[:max_slices]
    if not selected:
        raise ValueError("no source slices fit the configured byte budget")
    contracts = {
        stage: {
            "prompt": (RESOURCES / "prompts" / f"{stage}.md").read_text(encoding="utf-8"),
            "schema": json.loads((RESOURCES / "schemas" / f"{stage}.json").read_text()),
        }
        for stage in ("analysis", "triage")
    }
    for contract in contracts.values():
        Draft202012Validator.check_schema(contract["schema"])
    index = [source.metadata() for source in sources]
    identity = {
        "version": __version__,
        "target": str(target),
        "source_index": index,
        "skipped": skipped,
        "agent": agent.identity,
        "contracts_sha256": digest(contracts),
        "slice_bytes": slice_bytes,
        "max_slices": max_slices,
    }
    if artifacts:
        identity.update(
            graph_sha256=artifacts["graph"]["identity_sha256"],
            recon_sha256=artifacts["recon"]["identity_sha256"],
            slices_sha256=digest(slices),
        )
    invocation_cache_hits = 0
    with run_lock(output):
        manifest_path = output / "manifest.json"
        if manifest_path.exists():
            state = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not resume:
                raise ValueError("output already has a run; use --resume or a new output directory")
            if state["identity"] != identity:
                raise ValueError("run inputs changed; use a new output directory")
            if max_calls < state["call_attempts"]:
                raise ValueError("max calls cannot be below the run's existing call attempts")
        elif any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("output is nonempty and has no manifest; refusing to overwrite it")
        else:
            state = {"schema_version": 1, "identity": identity, "call_attempts": 0}
        state.update(status="running", max_calls=max_calls)
        save_json(manifest_path, state)
        for filename in ("report.md", "findings.json", "validation-queue.json", "metrics.json"):
            (output / filename).unlink(missing_ok=True)
        save_json(output / "index.json", index)
        save_json(output / "slices.json", selected)
        for name, artifact in artifacts.items():
            save_json(output / f"{name}.json", artifact)
        from .recon import reviewed_lines

        coverage = {
            "indexed_files": len(sources),
            "indexed_lines": sum(item["lines"] for item in index),
            "selected_slices": len(selected),
            "total_slices": len(slices),
            "reviewed_lines": reviewed_lines(selected),
            "remaining_slices": [slice_summary(s) for s in slices[max_slices:]],
            "skipped": skipped + unsliced,
        }
        if artifacts:
            coverage.update(
                input_mode="graph_hypotheses",
                graph_coverage=artifacts["graph"]["coverage"],
                hypotheses=[
                    {
                        "id": item["id"],
                        "unknown_call_ids": item["unknown_call_ids"],
                        "external_call_ids": item["external_call_ids"],
                        "unlinked_annotation_ids": item["unlinked_annotation_ids"],
                    }
                    for item in artifacts["recon"]["hypotheses"]
                ],
            )
        save_json(output / "coverage.json", coverage)

        def call(stage: str, source_slice: dict, candidates: list[dict] | None = None):
            nonlocal invocation_cache_hits
            contract = contracts[stage]
            prompt = (
                contract["prompt"]
                + "\nUNTRUSTED_INPUT_JSON:\n"
                + encode(
                    {
                        "source_slice": source_slice,
                        "candidates": candidates or [],
                    }
                )
            )
            directory = output / "calls" / f"{source_slice['id']}.{stage}"
            cache_path = directory / "reply.json"
            input_sha256 = digest({"prompt": prompt, "schema": contract["schema"]})
            if cache_path.exists():
                record = json.loads(cache_path.read_text(encoding="utf-8"))
                if record["input_sha256"] != input_sha256 or record["reply_sha256"] != digest(
                    record["data"]
                ):
                    raise ValueError(f"cached reply checksum mismatch: {cache_path}")
                invocation_cache_hits += 1
            else:
                if state["call_attempts"] >= max_calls:
                    raise ValueError(
                        "agent call budget exhausted; resume with a higher --max-calls"
                    )
                state["call_attempts"] += 1
                state["active_call"] = f"{source_slice['id']}.{stage}"
                save_json(manifest_path, state)
                save_text(directory / "prompt.txt", prompt)
                started = time.monotonic()
                reply = agent.call(stage, source_slice["id"], prompt, contract["schema"], directory)
                validate_shape(stage, reply.data, contract["schema"])
                # Cache only replies that passed both schema and evidence/ID checks.
                if stage == "analysis":
                    candidates_for_slice(reply.data, source_slice)
                else:
                    apply_triage(candidates or [], reply.data)
                record = {
                    "input_sha256": input_sha256,
                    "reply_sha256": digest(reply.data),
                    "data": reply.data,
                    "usage": reply.usage,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                }
                save_json(cache_path, record)
            validate_shape(stage, record["data"], contract["schema"])
            return record["data"]

        try:
            findings = []
            raw_candidate_count = 0
            for source_slice in selected:
                analysis = call("analysis", source_slice)
                raw_candidate_count += len(analysis["candidates"])
                candidates = candidates_for_slice(analysis, source_slice)
                if candidates:
                    findings.extend(
                        apply_triage(candidates, call("triage", source_slice, candidates))
                    )
            counts = dict(Counter(finding["verdict"] for finding in findings))
            usage_records = [
                json.loads(path.read_text(encoding="utf-8"))["usage"]
                for path in sorted((output / "calls").glob("*/reply.json"))
            ]
            usage_totals = {}
            for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
                values = [
                    usage[key]
                    for usage in usage_records
                    if isinstance(usage, dict) and type(usage.get(key)) is int and usage[key] >= 0
                ]
                usage_totals[key] = sum(values) if values else None
            metrics = {
                "call_attempts": state["call_attempts"],
                "cache_hits": invocation_cache_hits,
                "raw_candidates": raw_candidate_count,
                "unique_candidates": len(findings),
                "verdict_counts": counts,
                "reported_token_usage": (
                    usage_totals
                    if any(value is not None for value in usage_totals.values())
                    else None
                ),
                "validation_executions": 0,
                "confirmed_findings": 0,
            }
            save_json(output / "findings.json", findings)
            save_json(
                output / "validation-queue.json",
                [finding for finding in findings if finding["verdict"] != "rejected"],
            )
            save_json(output / "metrics.json", metrics)
            save_text(
                output / "report.md",
                report_text(
                    findings,
                    coverage,
                    metrics,
                    agent.identity["provider"] == "replay",
                ),
            )
            state.update(status="complete", active_call=None, error_type=None)
            save_json(manifest_path, state)
            return metrics
        except (Exception, KeyboardInterrupt) as error:
            state.update(status="failed", error_type=type(error).__name__)
            save_json(manifest_path, state)
            raise
