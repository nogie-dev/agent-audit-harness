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
from .triage import apply_triage, cluster_findings, input_gaps

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
MAX_AGENT_CALLS = 128
CITATION_CODES = frozenset(
    {"candidate_quote_mismatch", "source_slice_mismatch", "triage_column_mismatch"}
)
MAX_CITATION_FEEDBACK_ERRORS = 8


class CitationError(ValueError):
    def __init__(self, code: str, message: str, details: dict):
        self.code = code
        self.details = details
        super().__init__(message)


def raise_citation_errors(errors: list[CitationError]):
    if not errors:
        return
    if len(errors) == 1:
        raise errors[0]
    first = errors[0]
    reported = errors[:MAX_CITATION_FEEDBACK_ERRORS]
    raise CitationError(
        first.code,
        f"{len(errors)} source citations failed validation",
        {
            **first.details,
            "errors": [{"citation_code": error.code, **error.details} for error in reported],
            "omitted_error_count": len(errors) - len(reported),
        },
    )


def encode(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def digest(value) -> str:
    return hashlib.sha256(encode(value).encode()).hexdigest()


def citation_repair_prompt(prompt: str, code: str, reply: dict, details: dict | None = None) -> str:
    return (
        prompt
        + "\nUNTRUSTED_CITATION_REPAIR_JSON:\n"
        + json.dumps(
            {
                "citation_code": code,
                "rejected_reply": reply,
                **({"citation_details": details} if details is not None else {}),
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=0,
        )
        + "\n"
    )


def checked_citation_repair(record: dict, input_sha256: str) -> dict:
    if (
        not isinstance(record, dict)
        or set(record) - {"citation_details"}
        != {
            "input_sha256",
            "citation_code",
            "rejected_reply",
            "reply_sha256",
            "failed_attempt",
            "repair_attempt",
        }
        or record["input_sha256"] != input_sha256
        or type(record["citation_code"]) is not str
        or record["citation_code"] not in CITATION_CODES
        or not isinstance(record["rejected_reply"], dict)
        or record["reply_sha256"] != digest(record["rejected_reply"])
        or (
            "citation_details" in record
            and (
                not isinstance(record["citation_details"], dict)
                or len(encode(record["citation_details"]).encode()) > 64 * 1024
            )
        )
        or type(record["failed_attempt"]) is not int
        or record["failed_attempt"] < 1
        or (
            record["repair_attempt"] is not None
            and (
                type(record["repair_attempt"]) is not int
                or record["repair_attempt"] <= record["failed_attempt"]
            )
        )
    ):
        raise ValueError("citation repair checkpoint changed or is malformed")
    return record


def citation_repair_outcome(rejected: dict, corrected: dict) -> str:
    if "candidates" in rejected and len(corrected.get("candidates", [])) < len(
        rejected["candidates"]
    ):
        return "candidates_withdrawn"

    def without_citations(value):
        if isinstance(value, list):
            return [without_citations(item) for item in value]
        if isinstance(value, dict):
            citation_keys = (
                {"path", "line", "column", "quote"}
                if {"path", "line", "quote"} <= value.keys()
                else set()
            )
            return {
                key: without_citations(item)
                for key, item in value.items()
                if key not in citation_keys
            }
        return value

    return (
        "citation_corrected"
        if without_citations(rejected) == without_citations(corrected)
        else "reply_revised"
    )


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


def citation_details(evidence: dict, fragments: list[dict], field: str) -> dict:
    details = {
        "field": field,
        "path": evidence["path"],
        "line": evidence["line"],
        "column": evidence.get("column"),
        "source_context": None,
        "context_status": "outside_supplied_fragments",
        "first_matching_byte_column": None,
        "exact_quote_matches": [],
        "omitted_exact_quote_matches": 0,
    }
    seen_matches = set()
    for fragment in fragments:
        if evidence["path"] != fragment["path"]:
            continue
        lines = source_lines(fragment["text"])
        for offset, line in enumerate(lines):
            position = "".join(lines[offset:]).find(evidence["quote"])
            if not evidence["quote"].strip() or not 0 <= position < len(line.rstrip("\r\n")):
                continue
            match = (
                fragment["path"],
                fragment["first_line"] + offset,
                len(line[:position].encode()) + 1,
            )
            if match in seen_matches:
                continue
            seen_matches.add(match)
            if len(details["exact_quote_matches"]) < 8:
                details["exact_quote_matches"].append(
                    {"path": match[0], "line": match[1], "column": match[2]}
                )
            else:
                details["omitted_exact_quote_matches"] += 1
    for fragment in fragments:
        if evidence["path"] != fragment["path"] or not (
            fragment["first_line"] <= evidence["line"] <= fragment["last_line"]
        ):
            continue
        lines = source_lines(fragment["text"])
        offset = evidence["line"] - fragment["first_line"]
        first, last = max(0, offset - 1), min(len(lines), offset + 2)
        text = "".join(lines[first:last])
        if len(text.encode()) <= 4096:
            details["source_context"] = {
                "path": fragment["path"],
                "first_line": fragment["first_line"] + first,
                "last_line": fragment["first_line"] + last - 1,
                "source_sha256": fragment.get("source_sha256"),
                "text": text,
            }
            details["context_status"] = "provided"
        else:
            details["context_status"] = "omitted_byte_budget"
        position = "".join(lines[offset:]).find(evidence["quote"])
        if evidence["quote"].strip() and 0 <= position < len(lines[offset].rstrip("\r\n")):
            details["first_matching_byte_column"] = len(lines[offset][:position].encode()) + 1
        break
    return details


def validate_evidence(
    evidence: dict, fragments: list[dict], *, location: str = "/evidence"
) -> dict:
    within_source = False
    for fragment in fragments:
        if evidence["path"] != fragment["path"] or not (
            fragment["first_line"] <= evidence["line"] <= fragment["last_line"]
        ):
            continue
        within_source = True
        lines = source_lines(fragment["text"])
        offset = evidence["line"] - fragment["first_line"]
        quote = evidence["quote"]
        position = "".join(lines[offset:]).find(quote)
        if quote.strip() and 0 <= position < len(lines[offset].rstrip("\r\n")):
            return fragment
    if within_source:
        raise CitationError(
            "candidate_quote_mismatch",
            "candidate quote does not begin on the cited source line",
            citation_details(evidence, fragments, location + "/quote"),
        )
    raise CitationError(
        "source_slice_mismatch",
        "candidate path or line is outside its source slice",
        citation_details(
            evidence,
            fragments,
            location
            + ("/line" if any(f["path"] == evidence["path"] for f in fragments) else "/path"),
        ),
    )


def candidates_for_slice(data: dict, source_slice: dict) -> list[dict]:
    if data.get("requests") and data["candidates"]:
        raise ValueError("analysis must request evidence or return candidates, not both")
    if data.get("model_proposals") and (data["candidates"] or data.get("requests")):
        raise ValueError("analysis must propose models separately from candidates and requests")
    candidates, errors = {}, []
    for number, candidate in enumerate(data["candidates"]):
        try:
            fragment = validate_evidence(
                candidate,
                source_slice.get("fragments", [source_slice]),
                location=f"/candidates/{number}",
            )
        except CitationError as error:
            errors.append(error)
            continue
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
    raise_citation_errors(errors)
    return list(candidates.values())


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


def report_text(
    findings: list[dict], coverage: dict, metrics: dict, replay: bool, clusters=None
) -> str:
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
    if metrics.get("citation_repairs"):
        lines.extend(
            [
                f"Citation repair requests: {metrics['citation_repairs']}; "
                f"accepted outcomes: {metrics.get('citation_repair_outcomes', {})}.",
                "Candidate withdrawal or revised reasoning is not citation-only correction.",
                "",
            ]
        )
    if coverage.get("investigations"):
        lines.extend(
            [
                f"Evidence queries: {metrics['investigation_queries']}; "
                f"payload bytes: {metrics['investigation_payload_bytes']}; "
                f"unavailable/omitted responses: {metrics['investigation_gap_count']}.",
                "Requests, evidence, budgets and gaps are retained in investigations/.",
                "Empty candidates or unavailable query results do not establish safety.",
                "",
            ]
        )
    if "static_analysis" in coverage:
        static = coverage["static_analysis"]
        lines.extend(
            [
                f"Static evidence: {static['observations']} pattern facts, "
                f"{static['taint_results']} analyzer taint reports, "
                f"{static['gaps']} analysis gaps.",
                "These follow declared rule models; calls are separate structural evidence.",
                "See static.json and slice omissions in coverage.json. No runtime validation.",
                "",
            ]
        )
    if coverage.get("model_analysis"):
        lines.extend(
            [
                f"Second static passes: {metrics['model_second_passes']}; "
                f"reused model checkpoints: {metrics['model_cache_hits']}; "
                f"retained model/context gaps: {metrics['model_gap_count']}.",
                "Source-backed models are declarations, not verified wrapper semantics.",
                "First evidence stays in static.json; models/ keeps second results and contexts.",
                "",
            ]
        )
    for cluster in clusters or []:
        lines.extend(
            [
                f"## {cluster['id']} — {cluster['status']}",
                "",
                "Members: " + ", ".join(cluster["candidate_ids"]),
                "Grouping is a declared cause/fix hypothesis, not a validated vulnerability.",
                "",
            ]
        )
        if cluster["root_cause"]:
            cause = cluster["root_cause"]
            lines.extend(
                [
                    "Proposed common cause: " + plain(cause["description"]),
                    "Proposed shared fix: " + plain(cause["fix"]["description"]),
                    "",
                ]
            )
            for label, point in (
                ("Control", cause["evidence"]),
                ("Repair location", cause["fix"]["evidence"]),
            ):
                lines.extend(
                    [
                        f"{label}: {plain(point['path'])}:{point['line']}:{point['column']} "
                        "(UTF-8 byte column)",
                        *["> " + plain(line) for line in point["quote"].splitlines()],
                        "",
                    ]
                )
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
        if "cluster_id" in finding:
            lines.extend(["Cause group: " + finding["cluster_id"], ""])
        for kind, label in (("counterevidence", "Counterevidence"), ("unresolved", "Unresolved")):
            for item in finding.get(kind, []):
                lines.extend([label + ": " + plain(item["claim"]), ""])
                point = item["evidence"]
                if point:
                    lines.extend(
                        [
                            f"{plain(point['path'])}:{point['line']}:{point['column']} "
                            "(UTF-8 byte column)",
                            *["> " + plain(line) for line in point["quote"].splitlines()],
                            "",
                        ]
                    )
                else:
                    lines.extend(["No source evidence supplied for this unresolved claim.", ""])
        if "input_gaps" in finding:
            lines.extend(
                [
                    "Preserved input gaps (including omitted context; see coverage.json):",
                    "",
                    *["> " + plain(line) for line in encode(finding["input_gaps"]).splitlines()],
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


def prepare_review(
    target, sources, slice_bytes, graph_file=None, recon_file=None, static_file=None
):
    if (graph_file is None) != (recon_file is None):
        raise ValueError("--graph and --recon must be supplied together")
    if graph_file is None:
        if static_file is not None:
            raise ValueError("--static requires --graph and --recon")
        slices, gaps = make_slices(sources, slice_bytes)
        return slices, gaps, {}
    from .recon import current_graph, make_graph_slices, read_recon

    graph = current_graph(target, graph_file, sources)
    recon = read_recon(recon_file, graph, sources)
    artifacts = {"graph": graph, "recon": recon}
    if static_file is not None:
        from .static_analysis import read_static

        artifacts["static"] = read_static(static_file, graph, sources)
    original_static = recon["spec"].get("proposal_origin", {}).get("static_sha256")
    if original_static and artifacts.get("static", {}).get("identity_sha256") != original_static:
        raise ValueError("proposed recon requires its original --static artifact")
    origin = recon["spec"].get("proposal_origin")
    if origin:
        from .recon_proposal import proposal_plan, recon_context

        context = recon_context(
            graph,
            sources,
            artifacts.get("static") if original_static else None,
            origin["input_bytes"],
        )
        if digest(context) != origin["context_sha256"]:
            raise ValueError("proposed recon input context differs")
        proposal_plan(
            {"hypotheses": recon["spec"]["hypotheses"], "unresolved": []}, context, graph, sources
        )
        artifacts["recon-context"] = context
    slices, gaps = make_graph_slices(graph, recon, sources, slice_bytes, artifacts.get("static"))
    return slices, gaps, artifacts


def run_pipeline(
    target: Path,
    output: Path,
    agent,
    *,
    max_slices: int = 8,
    slice_bytes: int = 16_000,
    max_calls: int = 16,
    max_queries: int = 4,
    query_bytes: int = 16_000,
    repair_citations: bool = False,
    resume: bool = False,
    graph_file: Path | None = None,
    recon_file: Path | None = None,
    static_file: Path | None = None,
) -> dict:
    if max_slices < 1 or not 1 <= max_calls <= MAX_AGENT_CALLS:
        raise ValueError("max slices must be positive and max calls must be 1..128")
    if type(repair_citations) is not bool:
        raise ValueError("repair citations must be a boolean")
    if not 0 <= max_queries <= 32 or not 1024 <= query_bytes <= 64 * 1024:
        raise ValueError("query limits must be 0..32 queries and 1024..65536 bytes per slice")
    from .investigation import answer_requests, evidence_slice
    from .model_analysis import compile_models, model_context, run_models

    target, output = target.resolve(), output.resolve()
    if output.is_relative_to(target):
        raise ValueError("output must be outside the target directory")
    sources, skipped = index_target(target)
    slices, unsliced, artifacts = prepare_review(
        target, sources, slice_bytes, graph_file, recon_file, static_file
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
        "max_queries": max_queries,
        "query_bytes": query_bytes,
        "repair_citations": repair_citations,
        "query_tool_sha256": digest(
            {
                name: hashlib.sha256((RESOURCES / name).read_bytes()).hexdigest()
                for name in (
                    "agents.py",
                    "pipeline.py",
                    "investigation.py",
                    "graph.py",
                    "triage.py",
                    "static_analysis.py",
                    "model_analysis.py",
                    "recon.py",
                    "recon_proposal.py",
                    "schemas/research-plan.json",
                    "schemas/recon-proposal.json",
                    "analyzers/semgrep.py",
                    "schemas/static-rules.json",
                    "schemas/static-analysis.json",
                )
            }
        ),
    }
    if artifacts:
        identity.update(
            graph_sha256=artifacts["graph"]["identity_sha256"],
            recon_sha256=artifacts["recon"]["identity_sha256"],
            slices_sha256=digest(slices),
        )
        if "static" in artifacts:
            identity["static_sha256"] = artifacts["static"]["identity_sha256"]
    invocation_cache_hits = 0
    query_cache_hits = 0
    investigations = {}
    model_results = {}
    model_contexts = {}
    model_cache_hits = 0
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
        for filename in (
            "report.md",
            "findings.json",
            "clusters.json",
            "validation-queue.json",
            "metrics.json",
        ):
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
            if "static" in artifacts:
                static = artifacts["static"]
                coverage["static_analysis"] = {
                    "identity_sha256": static["identity_sha256"],
                    "engine": static["engine"],
                    "coverage": static["coverage"],
                    "limitations": static["limitations"],
                    **{key: len(static[key]) for key in ("observations", "taint_results", "gaps")},
                }
        save_json(output / "coverage.json", coverage)

        def call(
            stage,
            source_slice,
            history,
            candidates=None,
            call_id=None,
            model_result=None,
            model_static=None,
        ):
            nonlocal invocation_cache_hits
            contract = contracts[stage]
            call_id = call_id or source_slice["id"]
            evidence = evidence_slice(source_slice, history)
            model_packet = None
            if model_result is not None:
                hypothesis = next(
                    h
                    for h in artifacts["recon"]["hypotheses"]
                    if h["id"] == source_slice["hypothesis"]["id"]
                )
                model_packet = model_context(
                    model_result,
                    model_static,
                    evidence,
                    hypothesis,
                    artifacts["graph"],
                    slice_bytes,
                )
                ref = f"models/{source_slice['id']}/contexts/{call_id}.{stage}.json"
                save_json(output / ref, model_packet)
                model_contexts[ref] = model_packet
                model_packet = {
                    key: value for key, value in model_packet.items() if key != "omissions"
                }
                model_packet["omissions_ref"] = ref

            def check_reply(data):
                validate_shape(stage, data, contract["schema"])
                if stage == "analysis":
                    candidates_for_slice(data, evidence)
                    if data.get("requests") and not history["budget"]["remaining_queries"]:
                        raise ValueError(
                            "investigation query budget exhausted; analysis is incomplete"
                        )
                    if data.get("model_proposals"):
                        if "static" not in artifacts or model_result is not None:
                            raise ValueError(
                                "models require --static and a remaining second pass per slice"
                            )
                        compile_models(
                            data["model_proposals"],
                            artifacts["graph"],
                            sources,
                            evidence,
                            artifacts["static"],
                        )
                else:
                    apply_triage(candidates or [], data, evidence)

            packet = {
                "source_slice": source_slice,
                "candidates": candidates or [],
                "investigation": history,
                "model_analysis": {
                    "remaining_passes": int("static" in artifacts and model_result is None),
                    "max_models": 4,
                    "result": model_packet,
                },
            }
            if stage == "analysis":
                fragment_paths = {
                    part["path"] for part in source_slice.get("fragments", [source_slice])
                }
                packet["source_line_counts"] = {
                    item["path"]: item["lines"] for item in index if item["path"] in fragment_paths
                }
            prompt = (
                contract["prompt"]
                + "\nUNTRUSTED_INPUT_JSON:\n"
                + json.dumps(
                    packet,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=0,
                )
                + "\n"
            )
            directory = output / "calls" / f"{call_id}.{stage}"
            cache_path = directory / "reply.json"
            input_sha256 = digest({"prompt": prompt, "schema": contract["schema"]})
            repair_path = directory / "citation-repair.json"
            repair = None
            effective_prompt = prompt
            if repair_path.exists():
                from .agents import strip_optional_nulls

                if not repair_citations:
                    raise ValueError("citation repair is not enabled for this run")
                repair = checked_citation_repair(json.loads(repair_path.read_text()), input_sha256)
                failed_attempt = directory / f"attempt-{repair['failed_attempt']:04d}"
                if (
                    repair["failed_attempt"] > state["call_attempts"]
                    or strip_optional_nulls(
                        json.loads((failed_attempt / "raw-response.json").read_text()),
                        contract["schema"],
                    )
                    != repair["rejected_reply"]
                    or json.loads((failed_attempt / "failure.json").read_text()).get(
                        "citation_code"
                    )
                    != repair["citation_code"]
                    or (
                        "citation_details" in repair
                        and json.loads((failed_attempt / "failure.json").read_text()).get(
                            "citation_details"
                        )
                        != repair["citation_details"]
                    )
                    or (failed_attempt / "prompt.txt").read_text() != prompt
                ):
                    raise ValueError("citation repair original rejection changed")
                try:
                    check_reply(repair["rejected_reply"])
                except CitationError as error:
                    if error.code != repair["citation_code"] or (
                        "citation_details" in repair and error.details != repair["citation_details"]
                    ):
                        raise ValueError("citation repair rejection changed") from error
                else:
                    raise ValueError("citation repair reply is no longer rejected")
                effective_prompt = citation_repair_prompt(
                    prompt,
                    repair["citation_code"],
                    repair["rejected_reply"],
                    repair.get("citation_details"),
                )
            if cache_path.exists():
                from .agents import strip_optional_nulls

                record = json.loads(cache_path.read_text(encoding="utf-8"))
                if (
                    record["input_sha256"] != input_sha256
                    or record["reply_sha256"] != digest(record["data"])
                    or record.get("effective_input_sha256")
                    != digest({"prompt": effective_prompt, "schema": contract["schema"]})
                ):
                    raise ValueError(f"cached reply checksum mismatch: {cache_path}")
                if repair is not None and record.get("attempt") != repair["repair_attempt"]:
                    raise ValueError("cached citation repair attempt differs")
                if repair is not None and record.get("citation_repair_outcome") != (
                    citation_repair_outcome(repair["rejected_reply"], record["data"])
                ):
                    raise ValueError("cached citation repair outcome differs")
                if (
                    type(record.get("attempt")) is not int
                    or not 1 <= record["attempt"] <= state["call_attempts"]
                ):
                    raise ValueError("cached reply attempt is invalid")
                successful_attempt = directory / f"attempt-{record['attempt']:04d}"
                if (
                    (successful_attempt / "failure.json").exists()
                    or (successful_attempt / "prompt.txt").read_text() != effective_prompt
                    or strip_optional_nulls(
                        json.loads((successful_attempt / "raw-response.json").read_text()),
                        contract["schema"],
                    )
                    != record["data"]
                ):
                    raise ValueError("cached reply original attempt changed")
                invocation_cache_hits += 1
            else:
                while True:
                    if repair is not None and repair["repair_attempt"] is not None:
                        raise ValueError("citation repair already attempted; use a new run")
                    if state["call_attempts"] >= max_calls:
                        raise ValueError(
                            "agent call budget exhausted; resume with a higher --max-calls"
                        )
                    state["call_attempts"] += 1
                    state["active_call"] = f"{call_id}.{stage}"
                    save_json(manifest_path, state)
                    if repair is not None:
                        repair["repair_attempt"] = state["call_attempts"]
                        save_json(repair_path, repair)
                    save_text(directory / "prompt.txt", prompt)
                    attempt = directory / f"attempt-{state['call_attempts']:04d}"
                    save_text(attempt / "prompt.txt", effective_prompt)
                    started = time.monotonic()
                    reply = None
                    try:
                        reply = agent.call(
                            stage,
                            call_id + (".r0001" if repair is not None else ""),
                            effective_prompt,
                            contract["schema"],
                            attempt,
                        )
                        if not (attempt / "raw-response.json").exists():
                            save_json(attempt / "raw-response.json", reply.data)
                        raw = json.loads((attempt / "raw-response.json").read_text())
                        if agent.identity["provider"] == "codex":
                            from .agents import strip_optional_nulls

                            raw = strip_optional_nulls(raw, contract["schema"])
                        if raw != reply.data:
                            raise ValueError("agent raw response differs from structured reply")
                        check_reply(reply.data)
                    except (Exception, KeyboardInterrupt) as error:
                        save_json(
                            attempt / "failure.json",
                            {
                                "type": type(error).__name__,
                                "elapsed_seconds": round(time.monotonic() - started, 3),
                                "usage": reply.usage if reply is not None else None,
                                **(
                                    {"citation_code": error.code, "citation_details": error.details}
                                    if isinstance(error, CitationError)
                                    else {}
                                ),
                            },
                        )
                        if (
                            isinstance(error, CitationError)
                            and reply is not None
                            and repair_citations
                            and repair is None
                        ):
                            repair = {
                                "input_sha256": input_sha256,
                                "citation_code": error.code,
                                "citation_details": error.details,
                                "rejected_reply": reply.data,
                                "reply_sha256": digest(reply.data),
                                "failed_attempt": state["call_attempts"],
                                "repair_attempt": None,
                            }
                            save_json(repair_path, repair)
                            effective_prompt = citation_repair_prompt(
                                prompt, error.code, reply.data, error.details
                            )
                            continue
                        raise
                    record = {
                        "input_sha256": input_sha256,
                        "effective_input_sha256": digest(
                            {"prompt": effective_prompt, "schema": contract["schema"]}
                        ),
                        "attempt": state["call_attempts"],
                        "reply_sha256": digest(reply.data),
                        "data": reply.data,
                        "usage": reply.usage,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        **(
                            {
                                "citation_repair_outcome": citation_repair_outcome(
                                    repair["rejected_reply"], reply.data
                                )
                            }
                            if repair is not None
                            else {}
                        ),
                    }
                    break
                save_json(cache_path, record)
            check_reply(record["data"])
            return record["data"]

        try:
            findings = []
            raw_candidate_count = 0
            for source_slice in selected:
                history = {
                    "responses": [],
                    "budget": {"remaining_queries": max_queries, "remaining_bytes": query_bytes},
                }
                investigations[source_slice["id"]] = history
                round_number = 0
                call_id = source_slice["id"]
                model_result, model_static = None, None
                while True:
                    analysis = call(
                        "analysis",
                        source_slice,
                        history,
                        call_id=call_id,
                        model_result=model_result,
                        model_static=model_static,
                    )
                    if analysis.get("model_proposals"):
                        model_result, model_static, hit = run_models(
                            target,
                            output,
                            evidence_slice(source_slice, history),
                            analysis["model_proposals"],
                            artifacts["graph"],
                            sources,
                            artifacts["static"],
                            identity,
                        )
                        model_cache_hits += hit
                        model_results[source_slice["id"]] = {
                            "result": model_result,
                            "static": model_static,
                        }
                        call_id = source_slice["id"] + ".m0001"
                        coverage["model_analysis"] = [
                            {
                                "slice_id": key,
                                "artifact": f"models/{key}/result.json",
                                "before_sha256": value["result"]["before_sha256"],
                                "after_ref": value["result"]["after_ref"],
                                "after_sha256": value["result"]["after_sha256"],
                                "declared_models": sum(
                                    m["status"] == "declared"
                                    for m in value["result"]["plan"]["models"]
                                ),
                                "model_gap_ids": [g["id"] for g in value["result"]["plan"]["gaps"]],
                                "second_records": {
                                    kind: len(value["static"][kind])
                                    for kind in ("observations", "taint_results", "gaps")
                                }
                                if value["static"] is not None
                                else None,
                            }
                            for key, value in model_results.items()
                        ]
                        save_json(output / "coverage.json", coverage)
                        continue
                    if not analysis.get("requests"):
                        break
                    round_number += 1
                    call_id = source_slice["id"] + f".q{round_number:04d}"
                    query_path = (
                        output / "queries" / f"{source_slice['id']}.q{round_number:04d}.json"
                    )
                    query_hash = digest(
                        {
                            "run_identity": identity,
                            "slice_id": source_slice["id"],
                            "requests": analysis["requests"],
                            "history": history,
                        }
                    )
                    if query_path.exists():
                        record = json.loads(query_path.read_text())
                        if record["input_sha256"] != query_hash or record["reply_sha256"] != digest(
                            record["data"]
                        ):
                            raise ValueError("cached query checksum mismatch: " + str(query_path))
                        query_cache_hits += 1
                        answered = record["data"]
                    else:
                        answered = answer_requests(
                            artifacts.get("graph"),
                            sources,
                            analysis["requests"],
                            history,
                            source_slice["id"],
                            static=artifacts.get("static"),
                        )
                        save_json(
                            query_path,
                            {
                                "input_sha256": query_hash,
                                "reply_sha256": digest(answered),
                                "data": answered,
                            },
                        )
                    history["responses"].extend(answered["responses"])
                    history["budget"] = answered["budget"]
                    save_json(output / "investigations" / f"{source_slice['id']}.json", history)
                    coverage["investigations"] = [
                        {
                            "slice_id": key,
                            "artifact": f"investigations/{key}.json",
                            "requests": len(value["responses"]),
                            "gap_ids": [
                                r["id"] for r in value["responses"] if r["status"] != "provided"
                            ],
                            "budget": value["budget"],
                        }
                        for key, value in investigations.items()
                        if value["responses"]
                    ]
                    coverage["reviewed_lines"] = reviewed_lines(
                        [
                            evidence_slice(item, investigations[item["id"]])
                            if item["id"] in investigations
                            else item
                            for item in selected
                        ]
                    )
                    save_json(output / "coverage.json", coverage)
                evidence = evidence_slice(source_slice, history)
                raw_candidate_count += len(analysis["candidates"])
                candidates = candidates_for_slice(analysis, evidence)
                if candidates:
                    gaps = input_gaps(evidence, artifacts)
                    triage = call(
                        "triage",
                        source_slice,
                        history,
                        candidates,
                        model_result=model_result,
                        model_static=model_static,
                    )
                    if model_result is not None:
                        gaps["model_ref"] = f"models/{source_slice['id']}/result.json"
                        contexts = {
                            key: value
                            for key, value in model_contexts.items()
                            if key.startswith(f"models/{source_slice['id']}/")
                        }
                        gaps["model_context_refs"] = list(contexts)
                        gaps["model_gap_ids"] = list(
                            dict.fromkeys(
                                g["id"] for value in contexts.values() for g in value["gaps"]
                            )
                        )
                        if model_static is not None:
                            gaps["model_static_ref"] = model_result["after_ref"]
                            gaps["model_static_gap_ids"] = input_gaps(
                                evidence, {**artifacts, "static": model_static}
                            )["static_gap_ids"]
                    if history["responses"]:
                        gaps["investigation_ref"] = f"investigations/{source_slice['id']}.json"
                        gaps["investigation_gap_ids"] = [
                            r["id"] for r in history["responses"] if r["status"] != "provided"
                        ]
                    findings.extend(
                        apply_triage(
                            candidates,
                            triage,
                            evidence,
                            gaps,
                        )
                    )
            clusters = cluster_findings(findings)
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
                "citation_repairs": sum(
                    json.loads(path.read_text())["repair_attempt"] is not None
                    for path in (output / "calls").glob("*/citation-repair.json")
                ),
                "failed_call_attempts": len(
                    list((output / "calls").glob("*/attempt-*/failure.json"))
                ),
                "citation_repair_outcomes": dict(
                    Counter(
                        record["citation_repair_outcome"]
                        for record in (
                            json.loads(path.read_text())
                            for path in (output / "calls").glob("*/reply.json")
                        )
                        if "citation_repair_outcome" in record
                    )
                ),
                "query_cache_hits": query_cache_hits,
                "model_cache_hits": model_cache_hits,
                "model_second_passes": sum(
                    value["static"] is not None for value in model_results.values()
                ),
                "model_gap_count": len(
                    {g["id"] for value in model_contexts.values() for g in value["gaps"]}
                ),
                "investigation_queries": sum(
                    max_queries - value["budget"]["remaining_queries"]
                    for value in investigations.values()
                ),
                "investigation_payload_bytes": sum(
                    query_bytes - value["budget"]["remaining_bytes"]
                    for value in investigations.values()
                ),
                "investigation_gap_count": sum(
                    response["status"] != "provided"
                    for value in investigations.values()
                    for response in value["responses"]
                ),
                "raw_candidates": raw_candidate_count,
                "unique_candidates": len(findings),
                "verdict_counts": counts,
                "cluster_count": len(clusters),
                "cluster_status_counts": dict(Counter(c["status"] for c in clusters)),
                "reported_token_usage": (
                    usage_totals
                    if any(value is not None for value in usage_totals.values())
                    else None
                ),
                "validation_executions": 0,
                "confirmed_findings": 0,
            }
            save_json(output / "findings.json", findings)
            save_json(output / "clusters.json", clusters)
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
                    clusters,
                ),
            )
            state.update(status="complete", active_call=None, error_type=None)
            save_json(manifest_path, state)
            return metrics
        except (Exception, KeyboardInterrupt) as error:
            state.update(status="failed", error_type=type(error).__name__)
            save_json(manifest_path, state)
            raise
