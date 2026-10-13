"""Import bounded source-backed analysis/triage without executing a target or a model."""

import hashlib
import json
from collections import Counter, defaultdict

from . import __version__
from .pipeline import (
    RESOURCES,
    candidates_for_slice,
    digest,
    encode,
    index_target,
    run_lock,
    save_json,
    save_text,
    source_lines,
    validate_shape,
)
from .recon import current_graph, reviewed_lines
from .static_analysis import attach_records, read_static, selected_records
from .triage import apply_triage, checked_evidence, cluster_findings, input_gaps
from .validation import read_regular


def intake_frame(spec, sources, byte_limit, artifacts):
    if not 1024 <= byte_limit <= 64000:
        raise ValueError("import input bytes must be between 1024 and 64000")
    source_map = {s.path: s for s in sources}
    frame = {"id": "s0001", "fragments": [], "omitted_counts": {}}
    if "hypothesis_id" in spec:
        frame["hypothesis"] = {"id": spec["hypothesis_id"]}
    ranges = defaultdict(list)
    for item in spec["fragments"]:
        source = source_map.get(item["path"])
        if source is None or item["sha256"] != source.sha256:
            raise ValueError("import fragment is unavailable or source hash differs")
        first, last = item["first_line"], item["last_line"]
        lines = source_lines(source.text)
        if not 1 <= first <= last <= len(lines) or last - first >= 200:
            raise ValueError("import source range must contain at most 200 physical lines")
        if any(first <= end and start <= last for start, end in ranges[source.path]):
            raise ValueError("import source ranges overlap")
        ranges[source.path].append((first, last))
        frame["fragments"].append(
            {
                "path": source.path,
                "first_line": first,
                "last_line": last,
                "text": "".join(lines[first - 1 : last]),
                "source_sha256": source.sha256,
            }
        )
    frame["context_function_ids"] = [
        f["id"]
        for f in artifacts.get("graph", {}).get("functions", [])
        if any(f["line"] <= end and start <= f["end_line"] for start, end in ranges[f["path"]])
    ]
    omissions = []
    if "static" in artifacts:
        static = artifacts["static"]
        records = selected_records(
            static,
            {"function_ids": frame["context_function_ids"], "annotations": [], "registrations": []},
            artifacts["graph"],
        )
        frame["omitted_counts"] = {"static_" + k: len(v) for k, v in records.items()}
        frame["static_analysis"] = {
            "artifact_sha256": static["identity_sha256"],
            "engine": {key: static["engine"][key] for key in ("name", "version", "scope")},
            "rules": [],
            "observations": [],
            "taint_results": [],
            "gaps": [],
        }
    if len(encode(frame).encode()) > byte_limit:
        raise ValueError("import source context exceeds input byte budget; select smaller ranges")
    if "static" in artifacts:
        frame = attach_records(frame, records, static, byte_limit, omissions)
    return frame, omissions


def import_review(
    target, spec_file, output, *, graph_file=None, static_file=None, input_bytes=16000
):
    target, output = target.resolve(), output.resolve()
    if output.is_relative_to(target) or spec_file.resolve().is_relative_to(target):
        raise ValueError("import specification and output must be outside target")
    with run_lock(output):
        if any(p.name != ".lock" for p in output.iterdir()):
            raise ValueError("import output is nonempty; use a new directory")
        state = {"status": "preparing", "call_attempts": 0, "provider": "source_backed_import"}
        save_json(output / "manifest.json", state)
        try:
            raw = read_regular(spec_file.parent.resolve(), spec_file.name)
            (output / "import-input.json").write_bytes(raw)
            spec = json.loads(raw)
            schema = json.loads((RESOURCES / "schemas/candidate-import.json").read_text())
            validate_shape("candidate import", spec, schema)
            analysis_schema = json.loads((RESOURCES / "schemas/analysis.json").read_text())
            validate_shape("imported analysis", spec["analysis"], analysis_schema)
            sources, skipped = index_target(target)
            index = [s.metadata() for s in sources]
            if digest(index) != spec["source_index_sha256"]:
                raise ValueError("import source index differs; refresh the external report")
            artifacts = {}
            if static_file and not graph_file:
                raise ValueError("import --static requires --graph")
            if graph_file:
                artifacts["graph"] = current_graph(target, graph_file, sources)
            if static_file:
                artifacts["static"] = read_static(static_file, artifacts["graph"], sources)
            frame, omissions = intake_frame(spec, sources, input_bytes, artifacts)
            candidates = candidates_for_slice(spec["analysis"], frame)
            if len(candidates) != len(spec["analysis"]["candidates"]):
                raise ValueError(
                    "duplicate imported candidate occurrences; separate their hypotheses"
                )
            retained = [
                {
                    **item,
                    "evidence": checked_evidence(item["evidence"], frame)
                    if item["evidence"] is not None
                    else None,
                }
                for item in spec["gaps"]
            ]
            if len({g["id"] for g in retained}) != len(retained):
                raise ValueError("duplicate external gap IDs")
            retained.append(
                {
                    "id": None,
                    "reason": "Import does not establish actual entrypoint reachability.",
                    "evidence": None,
                }
            )
            gaps = input_gaps(frame, artifacts)
            gaps.update(
                import_ref="import-gaps.json",
                import_gap_ids=[
                    "ig-" + digest([spec["source_index_sha256"], spec.get("hypothesis_id"), g])[:24]
                    for g in retained
                ],
            )
            findings = apply_triage(candidates, spec["triage"], frame, gaps)
            clusters = cluster_findings(findings)
            current, current_skipped = index_target(target)
            if current != sources or current_skipped != skipped:
                raise ValueError("import source changed while checking evidence")
            if graph_file and current_graph(target, graph_file, current) != artifacts["graph"]:
                raise ValueError("import graph changed")
            if (
                static_file
                and read_static(static_file, artifacts["graph"], current) != artifacts["static"]
            ):
                raise ValueError("import static evidence changed")
            if read_regular(spec_file.parent.resolve(), spec_file.name) != raw:
                raise ValueError("import specification changed")
            identity = {
                "version": __version__,
                "target": str(target),
                "source_index": index,
                "skipped": skipped,
                "input_bytes": input_bytes,
                "agent": {
                    "provider": "source_backed_import",
                    "document_sha256": hashlib.sha256(raw).hexdigest(),
                },
                "contracts_sha256": digest(
                    {
                        "import": schema,
                        "analysis": analysis_schema,
                        "triage": json.loads((RESOURCES / "schemas/triage.json").read_text()),
                    }
                ),
                "tools_sha256": digest(
                    {
                        name: hashlib.sha256((RESOURCES / name).read_bytes()).hexdigest()
                        for name in (
                            "intake.py",
                            "pipeline.py",
                            "triage.py",
                            "graph.py",
                            "recon.py",
                            "static_analysis.py",
                            "validation.py",
                        )
                    }
                ),
                **{name + "_sha256": value["identity_sha256"] for name, value in artifacts.items()},
            }
            coverage = {
                "input_mode": "source_backed_import",
                "indexed_files": len(index),
                "indexed_lines": sum(i["lines"] for i in index),
                "reviewed_lines": reviewed_lines([frame]),
                "skipped": skipped,
                "static_omissions": omissions,
                "import_gap_ids": gaps["import_gap_ids"],
                "note": "Provided source is not semantic coverage; imported claims are hypotheses.",
            }
            metrics = {
                "call_attempts": 0,
                "raw_candidates": len(candidates),
                "unique_candidates": len(findings),
                "verdict_counts": dict(Counter(f["verdict"] for f in findings)),
                "validation_executions": 0,
                "confirmed_findings": 0,
            }
            documents = {
                "index": index,
                "slices": [frame],
                "findings": findings,
                "clusters": clusters,
                "validation-queue": [f for f in findings if f["verdict"] != "rejected"],
                "coverage": coverage,
                "metrics": metrics,
                "import-gaps": [
                    dict(g, id=identifier, external_id=g["id"])
                    for g, identifier in zip(retained, gaps["import_gap_ids"], strict=True)
                ],
                **artifacts,
            }
            for name, data in documents.items():
                save_json(output / f"{name}.json", data)
            save_text(
                output / "report.md",
                f"Imported {len(findings)} source-backed candidate(s).\n\n"
                "Triage meaning is supplied and unvalidated. Rejected and uncertain results, "
                "counterevidence and gaps are retained. No target or model was executed; "
                "empty findings do not mean safe. See import-input.json and import-gaps.json.\n",
            )
            state.update(status="complete", identity=identity)
            save_json(output / "manifest.json", state)
        except (Exception, KeyboardInterrupt) as error:
            state.update(
                status="failed", failure={"type": type(error).__name__, "detail": str(error)[:8000]}
            )
            save_json(output / "manifest.json", state)
            raise
    return metrics
