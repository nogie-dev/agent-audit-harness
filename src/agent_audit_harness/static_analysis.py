"""Source-checked analyzer evidence alongside, never inside, the call graph."""

import hashlib
import json
import re
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

from .analyzers import semgrep
from .graph import MAX_GRAPH_BYTES
from .pipeline import (
    RESOURCES,
    digest,
    encode,
    index_target,
    run_lock,
    save_json,
    save_text,
    source_lines,
    validate_shape,
)
from .recon import current_graph, read_document

DEFAULT_RULES = RESOURCES / "analyzers" / "default-rules.json"
CALL_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(\.\.\.\)"


def validate_rules(spec):
    validate_shape(
        "static rules", spec, json.loads((RESOURCES / "schemas/static-rules.json").read_text())
    )
    if len({rule["id"] for rule in spec["rules"]}) != len(spec["rules"]):
        raise ValueError("duplicate static rule IDs")
    for rule in spec["rules"]:
        if "call_models" in rule and (
            rule["sanitizer_patterns"]
            or any(
                not re.fullmatch(CALL_PATTERN, p)
                for role in ("source", "sink")
                for p in rule[role + "_patterns"]
            )
        ):
            raise ValueError("call models require simple calls and cannot declare sanitizers")


def source_range(source, start, end):
    content = source.text.encode()
    if not 0 <= start < end <= len(content):
        raise ValueError("analyzer location outside source bytes")
    lines = source_lines(source.text)
    starts, offset = [], 0
    for line in lines:
        starts.append(offset)
        offset += len(line.encode())
    if source.text.endswith(("\r", "\n")):
        starts.append(offset)

    def position(offset):
        index = bisect_right(starts, offset) - 1
        return index + 1, offset - starts[index] + 1

    line, column = position(start)
    end_line, end_column = position(end)
    try:
        quote = content[start:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("analyzer range splits a UTF-8 character") from error
    return {
        "path": source.path,
        "line": line,
        "column": column,
        "end_line": end_line,
        "end_column": end_column,
        "start_offset": start,
        "end_offset": end,
        "quote": quote,
        "source_sha256": source.sha256,
    }


def locate(raw, sources, graph):
    source = sources.get(raw["path"])
    if source is None:
        raise ValueError("analyzer source path is not indexed")
    start, end = raw["start"], raw["end"]
    if type(start["offset"]) is not int or type(end["offset"]) is not int:
        raise ValueError("invalid analyzer byte offsets")
    evidence = source_range(source, start["offset"], end["offset"])
    if (start["line"], start["col"], end["line"], end["col"]) != (
        evidence["line"],
        evidence["column"],
        evidence["end_line"],
        evidence["end_column"],
    ):
        raise ValueError("analyzer line/column disagrees with source bytes")
    owners = []
    for function in graph["functions"]:
        if function["path"] != source.path:
            continue
        if function["line"] <= evidence["line"] <= evidence["end_line"] <= function["end_line"]:
            if evidence["line"] == function["line"] and evidence["column"] < function.get(
                "column", 1
            ):
                continue
            if (
                evidence["end_line"] == function["end_line"]
                and evidence["end_column"] > function.get("end_column", 10**9) + 1
            ):
                continue
            owners.append(function)
    owner = (
        min(owners, key=lambda f: (f["end_line"] - f["line"], -f["line"], f["id"]))
        if owners
        else None
    )
    evidence["function_id"] = owner["id"] if owner else None
    evidence["call_ids"] = sorted(
        call["id"]
        for call in graph["calls"]
        if call["path"] == source.path
        and (evidence["line"], evidence["column"])
        <= (call["line"], call["column"])
        < (evidence["end_line"], evidence["end_column"])
        and (not owner or call["caller"] == owner["id"])
    )
    return evidence


def record_id(rule_id, role, evidence):
    return digest([rule_id, role, evidence])[:24]


def gap(reason, *, call=None, detail="", provenance="adapter_scope", finding_id=None):
    item = {
        "reason": reason,
        "provenance": provenance,
        "detail": detail,
        "call_id": call["id"] if call else None,
        "function_id": call["caller"] if call else None,
        "path": call["path"] if call else None,
        "finding_id": finding_id,
    }
    return {"id": digest(item)[:24], **item}


def boundary_gaps(graph, observations):
    calls = {call["id"]: call for call in graph["calls"]}
    modeled = {
        ref
        for observation in observations
        for ref in observation["evidence"]["call_ids"]
        if (calls[ref]["line"], calls[ref]["column"])
        == (observation["evidence"]["line"], observation["evidence"]["column"])
    }
    gaps = []
    for call in graph["calls"]:
        if call["id"] in modeled and call["status"] == "external":
            continue
        reason = (
            "interprocedural_not_analyzed"
            if call["status"] == "resolved"
            else "call_semantics_not_modeled"
        )
        gaps.append(
            gap(
                reason,
                call=call,
                detail=call["status"] + ": " + call["reason"],
                provenance="graph_structure",
            )
        )
    if graph["coverage"]["status"] == "partial":
        gaps.append(gap("graph_parse_partial", provenance="graph_structure"))
    return gaps


def trace_points(finding):
    return [finding["sink"], *finding["steps"], *([finding["source"]] if finding["source"] else [])]


def model_binding_gaps(spec, observations, taints, graph):
    models = {r["id"]: r["call_models"] for r in spec["rules"] if "call_models" in r}
    functions = {f["id"] for f in graph["functions"]}
    if any(ref not in functions for model in models.values() for ref in model.values()):
        raise ValueError("call model references an unknown function")
    calls = defaultdict(list)
    for call in graph["calls"]:
        calls[call["path"], call["line"], call["column"]].append(call)
    gaps = []
    for item in [*observations, *taints]:
        model = models.get(item["rule_id"])
        if model is None:
            continue
        endpoints = (
            [(item["role"], item["evidence"])]
            if "role" in item
            else [(role, item[role]) for role in ("source", "sink")]
        )
        for role, point in endpoints:
            if point is None:
                continue
            matches = calls.get((point["path"], point["line"], point["column"]), [])
            call = matches[0] if len(matches) == 1 else None
            if call is None or call["status"] != "resolved" or call["callee"] != model[role]:
                gaps.append(
                    gap(
                        "model_endpoint_binding_unverified",
                        call=call,
                        finding_id=item["id"] if "sink" in item else None,
                        detail=f"{item['rule_id']} {role}: function binding is unverified",
                    )
                )
    return list({g["id"]: g for g in gaps}.values())


def related_gaps(finding, gaps):
    owners = {point["function_id"] for point in trace_points(finding)}
    return {
        item["id"]
        for item in gaps
        if item["finding_id"] == finding["id"]
        or (
            item["finding_id"] is None
            and (item["function_id"] is None or item["function_id"] in owners)
        )
    }


def scope_gap(finding):
    if len({(point["path"], point["function_id"]) for point in trace_points(finding)}) > 1:
        return gap("trace_scope_not_verified", finding_id=finding["id"])
    return None


def normalize(raw, ids, graph, sources, spec=None):
    source_map = {source.path: source for source in sources}
    observations, taints, trace_gaps = [], [], []
    for result in raw["results"]:
        if result["check_id"] not in ids or result["extra"]["engine_kind"] != "OSS":
            raise ValueError("unexpected analyzer rule or engine")
        rule_id, role = ids[result["check_id"]]
        evidence = locate(result, source_map, graph)
        if role != "taint":
            observations.append(
                {
                    "id": record_id(rule_id, role, evidence),
                    "rule_id": rule_id,
                    "role": role,
                    "provenance": "semgrep_pattern",
                    "evidence": evidence,
                }
            )
            continue
        finding_id = record_id(rule_id, "taint", evidence)
        trace = result["extra"].get("dataflow_trace") or {}
        missing = []

        def endpoint(name, trace=trace, missing=missing):
            value = trace.get("taint_" + name)
            if value is None:
                missing.append("missing_" + name + "_trace")
                return None
            if not isinstance(value, list) or len(value) != 2:
                raise ValueError("malformed analyzer call trace")
            if value[0] != "CliLoc":
                missing.append("unsupported_" + name + "_trace")
                return None
            location, content = value[1]
            item = locate(location, source_map, graph)
            if item["quote"] != content:
                raise ValueError("analyzer trace quote differs from source")
            return item

        source, trace_sink = endpoint("source"), endpoint("sink")
        if trace_sink is not None and trace_sink != evidence:
            raise ValueError("analyzer sink trace differs from finding location")
        steps = []
        for step in trace.get("intermediate_vars", []):
            item = locate(step["location"], source_map, graph)
            if item["quote"] != step["content"]:
                raise ValueError("analyzer intermediate quote differs from source")
            steps.append(item)
        local = [gap(reason, finding_id=finding_id, provenance="semgrep_ce") for reason in missing]
        trace_gaps.extend(local)
        taints.append(
            {
                "id": finding_id,
                "rule_id": rule_id,
                "provenance": "semgrep_taint",
                "source": source,
                "sink": evidence,
                "steps": steps,
                "trace_status": "partial" if missing else "reported",
                "gap_ids": [item["id"] for item in local],
            }
        )
    observations = list({item["id"]: item for item in observations}.values())
    gaps = [*boundary_gaps(graph, observations), *trace_gaps]
    if spec is not None:
        gaps.extend(model_binding_gaps(spec, observations, taints, graph))
    gaps.extend(item for finding in taints if (item := scope_gap(finding)) is not None)
    gaps.extend(
        gap("analyzer_diagnostic", detail=detail, provenance="semgrep_ce")
        for detail in raw["diagnostics"]
    )
    scanned = set(raw["scanned"])
    selected = {
        source.path
        for source in sources
        if Path(source.path).suffix == semgrep.LANGUAGES[graph["language"]]
    }
    if not scanned <= selected:
        raise ValueError("analyzer scanned paths differ from supplied language")
    gaps.extend(gap("source_not_scanned", detail=path) for path in sorted(selected - scanned))
    for finding in taints:
        finding["gap_ids"] = sorted(related_gaps(finding, gaps))
        if finding["gap_ids"]:
            finding["trace_status"] = "partial"
    return (
        sorted(observations, key=lambda i: i["id"]),
        sorted(taints, key=lambda i: i["id"]),
        sorted(gaps, key=lambda i: i["id"]),
    )


def validate_static(artifact, graph, sources):
    validate_shape(
        "static analysis",
        artifact,
        json.loads((RESOURCES / "schemas/static-analysis.json").read_text()),
    )
    validate_rules(artifact["rule_spec"])
    if (
        artifact["graph_sha256"] != graph["identity_sha256"]
        or artifact["source_index"] != [s.metadata() for s in sources]
        or artifact["target"] != graph["target"]
        or artifact["language"] != graph["language"]
    ):
        raise ValueError("static analysis graph/source identity differs; rebuild static analysis")
    if artifact["rules_sha256"] != digest(artifact["rule_spec"]):
        raise ValueError("static rule checksum mismatch")
    config, _ = semgrep.generated_rules(artifact["rule_spec"], artifact["language"])
    if artifact["engine"]["generated_rules_sha256"] != digest(config):
        raise ValueError("static generated rule checksum mismatch")
    source_map = {source.path: source for source in sources}
    rule_ids = {
        rule["id"]
        for rule in artifact["rule_spec"]["rules"]
        if rule["language"] == artifact["language"]
    }
    observations = {item["id"]: item for item in artifact["observations"]}
    taints = {item["id"]: item for item in artifact["taint_results"]}
    gaps = {item["id"]: item for item in artifact["gaps"]}
    if (
        len(observations) != len(artifact["observations"])
        or len(taints) != len(artifact["taint_results"])
        or len(gaps) != len(artifact["gaps"])
    ):
        raise ValueError("duplicate static record IDs")

    def evidence(item):
        raw = {
            "path": item["path"],
            "start": {"line": item["line"], "col": item["column"], "offset": item["start_offset"]},
            "end": {
                "line": item["end_line"],
                "col": item["end_column"],
                "offset": item["end_offset"],
            },
        }
        if locate(raw, source_map, graph) != item:
            raise ValueError("static evidence quote/hash/graph references differ")

    for item in observations.values():
        evidence(item["evidence"])
        if item["rule_id"] not in rule_ids or item["id"] != record_id(
            item["rule_id"], item["role"], item["evidence"]
        ):
            raise ValueError("invalid static observation rule/ID")
    for item in gaps.values():
        if item["id"] != digest({k: v for k, v in item.items() if k != "id"})[:24]:
            raise ValueError("invalid static gap ID")
        if item["call_id"] is not None:
            call = next((c for c in graph["calls"] if c["id"] == item["call_id"]), None)
            if call is None or (item["function_id"], item["path"]) != (
                call["caller"],
                call["path"],
            ):
                raise ValueError("invalid static boundary reference")
        if item["finding_id"] is not None and item["finding_id"] not in taints:
            raise ValueError("unknown static gap finding")
    if any(item["id"] not in gaps for item in boundary_gaps(graph, artifact["observations"])):
        raise ValueError("static call boundary gaps were omitted")
    if any(
        item["id"] not in gaps
        for item in model_binding_gaps(
            artifact["rule_spec"], artifact["observations"], artifact["taint_results"], graph
        )
    ):
        raise ValueError("static model binding gaps were omitted")
    selected = {
        s.path for s in sources if Path(s.path).suffix == semgrep.LANGUAGES[artifact["language"]]
    }
    scanned = set(artifact["coverage"]["scanned_files"])
    if not scanned <= selected or any(
        gap("source_not_scanned", detail=p)["id"] not in gaps for p in selected - scanned
    ):
        raise ValueError("invalid static scanned files/gaps")
    for item in taints.values():
        for point in trace_points(item):
            evidence(point)
        if item["rule_id"] not in rule_ids or item["id"] != record_id(
            item["rule_id"], "taint", item["sink"]
        ):
            raise ValueError("invalid taint rule/ID")
        if any(ref not in gaps for ref in item["gap_ids"]) or (
            item["trace_status"] == "partial"
        ) != bool(item["gap_ids"]):
            raise ValueError("invalid taint gap references/status")
        if set(item["gap_ids"]) != related_gaps(item, gaps.values()):
            raise ValueError("taint boundary gaps were omitted or unrelated")
        boundary = scope_gap(item)
        if boundary is not None and boundary["id"] not in item["gap_ids"]:
            raise ValueError("cross-scope taint requires an explicit gap")
        if item["source"] is None and not any(
            gaps[ref]["reason"] in {"missing_source_trace", "unsupported_source_trace"}
            for ref in item["gap_ids"]
        ):
            raise ValueError("missing taint source requires an explicit gap")
        for role in ("source", "sink"):
            point = item[role]
            if point is not None and not any(
                o["rule_id"] == item["rule_id"] and o["role"] == role and o["evidence"] == point
                for o in observations.values()
            ):
                raise ValueError("taint endpoint lacks source/sink model evidence")
    if artifact["coverage"]["status"] != ("partial" if gaps else "analyzed"):
        raise ValueError("static coverage differs from gaps")
    expected = {k: v for k, v in artifact.items() if k != "identity_sha256"}
    if artifact["identity_sha256"] != digest(expected):
        raise ValueError("static analysis checksum mismatch")


def read_static(path, graph, sources):
    if path.stat().st_size > MAX_GRAPH_BYTES:
        raise ValueError("static analysis exceeds 64 MiB")
    artifact = json.loads(path.read_text(encoding="utf-8"))
    validate_static(artifact, graph, sources)
    return artifact


def build_static(
    target, graph_file, rules_file, output, *, timeout=30, cache=None, expected_engine=None
):
    target, output = target.resolve(), output.resolve()
    if output.is_relative_to(target) or rules_file.resolve().is_relative_to(target):
        raise ValueError("static output and explicit rules must be outside target")
    if timeout < 1:
        raise ValueError("static timeout must be positive")
    sources, skipped = index_target(target)
    graph = current_graph(target, graph_file, sources)
    spec = read_document(rules_file)
    validate_rules(spec)
    normalizer_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("static output is nonempty; use a new output directory")
        try:
            if (
                expected_engine is not None
                and expected_engine.get("normalizer_sha256") != normalizer_hash
            ):
                raise ValueError(
                    "second analysis normalizer differs from the first; rebuild static analysis"
                )
            raw, ids, engine = semgrep.scan(
                target,
                sources,
                spec,
                graph["language"],
                cache or Path.cwd() / ".cache/semgrep",
                timeout,
                **({"expected_engine": expected_engine} if expected_engine is not None else {}),
            )
            engine["normalizer_sha256"] = normalizer_hash
            try:
                observations, taints, gaps = normalize(raw, ids, graph, sources, spec)
            except (KeyError, TypeError, IndexError, AttributeError) as error:
                raise ValueError("malformed analyzer evidence") from error
            current, current_skipped = index_target(target)
            if (
                [s.metadata() for s in current] != [s.metadata() for s in sources]
                or current_skipped != skipped
                or read_document(rules_file) != spec
                or current_graph(target, graph_file, current) != graph
                or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != normalizer_hash
            ):
                raise ValueError("static source/rules/normalizer changed during analysis")
            artifact = {
                "schema_version": 1,
                "target": str(target),
                "language": graph["language"],
                "graph_sha256": graph["identity_sha256"],
                "source_index": [s.metadata() for s in sources],
                "engine": engine,
                "rule_spec": spec,
                "rules_sha256": digest(spec),
                "observations": observations,
                "taint_results": taints,
                "gaps": gaps,
                "coverage": {
                    "status": "partial" if gaps else "analyzed",
                    "scanned_files": raw["scanned"],
                    "note": "Rule-limited intra-function analysis. Empty results do not mean safe.",
                },
                "limitations": [
                    "Source/sink/sanitizer roles follow declared patterns; exposure is not proven.",
                    "Sanitizer matches are model assumptions, not verified security controls.",
                    "Unknown calls may propagate taint conservatively; gaps remain explicit.",
                    "Calls are structural facts; no cross-function/file taint is synthesized.",
                    "Analyzer reports are hypotheses; no runtime validation or confirmed finding.",
                ],
            }
            artifact["identity_sha256"] = digest(artifact)
            validate_static(artifact, graph, sources)
            if len(encode(artifact).encode()) > MAX_GRAPH_BYTES:
                raise ValueError("static analysis exceeds 64 MiB")
            save_json(output / "static.json", artifact)
            save_json(output / "analyzer-output.json", raw)
            rows = [
                "# Static analysis evidence",
                "",
                "Analyzer reports only; no confirmed vulnerabilities.",
                "",
                f"Engine: {engine['name']} {engine['version']} ({engine['scope']})",
                f"Pattern facts: {len(observations)}; taint reports: {len(taints)}; "
                f"gaps: {len(gaps)}",
                "",
            ]
            for item in taints:
                source = item["source"]
                rows.append(
                    "- "
                    + json.dumps(
                        {
                            "rule": item["rule_id"],
                            "source": f"{source['path']}:{source['line']}" if source else None,
                            "sink": f"{item['sink']['path']}:{item['sink']['line']}",
                            "trace": item["trace_status"],
                            "gaps": item["gap_ids"],
                        },
                        ensure_ascii=True,
                    )
                    .replace("<", "\\u003c")
                    .replace("`", "\\u0060")
                )
            rows.extend(
                [
                    "",
                    "Call boundaries and source/sink/variable quotes are preserved in static.json.",
                    "",
                ]
            )
            save_text(output / "report.md", "\n".join(rows))
            return artifact
        except (Exception, KeyboardInterrupt) as error:
            save_json(
                output / "failure.json",
                {
                    "status": "failed",
                    "error_type": type(error).__name__,
                    "detail": str(error)[:8000],
                },
            )
            raise


def selected_records(artifact, hypothesis, graph):
    owners = set(hypothesis["function_ids"]) | {a["function"] for a in hypothesis["annotations"]}
    owners.update(r["caller"] for r in hypothesis["registrations"])
    files = {node["path"] for node in graph["functions"] if node["id"] in owners}
    observations = [
        o
        for o in artifact["observations"]
        if o["evidence"]["function_id"] in owners
        or (o["evidence"]["function_id"] is None and o["evidence"]["path"] in files)
    ]
    taints = [
        t
        for t in artifact["taint_results"]
        if t["sink"]["function_id"] in owners
        or (t["source"] and t["source"]["function_id"] in owners)
    ]
    finding_ids = {t["id"] for t in taints}
    gaps = [
        g
        for g in artifact["gaps"]
        if g["function_id"] in owners
        or (g["function_id"] is None and g["finding_id"] in finding_ids | {None})
    ]
    return {"observations": observations, "taint_results": taints, "gaps": gaps}


def attach_records(source_slice, records, artifact, byte_limit, gaps, *, fragments=None):
    rules = {rule["id"]: rule for rule in artifact["rule_spec"]["rules"]}

    def supplied(evidence):
        return any(
            fragment["path"] == evidence["path"]
            and fragment["first_line"]
            <= evidence["line"]
            <= evidence["end_line"]
            <= fragment["last_line"]
            for fragment in (fragments if fragments is not None else source_slice["fragments"])
        )

    for kind in ("taint_results", "observations", "gaps"):
        for item in records[kind]:
            points = (
                [item["sink"], *item["steps"], *([item["source"]] if item["source"] else [])]
                if kind == "taint_results"
                else [item["evidence"]]
                if kind == "observations"
                else []
            )
            evidence = source_slice["static_analysis"]
            models = {rule["id"]: rule for rule in evidence["rules"]}
            if kind != "gaps":
                models[item["rule_id"]] = rules[item["rule_id"]]
            candidate = {
                **source_slice,
                "static_analysis": {
                    **evidence,
                    "rules": list(models.values()),
                    kind: [*evidence[kind], item],
                },
            }
            present = all(supplied(point) for point in points)
            if present and len(encode(candidate).encode()) <= byte_limit:
                source_slice = candidate
                source_slice["omitted_counts"]["static_" + kind] -= 1
            else:
                gaps.append(
                    {
                        "hypothesis_id": source_slice.get("hypothesis", {}).get("id"),
                        "kind": "static_" + kind,
                        "id": item["id"],
                        "reason": "slice_byte_budget" if present else "static_source_not_supplied",
                    }
                )
    return source_slice
