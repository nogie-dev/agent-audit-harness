"""Source-backed hypotheses and bounded graph slices; security labels stay hypotheses."""

import json
from pathlib import Path

from .extractors.inputs import read_input
from .graph import reachable, read_graph, select_function
from .pipeline import (
    MAX_FILE_BYTES,
    RESOURCES,
    digest,
    encode,
    index_target,
    run_lock,
    save_json,
    source_lines,
    validate_evidence,
    validate_shape,
)


def read_document(path: Path) -> dict:
    return json.loads(read_input(path.parent.resolve(), path.name).text)


def current_graph(target: Path, graph_file: Path, sources: list) -> dict:
    graph = read_graph(graph_file)
    if graph["schema_version"] != 2:
        raise ValueError("recon requires a v2 graph; rebuild the legacy graph")
    if graph["target"] != str(target.resolve()) or graph["source_index"] != [
        source.metadata() for source in sources
    ]:
        raise ValueError("graph source changed or target differs; rebuild the graph")
    for item in graph["input_config"]:
        if read_input(target, item["path"]).metadata() != item:
            raise ValueError("graph configuration changed; rebuild the graph")
    return graph


def make_recon(graph: dict, sources: list, spec: dict) -> dict:
    schema = json.loads((RESOURCES / "schemas" / "research-plan.json").read_text())
    validate_shape("research plan", spec, schema)
    ids = [item["id"] for item in spec["hypotheses"]]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate hypothesis IDs")
    source_map = {source.path: source for source in sources}
    calls = {call["id"]: call for call in graph["calls"]}
    hypotheses = []
    for item in spec["hypotheses"]:
        entry = select_function(graph, item["entry"])
        working_set = reachable(graph, entry["id"])
        function_ids = [function["id"] for function in working_set["functions"]]
        annotations = []
        for annotation in item["annotations"]:
            function = select_function(graph, annotation["function"])
            source = source_map[function["path"]]
            lines = source_lines(source.text)[function["line"] - 1 : function["end_line"]]
            if "column" in function:
                if function["column"] > len(lines[0].encode()) or function["end_column"] > len(
                    lines[-1].encode()
                ):
                    raise ValueError("function columns exceed actual source")
                tail = lines[-1].encode()[function["end_column"] :]
                if tail.strip():
                    lines[-1] = lines[-1].encode()[: function["end_column"]].decode()
                lines[0] = lines[0].encode()[function["column"] - 1 :].decode()
            fragment = {
                "path": source.path,
                "first_line": function["line"],
                "last_line": function["end_line"],
                "text": "".join(lines),
                "source_sha256": source.sha256,
                "id": item["id"],
            }
            validate_evidence(annotation["evidence"], [fragment])
            annotations.append(
                {
                    **annotation,
                    "function": function["id"],
                    "source_sha256": source.sha256,
                    "status": "provided_hypothesis",
                    "call_relation": (
                        "reachable_by_direct_calls"
                        if function["id"] in function_ids
                        else "not_linked_by_direct_calls"
                    ),
                }
            )
        registrations = []
        if graph["language"] == "go":
            from .extractors.golang import entry_registrations

            for registration in entry_registrations(graph, entry["id"]):
                call = calls[registration["call_id"]]
                source = source_map[call["path"]]
                registrations.append(
                    {
                        **registration,
                        "status": "registration_only",
                        "evidence": {
                            "path": source.path,
                            "line": call["line"],
                            "quote": source_lines(source.text)[call["line"] - 1].rstrip("\r\n"),
                            "source_sha256": source.sha256,
                        },
                    }
                )
        hypotheses.append(
            {
                "id": item["id"],
                "question": item["question"],
                "assumptions": item["assumptions"],
                "entry": entry["id"],
                "entry_status": "provided_hypothesis",
                "registrations": registrations,
                "annotations": annotations,
                "function_ids": function_ids,
                "call_ids": [call["id"] for call in working_set["calls"]],
                "unknown_call_ids": [
                    call["id"]
                    for call in working_set["calls"]
                    if call["status"] in {"unresolved", "ambiguous"}
                ],
                "external_call_ids": [
                    call["id"] for call in working_set["calls"] if call["status"] == "external"
                ],
                "unlinked_annotation_ids": sorted(
                    {
                        annotation["function"]
                        for annotation in annotations
                        if annotation["function"] not in function_ids
                    }
                ),
            }
        )
    scopes = sorted({node["scope"] for node in [*graph["functions"], *graph.get("contexts", [])]})
    result = {
        "schema_version": 1,
        "graph_sha256": graph["identity_sha256"],
        "spec": spec,
        "components": [
            {
                "scope": scope,
                "function_ids": [
                    node["id"] for node in graph["functions"] if node["scope"] == scope
                ],
                "context_ids": [
                    node["id"] for node in graph.get("contexts", []) if node["scope"] == scope
                ],
            }
            for scope in scopes
        ],
        "hypotheses": hypotheses,
        "coverage": graph["coverage"],
        "limitations": [
            *graph["limitations"],
            *([] if "contexts" in graph else ["Declaration context is unavailable in this graph."]),
            "Researcher-supplied hypotheses; no automatic whole-repository threat model.",
            "Registration is not invocation, server deployment or attacker reachability.",
            "Annotation quotes are verified; their security meaning remains a hypothesis.",
            "Control presence does not prove effectiveness; no traversal stops at a barrier.",
            "Direct-call reachability only; unresolved calls may hide additional paths.",
        ],
    }
    result["identity_sha256"] = digest(result)
    if len(encode(result).encode()) > MAX_FILE_BYTES:
        raise ValueError("recon exceeds 512 KiB; select fewer hypotheses")
    return result


def build_recon(target: Path, graph_file: Path, spec_file: Path, output: Path) -> dict:
    target, output = target.resolve(), output.resolve()
    if output.is_relative_to(target):
        raise ValueError("recon output must be outside the target")
    sources, _ = index_target(target)
    graph = current_graph(target, graph_file, sources)
    result = make_recon(graph, sources, read_document(spec_file))
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("recon output is nonempty; use a new directory")
        save_json(output / "recon.json", result)
    return result


def read_recon(path: Path, graph: dict, sources: list) -> dict:
    result = read_document(path)
    if not isinstance(result, dict) or "spec" not in result:
        raise ValueError("invalid recon artifact")
    expected = make_recon(graph, sources, result["spec"])
    if result != expected:
        raise ValueError("recon changed or graph differs; rebuild recon")
    return result


def merge_fragments(units: list, source_map: dict) -> list[dict]:
    fragments = []
    for unit in sorted(units, key=lambda item: (item["path"], item["line"], item["end_line"])):
        if (
            fragments
            and fragments[-1]["path"] == unit["path"]
            and unit["line"] <= fragments[-1]["last_line"] + 1
        ):
            fragment = fragments[-1]
            fragment["last_line"] = max(fragment["last_line"], unit["end_line"])
            fragment["definition_ids"].append(unit["id"])
        else:
            fragments.append(
                {
                    "path": unit["path"],
                    "first_line": unit["line"],
                    "last_line": unit["end_line"],
                    "definition_ids": [unit["id"]],
                }
            )
    for fragment in fragments:
        source = source_map[fragment["path"]]
        fragment["text"] = "".join(
            source_lines(source.text)[fragment["first_line"] - 1 : fragment["last_line"]]
        )
        fragment["source_sha256"] = source.sha256
        fragment["definition_ids"] = sorted(set(fragment["definition_ids"]))
    return fragments


def make_graph_slices(
    graph: dict, recon: dict, sources: list, byte_limit: int
) -> tuple[list, list]:
    if not 1024 <= byte_limit <= 64_000:
        raise ValueError("slice bytes must be between 1024 and 64000")
    functions = {node["id"]: node for node in graph["functions"]}
    contexts = {node["id"]: node for node in graph.get("contexts", [])}
    source_map = {source.path: source for source in sources}
    calls = {call["id"]: call for call in graph["calls"]}
    slices, gaps = [], []
    for number, hypothesis in enumerate(recon["hypotheses"], 1):
        ordered = list(
            dict.fromkeys(
                [
                    hypothesis["entry"],
                    *[item["function"] for item in hypothesis["annotations"]],
                    *[item["caller"] for item in hypothesis["registrations"]],
                    *hypothesis["function_ids"],
                ]
            )
        )
        units, visited = [], set()
        for function_id in ordered:
            node = functions[function_id]
            units.append(("functions", node))
            pending = list(node.get("context_ids", []))
            while pending:
                context_id = pending.pop(0)
                if context_id in visited:
                    continue
                visited.add(context_id)
                context = contexts[context_id]
                units.append(("contexts", context))
                pending.extend(context["references"])
        call_ids = list(
            dict.fromkeys(
                [*hypothesis["call_ids"], *[r["call_id"] for r in hypothesis["registrations"]]]
            )
        )
        omitted = {
            "functions": len(ordered),
            "contexts": len(visited),
            "calls": len(call_ids),
            "annotations": len(hypothesis["annotations"]),
        }
        source_slice = {
            "id": f"s{number:04d}",
            "hypothesis": {
                key: hypothesis[key] for key in ("id", "question", "assumptions", "entry")
            },
            "fragments": [],
            "calls": [],
            "annotations": [],
            "omitted_counts": omitted,
            "note": (
                "Call facts are not taint or runtime reachability. Full gaps are in coverage.json; "
                "security labels are hypotheses."
            ),
        }
        accepted, included_functions = [], set()

        def fits(candidate):
            return len(encode(candidate).encode()) <= byte_limit

        for kind, node in units:
            candidate = {
                **source_slice,
                "fragments": merge_fragments([*accepted, node], source_map),
            }
            if fits(candidate):
                accepted.append(node)
                source_slice["fragments"] = candidate["fragments"]
                omitted[kind] -= 1
                if kind == "functions":
                    included_functions.add(node["id"])
            else:
                gaps.append(
                    {
                        "hypothesis_id": hypothesis["id"],
                        "kind": kind,
                        "id": node["id"],
                        "path": node["path"],
                        "reason": "slice_byte_budget",
                    }
                )
                if node["id"] == hypothesis["entry"]:
                    break
        if hypothesis["entry"] not in included_functions:
            gaps.append(
                {
                    "hypothesis_id": hypothesis["id"],
                    "kind": "hypothesis",
                    "reason": "entry_definition_exceeds_budget",
                }
            )
            continue
        for annotation in hypothesis["annotations"]:
            candidate = {**source_slice, "annotations": [*source_slice["annotations"], annotation]}
            if annotation["function"] in included_functions and fits(candidate):
                source_slice = candidate
                omitted["annotations"] -= 1
            else:
                gaps.append(
                    {
                        "hypothesis_id": hypothesis["id"],
                        "kind": "annotation",
                        "id": annotation["function"],
                        "reason": "annotation_not_supplied",
                    }
                )
        for call_id in call_ids:
            call = calls[call_id]
            candidate = {**source_slice, "calls": [*source_slice["calls"], call]}
            if call["caller"] in included_functions and fits(candidate):
                source_slice = candidate
                omitted["calls"] -= 1
            else:
                gaps.append(
                    {
                        "hypothesis_id": hypothesis["id"],
                        "kind": "call",
                        "id": call_id,
                        "status": call["status"],
                        "reason": "call_not_supplied",
                    }
                )
        slices.append(source_slice)
    return slices, gaps


def reviewed_lines(slices: list) -> int:
    lines = set()
    for source_slice in slices:
        for fragment in source_slice.get("fragments", [source_slice]):
            lines.update(
                (fragment["path"], number)
                for number in range(fragment["first_line"], fragment["last_line"] + 1)
            )
    return len(lines)
