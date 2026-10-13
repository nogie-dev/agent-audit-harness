"""Bounded, read-only queries over verified in-memory graph/source snapshots."""

from bisect import bisect_right
from collections import defaultdict

from .graph import reachable, resolve
from .pipeline import digest, encode, source_lines


def fragments_for_ranges(sources, ranges):
    grouped = defaultdict(list)
    for path, first, last in ranges:
        grouped[path].append((first, last))
    fragments = []
    for path, spans in sorted(grouped.items()):
        merged = []
        for first, last in sorted(spans):
            if merged and first <= merged[-1][1] + 1:
                merged[-1][1] = max(last, merged[-1][1])
            else:
                merged.append([first, last])
        source = sources[path]
        lines = source_lines(source.text)
        for first, last in merged:
            if not 1 <= first <= last <= len(lines):
                raise ValueError("query range is outside indexed source")
            fragments.append(
                {
                    "path": path,
                    "first_line": first,
                    "last_line": last,
                    "text": "".join(lines[first - 1 : last]),
                    "source_sha256": source.sha256,
                }
            )
    return fragments


def query_data(graph, sources, request, static=None):
    if request["operation"] == "source":
        path, first, last = request["path"], request["first_line"], request["last_line"]
        if path not in sources:
            return None, "source_not_indexed"
        if not 1 <= first <= last <= len(source_lines(sources[path].text)) or last - first >= 200:
            return None, "invalid_source_range"
        data = {"fragments": fragments_for_ranges(sources, [(path, first, last)])}
    elif graph is None:
        return None, "graph_not_available"
    else:
        try:
            structure = (resolve if request["operation"] == "resolve" else reachable)(
                graph, request["selector"]
            )
        except ValueError:
            return None, "selector_missing_or_ambiguous"
        nodes = structure["functions"] + structure["contexts"]
        calls = (
            structure.get("calls", [])
            + structure.get("incoming_calls", [])
            + structure.get("outgoing_calls", [])
        )
        ranges = [(node["path"], node["line"], node["end_line"]) for node in nodes]
        ranges.extend((call["path"], call["line"], call["line"]) for call in calls)
        data = {"structure": structure, "fragments": fragments_for_ranges(sources, ranges)}
    if graph is not None:
        from .triage import input_gaps

        ranges = defaultdict(list)
        for part in data["fragments"]:
            ranges[part["path"]].append((part["first_line"], part["last_line"]))

        def overlaps(node):
            spans = ranges.get(node["path"], [])
            index = (
                bisect_right(spans, node.get("end_line", node["line"]), key=lambda span: span[0])
                - 1
            )
            return index >= 0 and spans[index][1] >= node["line"]

        data["graph_sha256"] = graph["identity_sha256"]
        data["context_function_ids"] = [f["id"] for f in graph["functions"] if overlaps(f)]
        if request["operation"] == "source":
            data["structure"] = {"calls": [c for c in graph["calls"] if overlaps(c)]}
        calls = [
            call
            for key in ("calls", "incoming_calls", "outgoing_calls")
            for call in data["structure"].get(key, [])
        ]
        gaps = input_gaps(
            {"query_function_ids": data["context_function_ids"], "calls": calls},
            {"graph": graph, **({"static": static} if static is not None else {})},
        )
        data["input_gaps"] = {key: value for key, value in gaps.items() if key.endswith("_ids")}
        if static is not None:
            data["static_artifact_sha256"] = static["identity_sha256"]
            static_ids = set(gaps["static_gap_ids"])
            data["static_gaps"] = [g for g in static["gaps"] if g["id"] in static_ids]
        modifier_ids = set(gaps["modifier_gap_function_ids"])
        data["modifier_gaps"] = [
            {"function_id": f["id"], "gaps": f["metadata"]["modifier_flow"]["gaps"]}
            for f in graph["functions"]
            if f["id"] in modifier_ids
        ]
    return data, None


def answer_requests(graph, sources, requests, history, slice_id, *, static=None):
    source_map = {source.path: source for source in sources}
    budget = history["budget"].copy()
    responses = []
    for offset, request in enumerate(requests, len(history["responses"]) + 1):
        response = {
            "id": "iq-" + digest([slice_id, offset, request])[:16],
            "request": request,
            "status": "omitted",
            "reason": "query_count_budget_exhausted",
            "data": None,
            "payload_bytes": 0,
        }
        if budget["remaining_queries"]:
            budget["remaining_queries"] -= 1
            data, reason = query_data(graph, source_map, request, static)
            size = len(encode(data).encode()) if data is not None else 0
            response.update(status="unavailable", reason=reason)
            if data is not None:
                if size > budget["remaining_bytes"]:
                    response.update(
                        status="omitted", reason="query_byte_budget_exhausted", required_bytes=size
                    )
                else:
                    response.update(status="provided", reason=None, data=data, payload_bytes=size)
                    budget["remaining_bytes"] -= size
        responses.append(response)
    return {"responses": responses, "budget": budget}


def evidence_slice(source_slice, history):
    fragments = list(source_slice.get("fragments", [source_slice]))
    calls = {call["id"]: call for call in source_slice.get("calls", [])}
    flows = {flow["function_id"]: flow for flow in source_slice.get("modifier_flows", [])}
    query_owners = set(source_slice.get("query_function_ids", []))
    for response in history["responses"]:
        if response["status"] != "provided":
            continue
        data = response["data"]
        fragments.extend(data["fragments"])
        query_owners.update(data.get("context_function_ids", []))
        structure = data.get("structure", {})
        for key in ("calls", "incoming_calls", "outgoing_calls"):
            calls.update((call["id"], call) for call in structure.get(key, []))
        for function in structure.get("functions", []):
            if flow := function.get("metadata", {}).get("modifier_flow"):
                flows[function["id"]] = {"function_id": function["id"], "flow": flow}
    return {
        **source_slice,
        "fragments": fragments,
        "calls": list(calls.values()),
        "modifier_flows": list(flows.values()),
        "query_function_ids": sorted(query_owners),
    }
