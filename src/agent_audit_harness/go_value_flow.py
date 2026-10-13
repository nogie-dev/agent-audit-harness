"""Bounded Go/Python syntax-value paths between declared static roles."""

from collections import defaultdict, deque

MAX_ROLE_PAIRS = 128
MAX_STATES = 256
MAX_HOPS = 8


def go_value_flows(graph, static):
    if graph["language"] not in {"go", "python"} or static is None:
        return [], []
    calls = {call["id"]: call for call in graph["calls"]}
    by_caller = defaultdict(list)
    for call in graph["calls"]:
        by_caller[call["caller"]].append(call)
    for group in by_caller.values():
        group.sort(key=lambda call: (call["path"], call["line"], call["column"], call["id"]))
    sources = [item for item in static["observations"] if item["role"] == "source"]
    sinks = [item for item in static["observations"] if item["role"] == "sink"]
    pairs = [
        (source, sink)
        for source in sources
        for sink in sinks
        if source["rule_id"] == sink["rule_id"]
    ]
    flows, gaps = [], []
    for source, sink in pairs[:MAX_ROLE_PAIRS]:
        source_calls = [
            calls[ref]
            for ref in source["evidence"]["call_ids"]
            if ref in calls
            and calls[ref]["dispatch"] == "direct"
            and calls[ref]["status"] in {"resolved", "external"}
            and (calls[ref]["line"], calls[ref]["column"])
            == (source["evidence"]["line"], source["evidence"]["column"])
            and (
                calls[ref].get("metadata", {}).get("call_end_line"),
                calls[ref].get("metadata", {}).get("call_end_column"),
            )
            == (source["evidence"]["end_line"], source["evidence"]["end_column"])
        ]
        sink_ids = {
            ref
            for ref in sink["evidence"]["call_ids"]
            if ref in calls
            and calls[ref]["dispatch"] == "direct"
            and calls[ref]["status"] in {"resolved", "external"}
            and (calls[ref]["line"], calls[ref]["column"])
            == (sink["evidence"]["line"], sink["evidence"]["column"])
            and (
                calls[ref].get("metadata", {}).get("call_end_line"),
                calls[ref].get("metadata", {}).get("call_end_column"),
            )
            == (sink["evidence"]["end_line"], sink["evidence"]["end_column"])
        }
        starts = {
            (
                call["path"],
                call["line"],
                call["column"],
                call["metadata"]["call_end_line"],
                call["metadata"]["call_end_column"],
            ): call["id"]
            for call in source_calls
        }
        pending = deque([(source["evidence"]["function_id"], None, [])])
        visited = set()
        found = None
        budget_exhausted = False
        while pending and len(visited) < MAX_STATES:
            function, parameter, path = pending.popleft()
            if (function, parameter) in visited:
                continue
            visited.add((function, parameter))
            for call in by_caller[function]:
                for origin in call.get("metadata", {}).get("argument_origins", []):
                    if parameter is None:
                        if origin["kind"] != "call_result":
                            continue
                        start = (
                            origin["path"],
                            origin["line"],
                            origin["column"],
                            origin["end_line"],
                            origin["end_column"],
                        )
                        source_call = starts.get(start)
                        if source_call is None:
                            continue
                        route = [source_call]
                    else:
                        if origin["kind"] != "parameter" or origin["parameter_index"] != parameter:
                            continue
                        route = path
                    if call["id"] in sink_ids:
                        found = {
                            "source_observation_id": source["id"],
                            "sink_observation_id": sink["id"],
                            "call_ids": [*route, call["id"]],
                            "status": "bounded_syntax_value_path",
                        }
                        break
                    if call["status"] != "resolved" or len(route) >= MAX_HOPS:
                        continue
                    for transfer in call.get("metadata", {}).get("argument_transfers", []):
                        if transfer["argument_index"] == origin["argument_index"]:
                            if len(pending) + len(visited) < MAX_STATES:
                                pending.append(
                                    (
                                        call["callee"],
                                        transfer["parameter_index"],
                                        [*route, call["id"]],
                                    )
                                )
                            else:
                                budget_exhausted = True
                if found:
                    break
            if found:
                break
        if found:
            flows.append(found)
        else:
            gaps.append(
                {
                    "source_observation_id": source["id"],
                    "sink_observation_id": sink["id"],
                    "reason": "value_flow_state_budget"
                    if budget_exhausted
                    else "no_supported_value_path",
                }
            )
    if len(pairs) > MAX_ROLE_PAIRS:
        gaps.append(
            {"reason": "value_flow_role_pair_budget", "omitted_pairs": len(pairs) - MAX_ROLE_PAIRS}
        )
    return flows, gaps
