"""Bounded recon proposals from registration and declared static-role evidence."""

import hashlib
import json
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

from .go_value_flow import go_value_flows
from .pipeline import (
    RESOURCES,
    digest,
    encode,
    index_target,
    run_lock,
    save_json,
    save_text,
    source_lines,
)
from .recon import current_graph, make_recon, merge_fragments
from .static_analysis import read_static
from .triage import checked_evidence

MAX_RECON_RELATION_PAIRS = 256


def recon_context(graph, sources, static, byte_limit):
    if not 1024 <= byte_limit <= 64000:
        raise ValueError("recon input bytes must be between 1024 and 64000")
    functions = {f["id"]: f for f in graph["functions"]}
    calls = {c["id"]: c for c in graph["calls"]}
    source_map = {s.path: s for s in sources}
    lines = {s.path: source_lines(s.text) for s in sources}
    candidates = []
    if graph["language"] == "go":
        from .extractors.golang import entry_registrations

        for registration in entry_registrations(graph):
            call = calls[registration["call_id"]]
            candidates.append(
                {
                    "kind": "registration",
                    "status": "registration_only",
                    **registration,
                    "evidence": {
                        "path": call["path"],
                        "line": call["line"],
                        "column": 1,
                        "quote": lines[call["path"]][call["line"] - 1].rstrip("\r\n"),
                    },
                }
            )
    elif graph["language"] == "solidity":
        for function in graph["functions"]:
            metadata = function["metadata"]
            if (
                function["kind"] not in {"function", "fallback", "receive"}
                or metadata["visibility"] not in {"public", "external"}
                or not metadata["implemented"]
            ):
                continue
            line = lines[function["path"]][function["line"] - 1]
            quote = line.encode()[function["column"] - 1 :].decode().split("(", 1)[0].strip()
            candidates.append(
                {
                    "kind": "entry_visibility",
                    "status": "visibility_only",
                    "function": function["id"],
                    "visibility": metadata["visibility"],
                    "contract_kind": metadata["contract_kind"],
                    "evidence": {
                        "path": function["path"],
                        "line": function["line"],
                        "column": function["column"],
                        "quote": quote,
                    },
                }
            )
    if static:
        for observation in static["observations"]:
            candidates.append(
                {
                    "kind": "static_role",
                    "status": "declared_role",
                    "function": observation["evidence"]["function_id"],
                    "role": observation["role"],
                    "rule_id": observation["rule_id"],
                    "observation_id": observation["id"],
                    "evidence": {
                        k: observation["evidence"][k] for k in ("path", "line", "column", "quote")
                    },
                }
            )
    data = {
        "graph_sha256": graph["identity_sha256"],
        "static_sha256": static["identity_sha256"] if static else None,
        "facts": [],
        "functions": [],
        "fragments": [],
        "calls": [],
        "relationships": [],
        "value_flows": [],
        "note": "Calls are structural; visibility and roles do not prove exposure or control.",
    }
    omissions, nodes = [], {}
    for fact in candidates:
        fact = {"id": "rf-" + digest(fact)[:24], **fact}
        omitted = {
            "id": fact["id"],
            "kind": fact["kind"],
            "function": fact["function"],
            "path": fact["evidence"]["path"],
            "line": fact["evidence"]["line"],
            "column": fact["evidence"]["column"],
            "source_sha256": source_map[fact["evidence"]["path"]].sha256,
        }
        node = functions.get(fact["function"])
        if node is None:
            omissions.append({**omitted, "reason": "role_without_function"})
            continue
        selected = {**nodes, node["id"]: node}
        if fact["kind"] == "registration":
            caller = functions[fact["caller"]]
            selected[caller["id"]] = caller
        candidate = {
            **data,
            "facts": [*data["facts"], fact],
            "functions": [
                {key: f[key] for key in ("id", "name", "path", "line", "end_line")}
                for f in selected.values()
            ],
            "fragments": merge_fragments(list(selected.values()), source_map),
        }
        if len(encode(candidate).encode()) > byte_limit:
            omissions.append({**omitted, "reason": "recon_input_byte_budget"})
        else:
            nodes, data = selected, candidate
    value_flows, flow_gaps = go_value_flows(graph, static)
    for flow in value_flows:
        for ref in flow["call_ids"]:
            node = functions[calls[ref]["caller"]]
            if node["id"] in nodes:
                continue
            selected = {**nodes, node["id"]: node}
            candidate = {
                **data,
                "functions": [
                    {key: f[key] for key in ("id", "name", "path", "line", "end_line")}
                    for f in selected.values()
                ],
                "fragments": merge_fragments(list(selected.values()), source_map),
            }
            if len(encode(candidate).encode()) <= byte_limit:
                nodes, data = selected, candidate
            else:
                flow_gaps.append(
                    {
                        "reason": "value_flow_intermediate_byte_budget",
                        "source_observation_id": flow["source_observation_id"],
                        "sink_observation_id": flow["sink_observation_id"],
                    }
                )
    ordered_calls = sorted(
        graph["calls"],
        key=lambda call: (
            call["status"] != "resolved",
            call["status"] == "external",
            call["path"],
            call["line"],
            call["column"],
            call["id"],
        ),
    )
    for call in ordered_calls:
        if call["caller"] not in nodes:
            continue
        summary = {
            key: call[key]
            for key in (
                "id",
                "caller",
                "callee",
                "callee_name",
                "path",
                "line",
                "column",
                "status",
                "dispatch",
                "execution",
                "reason",
            )
        }
        candidate = {**data, "calls": [*data["calls"], summary]}
        if len(encode(candidate).encode()) > byte_limit:
            omissions.append(
                {
                    "id": call["id"],
                    "kind": "call",
                    "function": call["caller"],
                    "path": call["path"],
                    "line": call["line"],
                    "column": call["column"],
                    "source_sha256": source_map[call["path"]].sha256,
                    "reason": "recon_input_byte_budget",
                }
            )
        else:
            data = candidate
    observations = {item["id"]: item for item in static["observations"]} if static else {}
    for gap in flow_gaps:
        sink = observations.get(gap.get("sink_observation_id"))
        if sink is None:
            continue
        point = sink["evidence"]
        omissions.append(
            {
                "id": "vf-"
                + digest([gap.get("source_observation_id"), sink["id"], gap["reason"]])[:24],
                "kind": "value_flow",
                "function": point["function_id"],
                "path": point["path"],
                "line": point["line"],
                "column": point["column"],
                "source_sha256": point["source_sha256"],
                "reason": gap["reason"],
            }
        )
    direct = defaultdict(list)
    for call in graph["calls"]:
        if call["status"] == "resolved" and call["dispatch"] == "direct":
            direct[call["caller"]].append((call["callee"], call["id"]))
    for edges in direct.values():
        edges.sort()
    included_calls = {call["id"] for call in data["calls"]}
    entries = [
        fact
        for fact in data["facts"]
        if fact["kind"] in {"registration", "entry_visibility"} or fact.get("role") == "source"
    ]
    roles = [fact for fact in data["facts"] if fact["kind"] == "static_role"]
    total_pairs = len(entries) * len(roles) - sum(fact["kind"] == "static_role" for fact in entries)
    considered_pairs = 0
    for entry in entries:
        if considered_pairs == MAX_RECON_RELATION_PAIRS:
            break
        predecessors = {entry["function"]: None}
        pending = deque([entry["function"]])
        while pending:
            caller = pending.popleft()
            for callee, call_id in direct[caller]:
                if callee not in predecessors:
                    predecessors[callee] = (caller, call_id)
                    pending.append(callee)
        for role in roles:
            if role["id"] == entry["id"]:
                continue
            if considered_pairs == MAX_RECON_RELATION_PAIRS:
                break
            considered_pairs += 1
            path = None
            if role["function"] in predecessors:
                path = []
                current = role["function"]
                while predecessors[current] is not None:
                    current, call_id = predecessors[current]
                    path.append(call_id)
                path.reverse()
            reason = (
                "no_resolved_direct_path"
                if path is None
                else "intermediate_function_not_supplied"
                if any(calls[call_id]["caller"] not in nodes for call_id in path)
                else "recon_input_byte_budget"
                if any(call_id not in included_calls for call_id in path)
                else None
            )
            relationship = {
                "entry_fact_id": entry["id"],
                "role_fact_id": role["id"],
                "role": role["role"],
                "call_ids": path,
                "status": "structural_direct_calls",
            }
            if reason is None:
                candidate = {**data, "relationships": [*data["relationships"], relationship]}
                if len(encode(candidate).encode()) <= byte_limit:
                    data = candidate
                    continue
                reason = "recon_input_byte_budget"
            omissions.append(
                {
                    "id": "rr-" + digest([entry["id"], role["id"]])[:24],
                    "kind": "relationship",
                    "function": role["function"],
                    "path": role["evidence"]["path"],
                    "line": role["evidence"]["line"],
                    "column": role["evidence"]["column"],
                    "source_sha256": source_map[role["evidence"]["path"]].sha256,
                    "reason": reason,
                }
            )
    included_roles = {
        fact["observation_id"] for fact in data["facts"] if fact["kind"] == "static_role"
    }
    for flow in value_flows:
        if not {
            flow["source_observation_id"],
            flow["sink_observation_id"],
        } <= included_roles or any(ref not in included_calls for ref in flow["call_ids"]):
            flow_gaps.append(
                {
                    "reason": "value_flow_input_omitted",
                    "source_observation_id": flow["source_observation_id"],
                    "sink_observation_id": flow["sink_observation_id"],
                }
            )
            continue
        candidate = {**data, "value_flows": [*data["value_flows"], flow]}
        if len(encode(candidate).encode()) > byte_limit:
            flow_gaps.append(
                {
                    "reason": "value_flow_input_byte_budget",
                    "source_observation_id": flow["source_observation_id"],
                    "sink_observation_id": flow["sink_observation_id"],
                }
            )
        else:
            data = candidate
    counts = Counter(o["reason"] for o in omissions)
    gaps = [
        {"reason": reason, "detail": f"{count} facts/calls; see coverage.json"}
        for reason, count in sorted(counts.items())
    ]
    if total_pairs > considered_pairs:
        gaps.append(
            {
                "reason": "recon_relationship_pair_budget",
                "detail": f"{total_pairs - considered_pairs} entry/role pairs not examined.",
            }
        )
    if flow_gaps:
        flow_counts = Counter(gap["reason"] for gap in flow_gaps)
        gaps.extend(
            {"reason": reason, "detail": f"{count} Go role pairs; value path not established."}
            for reason, count in sorted(flow_counts.items())
        )
    if graph["coverage"]["status"] != "parsed":
        gaps.append(
            {"reason": "partial_graph", "detail": "See graph.json coverage and limitations."}
        )
    if graph["language"] == "solidity":
        gaps.append(
            {
                "reason": "deployment_unverified",
                "detail": "Deployment, proxy binding and caller reachability are unverified.",
            }
        )
    if not static:
        gaps.append({"reason": "static_not_supplied", "detail": "No static input-role evidence."})
    elif static["gaps"]:
        gaps.append(
            {
                "reason": "static_analysis_limited",
                "detail": f"{len(static['gaps'])} gaps in static.json; {static['identity_sha256']}",
            }
        )
    return {
        "data": data,
        "payload_bytes": len(encode(data).encode()),
        "byte_limit": byte_limit,
        "omissions": omissions,
        "gaps": gaps,
    }


def proposal_plan(reply, context, graph, sources):
    schema = json.loads((RESOURCES / "schemas/recon-proposal.json").read_text())
    from .pipeline import validate_shape

    validate_shape("recon proposal", reply, schema)
    data = context["data"]
    functions = {f["id"]: f for f in data["functions"]}
    facts = {f["id"]: f for f in data["facts"]}
    ids = [h["id"] for h in reply["hypotheses"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate proposed hypothesis IDs")
    for item in reply["hypotheses"]:
        entry = functions.get(item["entry"])
        if entry is None:
            raise ValueError("proposed entry is not a supplied graph function ID")
        selected = item["selection"]
        if not set(selected["fact_ids"]) <= facts.keys():
            raise ValueError("proposal references unavailable recon facts")
        if not any(
            facts[ref]["function"] == entry["id"]
            and (
                facts[ref]["kind"] in {"registration", "entry_visibility"}
                or facts[ref].get("role") == "source"
            )
            for ref in selected["fact_ids"]
        ):
            raise ValueError("proposed entry needs its registration, visibility or source fact")
        checked_evidence(selected["entry_evidence"], data)
        for annotation in item["annotations"]:
            if annotation["function"] not in functions:
                raise ValueError("annotation function was not supplied to recon")
            if "column" not in annotation["evidence"]:
                raise ValueError("proposed annotations require a byte column")
            checked_evidence(annotation["evidence"], data)
    origin = {
        "graph_sha256": graph["identity_sha256"],
        "source_index_sha256": digest([s.metadata() for s in sources]),
        "static_sha256": data["static_sha256"],
        "context_sha256": digest(context),
        "input_bytes": context["byte_limit"],
        "gaps": [
            *context["gaps"],
            *[{"reason": "recon_unresolved", "detail": claim} for claim in reply["unresolved"]],
        ],
    }
    selected_entries = {h["entry"] for h in reply["hypotheses"]}
    remaining = {
        f["function"]
        for f in data["facts"]
        if f["kind"] in {"registration", "entry_visibility"} or f.get("role") == "source"
    } - selected_entries
    if remaining:
        origin["gaps"].append(
            {
                "reason": "unselected_recon_entries",
                "detail": f"{len(remaining)} entries; {digest(sorted(remaining))}",
            }
        )
    if not reply["hypotheses"]:
        return None
    plan = {
        "schema_version": 1,
        "proposal_origin": origin,
        "hypotheses": sorted(
            reply["hypotheses"], key=lambda h: (h["selection"]["priority"], h["id"])
        ),
    }
    make_recon(graph, sources, plan)
    return plan


def propose_recon(
    target, graph_file, static_file, output, agent, *, input_bytes=16000, max_calls=1, resume=False
):
    target, output = target.resolve(), output.resolve()
    if output.is_relative_to(target):
        raise ValueError("recon output must be outside the target")
    if not 1 <= max_calls <= 16:
        raise ValueError("recon max calls must be between 1 and 16")
    sources, skipped = index_target(target)
    graph = current_graph(target, graph_file, sources)
    static = read_static(static_file, graph, sources) if static_file else None
    context = recon_context(graph, sources, static, input_bytes)
    prompt_text = (RESOURCES / "prompts/recon.md").read_text()
    schema = json.loads((RESOURCES / "schemas/recon-proposal.json").read_text())
    packet = {k: v for k, v in context.items() if k != "omissions"}
    packet["omissions_ref"] = "coverage.json"
    prompt = prompt_text + "\nUNTRUSTED_INPUT_JSON:\n" + encode(packet)
    identity = {
        "graph_sha256": graph["identity_sha256"],
        "static_sha256": static["identity_sha256"] if static else None,
        "context_sha256": digest(context),
        "provider": agent.identity,
        "index_skipped_sha256": digest(skipped),
        "prompt_sha256": digest(prompt),
        "schema_sha256": digest(schema),
        "tools_sha256": digest(
            {
                name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                for name in (
                    "recon_proposal.py",
                    "pipeline.py",
                    "graph.py",
                    "agents.py",
                    "recon.py",
                    "triage.py",
                    "static_analysis.py",
                    "extractors/golang.py",
                    "go_value_flow.py",
                    "schemas/research-plan.json",
                )
            }
        ),
    }
    manifest = output / "manifest.json"
    with run_lock(output):
        if resume:
            state = json.loads(manifest.read_text())
            if not isinstance(state, dict) or state.get("identity") != identity:
                raise ValueError("recon inputs changed; use a new output directory")
            if type(state.get("call_attempts")) is not int or not 0 <= state["call_attempts"] <= 16:
                raise ValueError("invalid recon call counter")
            for name, expected in (("context", context), ("graph", graph), ("static", static)):
                if (
                    expected is not None
                    and json.loads((output / f"{name}.json").read_text()) != expected
                ):
                    raise ValueError("saved recon input changed: " + name)
        else:
            if any(p.name != ".lock" for p in output.iterdir()):
                raise ValueError("recon output is nonempty; use --resume or a new directory")
            state = {"identity": identity, "call_attempts": 0}
        state["status"] = "running"
        save_json(manifest, state)
        save_json(output / "context.json", context)
        save_json(
            output / "coverage.json",
            {"omissions": context["omissions"], "skipped": skipped, "gaps": context["gaps"]},
        )
        save_json(output / "graph.json", graph)
        if static:
            save_json(output / "static.json", static)
        checkpoint = output / "calls/r0001.recon/reply.json"
        hit = checkpoint.exists()
        try:
            if hit:
                record = json.loads(checkpoint.read_text())
                if (
                    not isinstance(record, dict)
                    or {"input_sha256", "reply_sha256", "data", "attempt", "raw_sha256", "usage"}
                    != record.keys()
                ):
                    raise ValueError("invalid cached recon reply")
                if record["input_sha256"] != digest(prompt) or record["reply_sha256"] != digest(
                    record["data"]
                ):
                    raise ValueError("cached recon reply checksum mismatch")
                reply = record["data"]
                if type(record["attempt"]) is not int or not 1 <= record["attempt"] <= 16:
                    raise ValueError("invalid cached recon attempt")
                raw_path = checkpoint.parent / f"attempt-{record['attempt']:04d}/raw-response.json"
                if hashlib.sha256(raw_path.read_bytes()).hexdigest() != record["raw_sha256"]:
                    raise ValueError("cached recon raw response changed")
                if json.loads(raw_path.read_text()) != reply:
                    raise ValueError("cached recon reply differs from raw response")
            else:
                if state["call_attempts"] >= max_calls:
                    raise ValueError("recon call budget exhausted; resume with higher --max-calls")
                state["call_attempts"] += 1
                save_json(manifest, state)
                attempt = checkpoint.parent / f"attempt-{state['call_attempts']:04d}"
                save_text(attempt / "prompt.txt", prompt)
                started = time.monotonic()
                try:
                    response = agent.call("recon", "r0001", prompt, schema, attempt)
                    if not (attempt / "raw-response.json").exists():
                        save_json(attempt / "raw-response.json", response.data)
                    proposal_plan(response.data, context, graph, sources)
                except (Exception, KeyboardInterrupt) as error:
                    save_json(
                        attempt / "failure.json",
                        {
                            "type": type(error).__name__,
                            "elapsed_seconds": time.monotonic() - started,
                        },
                    )
                    raise
                reply = response.data
                save_json(
                    checkpoint,
                    {
                        "input_sha256": digest(prompt),
                        "reply_sha256": digest(reply),
                        "data": reply,
                        "usage": response.usage,
                        "attempt": state["call_attempts"],
                        "raw_sha256": hashlib.sha256(
                            (attempt / "raw-response.json").read_bytes()
                        ).hexdigest(),
                    },
                )
            plan = proposal_plan(reply, context, graph, sources)
            expected_recon = make_recon(graph, sources, plan) if plan else None
            result_hash = digest([plan, expected_recon])
            if state.get("result_sha256") and state["result_sha256"] != result_hash:
                raise ValueError("saved recon result identity changed")
            current, current_skipped = index_target(target)
            if (
                current != sources
                or current_skipped != skipped
                or current_graph(target, graph_file, current) != graph
            ):
                raise ValueError("recon source changed during proposal")
            if static_file and read_static(static_file, graph, current) != static:
                raise ValueError("recon static input changed during proposal")
            if plan is not None:
                if (
                    resume
                    and state.get("result_sha256")
                    and (
                        json.loads((output / "research-plan.json").read_text()) != plan
                        or json.loads((output / "recon.json").read_text()) != expected_recon
                    )
                ):
                    raise ValueError("saved recon plan or result changed")
                save_json(output / "research-plan.json", plan)
                save_json(output / "recon.json", expected_recon)
            state.update(
                status="complete" if plan else "no_hypotheses",
                cache_hit=hit,
                proposed_hypotheses=len(reply["hypotheses"]),
                result_sha256=result_hash,
            )
            save_json(manifest, state)
        except (Exception, KeyboardInterrupt) as error:
            state.update(
                status="failed", failure={"type": type(error).__name__, "detail": str(error)[:8000]}
            )
            save_json(manifest, state)
            raise
    return state
