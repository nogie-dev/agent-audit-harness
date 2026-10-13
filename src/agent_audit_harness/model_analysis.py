"""Source-backed call models and one bounded second static pass per slice."""

import hashlib
import json
import re
from collections import defaultdict

from .pipeline import RESOURCES, digest, encode, save_json, source_lines, validate_shape
from .static_analysis import (
    attach_records,
    build_static,
    read_static,
    selected_records,
    validate_rules,
)
from .triage import checked_evidence

CALLEE = re.compile(rb"([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)[ \t\r\n]*\(")


def model_gap(proposal_id, reason, *, detail="", call_id=None, scope=None):
    data = {
        "proposal_id": proposal_id,
        "reason": reason,
        "detail": detail,
        "call_id": call_id,
        "scope_sha256": scope,
    }
    return {"id": "mg-" + digest(data)[:24], **data}


def compile_models(proposals, graph, sources, evidence, before):
    schema = json.loads((RESOURCES / "schemas/analysis.json").read_text())
    validate_shape("model proposals", {"candidates": [], "model_proposals": proposals}, schema)
    if len({p["id"] for p in proposals}) != len(proposals):
        raise ValueError("duplicate model proposal IDs")
    source_map = {s.path: s for s in sources}
    line_map = {
        path: [line.encode() for line in source_lines(s.text)] for path, s in source_map.items()
    }
    functions = {f["id"]: f for f in graph["functions"]}
    rules = list(before["rule_spec"]["rules"])
    models, gaps = [], []
    for proposal_number, proposal in enumerate(proposals):
        scope = digest([graph["identity_sha256"], proposal])
        endpoints, patterns, unsupported_counts = {}, {}, {}
        local = []
        for role in ("source", "sink"):
            endpoint = proposal[role]
            proof = checked_evidence(
                endpoint["evidence"],
                evidence,
                location=f"/model_proposals/{proposal_number}/{role}/evidence",
            )
            endpoints[role] = {**endpoint, "evidence": proof}
            function = functions.get(endpoint["function_id"])
            unsupported_counts[role] = 0
            if function is None:
                local.append(model_gap(proposal["id"], "model_definition_unavailable", detail=role))
                patterns[role] = []
                continue
            if (
                proof["path"] != function["path"]
                or not function["line"]
                <= proof["line"]
                <= proof["line"] + len(source_lines(proof["quote"])) - 1
                <= function["end_line"]
            ):
                raise ValueError("model evidence is outside the cited function")
            names = set()
            for call in graph["calls"]:
                if call["status"] != "resolved" or call["callee"] != function["id"]:
                    continue
                lines = line_map[call["path"]]
                content = b"".join(
                    [
                        lines[call["line"] - 1][call["column"] - 1 : call["column"] - 1 + 4096],
                        *[line[:4096] for line in lines[call["line"] : call["line"] + 3]],
                    ]
                )[:4096]
                match = CALLEE.match(content)
                if match is None or len(match[1]) + 5 > 4096:
                    unsupported_counts[role] += 1
                else:
                    names.add(match[1].decode() + "(...)")
            if unsupported_counts[role]:
                local.append(
                    model_gap(
                        proposal["id"],
                        "model_call_spelling_unsupported",
                        detail=f"{role}: {unsupported_counts[role]} unsupported calls; graph.json",
                    )
                )
            patterns[role] = sorted(names)[:8]
            if len(names) > 8:
                local.append(
                    model_gap(proposal["id"], "model_spelling_budget_exhausted", detail=role)
                )
            if not patterns[role]:
                local.append(model_gap(proposal["id"], "no_supported_resolved_calls", detail=role))
        rule_id = "target-" + proposal["id"]
        accepted = all(patterns.values())
        if accepted and (len(rules) >= 16 or any(r["id"] == rule_id for r in rules)):
            accepted = False
            local.append(model_gap(proposal["id"], "model_rule_budget_or_id_collision"))
        if accepted:
            rules.append(
                {
                    "id": rule_id,
                    "language": graph["language"],
                    "cwe": proposal["cwe"],
                    "source_patterns": patterns["source"],
                    "sink_patterns": patterns["sink"],
                    "sanitizer_patterns": [],
                    "call_models": {
                        role: endpoints[role]["function_id"] for role in ("source", "sink")
                    },
                    "assumptions": [
                        *proposal["assumptions"],
                        "Source means function return; sink means the whole call. "
                        "Argument roles are unverified.",
                        "Wrapper semantics, runtime binding and exposure are hypotheses. "
                        "Interprocedural flow is unproven.",
                    ],
                }
            )
            local.append(model_gap(proposal["id"], "declared_model_semantics_unverified"))
        local = [
            model_gap(
                proposal["id"], g["reason"], detail=g["detail"], call_id=g["call_id"], scope=scope
            )
            for g in local
        ]
        models.append(
            {
                **proposal,
                **endpoints,
                "rule_id": rule_id if accepted else None,
                "status": "declared" if accepted else "unavailable",
                "patterns": patterns,
                "unsupported_call_counts": unsupported_counts,
                "gap_ids": [g["id"] for g in local],
            }
        )
        gaps.extend(local)
    spec = {"schema_version": 1, "rules": rules}
    validate_rules(spec)
    return {"models": models, "gaps": gaps, "rule_spec": spec}


def run_models(target, output, source_slice, proposals, graph, sources, before, identity):
    plan = compile_models(proposals, graph, sources, source_slice, before)
    directory = output / "models" / source_slice["id"]
    input_hash = digest({"run_identity": identity, "evidence": source_slice, "plan": plan})
    checkpoint = directory / "result.json"
    after = None
    if checkpoint.exists():
        record = json.loads(checkpoint.read_text())
        data = record["data"]
        if (
            record["input_sha256"] != input_hash
            or record["reply_sha256"] != digest(data)
            or data["plan_sha256"] != digest(plan)
            or data["before_sha256"] != before["identity_sha256"]
        ):
            raise ValueError("cached model analysis checksum mismatch")
        if json.loads((directory / "plan.json").read_text()) != plan:
            raise ValueError("cached model plan differs from source-backed proposals")
        if data["after_ref"] is not None:
            path = output / data["after_ref"]
            if not path.resolve().is_relative_to(directory.resolve()) or not re.fullmatch(
                r"attempt-[0-9]{4}/analysis/static.json", str(path.relative_to(directory))
            ):
                raise ValueError("cached model analysis path is outside its stage")
            after = read_static(path, graph, sources)
            if (
                hashlib.sha256((path.parent / "analyzer-output.json").read_bytes()).hexdigest()
                != data["after_raw_sha256"]
                or json.loads((path.parent.parent / "rules.json").read_text()) != plan["rule_spec"]
            ):
                raise ValueError("cached model raw evidence or rules changed")
            if (
                after["identity_sha256"] != data["after_sha256"]
                or after["rule_spec"] != plan["rule_spec"]
            ):
                raise ValueError("cached model analysis differs from the declared models")
            if any(
                after["engine"][key] != before["engine"][key]
                for key in (
                    "name",
                    "version",
                    "core_sha256",
                    "runtime_sha256",
                    "adapter_sha256",
                    "normalizer_sha256",
                    "requirements_sha256",
                )
            ):
                raise ValueError("cached second analysis engine differs from the first")
        elif data["after_sha256"] is not None or any(
            m["status"] == "declared" for m in plan["models"]
        ):
            raise ValueError("cached model analysis omitted its second pass")
        return {**data, "plan": plan}, after, True
    save_json(directory / "plan.json", plan)
    if any(m["status"] == "declared" for m in plan["models"]):
        numbers = [
            int(p.name.removeprefix("attempt-"))
            for p in directory.glob("attempt-*")
            if re.fullmatch(r"attempt-[0-9]{4}", p.name)
        ]
        attempt = directory / f"attempt-{max(numbers, default=0) + 1:04d}"
        save_json(attempt / "rules.json", plan["rule_spec"])
        try:
            after = build_static(
                target,
                output / "graph.json",
                attempt / "rules.json",
                attempt / "analysis",
                expected_engine=before["engine"],
            )
        except (Exception, KeyboardInterrupt) as error:
            save_json(
                attempt / "failure.json",
                {
                    "type": type(error).__name__,
                    "detail": str(error)[:8000],
                    "before_sha256": before["identity_sha256"],
                },
            )
            raise
    data = {
        "plan_sha256": digest(plan),
        "before_sha256": before["identity_sha256"],
        "after_sha256": after["identity_sha256"] if after else None,
        "after_ref": str((attempt / "analysis/static.json").relative_to(output)) if after else None,
        "after_raw_sha256": hashlib.sha256(
            (attempt / "analysis/analyzer-output.json").read_bytes()
        ).hexdigest()
        if after
        else None,
    }
    save_json(checkpoint, {"input_sha256": input_hash, "reply_sha256": digest(data), "data": data})
    return {**data, "plan": plan}, after, False


def model_context(result, after, source_slice, hypothesis, graph, byte_limit):
    plan = result["plan"]
    owners = set(hypothesis["function_ids"]) | set(source_slice.get("query_function_ids", []))
    selected = {**hypothesis, "function_ids": sorted(owners)}
    records = (
        selected_records(after, selected, graph)
        if after
        else {"observations": [], "taint_results": [], "gaps": []}
    )
    context = {
        "hypothesis": {"id": hypothesis["id"]},
        "models": plan["models"],
        "model_gaps": plan["gaps"],
        "omitted_counts": {"static_" + k: len(v) for k, v in records.items()},
        "static_analysis": {
            "artifact_sha256": result["after_sha256"],
            "engine": {key: after["engine"][key] for key in ("name", "version", "scope")}
            if after
            else None,
            "rules": [],
            "observations": [],
            "taint_results": [],
            "gaps": [],
        },
    }
    packet = {
        "before_sha256": result["before_sha256"],
        "after_sha256": result["after_sha256"],
        "after_ref": result["after_ref"],
        "byte_limit": byte_limit,
        "data": None,
        "status": "omitted",
        "payload_bytes": 0,
        "gaps": list(plan["gaps"]),
        "omissions": [],
    }
    scope = digest([source_slice["id"], result["before_sha256"], result["after_sha256"]])
    if len(encode(context).encode()) > byte_limit:
        packet["gaps"].append(model_gap(None, "model_context_byte_budget_exhausted", scope=scope))
        return packet
    omitted = []
    if after:
        context = attach_records(
            context, records, after, byte_limit, omitted, fragments=source_slice["fragments"]
        )
    grouped = defaultdict(list)
    for item in omitted:
        grouped[item["kind"], item["reason"]].append(item["id"])
    packet["omissions"] = omitted
    packet["gaps"].extend(
        model_gap(
            None,
            "model_context_" + reason,
            detail=f"{kind}: {len(ids)} omitted records; {digest(ids)}",
            scope=scope,
        )
        for (kind, reason), ids in grouped.items()
    )
    packet.update(
        status="provided" if after else "unavailable",
        data=context,
        payload_bytes=len(encode(context).encode()),
    )
    return packet
