import json
from collections import Counter


def checked_evidence(evidence, source_slice, *, location="/evidence"):
    from .pipeline import CitationError, citation_details, source_lines, validate_evidence

    fragments = source_slice.get("fragments", [source_slice])
    fragment = validate_evidence(evidence, fragments, location=location)
    lines = source_lines(fragment["text"])
    offset = evidence["line"] - fragment["first_line"]
    column = evidence["column"] - 1
    line = lines[offset].rstrip("\r\n").encode()
    if not 0 <= column < len(line) or not "".join(lines[offset:]).encode()[column:].startswith(
        evidence["quote"].encode()
    ):
        raise CitationError(
            "triage_column_mismatch",
            "triage quote does not begin at the cited UTF-8 byte column",
            citation_details(evidence, fragments, location + "/column"),
        )
    return {**evidence, "source_sha256": fragment["source_sha256"]}


def apply_triage(candidates, data, source_slice, gaps=None):
    from .pipeline import RESOURCES, CitationError, raise_citation_errors, validate_shape

    schema = json.loads((RESOURCES / "schemas" / "triage.json").read_text())
    validate_shape("triage", data, schema)
    decisions = [decision for group in data["groups"] for decision in group["decisions"]]
    expected = {candidate["id"] for candidate in candidates}
    actual = [decision["candidate_id"] for decision in decisions]
    if set(actual) != expected or len(actual) != len(expected):
        raise ValueError("triage must return exactly one decision for each known candidate")
    by_id, citation_errors = {}, []

    def checked_or_original(evidence, location):
        try:
            return checked_evidence(evidence, source_slice, location=location)
        except CitationError as error:
            citation_errors.append(error)
            return evidence

    for group_number, group in enumerate(data["groups"]):
        group_path = f"/groups/{group_number}"
        cause = group["root_cause"]
        if cause is None:
            if len(group["decisions"]) != 1:
                raise ValueError("unresolved root cause must remain a singleton")
        else:
            cause = {
                **cause,
                "evidence": checked_or_original(
                    cause["evidence"], group_path + "/root_cause/evidence"
                ),
                "fix": {
                    **cause["fix"],
                    "evidence": checked_or_original(
                        cause["fix"]["evidence"],
                        group_path + "/root_cause/fix/evidence",
                    ),
                },
            }
        for decision_number, decision in enumerate(group["decisions"]):
            decision_path = f"{group_path}/decisions/{decision_number}"
            if decision["verdict"] == "rejected" and not decision["counterevidence"]:
                raise ValueError("rejected candidate requires source-backed counterevidence")
            if decision["verdict"] == "uncertain" and not decision["unresolved"]:
                raise ValueError("uncertain candidate requires an unresolved claim")
            checked = {}
            for kind in ("counterevidence", "unresolved"):
                checked[kind] = [
                    {
                        **item,
                        "evidence": checked_or_original(
                            item["evidence"],
                            f"{decision_path}/{kind}/{item_number}/evidence",
                        )
                        if item["evidence"] is not None
                        else None,
                    }
                    for item_number, item in enumerate(decision[kind])
                ]
            by_id[decision["candidate_id"]] = {
                "verdict": decision["verdict"],
                "triage_rationale": decision["rationale"],
                "root_cause": cause,
                **checked,
                "input_gaps": gaps if gaps is not None else input_gaps(source_slice),
            }
    raise_citation_errors(citation_errors)
    return [{**candidate, **by_id[candidate["id"]]} for candidate in candidates]


def input_gaps(source_slice, artifacts=None):
    artifacts = artifacts or {}
    hypothesis = source_slice.get("hypothesis")
    full = (
        next(h for h in artifacts["recon"]["hypotheses"] if h["id"] == hypothesis["id"])
        if hypothesis and "recon" in artifacts
        else None
    )
    query_owners = set(source_slice.get("query_function_ids", [])) | set(
        source_slice.get("context_function_ids", [])
    )
    graph = artifacts.get("graph", {})
    calls = source_slice.get("calls", []) + [
        call for call in graph.get("calls", []) if call["caller"] in query_owners
    ]
    owners = query_owners.copy()
    if full:
        owners.update(full["function_ids"])
        owners.update(a["function"] for a in full["annotations"])
        owners.update(r["caller"] for r in full["registrations"])
    gaps = {
        "coverage_ref": "coverage.json",
        "unresolved_call_ids": list(
            dict.fromkeys(
                (full["unknown_call_ids"] if full else [])
                + [c["id"] for c in calls if c["status"] in {"unresolved", "ambiguous"}]
            )
        ),
        "external_call_ids": list(
            dict.fromkeys(
                (full["external_call_ids"] if full else [])
                + [c["id"] for c in calls if c["status"] == "external"]
            )
        ),
        "unlinked_annotation_ids": full["unlinked_annotation_ids"] if full else [],
        "omitted_counts": source_slice.get("omitted_counts", {}),
        "static_gap_ids": [],
        "modifier_gap_function_ids": [],
    }
    if full and full.get("recon_gaps"):
        gaps["recon_ref"] = "recon.json"
        gaps["recon_gap_ids"] = [g["id"] for g in full["recon_gaps"]]
        if "recon-context" in artifacts:
            gaps["recon_context_ref"] = "recon-context.json"
    if "graph" in artifacts and "static" in artifacts:
        from .static_analysis import selected_records

        records = selected_records(
            artifacts["static"],
            {"function_ids": sorted(owners), "annotations": [], "registrations": []},
            graph,
        )
        gaps["static_gap_ids"] = [g["id"] for g in records["gaps"]]
    else:
        gaps["static_gap_ids"] = [
            g["id"] for g in source_slice.get("static_analysis", {}).get("gaps", [])
        ]
    if "graph" in artifacts:
        gaps["modifier_gap_function_ids"] = [
            f["id"]
            for f in graph["functions"]
            if f["id"] in owners and f.get("metadata", {}).get("modifier_flow", {}).get("gaps")
        ]
    else:
        gaps["modifier_gap_function_ids"] = [
            f["function_id"] for f in source_slice.get("modifier_flows", []) if f["flow"]["gaps"]
        ]
    gaps["modifier_gap_function_ids"] = list(
        dict.fromkeys(
            gaps["modifier_gap_function_ids"]
            + [
                f["function_id"]
                for f in source_slice.get("modifier_flows", [])
                if f["flow"]["gaps"]
            ]
        )
    )
    return gaps


def cluster_findings(findings):
    from .pipeline import digest, encode

    groups = {}
    for finding in findings:
        cause = finding["root_cause"]
        # shortcut: exact declared controls/anchors only; broaden after measured missed merges.
        key = (
            [
                cause["invariant"],
                cause["evidence"],
                cause["fix"]["strategy"],
                cause["fix"]["evidence"],
            ]
            if cause
            else ["unresolved", finding["id"]]
        )
        groups.setdefault(encode(key), (key, []))[1].append(finding)
    clusters = []
    for key, members in groups.values():
        members.sort(key=lambda f: f["id"])
        cluster_id = "rc-" + digest(key)[:16]
        counts = dict(Counter(f["verdict"] for f in members))
        for finding in members:
            finding["cluster_id"] = cluster_id
        clusters.append(
            {
                "id": cluster_id,
                "root_cause": members[0]["root_cause"],
                "grouping_basis": "shared_cause_and_fix"
                if members[0]["root_cause"]
                else "unresolved_singleton",
                "candidate_ids": [f["id"] for f in members],
                "verdict_counts": counts,
                "status": next(iter(counts)) if len(counts) == 1 else "mixed",
                "counterevidence_candidate_ids": [f["id"] for f in members if f["counterevidence"]],
                "unresolved_candidate_ids": [f["id"] for f in members if f["unresolved"]],
            }
        )
    return sorted(clusters, key=lambda c: c["id"])
