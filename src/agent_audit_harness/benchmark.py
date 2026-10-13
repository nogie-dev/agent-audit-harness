"""Compare bounded review artifacts against researcher-labeled source locations."""

import hashlib
import json
import math
import statistics
import time
from collections import Counter
from pathlib import Path

from .agents import ReplayAgent, strip_optional_nulls
from .pipeline import (
    CITATION_CODES,
    MAX_AGENT_CALLS,
    RESOURCES,
    checked_citation_repair,
    citation_repair_outcome,
    citation_repair_prompt,
    digest,
    index_target,
    run_lock,
    run_pipeline,
    save_json,
    source_lines,
    validate_shape,
)
from .validation import read_regular


def checked_truth(target, truth_file):
    raw = read_regular(truth_file.parent, truth_file.name)
    truth = json.loads(raw)
    validate_shape(
        "benchmark truth",
        truth,
        json.loads((RESOURCES / "schemas/benchmark-truth.json").read_text()),
    )
    sources, skipped = index_target(target)
    by_path = {source.path: source for source in sources}
    ids, anchors = set(), set()
    cases = []
    for case in truth["cases"]:
        if case["id"] in ids:
            raise ValueError("benchmark labels duplicate or lack source-backed anchors")
        ids.add(case["id"])
        checked = []
        for location in [case, *case.get("accepted_locations", [])]:
            anchor = (location["path"], location["line"], location["cwe"])
            source = by_path.get(location["path"])
            lines = source_lines(source.text) if source else []
            if (
                anchor in anchors
                or not 1 <= location["line"] <= len(lines)
                or location["quote"] not in lines[location["line"] - 1]
            ):
                raise ValueError("benchmark labels duplicate or lack source-backed anchors")
            anchors.add(anchor)
            checked.append({**location, "source_sha256": source.sha256})
        cases.append({**case, "source_sha256": checked[0]["source_sha256"], "locations": checked})
    if {case["expected"] for case in cases} != {"positive", "negative"}:
        raise ValueError("benchmark truth requires positive and negative controls")
    return (
        cases,
        [source.metadata() for source in sources],
        skipped,
        hashlib.sha256(raw).hexdigest(),
    )


def root_cause_matches_case(finding, case):
    cause = finding.get("root_cause") or {}
    evidence = cause.get("evidence") or {}
    return any(
        (evidence.get("path"), evidence.get("line"), finding["cwe"])
        == (location["path"], location["line"], location["cwe"])
        and evidence.get("source_sha256") == location["source_sha256"]
        and location["quote"] in evidence.get("quote", "")
        for location in case.get("locations", [case])
    )


def location_diagnostics(findings, locations):
    diagnostics = {"representative_location": [], "root_cause_location": []}
    for finding in findings:
        cause = (finding.get("root_cause") or {}).get("evidence") or {}
        for kind, evidence in (
            ("representative_location", finding),
            ("root_cause_location", cause),
        ):
            expected = sorted(
                {
                    location["cwe"]
                    for location in locations
                    if (evidence.get("path"), evidence.get("line"))
                    == (location["path"], location["line"])
                    and (
                        kind == "representative_location"
                        or (
                            evidence.get("source_sha256") == location["source_sha256"]
                            and location["quote"] in evidence.get("quote", "")
                        )
                    )
                }
            )
            if expected:
                diagnostics[kind].append(
                    {
                        "candidate_id": finding["id"],
                        "verdict": finding["verdict"],
                        "reported_cwe": finding["cwe"],
                        "expected_cwes": expected,
                    }
                )
    return diagnostics


def score_run(run_dir, cases, elapsed, *, provider="replay"):
    findings = json.loads(read_regular(run_dir, "findings.json", 8 * 1024 * 1024))
    slices = json.loads(read_regular(run_dir, "slices.json", 8 * 1024 * 1024))
    coverage = json.loads(read_regular(run_dir, "coverage.json", 8 * 1024 * 1024))
    metrics = json.loads(read_regular(run_dir, "metrics.json", 8 * 1024 * 1024))
    manifest = json.loads(read_regular(run_dir, "manifest.json", 8 * 1024 * 1024))
    if manifest["status"] != "complete" or manifest["identity"]["agent"]["provider"] != provider:
        raise ValueError("benchmark run is incomplete or has a different provider")
    index = {source["path"]: source["sha256"] for source in manifest["identity"]["source_index"]}
    if (
        metrics["unique_candidates"] != len(findings)
        or metrics["verdict_counts"] != dict(Counter(item["verdict"] for item in findings))
        or any(index.get(item["path"]) != item["source_sha256"] for item in findings)
        or json.loads(read_regular(run_dir, "validation-queue.json", 8 * 1024 * 1024))
        != [item for item in findings if item["verdict"] != "rejected"]
    ):
        raise ValueError("benchmark run findings differ from metrics, source or queue")
    labels = []
    matched = set()
    counts = {
        "positive_retained": 0,
        "positive_missed": 0,
        "negative_flagged": 0,
        "negative_clear": 0,
        "uncovered_labels": 0,
    }
    for case in cases:
        locations = case.get("locations", [case])
        anchors = {(item["path"], item["line"], item["cwe"]) for item in locations}
        located = [
            finding
            for finding in findings
            if (finding["path"], finding["line"], finding["cwe"]) in anchors
        ]
        cause_located = [finding for finding in findings if root_cause_matches_case(finding, case)]
        matched.update(finding["id"] for finding in located)
        retained = [finding for finding in located if finding["verdict"] != "rejected"]
        covered = any(
            fragment["path"] == location["path"]
            and fragment["first_line"] <= location["line"] <= fragment["last_line"]
            for source_slice in slices
            for fragment in source_slice.get("fragments", [source_slice])
            for location in locations
        )
        if not covered:
            counts["uncovered_labels"] += 1
        key = (
            "positive_retained"
            if case["expected"] == "positive" and retained
            else "positive_missed"
            if case["expected"] == "positive"
            else "negative_flagged"
            if retained
            else "negative_clear"
        )
        counts[key] += 1
        labels.append(
            {
                "id": case["id"],
                "expected": case["expected"],
                "covered": covered,
                "retained_candidate_ids": [item["id"] for item in retained],
                "root_cause_candidate_ids": [item["id"] for item in cause_located],
                "rejected_candidate_ids": [
                    item["id"] for item in located if item["verdict"] == "rejected"
                ],
                "diagnostics": location_diagnostics(findings, locations),
                "status": key,
            }
        )
    return {
        "source_index": manifest["identity"]["source_index"],
        "agent": manifest["identity"]["agent"],
        "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
        "metrics": metrics,
        "coverage": coverage,
        "labeled_cases": labels,
        "label_counts": counts,
        "unlabeled_candidate_count": sum(finding["id"] not in matched for finding in findings),
        "artifact_sha256": {
            name: hashlib.sha256(read_regular(run_dir, name, 8 * 1024 * 1024)).hexdigest()
            for name in ("manifest.json", "findings.json", "coverage.json", "metrics.json")
        },
    }


def comparison_delta(arms, duration_key):
    baseline, candidate = arms["baseline"], arms["candidate"]
    first, second = baseline.get(duration_key), candidate.get(duration_key)
    first_usage = (
        baseline.get("attempt_reported_token_usage", baseline["metrics"]["reported_token_usage"])
        or {}
    )
    second_usage = (
        candidate.get("attempt_reported_token_usage", candidate["metrics"]["reported_token_usage"])
        or {}
    )
    token_complete = all(
        arm.get("complete_input_output_tokens", False) for arm in (baseline, candidate)
    )
    return {
        "direction": "candidate_minus_baseline",
        "label_count_delta": {
            key: candidate["label_counts"][key] - value
            for key, value in baseline["label_counts"].items()
        },
        "call_attempt_delta": (
            candidate["metrics"]["call_attempts"] - baseline["metrics"]["call_attempts"]
        ),
        "duration_basis": duration_key,
        "duration_seconds_delta": round(second - first, 3)
        if first is not None and second is not None
        else None,
        "reported_token_delta": {
            key: second_usage[key] - first_usage[key] for key in ("input_tokens", "output_tokens")
        }
        if token_complete
        else None,
    }


def original_citation_repair(run_dir, directory, manifest, base_prompt, schema):
    repair = checked_citation_repair(
        json.loads(
            read_regular(
                run_dir,
                (directory / "citation-repair.json").relative_to(run_dir).as_posix(),
                8 * 1024 * 1024,
            )
        ),
        digest({"prompt": base_prompt, "schema": schema}),
    )
    failed = directory / f"attempt-{repair['failed_attempt']:04d}"
    rejected = json.loads(
        read_regular(run_dir, (failed / "raw-response.json").relative_to(run_dir).as_posix())
    )
    if manifest["identity"]["agent"]["provider"] == "codex":
        rejected = strip_optional_nulls(rejected, schema)
    failure = json.loads(
        read_regular(run_dir, (failed / "failure.json").relative_to(run_dir).as_posix())
    )
    if (
        not manifest["identity"].get("repair_citations")
        or repair["failed_attempt"] > manifest["call_attempts"]
        or (
            repair["repair_attempt"] is not None
            and repair["repair_attempt"] > manifest["call_attempts"]
        )
        or rejected != repair["rejected_reply"]
        or failure.get("citation_code") != repair["citation_code"]
        or (
            "citation_details" in repair
            and failure.get("citation_details") != repair["citation_details"]
        )
        or read_regular(
            run_dir, (failed / "prompt.txt").relative_to(run_dir).as_posix(), 8 * 1024 * 1024
        ).decode()
        != base_prompt
    ):
        raise ValueError("benchmark citation repair rejection changed")
    return repair


def original_reply(run_dir, path, manifest):
    reply = json.loads(read_regular(run_dir, path.relative_to(run_dir).as_posix()))
    elapsed = reply.get("elapsed_seconds")
    if (
        reply.get("reply_sha256") != digest(reply.get("data"))
        or type(elapsed) not in (int, float)
        or not math.isfinite(elapsed)
        or not 0 <= elapsed <= 3600
    ):
        raise ValueError("benchmark call record is invalid")
    attempts = sorted(path.parent.glob("attempt-*/raw-response.json"))
    number = reply.get("attempt")
    if number is None:
        if len(attempts) != 1:
            raise ValueError("benchmark original agent response is missing or ambiguous")
        attempt = attempts[0].parent
    elif type(number) is int and number > 0:
        attempt = path.parent / f"attempt-{number:04d}"
    else:
        raise ValueError("benchmark reply attempt is invalid")
    stage = path.parent.name.rsplit(".", 1)[-1]
    schema = json.loads((RESOURCES / "schemas" / f"{stage}.json").read_text())
    raw = json.loads(
        read_regular(run_dir, (attempt / "raw-response.json").relative_to(run_dir).as_posix())
    )
    if manifest["identity"]["agent"]["provider"] == "codex":
        raw = strip_optional_nulls(raw, schema)
    if raw != reply["data"] or (attempt / "failure.json").exists():
        raise ValueError("benchmark reply differs from original agent response")
    base_prompt = read_regular(
        run_dir, (path.parent / "prompt.txt").relative_to(run_dir).as_posix(), 8 * 1024 * 1024
    ).decode()
    expected_prompt = base_prompt
    input_sha256 = digest({"prompt": base_prompt, "schema": schema})
    repair_path = path.parent / "citation-repair.json"
    if repair_path.exists():
        repair = original_citation_repair(run_dir, path.parent, manifest, base_prompt, schema)
        outcome = citation_repair_outcome(repair["rejected_reply"], reply["data"])
        if number != repair["repair_attempt"] or (
            "citation_repair_outcome" in reply and reply["citation_repair_outcome"] != outcome
        ):
            raise ValueError("benchmark citation repair outcome or attempt changed")
        expected_prompt = citation_repair_prompt(
            base_prompt,
            repair["citation_code"],
            repair["rejected_reply"],
            repair.get("citation_details"),
        )
    if (
        read_regular(
            run_dir, (attempt / "prompt.txt").relative_to(run_dir).as_posix(), 8 * 1024 * 1024
        ).decode()
        != expected_prompt
        or reply.get("input_sha256") != input_sha256
        or (
            "effective_input_sha256" in reply
            and reply["effective_input_sha256"]
            != digest({"prompt": expected_prompt, "schema": schema})
        )
    ):
        raise ValueError("benchmark original agent prompt evidence changed")
    return reply


def measured_calls(run_dir, metrics, manifest):
    paths = sorted((run_dir / "calls").glob("*/reply.json"))
    if (
        not paths
        or len(paths) > 128
        or metrics["cache_hits"] != 0
        or metrics["call_attempts"] != manifest["call_attempts"]
    ):
        raise ValueError("benchmark requires fresh complete call records")
    fields = ("input_tokens", "cached_input_tokens", "output_tokens")
    totals, reported = dict.fromkeys(fields, 0), dict.fromkeys(fields, 0)
    for path in paths:
        usage = original_reply(run_dir, path, manifest).get("usage")
        if usage is not None and not isinstance(usage, dict):
            raise ValueError("benchmark call usage is invalid")
        for field in fields:
            value = usage.get(field) if usage else None
            if type(value) is int and value >= 0:
                totals[field] += value
                reported[field] += 1
    expected = {field: totals[field] if reported[field] else None for field in fields}
    if metrics["reported_token_usage"] != (
        expected if any(value is not None for value in expected.values()) else None
    ):
        raise ValueError("benchmark token totals differ from original call records")
    attempts = attempt_report(run_dir, require_codex=False)
    if (
        attempts["unknown_calls"]
        or attempts["completed_calls"] != len(paths)
        or attempts["elapsed_coverage"]["recorded_attempts"] != manifest["call_attempts"]
    ):
        raise ValueError("benchmark requires complete attempt evidence")
    return {
        "recorded_call_seconds": attempts["recorded_call_seconds"],
        "failed_call_attempts": attempts["failed_calls"],
        "citation_repair_outcomes": attempts["citation_repair_outcomes"],
        "attempt_reported_token_usage": attempts["reported_token_usage"],
        "token_coverage": {
            field: {
                "reported_calls": attempts["token_coverage"][field]["reported_attempts"],
                "total_calls": manifest["call_attempts"],
            }
            for field in fields
        },
        "complete_input_output_tokens": all(
            attempts["token_coverage"][field]["reported_attempts"] == manifest["call_attempts"]
            for field in ("input_tokens", "output_tokens")
        ),
    }


def attempt_report(run_dir, *, require_codex=True):
    """Read successful, failed and unfinished attempts without executing them."""
    run_dir = run_dir.resolve()
    manifest_raw = read_regular(run_dir, "manifest.json", 8 * 1024 * 1024)
    manifest = json.loads(manifest_raw)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("identity"), dict):
        raise ValueError("attempt report manifest is invalid")
    agent = manifest["identity"].get("agent")
    if (
        manifest.get("status") not in {"complete", "failed", "running"}
        or not isinstance(agent, dict)
        or agent.get("provider") not in ({"codex"} if require_codex else {"codex", "replay"})
    ):
        raise ValueError("attempt report requires a finished Codex run")
    attempt_dirs = sorted((run_dir / "calls").glob("*/attempt-*"))
    count = manifest.get("call_attempts")
    if (
        type(count) is not int
        or not 0 <= count <= MAX_AGENT_CALLS
        or len(attempt_dirs) != count
        or {path.name for path in attempt_dirs} != {f"attempt-{i:04d}" for i in range(1, count + 1)}
    ):
        raise ValueError("attempt report call records do not match the manifest")
    fields = ("input_tokens", "cached_input_tokens", "output_tokens")
    totals = {field: 0 for field in fields}
    coverage = {field: 0 for field in fields}
    attempts = []
    for path in sorted(attempt_dirs, key=lambda item: int(item.name.removeprefix("attempt-"))):
        relative = path.relative_to(run_dir).as_posix()
        prompt = read_regular(run_dir, f"{relative}/prompt.txt", 8 * 1024 * 1024)
        prompt_sha256 = hashlib.sha256(prompt).hexdigest()
        has_events = (path / "events.jsonl").exists()
        events = (
            [
                json.loads(line)
                for line in read_regular(
                    run_dir, f"{relative}/events.jsonl", 8 * 1024 * 1024
                ).splitlines()
            ]
            if has_events or require_codex
            else []
        )
        if any(not isinstance(event, dict) for event in events):
            raise ValueError("attempt report event log is invalid")
        completed = [event for event in events if event.get("type") == "turn.completed"]
        if len(completed) > 1:
            raise ValueError("attempt report has multiple completed turns in one call")
        usage = completed[0].get("usage") if completed else None
        if usage is not None and not isinstance(usage, dict):
            raise ValueError("attempt report usage is invalid")
        failure_path = path / "failure.json"
        if failure_path.exists():
            failure = json.loads(read_regular(run_dir, f"{relative}/failure.json"))
            if not isinstance(failure, dict):
                raise ValueError("attempt report failure record is invalid")
            status, elapsed = "failed", failure.get("elapsed_seconds")
            failure_type = failure.get("type")
            citation_code = failure.get("citation_code")
            if not isinstance(failure_type, str) or not failure_type:
                raise ValueError("attempt report failure record is invalid")
            if citation_code is not None and (
                type(citation_code) is not str or citation_code not in CITATION_CODES
            ):
                raise ValueError("attempt report citation code is invalid")
            if (failure_type == "CitationError") != (citation_code is not None):
                raise ValueError("attempt report citation type and code differ")
            if has_events and failure.get("usage") is not None and failure["usage"] != usage:
                raise ValueError("attempt report failure usage differs from event evidence")
            if not has_events:
                usage = failure.get("usage")
        elif (path.parent / "reply.json").exists():
            reply = json.loads(
                read_regular(run_dir, f"{path.parent.relative_to(run_dir)}/reply.json")
            )
            if (
                not isinstance(reply, dict)
                or reply.get("reply_sha256") != digest(reply.get("data"))
                or (
                    has_events
                    and reply.get("usage") != usage
                    and reply.get("attempt") == int(path.name.removeprefix("attempt-"))
                )
            ):
                raise ValueError("attempt report reply differs from event evidence")
            success_number = reply.get("attempt")
            if success_number is None:
                unfinished = [
                    item
                    for item in path.parent.glob("attempt-*")
                    if not (item / "failure.json").exists()
                ]
                if len(unfinished) == 1:
                    success_number = int(unfinished[0].name.removeprefix("attempt-"))
            if success_number == int(path.name.removeprefix("attempt-")):
                if has_events and reply.get("usage") != usage:
                    raise ValueError("attempt report reply differs from event evidence")
                if not has_events:
                    usage = reply.get("usage")
                status, elapsed, failure_type, citation_code = (
                    "completed",
                    reply.get("elapsed_seconds"),
                    None,
                    None,
                )
                read_regular(run_dir, f"{relative}/raw-response.json")
            else:
                status, elapsed, failure_type, citation_code = "unknown", None, None, None
        else:
            status, elapsed, failure_type, citation_code = "unknown", None, None, None
        repair_outcome = None
        if (path.parent / "citation-repair.json").exists():
            stage = path.parent.name.rsplit(".", 1)[-1]
            schema = json.loads((RESOURCES / "schemas" / f"{stage}.json").read_text())
            base_prompt = read_regular(
                run_dir,
                (path.parent / "prompt.txt").relative_to(run_dir).as_posix(),
                8 * 1024 * 1024,
            ).decode()
            repair = original_citation_repair(run_dir, path.parent, manifest, base_prompt, schema)
            number = int(path.name.removeprefix("attempt-"))
            if number == repair["repair_attempt"]:
                if status == "completed":
                    checked = original_reply(run_dir, path.parent / "reply.json", manifest)
                    repair_outcome = citation_repair_outcome(
                        repair["rejected_reply"], checked["data"]
                    )
                else:
                    repair_outcome = "failed" if status == "failed" else "unknown"
                if prompt.decode() != citation_repair_prompt(
                    base_prompt,
                    repair["citation_code"],
                    repair["rejected_reply"],
                    repair.get("citation_details"),
                ):
                    raise ValueError("benchmark citation repair prompt changed")
            elif repair["repair_attempt"] is None and number == repair["failed_attempt"]:
                repair_outcome = "pending"
        if usage is not None and not isinstance(usage, dict):
            raise ValueError("attempt report usage is invalid")
        for field in fields:
            if usage is not None and field in usage:
                value = usage[field]
                if type(value) is not int or value < 0:
                    raise ValueError("attempt report usage is invalid")
                totals[field] += value
                coverage[field] += 1
        if elapsed is not None and (
            type(elapsed) not in (int, float)
            or not math.isfinite(elapsed)
            or not 0 <= elapsed <= 3600
        ):
            raise ValueError("attempt report elapsed time is invalid")
        attempts.append(
            {
                "number": int(path.name.removeprefix("attempt-")),
                "call": path.parent.name,
                "status": status,
                "failure_type": failure_type,
                "citation_code": citation_code,
                "citation_repair_outcome": repair_outcome,
                "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
                "prompt_sha256": prompt_sha256,
                "prompt_bytes": len(prompt),
                "usage": usage,
            }
        )
    report = {
        "measurement_kind": agent["provider"] + "_attempt_artifacts",
        "run": str(run_dir),
        "run_status": manifest["status"],
        "model": agent.get("model"),
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "call_attempts": count,
        "completed_calls": sum(item["status"] == "completed" for item in attempts),
        "failed_calls": sum(item["status"] == "failed" for item in attempts),
        "citation_failure_counts": dict(
            Counter(item["citation_code"] for item in attempts if item["citation_code"])
        ),
        "citation_repair_outcomes": dict(
            Counter(
                item["citation_repair_outcome"]
                for item in attempts
                if item["citation_repair_outcome"]
            )
        ),
        "unknown_calls": sum(item["status"] == "unknown" for item in attempts),
        "recorded_call_seconds": round(sum(item["elapsed_seconds"] or 0 for item in attempts), 3),
        "elapsed_coverage": {
            "recorded_attempts": sum(item["elapsed_seconds"] is not None for item in attempts),
            "total_attempts": count,
        },
        "reported_token_usage": {
            field: totals[field] if coverage[field] else None for field in fields
        },
        "token_coverage": {
            field: {"reported_attempts": coverage[field], "total_attempts": count}
            for field in fields
        },
        "attempts": attempts,
        "interpretation": (
            "Read-only local artifacts; recorded seconds exclude preparation, and token totals "
            "cover only attempts with provider usage. Missing values remain unknown."
        ),
    }
    return report


def summarize_attempts(run_dir, output):
    run_dir, output = run_dir.resolve(), output.resolve()
    if output.is_relative_to(run_dir) or run_dir.is_relative_to(output):
        raise ValueError("attempt report output must be outside the run")
    report = attempt_report(run_dir)
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("attempt report output is nonempty")
        save_json(output / "attempts.json", report)
    return report


def _compare_runs(target, truth_file, baseline_run, candidate_run, output):
    target, truth_file, baseline_run, candidate_run = (
        path.resolve() for path in (target, truth_file, baseline_run, candidate_run)
    )
    output = output.resolve() if output is not None else None
    if (
        truth_file.is_relative_to(target)
        or truth_file.is_relative_to(baseline_run)
        or truth_file.is_relative_to(candidate_run)
        or baseline_run == candidate_run
        or baseline_run.is_relative_to(target)
        or candidate_run.is_relative_to(target)
        or (
            output is not None
            and (
                output.is_relative_to(target)
                or output.is_relative_to(baseline_run)
                or output.is_relative_to(candidate_run)
                or output == truth_file
            )
        )
    ):
        raise ValueError("benchmark run input or output boundary is invalid")
    cases, source_index, skipped, truth_sha256 = checked_truth(target, truth_file)
    manifests = {
        name: json.loads(read_regular(directory, "manifest.json", 8 * 1024 * 1024))
        for name, directory in (("baseline", baseline_run), ("candidate", candidate_run))
    }
    fields = (
        "version",
        "target",
        "source_index",
        "skipped",
        "contracts_sha256",
        "slice_bytes",
        "max_slices",
        "max_queries",
        "query_bytes",
        "repair_citations",
        "query_tool_sha256",
    )
    base = manifests["baseline"]
    candidate = manifests["candidate"]
    base_identity, candidate_identity = base["identity"], candidate["identity"]
    current_contracts = {
        stage: {
            "prompt": (RESOURCES / "prompts" / f"{stage}.md").read_text(encoding="utf-8"),
            "schema": json.loads((RESOURCES / "schemas" / f"{stage}.json").read_text()),
        }
        for stage in ("analysis", "triage")
    }
    provider = base_identity["agent"]["provider"]
    if (
        provider not in {"replay", "codex"}
        or candidate_identity["agent"]["provider"] != provider
        or (provider == "codex" and base_identity["agent"] != candidate_identity["agent"])
        or any(base_identity.get(field) != candidate_identity.get(field) for field in fields)
        or base_identity["contracts_sha256"] != digest(current_contracts)
        or base_identity["target"] != str(target)
        or base_identity["source_index"] != source_index
        or base_identity["skipped"] != skipped
        or base["max_calls"] != candidate["max_calls"]
    ):
        raise ValueError("benchmark runs differ in target, source, provider, model or budget")
    arms = {}
    for name, directory in (("baseline", baseline_run), ("candidate", candidate_run)):
        arm = score_run(directory, cases, None, provider=provider)
        arm.update(measured_calls(directory, arm["metrics"], manifests[name]))
        arms[name] = arm
    report = {
        "schema_version": 1,
        "measurement_kind": "declared_codex_artifacts"
        if provider == "codex"
        else "offline_replay_artifacts",
        "truth_sha256": truth_sha256,
        "source_index_sha256": digest(source_index),
        "limits": {
            key: base_identity[key]
            for key in ("max_slices", "slice_bytes", "max_queries", "query_bytes")
        }
        | {
            "max_calls": base["max_calls"],
            "repair_citations": base_identity.get("repair_citations", False),
        },
        "run_directories": {"baseline": str(baseline_run), "candidate": str(candidate_run)},
        "cases": cases,
        "arms": arms,
        "comparison": comparison_delta(arms, "recorded_call_seconds"),
        "interpretation": (
            "Read-only comparison of local run artifacts; provider identity and researcher "
            "labels are declarations. Attempt costs include preserved failures; missing usage "
            "remains unknown, while run metrics retain successful-reply totals."
        ),
    }
    report["identity_sha256"] = digest(report)
    if output is not None:
        with run_lock(output):
            if any(path.name != ".lock" for path in output.iterdir()):
                raise ValueError("benchmark output is nonempty; use a new directory")
            save_json(output / "benchmark.json", report)
    return report


def compare_runs(target, truth_file, baseline_run, candidate_run, output):
    try:
        return _compare_runs(target, truth_file, baseline_run, candidate_run, output)
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("benchmark run artifact is malformed") from error


def distribution(values):
    return {
        "values": values,
        "min": min(values),
        "median": statistics.median(values),
        "max": max(values),
    }


def call_profile(run_dir):
    stages = {
        name: {"calls": 0, "prompt_bytes": 0, "recorded_call_seconds": 0.0}
        for name in ("analysis", "triage")
    }
    manifest = json.loads(read_regular(run_dir, "manifest.json", 8 * 1024 * 1024))
    for reply_path in sorted((run_dir / "calls").glob("*/reply.json")):
        original_reply(run_dir, reply_path, manifest)
    report = attempt_report(run_dir, require_codex=False)
    if (
        report["unknown_calls"]
        or report["elapsed_coverage"]["recorded_attempts"] != report["call_attempts"]
    ):
        raise ValueError("benchmark profile requires complete attempt evidence")
    for attempt in report["attempts"]:
        stage = attempt["call"].rsplit(".", 1)[-1]
        if stage not in stages:
            raise ValueError("benchmark call has an unknown stage")
        stages[stage]["calls"] += 1
        stages[stage]["prompt_bytes"] += attempt["prompt_bytes"]
        stages[stage]["recorded_call_seconds"] += attempt["elapsed_seconds"]
    for values in stages.values():
        values["recorded_call_seconds"] = round(values["recorded_call_seconds"], 3)
    return stages


def _summarize_benchmarks(target, truth_file, report_dirs, output):
    target, truth_file, output = (path.resolve() for path in (target, truth_file, output))
    report_dirs = [path.resolve() for path in report_dirs]
    if (
        not 2 <= len(report_dirs) <= 16
        or len(set(report_dirs)) != len(report_dirs)
        or truth_file.is_relative_to(target)
        or output.is_relative_to(target)
        or output == truth_file
        or any(
            directory.is_relative_to(target)
            or truth_file.is_relative_to(directory)
            or output.is_relative_to(directory)
            for directory in report_dirs
        )
    ):
        raise ValueError("benchmark summary needs 2..16 distinct reports outside the target")
    reports, references, profiles, used_runs = [], [], [], set()
    first_identity = None
    for directory in report_dirs:
        raw = read_regular(directory, "benchmark.json", 8 * 1024 * 1024)
        saved = json.loads(raw)
        if saved["measurement_kind"] not in {
            "declared_codex_artifacts",
            "offline_replay_artifacts",
        }:
            raise ValueError("benchmark summary requires completed-run comparison reports")
        paths = saved["run_directories"]
        runs = {name: Path(paths[name]) for name in ("baseline", "candidate")}
        if any(
            not path.is_absolute()
            or str(path.resolve()) != str(path)
            or directory.is_relative_to(path)
            or output.is_relative_to(path)
            or path in used_runs
            for path in runs.values()
        ):
            raise ValueError("benchmark summary reuses a run or overlaps source artifacts")
        fresh = _compare_runs(target, truth_file, runs["baseline"], runs["candidate"], None)
        old_fields = {key for key in ("comparison",) if key not in saved}
        old_diagnostics = any(
            "diagnostics" not in label
            for arm in saved["arms"].values()
            for label in arm["labeled_cases"]
        )
        compatible = json.loads(json.dumps(fresh))
        for key in old_fields:
            compatible.pop(key)
        if old_diagnostics:
            for arm in compatible["arms"].values():
                for label in arm["labeled_cases"]:
                    label.pop("diagnostics")
        legacy = (
            (old_fields or old_diagnostics)
            and saved.get("identity_sha256")
            == digest({key: value for key, value in saved.items() if key != "identity_sha256"})
            and {key: value for key, value in saved.items() if key != "identity_sha256"}
            == {key: value for key, value in compatible.items() if key != "identity_sha256"}
        )
        if saved != fresh and not legacy:
            raise ValueError("benchmark pair report or underlying run evidence changed")
        identities = {
            name: json.loads(read_regular(path, "manifest.json", 8 * 1024 * 1024))["identity"]
            for name, path in runs.items()
        }
        identity = (
            saved["measurement_kind"],
            saved["truth_sha256"],
            saved["source_index_sha256"],
            saved["limits"],
            identities,
        )
        if first_identity is None:
            first_identity = identity
        elif identity != first_identity:
            raise ValueError("benchmark repeats differ in source, model, configuration or budget")
        used_runs.update(runs.values())
        reports.append(fresh)
        profiles.append({name: call_profile(path) for name, path in runs.items()})
        references.append(
            {
                "path": str(directory),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "identity_sha256": saved["identity_sha256"],
                "run_directories": paths,
            }
        )
    first = reports[0]
    comparisons = [report["comparison"] for report in reports]
    token_complete = [item["reported_token_delta"] is not None for item in comparisons]
    queue_sizes = [
        {
            arm: report["arms"][arm]["metrics"]["unique_candidates"]
            - report["arms"][arm]["metrics"]["verdict_counts"].get("rejected", 0)
            for arm in ("baseline", "candidate")
        }
        for report in reports
    ]
    cases = []
    for index, case in enumerate(first["cases"]):
        cases.append(
            {
                "id": case["id"],
                "expected": case["expected"],
                "status_counts": {
                    arm: dict(
                        Counter(
                            report["arms"][arm]["labeled_cases"][index]["status"]
                            for report in reports
                        )
                    )
                    for arm in ("baseline", "candidate")
                },
                "root_cause_evidence_counts": {
                    arm: dict(
                        Counter(
                            "cited"
                            if report["arms"][arm]["labeled_cases"][index][
                                "root_cause_candidate_ids"
                            ]
                            else "absent"
                            for report in reports
                        )
                    )
                    for arm in ("baseline", "candidate")
                },
            }
        )
    summary = {
        "schema_version": 1,
        "measurement_kind": "repeated_" + first["measurement_kind"],
        "repeat_count": len(reports),
        "truth_sha256": first["truth_sha256"],
        "source_index_sha256": first["source_index_sha256"],
        "limits": first["limits"],
        "agent": first["arms"]["baseline"]["agent"],
        "arm_identity_sha256": {
            name: digest(first_identity[4][name]) for name in ("baseline", "candidate")
        },
        "pairs": references,
        "per_pair_profiles": profiles,
        "case_variation": cases,
        "label_count_delta": {
            key: distribution([item["label_count_delta"][key] for item in comparisons])
            for key in comparisons[0]["label_count_delta"]
        },
        "unlabeled_candidate_delta": distribution(
            [
                report["arms"]["candidate"]["unlabeled_candidate_count"]
                - report["arms"]["baseline"]["unlabeled_candidate_count"]
                for report in reports
            ]
        ),
        "call_attempt_delta": distribution([item["call_attempt_delta"] for item in comparisons]),
        "review_queue_size": {
            arm: distribution([item[arm] for item in queue_sizes])
            for arm in ("baseline", "candidate")
        },
        "review_queue_delta": distribution(
            [item["candidate"] - item["baseline"] for item in queue_sizes]
        ),
        "prompt_byte_delta": distribution(
            [
                sum(stage["prompt_bytes"] for stage in profile["candidate"].values())
                - sum(stage["prompt_bytes"] for stage in profile["baseline"].values())
                for profile in profiles
            ]
        ),
        "stage_delta": {
            stage: {
                key: distribution(
                    [
                        profile["candidate"][stage][key] - profile["baseline"][stage][key]
                        for profile in profiles
                    ]
                )
                for key in ("calls", "prompt_bytes", "recorded_call_seconds")
            }
            for stage in ("analysis", "triage")
        },
        "recorded_call_seconds_delta": distribution(
            [item["duration_seconds_delta"] for item in comparisons]
        ),
        "complete_token_pairs": sum(token_complete),
        "reported_token_delta": {
            key: distribution([item["reported_token_delta"][key] for item in comparisons])
            for key in ("input_tokens", "output_tokens")
        }
        if all(token_complete)
        else None,
        "interpretation": (
            "Repeated paired local artifacts; medians and ranges are descriptive only. "
            "Provider identities and researcher labels are declarations, not independent proof."
        ),
    }
    summary["identity_sha256"] = digest(summary)
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("benchmark summary output is nonempty")
        save_json(output / "benchmark-summary.json", summary)
    return summary


def summarize_benchmarks(target, truth_file, report_dirs, output):
    try:
        return _summarize_benchmarks(target, truth_file, report_dirs, output)
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("benchmark summary input is malformed") from error


def benchmark_replay(
    target,
    truth_file,
    baseline_replay,
    candidate_replay,
    output,
    *,
    candidate_graph=None,
    candidate_recon=None,
    candidate_static=None,
    max_slices=8,
    slice_bytes=16_000,
    max_calls=16,
    max_queries=4,
    query_bytes=16_000,
):
    target, truth_file, baseline_replay, candidate_replay, output = (
        path.resolve() for path in (target, truth_file, baseline_replay, candidate_replay, output)
    )
    if (
        output.is_relative_to(target)
        or truth_file.is_relative_to(target)
        or truth_file.is_relative_to(baseline_replay)
        or truth_file.is_relative_to(candidate_replay)
        or baseline_replay.is_relative_to(target)
        or candidate_replay.is_relative_to(target)
        or output.is_relative_to(baseline_replay)
        or output.is_relative_to(candidate_replay)
        or output == truth_file
        or (
            candidate_recon is None
            and (candidate_graph is not None or candidate_static is not None)
        )
        or (candidate_recon is not None and candidate_graph is None)
        or (candidate_static is not None and candidate_recon is None)
    ):
        raise ValueError("benchmark output or candidate graph/recon/static boundary is invalid")
    cases, source_index, skipped, truth_sha256 = checked_truth(target, truth_file)
    agents = {"baseline": ReplayAgent(baseline_replay), "candidate": ReplayAgent(candidate_replay)}
    limits = {
        "max_slices": max_slices,
        "slice_bytes": slice_bytes,
        "max_calls": max_calls,
        "max_queries": max_queries,
        "query_bytes": query_bytes,
    }
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("benchmark output is nonempty; use a new directory")
        state = {
            "schema_version": 1,
            "status": "running",
            "target": str(target),
            "source_index": source_index,
            "skipped": skipped,
            "truth_sha256": truth_sha256,
            "limits": limits,
            "run_directories": {name: str(output / name) for name in agents},
        }
        save_json(output / "benchmark-state.json", state)
        results = {}
        try:
            for name, agent in agents.items():
                started = time.monotonic()
                run_pipeline(
                    target,
                    output / name,
                    agent,
                    **limits,
                    graph_file=candidate_graph if name == "candidate" else None,
                    recon_file=candidate_recon if name == "candidate" else None,
                    static_file=candidate_static if name == "candidate" else None,
                )
                results[name] = score_run(output / name, cases, time.monotonic() - started)
                if results[name]["source_index"] != source_index:
                    raise ValueError("benchmark source snapshot changed between arms")
            report = {
                "schema_version": 1,
                "measurement_kind": "offline_replay_orchestration",
                "truth_sha256": truth_sha256,
                "source_index_sha256": digest(source_index),
                "limits": limits,
                "cases": cases,
                "arms": results,
                "comparison": comparison_delta(results, "elapsed_seconds"),
                "interpretation": (
                    "Researcher labels and recorded replies; not live model accuracy or token cost."
                ),
            }
            report["identity_sha256"] = digest(report)
            save_json(output / "benchmark.json", report)
            state["status"] = "complete"
            state["report_sha256"] = report["identity_sha256"]
            save_json(output / "benchmark-state.json", state)
            return report
        except (Exception, KeyboardInterrupt) as error:
            state["status"] = "failed"
            state["error_type"] = type(error).__name__
            save_json(output / "benchmark-state.json", state)
            raise
