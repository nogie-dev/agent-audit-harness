"""Advance reviewed impact measurements one isolated worker and researcher gate at a time."""

import hashlib
import json
import tempfile
from pathlib import Path

from .impact import review_impact, verified_input
from .judgment import evaluate_run, read_worker
from .pipeline import digest, run_lock, save_json
from .validation import read_regular

MAX_ATTEMPTS_PER_STAGE = 3


def read_impact_review(directory):
    saved = json.loads(read_regular(directory, "impact-review.json"))
    if (
        not isinstance(saved, dict)
        or saved.get("status") != "reviewed"
        or saved.get("decision") != "approve"
        or saved.get("identity_sha256")
        != digest({key: value for key, value in saved.items() if key != "identity_sha256"})
        or not isinstance(saved.get("input"), dict)
        or any(
            not isinstance(saved["input"].get(key), str) or not saved["input"][key]
            for key in ("kind", "path")
        )
        or any(
            not isinstance(saved.get(key), str) or not saved[key]
            for key in ("reviewer", "rationale")
        )
    ):
        raise ValueError("impact plan lacks a valid researcher approval")
    reference = saved["input"]
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix="impact-recheck-") as temporary:
        fresh = review_impact(
            reference["kind"],
            Path(reference["path"]),
            directory / "plan-input.json",
            Path(temporary) / "review",
            decision=saved["decision"],
            reviewer=saved["reviewer"],
            rationale=saved["rationale"],
        )
    if fresh != saved:
        raise ValueError("impact review differs from original validated inputs")
    for stage in saved["stages"]:
        copied = directory / "stages" / stage["id"] / "poc-review"
        original = Path(stage["poc_review"])
        for name in ("review.json", "proposal.json", "recipe.json"):
            if read_regular(copied, name) != read_regular(original, name):
                raise ValueError("impact stage approved PoC copy changed")
    plan = json.loads(read_regular(directory, "plan-input.json"))
    base = verified_input(reference["kind"], Path(reference["path"]))
    return saved, plan, base


def assess_worker(review_dir, review, plan, base, index, worker_dir):
    stage = review["stages"][index]
    expected = plan["stages"][index]["expected_outcome"]
    record = {
        "stage_id": stage["id"],
        "stage_index": index,
        "worker": str(worker_dir),
        "raw_result_sha256": None,
        "result_sha256": None,
        "worker_status": "unreadable",
        "expected_outcome": expected,
        "evaluation": None,
        "gate_pass": False,
        "blockers": [],
        "failure": None,
    }
    try:
        raw = read_regular(worker_dir, "result.json", 8 * 1024 * 1024)
        record["raw_result_sha256"] = hashlib.sha256(raw).hexdigest()
        run = read_worker(worker_dir)
        result = run["result"]
        record["result_sha256"] = result["identity_sha256"]
        record["worker_status"] = result["status"]
        recipe = json.loads(
            read_regular(review_dir / "stages" / stage["id"] / "poc-review", "recipe.json")
        )
        identity = result.get("identity", {})
        original = base["identity"]
        if (
            run["candidate"] != base["candidate"]
            or run["recipe"] != recipe
            or identity.get("recipe_sha256") != stage["recipe_sha256"]
            or identity.get("poc_review_sha256") != stage["poc_review_sha256"]
            or identity.get("poc_proposal_sha256") != stage["poc_proposal_sha256"]
            or any(
                identity.get(key) != original.get(key)
                for key in (
                    "review_sha256",
                    "queue_sha256",
                    "configuration_id",
                    "worker_sha256",
                    "recipe_schema_sha256",
                )
            )
            or result["target"] != base["target"]
            or result["image"] != base["image"]
        ):
            record["blockers"].append("worker_or_approved_stage_identity_differs")
        evaluation = evaluate_run(run)
        record["evaluation"] = evaluation
        record["blockers"].extend(evaluation["blockers"])
        if not evaluation["reliable"]:
            record["blockers"].append("execution_not_reliable")
        if not evaluation["entrypoint_reached"]:
            record["blockers"].append("entrypoint_not_observed")
        if evaluation["outcome"] != expected:
            record["blockers"].append("stage_property_not_observed")
        record["gate_pass"] = not record["blockers"]
    except (Exception, KeyboardInterrupt) as error:
        record["failure"] = {"type": type(error).__name__, "detail": str(error)[:2000]}
        record["blockers"].append("invalid_or_incomplete_worker_evidence")
    return record


def summarize(review, plan, attempts):
    next_index, status = 0, "ready"
    approved = {}
    counts = {}
    workers = set()
    for number, item in enumerate(attempts):
        if status in {"stopped", "complete"} or item["stage_index"] != next_index:
            raise ValueError("impact checkpoint stage order is invalid")
        counts[next_index] = counts.get(next_index, 0) + 1
        worker = item["assessment"]["worker"]
        if counts[next_index] > MAX_ATTEMPTS_PER_STAGE or worker in workers:
            raise ValueError("impact checkpoint attempt budget or worker reuse is invalid")
        workers.add(worker)
        if item["researcher_decision"] == "reject":
            status = "stopped"
        elif item["researcher_decision"] == "approve" and item["assessment"]["gate_pass"]:
            approved[item["stage_id"]] = number
            next_index += 1
            status = "complete" if next_index == len(review["stages"]) else "ready"
        else:
            status = "paused"
    resolutions = {(item["kind"], item["index"]): item for item in plan["resolutions"]}
    issues = {}
    for kind in ("unresolved", "counterevidence"):
        issues[kind] = []
        for index, claim in enumerate(plan[kind]):
            resolution = resolutions.get((kind, index))
            attempt = approved.get(resolution["stage_id"]) if resolution else None
            issues[kind].append(
                {
                    "claim": claim,
                    "resolved": attempt is not None,
                    "resolution": resolution,
                    "evidence_ref": {
                        "stage_id": resolution["stage_id"],
                        "attempt": attempt + 1,
                        "worker_result_sha256": attempts[attempt]["assessment"]["result_sha256"],
                    }
                    if attempt is not None
                    else None,
                }
            )
    open_issues = any(not issue["resolved"] for values in issues.values() for issue in values)
    validated = status == "complete" and not open_issues
    return {
        "status": status,
        "next_stage_index": next_index,
        "stage_results": [
            {
                "stage_id": key,
                "attempt": number + 1,
                "worker_result_sha256": attempts[number]["assessment"]["result_sha256"],
            }
            for key, number in approved.items()
        ],
        "issues": issues,
        "impact_validated": validated,
        "verdict": (
            "impact_observed"
            if validated
            else "observed_with_open_issues"
            if status == "complete"
            else "inconclusive"
        ),
    }


def read_checkpoint(output, review_dir, review, plan, base):
    saved = json.loads(read_regular(output, "impact-state.json"))
    if (
        not isinstance(saved, dict)
        or saved.get("schema_version") != 1
        or saved.get("review_sha256") != review["identity_sha256"]
        or saved.get("tool_sha256") != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        or saved.get("identity_sha256")
        != digest({key: value for key, value in saved.items() if key != "identity_sha256"})
        or not isinstance(saved.get("attempts"), list)
        or len(saved["attempts"]) > len(review["stages"]) * MAX_ATTEMPTS_PER_STAGE
    ):
        raise ValueError("impact checkpoint identity is invalid")
    for item in saved["attempts"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("assessment"), dict)
            or item.get("researcher_decision") not in {"approve", "retry", "reject"}
            or not isinstance(item.get("researcher"), str)
            or not item["researcher"].strip()
            or not isinstance(item.get("rationale"), str)
            or not item["rationale"].strip()
            or len(item["researcher"]) > 128
            or len(item["rationale"]) > 4000
        ):
            raise ValueError("impact checkpoint researcher receipt is invalid")
        index = item.get("stage_index")
        worker = item["assessment"].get("worker")
        if (
            type(index) is not int
            or not 0 <= index < len(review["stages"])
            or not isinstance(worker, str)
            or not Path(worker).is_absolute()
            or Path(worker).is_relative_to(Path(base["target"]))
            or Path(worker).is_relative_to(review_dir)
            or any(
                Path(worker).is_relative_to(path)
                for path in base["protected_paths"]
                + [Path(stage["poc_review"]) for stage in review["stages"]]
            )
        ):
            raise ValueError("impact checkpoint stage index is invalid")
        fresh = assess_worker(review_dir, review, plan, base, index, Path(worker))
        if fresh != item["assessment"] or item.get("stage_id") != review["stages"][index]["id"]:
            raise ValueError("impact checkpoint worker evidence changed")
    expected = summarize(review, plan, saved["attempts"])
    if any(saved.get(key) != value for key, value in expected.items()):
        raise ValueError("impact checkpoint gate summary differs from evidence")
    return saved


def impact_step(review_dir, worker_dir, output, *, stage_id, decision, reviewer, rationale):
    review_dir, worker_dir, output = (path.resolve() for path in (review_dir, worker_dir, output))
    review, plan, base = read_impact_review(review_dir)
    protected = base["protected_paths"] + [Path(stage["poc_review"]) for stage in review["stages"]]
    if (
        decision not in {"approve", "retry", "reject"}
        or not reviewer.strip()
        or not rationale.strip()
        or len(reviewer) > 128
        or len(rationale) > 4000
        or any(
            output.is_relative_to(path)
            for path in (review_dir, worker_dir, Path(base["target"]), Path(base["path"]))
        )
        or worker_dir.is_relative_to(Path(base["target"]))
        or worker_dir.is_relative_to(review_dir)
        or any(output.is_relative_to(path) or worker_dir.is_relative_to(path) for path in protected)
    ):
        raise ValueError("impact stage decision or artifact boundary is invalid")
    with run_lock(output):
        state_file = output / "impact-state.json"
        if state_file.exists():
            state = read_checkpoint(output, review_dir, review, plan, base)
        else:
            if any(path.name != ".lock" for path in output.iterdir()):
                raise ValueError("impact checkpoint output is nonempty")
            state = {
                "schema_version": 1,
                "review_sha256": review["identity_sha256"],
                "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "attempts": [],
                **summarize(review, plan, []),
            }
        if state["status"] in {"stopped", "complete"}:
            raise ValueError("impact checkpoint is terminal; start a new reviewed experiment")
        index = state["next_stage_index"]
        stage = review["stages"][index]
        if stage_id != stage["id"]:
            raise ValueError("impact stage is out of order")
        if (
            sum(item["stage_id"] == stage_id for item in state["attempts"])
            >= MAX_ATTEMPTS_PER_STAGE
        ):
            raise ValueError("impact stage attempt budget is exhausted")
        if any(item["assessment"]["worker"] == str(worker_dir) for item in state["attempts"]):
            raise ValueError("impact worker artifact was already submitted")
        assessment = assess_worker(review_dir, review, plan, base, index, worker_dir)
        state["attempts"].append(
            {
                "stage_id": stage_id,
                "stage_index": index,
                "assessment": assessment,
                "researcher_decision": decision,
                "researcher": reviewer,
                "rationale": rationale,
            }
        )
        state.update(summarize(review, plan, state["attempts"]))
        state["identity_sha256"] = digest(
            {key: value for key, value in state.items() if key != "identity_sha256"}
        )
        save_json(state_file, state)
        return state
