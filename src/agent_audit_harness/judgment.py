"""Evaluate frozen, reviewed oracles against worker evidence; never execute code."""

import hashlib
import json
from pathlib import Path

from .pipeline import (
    MAX_SOURCE_BYTES,
    RESOURCES,
    digest,
    run_lock,
    save_json,
    source_lines,
    validate_shape,
)
from .triage import checked_evidence
from .validation import execution_command, read_json, read_regular, verify_policy


def candidate_issues(candidate):
    candidate = candidate or {}
    issues = []
    for kind in ("unresolved", "counterevidence"):
        issues.extend({"kind": kind, "detail": item} for item in candidate.get(kind, []))
    for kind, values in candidate.get("input_gaps", {}).items():
        if kind == "omitted_counts":
            issues.extend(
                {"kind": kind, "detail": {key: count}}
                for key, count in sorted(values.items())
                if count
            )
        elif kind.endswith("_ids"):
            issues.extend({"kind": kind, "detail": item} for item in values)
    unique = {"vi-" + digest(issue)[:16]: issue for issue in issues}
    return [{"id": key, **value} for key, value in sorted(unique.items())]


def source_proof(evidence, sources):
    data = sources[evidence["path"]]
    text = data.decode("utf-8")
    return checked_evidence(
        evidence,
        {
            "fragments": [
                {
                    "path": evidence["path"],
                    "first_line": 1,
                    "last_line": len(source_lines(text)),
                    "text": text,
                    "source_sha256": hashlib.sha256(data).hexdigest(),
                }
            ]
        },
    )


def check_oracle(recipe, candidate, reviewed, executed, *, issues=None):
    oracle = recipe.get("oracle")
    if oracle is None:
        return {}
    harness = oracle["harness_path"]
    if len(recipe["command"]) < 2 or recipe["command"][1] != "/input/" + harness:
        raise ValueError("oracle command must invoke the supplied harness through an interpreter")
    if harness not in reviewed or reviewed[harness] != executed[harness]:
        raise ValueError("oracle harness must be supplied and unchanged")
    if oracle["source"]["path"] != candidate["path"] or harness == candidate["path"]:
        raise ValueError("oracle must cite candidate source and use a separate harness")
    proofs = {"source": source_proof(oracle["source"], reviewed)}
    markers = [oracle[key] for key in ("completed", "reproduced", "not_reproduced")]
    entry = oracle["entrypoint"]
    if entry:
        if entry["invocation"]["path"] != harness or entry["source"]["path"] == harness:
            raise ValueError("entrypoint requires target source and a harness invocation")
        proofs["entrypoint"] = source_proof(entry["source"], executed)
        proofs["invocation"] = source_proof(entry["invocation"], executed)
        markers.append(entry["observation"])
    configurations = recipe.get("configurations", [])
    ids = [item["id"] for item in configurations]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate configuration ID")
    if configurations:
        proofs["configurations"] = {}
    for item in configurations:
        if item["invocation"]["path"] != harness or item["source"]["path"] == harness:
            raise ValueError(
                "configuration requires target evidence and unchanged harness invocation"
            )
        proofs["configurations"][item["id"]] = {
            "source": source_proof(item["source"], executed),
            "invocation": source_proof(item["invocation"], executed),
        }
        markers.append(item["observation"])
    if len({digest(marker) for marker in markers}) != len(markers):
        raise ValueError("oracle observations must be distinct")
    if any(any(char in marker["line"] for char in "\r\n\0") for marker in markers):
        raise ValueError("oracle observation must be one nonempty physical line")
    known = {issue["id"] for issue in (candidate_issues(candidate) if issues is None else issues)}
    resolutions = [item["issue_id"] for item in oracle["resolutions"]]
    if len(set(resolutions)) != len(resolutions) or not set(resolutions) <= known:
        raise ValueError("oracle resolutions must uniquely reference existing issues")
    if not configurations and any(
        r["requirement"] == "configuration" for r in oracle["resolutions"]
    ):
        raise ValueError("configuration issue resolution requires declared configurations")
    return proofs


def read_worker(directory):
    result = json.loads(read_regular(directory, "result.json", 8 * 1024 * 1024))
    if result.get("schema_version") != 1 or result.get("identity_sha256") != digest(
        {key: value for key, value in result.items() if key != "identity_sha256"}
    ):
        raise ValueError("worker result is unfinished or its checksum is invalid")
    files, total = {}, 0
    if len(result["evidence"]) > 600:
        raise ValueError("worker evidence count exceeds limit")
    for item in result["evidence"]:
        path = item["path"]
        if path in files or path == "result.json":
            raise ValueError("duplicate or self-referential worker evidence")
        data = read_regular(directory, path, 8 * 1024 * 1024)
        if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("worker evidence checksum is invalid: " + path)
        total += len(data)
        if total > 3 * MAX_SOURCE_BYTES:
            raise ValueError("worker evidence exceeds 96 MiB")
        files[path] = data
    recipe = json.loads(files["recipe.json"]) if "recipe.json" in files else None
    candidate = json.loads(files["candidate.json"]) if "candidate.json" in files else None
    run = {
        "directory": str(directory),
        "result": result,
        "files": files,
        "recipe": recipe,
        "candidate": candidate,
        "proofs": {},
    }
    if result["status"] not in {"completed", "process_failed"} and not (
        candidate
        and result.get("identity")
        and {"poc-review.json", "poc-proposal.json"} <= files.keys()
    ):
        return run
    validate_shape(
        "validation recipe", recipe, read_json(RESOURCES / "schemas/validation-recipe.json")
    )
    identity = result["identity"]
    execution_command(recipe, identity.get("configuration_id"))
    if (
        identity["recipe_sha256"] != digest(recipe)
        or identity["candidate_id"] != candidate["id"]
        or recipe["candidate_id"] != candidate["id"]
        or identity["image"] != result["image"]
        or candidate["verdict"] not in {"needs_validation", "uncertain"}
    ):
        raise ValueError("worker recipe/candidate identity mismatch")
    if recipe.get("attachments") or "poc_review_sha256" in recipe:
        from .poc import poc_issues, verify_review

        receipt = json.loads(files["poc-review.json"])
        proposal = json.loads(files["poc-proposal.json"])
        verify_review(
            receipt,
            proposal,
            recipe,
            candidate,
            identity["review_sha256"],
            identity["queue_sha256"],
            identity["source_index_sha256"],
        )
        if (
            identity.get("poc_review_sha256") != receipt["identity_sha256"]
            or identity.get("poc_proposal_sha256") != proposal["identity_sha256"]
        ):
            raise ValueError("worker PoC review identity mismatch")
        run["issues"] = poc_issues(proposal)
        run["poc_review"] = receipt
    if result["status"] not in {"completed", "process_failed"}:
        return run
    if oracle := recipe.get("oracle"):
        manifest = json.loads(files["source-manifest.json"])
        reviewed, executed = {}, {}
        changes = {item["path"]: item for item in recipe.get("replacements", [])}
        if len(changes) != len(recipe.get("replacements", [])) or len(
            {i["path"] for i in recipe["inputs"]}
        ) != len(recipe["inputs"]):
            raise ValueError("duplicate replacement or input")
        expected = []
        from .validation import attachment_sources

        attachments = attachment_sources(recipe, {item["path"] for item in recipe["inputs"]})
        for item in recipe["inputs"] + recipe.get("attachments", []):
            path = item["path"]
            before = ("reviewed-input/" if path in changes else "input/") + path
            after = "input/" + path
            old, new = files[before], files[after]
            old_hash, new_hash = hashlib.sha256(old).hexdigest(), hashlib.sha256(new).hexdigest()
            if old_hash != item["sha256"]:
                raise ValueError("reviewed source does not match recipe")
            if path in attachments and old != attachments[path]:
                raise ValueError("PoC attachment content differs from reviewed recipe")
            if path in changes:
                change = changes[path]
                if (
                    old_hash != change["before_sha256"]
                    or new_hash != change["after_sha256"]
                    or new != change["content"].encode()
                    or old == new
                ):
                    raise ValueError("executed replacement does not match recipe")
            elif old != new:
                raise ValueError("undeclared source change")
            reviewed[path], executed[path] = old, new
            expected.append(
                {
                    "path": path,
                    "reviewed_sha256": old_hash,
                    "executed_sha256": new_hash,
                    "reviewed_artifact": before,
                    "executed_artifact": after,
                }
            )
        if (
            set(changes) - set(reviewed)
            or manifest != expected
            or digest(manifest) != identity["source_manifest_sha256"]
        ):
            raise ValueError("worker source manifest mismatch")
        if hashlib.sha256(reviewed[candidate["path"]]).hexdigest() != candidate["source_sha256"]:
            raise ValueError("candidate source identity mismatch")
        run["proofs"] = check_oracle(
            recipe, candidate, reviewed, executed, issues=run.get("issues")
        )
        run["oracle"] = oracle
    policy = json.loads(files["policy.json"])
    verify_policy(
        policy,
        Path(policy["mounts"][0]["Source"]),
        result["image"],
        recipe,
        identity.get("configuration_id"),
    )
    return run


def observe(run, observation):
    path = "logs/execute." + observation["stream"] + ".log"
    matches = [
        number
        for number, line in enumerate(source_lines(run["files"][path].decode("utf-8")), 1)
        if line.endswith("\n") and line.rstrip("\r\n") == observation["line"]
    ]
    return {
        "path": path,
        "sha256": hashlib.sha256(run["files"][path]).hexdigest(),
        "quote": observation["line"],
        "lines": matches,
        "unique": len(matches) == 1,
    }


def evaluate_run(run):
    result, recipe = run["result"], run["recipe"]
    evaluation = {
        "execution_status": result["status"],
        "exit_code": result["exit_code"],
        "oom_killed": result["oom_killed"],
        "cleanup": result["cleanup"],
        "worker_failure": result["failure"],
        "reliable": False,
        "outcome": "unknown",
        "entrypoint_reached": False,
        "observations": {},
        "source_proofs": run["proofs"],
        "blockers": [],
    }
    configurations = (recipe or {}).get("configurations", [])
    selected_id = result.get("identity", {}).get("configuration_id")
    evaluation["configuration"] = {
        "id": selected_id,
        "applied": False,
        "status": "unknown" if configurations else "not_declared",
        "observations": {},
    }
    if result["status"] not in {"completed", "process_failed"}:
        evaluation["blockers"].append("worker_" + result["status"])
        return evaluation
    state = json.loads(run["files"]["state.json"])
    if (
        result["cleanup"]["status"] != "removed"
        or result["execution_started"] is not True
        or result["execution_attempted"] is not True
        or result["oom_killed"] is not False
        or state["Running"]
        or state["Error"]
        or state["OOMKilled"]
        or state["StartedAt"].startswith("0001-")
        or state["ExitCode"] != result["exit_code"]
        or state.get("Status", "exited") != "exited"
        or any(state.get(key, False) for key in ("Dead", "Paused", "Restarting"))
    ):
        evaluation["blockers"].append("execution_or_cleanup_incomplete")
        return evaluation
    oracle = recipe.get("oracle")
    if not oracle:
        evaluation["reliable"] = result["status"] == "completed" and result["exit_code"] == 0
        evaluation["blockers"].append("no_predeclared_oracle")
        return evaluation
    if result["exit_code"] not in oracle["expected_exit_codes"]:
        evaluation["blockers"].append("unexpected_exit_code")
        return evaluation
    observations = {
        key: observe(run, oracle[key]) for key in ("completed", "reproduced", "not_reproduced")
    }
    evaluation["observations"] = observations
    complete = observations["completed"]
    present = [key for key in ("reproduced", "not_reproduced") if observations[key]["lines"]]
    if len(present) > 1 or any(len(value["lines"]) > 1 for value in observations.values()):
        evaluation["blockers"].append("conflicting_or_duplicate_observations")
        return evaluation
    if not complete["unique"]:
        evaluation["blockers"].append("check_did_not_complete")
        return evaluation
    evaluation["reliable"] = True
    if not present:
        evaluation["blockers"].append("no_outcome_observed")
        return evaluation
    outcome = present[0]
    observed = observations[outcome]
    if (
        oracle[outcome]["stream"] != oracle["completed"]["stream"]
        or observed["lines"][0] >= complete["lines"][0]
    ):
        evaluation["reliable"] = False
        evaluation["blockers"].append("outcome_completion_order_unknown")
        return evaluation
    evaluation["outcome"] = outcome
    if configurations:
        config = evaluation["configuration"]
        selected = next(c for c in configurations if c["id"] == selected_id)
        config["settings"] = selected["settings"]
        config["observations"] = {c["id"]: observe(run, c["observation"]) for c in configurations}
        observed_config = config["observations"][selected_id]
        observations["configuration"] = observed_config
        config["applied"] = (
            observed_config["unique"]
            and selected["observation"]["stream"] == oracle[outcome]["stream"]
            and observed_config["lines"][0] < observed["lines"][0]
            and not any(
                o["lines"] for key, o in config["observations"].items() if key != selected_id
            )
        )
        config["status"] = "observed" if config["applied"] else "unverified"
        if not config["applied"]:
            evaluation["blockers"].append("declared_configuration_not_observed")
    entry = oracle["entrypoint"]
    if entry:
        observed_entry = observe(run, entry["observation"])
        observations["entrypoint"] = observed_entry
        evaluation["entrypoint_reached"] = (
            entry["kind"] == "entrypoint"
            and observed_entry["unique"]
            and entry["observation"]["stream"] == oracle[outcome]["stream"]
            and observed_entry["lines"][0] < observed["lines"][0]
        )
    if not evaluation["entrypoint_reached"]:
        evaluation["blockers"].append("actual_entrypoint_not_observed")
    return evaluation


def compare_runs(baseline, fixed, original, updated):
    comparison = {
        "supplied": fixed is not None,
        "comparable": False,
        "fix_verified": False,
        "changes": [],
        "blockers": [],
    }
    if fixed is None:
        comparison["blockers"].append("fixed_run_missing")
        return comparison
    old, new = baseline["recipe"], fixed["recipe"]
    changes = new.get("replacements", []) if new else []
    comparison["changes"] = [{k: v for k, v in item.items() if k != "content"} for item in changes]
    keys = ("image", "review_sha256", "queue_sha256", "worker_sha256", "recipe_schema_sha256")
    identities = baseline["result"].get("identity", {}), fixed["result"].get("identity", {})
    comparison["comparable"] = bool(
        old
        and new
        and changes
        and not old.get("replacements")
        and {k: v for k, v in old.items() if k != "replacements"}
        == {k: v for k, v in new.items() if k != "replacements"}
        and digest(baseline["candidate"]) == digest(fixed["candidate"])
        and identities[0].get("configuration_id") == identities[1].get("configuration_id")
        and all(
            identities[0].get(k) is not None and identities[0][k] == identities[1].get(k)
            for k in keys
        )
        and baseline["result"].get("engine") == fixed["result"].get("engine")
        and old.get("oracle")
        and old["oracle"]["source"]["path"] in {c["path"] for c in changes}
        and old["oracle"]["harness_path"] not in {c["path"] for c in changes}
    )
    if not comparison["comparable"]:
        comparison["blockers"].append("comparison_inputs_differ")
    elif not updated["reliable"]:
        comparison["blockers"].append("fixed_execution_inconclusive")
    elif updated["outcome"] != "not_reproduced":
        comparison["blockers"].append("fixed_run_still_reproduces_or_has_no_negative_observation")
    elif not updated["entrypoint_reached"]:
        comparison["blockers"].append("fixed_entrypoint_not_observed")
    elif old.get("configurations") and not (
        original["configuration"]["applied"] and updated["configuration"]["applied"]
    ):
        comparison["blockers"].append("configuration_application_unverified")
    else:
        comparison["fix_verified"] = (
            original["outcome"] == "reproduced" and original["entrypoint_reached"]
        )
    return comparison


def judge(baseline, output, *, fixed=None):
    baseline, output = baseline.resolve(), output.resolve()
    fixed = fixed.resolve() if fixed else None
    if any(output.is_relative_to(path) for path in (baseline, fixed) if path):
        raise ValueError("judgment output must be outside worker artifacts")
    for directory in (baseline, fixed):
        if directory:
            try:
                hint = json.loads(read_regular(directory, "result.json", 8 * 1024 * 1024))
            except (OSError, ValueError):
                continue
            if (
                isinstance(hint, dict)
                and isinstance(hint.get("target"), str)
                and output.is_relative_to(Path(hint["target"]).resolve())
            ):
                raise ValueError("judgment output must be outside target")
    with run_lock(output):
        if any(p.name != ".lock" for p in output.iterdir()):
            raise ValueError("judgment output is nonempty; use a new directory")
        decision = {
            "schema_version": 1,
            "status": "failed",
            "verdict": "inconclusive",
            "validated_findings": 0,
            "candidate": None,
            "runs": {},
            "issues": [],
            "promotion": {"eligible": False, "to": "validated", "blockers": []},
            "failure": None,
        }
        decision["inputs"] = {"baseline": str(baseline), "fixed": str(fixed) if fixed else None}
        try:
            original_run = read_worker(baseline)
            decision["candidate"] = original_run["candidate"]
            decision["issues"] = [
                {
                    **issue,
                    "resolved": False,
                    "resolution": None,
                    "evidence_requirement": None,
                    "evidence_refs": [],
                }
                for issue in original_run.get("issues", candidate_issues(original_run["candidate"]))
                if original_run["candidate"]
            ]
            original = evaluate_run(original_run)
            decision["runs"]["baseline"] = original
            fixed_run = read_worker(fixed) if fixed else None
            candidate = original_run["candidate"]
            issues = original_run.get("issues", candidate_issues(candidate))
            if "poc_review" in original_run:
                decision["poc_review"] = original_run["poc_review"]
            updated = evaluate_run(fixed_run) if fixed_run else None
            decision["runs"] = {"baseline": original, "fixed": updated}
            comparison = compare_runs(original_run, fixed_run, original, updated)
            decision["comparison"] = comparison
            requirements = {
                "reproduction": original["reliable"] and original["outcome"] == "reproduced",
                "entrypoint": original["entrypoint_reached"],
                "fix_comparison": comparison["fix_verified"],
            }
            if (original_run["recipe"] or {}).get("configurations"):
                requirements["configuration"] = bool(
                    original["configuration"]["applied"]
                    and updated
                    and updated["configuration"]["applied"]
                )
            oracle = (original_run["recipe"] or {}).get("oracle")
            resolutions = (
                {item["issue_id"]: item for item in oracle["resolutions"]} if oracle else {}
            )
            decision["issues"] = []
            requirement_refs = {
                "reproduction": [{"run": "baseline", "observation": "reproduced"}],
                "entrypoint": [{"run": "baseline", "observation": "entrypoint"}],
                "fix_comparison": [
                    {"run": "baseline", "observation": "reproduced"},
                    {"run": "fixed", "observation": "not_reproduced"},
                ],
            }
            if "configuration" in requirements:
                requirement_refs["configuration"] = [
                    {"run": phase, "observation": "configuration"}
                    for phase in ("baseline", "fixed")
                ]
            for issue in issues if candidate else []:
                resolution = resolutions.get(issue["id"])
                resolved = bool(resolution and requirements[resolution["requirement"]])
                decision["issues"].append(
                    {
                        **issue,
                        "resolved": resolved,
                        "resolution": resolution,
                        "evidence_requirement": resolution["requirement"] if resolved else None,
                        "evidence_refs": requirement_refs[resolution["requirement"]]
                        if resolved
                        else [],
                    }
                )
            blockers = decision["promotion"]["blockers"]
            blockers.extend(original["blockers"])
            blockers.extend(comparison["blockers"])
            blockers.extend(
                "unresolved:" + issue["id"] for issue in decision["issues"] if not issue["resolved"]
            )
            if not requirements["reproduction"]:
                blockers.append("vulnerability_not_reproduced")
            eligible = all(requirements.values()) and all(
                issue["resolved"] for issue in decision["issues"]
            )
            decision["promotion"].update(eligible=eligible, requirements=requirements)
            if eligible:
                verdict = "validated"
            elif not original["reliable"] or (
                fixed and (not comparison["comparable"] or not updated["reliable"])
            ):
                verdict = "inconclusive"
            elif original["outcome"] == "not_reproduced":
                verdict = "not_reproduced"
            elif original["outcome"] == "reproduced":
                verdict = (
                    "inconclusive"
                    if any(not i["resolved"] for i in decision["issues"])
                    else "reproduced"
                )
            else:
                verdict = "execution_only"
            decision.update(status="complete", verdict=verdict, validated_findings=int(eligible))
            decision["identity"] = {
                "baseline": {
                    "directory": str(baseline),
                    "result_sha256": original_run["result"]["identity_sha256"],
                },
                "fixed": {
                    "directory": str(fixed),
                    "result_sha256": fixed_run["result"]["identity_sha256"],
                }
                if fixed
                else None,
                "judge_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "recipe_schema_sha256": hashlib.sha256(
                    (RESOURCES / "schemas/validation-recipe.json").read_bytes()
                ).hexdigest(),
            }
        except (Exception, KeyboardInterrupt) as error:
            decision["failure"] = {"type": type(error).__name__, "detail": str(error)[:2000]}
            decision["promotion"]["blockers"].append("invalid_or_incomplete_evidence")
        decision["identity_sha256"] = digest(decision)
        save_json(output / "judgment.json", decision)
        return decision
