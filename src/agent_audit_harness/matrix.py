"""Freeze bounded build cases, use the existing isolated worker, then judge each case."""

import hashlib
import json
from pathlib import Path

from .judgment import judge, read_worker
from .pipeline import RESOURCES, digest, run_lock, save_json, validate_shape
from .poc import check_reply, poc_context, poc_issues, verify_review
from .validation import read_regular, validate


def tool_identity():
    return {
        name: hashlib.sha256((RESOURCES / name).read_bytes()).hexdigest()
        for name in (
            "matrix.py",
            "validation.py",
            "judgment.py",
            "poc.py",
            "pipeline.py",
            "intake.py",
            "triage.py",
            "recon.py",
            "graph.py",
            "static_analysis.py",
            "validation_watchdog.py",
            "schemas/poc-proposal.json",
            "schemas/validation-matrix.json",
            "schemas/validation-recipe.json",
            "schemas/poc-review.json",
        )
    }


def seal(data):
    return {**data, "identity_sha256": digest(data)}


def read_sealed(directory, name):
    data = json.loads(read_regular(directory, name))
    if not isinstance(data, dict) or data.get("identity_sha256") != digest(
        {k: v for k, v in data.items() if k != "identity_sha256"}
    ):
        raise ValueError("matrix artifact is unfinished or changed: " + name)
    return data


def read_matrix(directory):
    state = read_sealed(directory, "manifest.json")
    if state.get("schema_version") != 1 or state.get("status") != "prepared":
        raise ValueError("matrix preparation is unfinished")
    files = {}
    if set(state["identity"]["files"]) != {
        "matrix-input.json",
        "recipe.json",
        "fixed-recipe.json",
        "poc-review/review.json",
        "poc-review/proposal.json",
    }:
        raise ValueError("matrix input file inventory differs")
    for name, checksum in state["identity"]["files"].items():
        raw = read_regular(directory, name)
        if hashlib.sha256(raw).hexdigest() != checksum:
            raise ValueError("prepared matrix input changed: " + name)
        files[name] = json.loads(raw)
    spec, recipe, fixed = (
        files[name] for name in ("matrix-input.json", "recipe.json", "fixed-recipe.json")
    )
    validate_shape(
        "validation matrix",
        spec,
        json.loads((RESOURCES / "schemas/validation-matrix.json").read_text()),
    )
    schema = json.loads((RESOURCES / "schemas/validation-recipe.json").read_text())
    for item in (recipe, fixed):
        validate_shape("matrix recipe", item, schema)
    receipt, proposal = files["poc-review/review.json"], files["poc-review/proposal.json"]
    context = proposal["context"]
    verify_review(
        receipt,
        proposal,
        recipe,
        context["candidate"],
        context["review_sha256"],
        context["queue_sha256"],
        context["source_index_sha256"],
    )
    if (
        spec["poc_review_sha256"] != receipt["identity_sha256"]
        or spec["recipe_sha256"] != digest(recipe)
        or spec["fixed_recipe_sha256"] != digest(fixed)
        or recipe.get("replacements")
        or not fixed.get("replacements")
        or {k: v for k, v in fixed.items() if k != "replacements"} != recipe
        or context["target"] != state["target"]
    ):
        raise ValueError("matrix recipe/source/review identity differs")
    case_ids = [c["id"] for c in spec["cases"]]
    configurations = [c["id"] for c in recipe.get("configurations", [])]
    if (
        len(set(case_ids)) != len(case_ids)
        or len(set(configurations)) != len(configurations)
        or set(case_ids) != set(configurations)
    ):
        raise ValueError("matrix must include each declared configuration exactly once")
    return state, files


def prepare_matrix(target, review, spec_file, output):
    target, review, spec_file, output = (p.resolve() for p in (target, review, spec_file, output))
    if (
        review.is_relative_to(target)
        or spec_file.is_relative_to(target)
        or output.is_relative_to(target)
        or output.is_relative_to(review)
    ):
        raise ValueError("matrix inputs/output must be outside target; output outside review")
    with run_lock(output):
        if any(p.name != ".lock" for p in output.iterdir()):
            raise ValueError("matrix output is nonempty; use a new directory")
        state = {
            "schema_version": 1,
            "status": "preparing",
            "target": str(target),
            "review": str(review),
        }
        save_json(output / "manifest.json", state)
        try:
            raw = read_regular(spec_file.parent, spec_file.name)
            (output / "matrix-input.json").write_bytes(raw)
            spec = json.loads(raw)
            validate_shape(
                "validation matrix",
                spec,
                json.loads((RESOURCES / "schemas/validation-matrix.json").read_text()),
            )
            approval = (spec_file.parent / spec["poc_review"]).resolve()
            fixed_file = (spec_file.parent / spec["fixed_recipe"]).resolve()
            if (
                approval.is_relative_to(target)
                or fixed_file.is_relative_to(target)
                or output.is_relative_to(approval)
            ):
                raise ValueError(
                    "matrix recipes/reviews must be outside target; output outside approval"
                )
            for name in ("recipe.json", "review.json", "proposal.json"):
                destination = output / (
                    "recipe.json" if name == "recipe.json" else "poc-review/" + name
                )
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(read_regular(approval, name))
            (output / "fixed-recipe.json").write_bytes(
                read_regular(fixed_file.parent, fixed_file.name)
            )
            names = (
                "matrix-input.json",
                "recipe.json",
                "fixed-recipe.json",
                "poc-review/review.json",
                "poc-review/proposal.json",
            )
            state.update(
                status="prepared",
                identity={
                    "tools": tool_identity(),
                    "files": {
                        name: hashlib.sha256(read_regular(output, name)).hexdigest()
                        for name in names
                    },
                },
            )
            save_json(output / "manifest.json", seal(state))
            _, files = read_matrix(output)
            proposal = files["poc-review/proposal.json"]
            old = proposal["context"]
            context, contents = poc_context(
                target,
                review,
                old["candidate"]["id"],
                old["byte_limit"],
                support_paths=old.get("support_paths", ()),
            )
            if context != old:
                raise ValueError("matrix review/source differs from approved PoC")
            check_reply(proposal["data"], context, contents)
            if (
                read_regular(spec_file.parent, spec_file.name) != raw
                or any(
                    read_regular(approval, name)
                    != read_regular(
                        output, "recipe.json" if name == "recipe.json" else "poc-review/" + name
                    )
                    for name in ("recipe.json", "review.json", "proposal.json")
                )
                or read_regular(fixed_file.parent, fixed_file.name)
                != read_regular(output, "fixed-recipe.json")
            ):
                raise ValueError("matrix inputs changed during preparation")
        except (Exception, KeyboardInterrupt) as error:
            state.update(
                status="failed", failure={"type": type(error).__name__, "detail": str(error)[:2000]}
            )
            save_json(
                output / "manifest.json",
                seal({k: v for k, v in state.items() if k != "identity_sha256"}),
            )
            raise
    return state


def validate_matrix(directory, *, max_runs=8, docker="docker", docker_host=None):
    directory = directory.resolve()
    if type(max_runs) is not int or not 0 <= max_runs <= 8:
        raise ValueError("matrix run budget must be between 0 and 8")
    with run_lock(directory):
        state, files = read_matrix(directory)
        if state["identity"]["tools"] != tool_identity():
            raise ValueError("matrix tools changed; prepare a new matrix")
        if (directory / "execution.json").exists() or (directory / "cases").exists():
            raise ValueError("matrix execution already started; no implicit restart")
        target, review = Path(state["target"]), Path(state["review"])
        old = files["poc-review/proposal.json"]["context"]
        context, _ = poc_context(
            target,
            review,
            old["candidate"]["id"],
            old["byte_limit"],
            support_paths=old.get("support_paths", ()),
        )
        if context != old:
            raise ValueError("matrix source/review changed before execution")
        execution = {
            "schema_version": 1,
            "status": "running",
            "matrix_sha256": state["identity_sha256"],
            "max_runs": max_runs,
            "run_attempts": 0,
            "cases": [
                {
                    **case,
                    "runs": {
                        phase: {"status": "not_started", "reason": "not_attempted"}
                        for phase in ("baseline", "fixed")
                    },
                }
                for case in files["matrix-input.json"]["cases"]
            ],
            "stop_reason": None,
        }
        for record in execution["cases"]:
            case = record
            for phase, recipe in (("baseline", "recipe.json"), ("fixed", "fixed-recipe.json")):
                if execution["stop_reason"] or execution["run_attempts"] >= max_runs:
                    execution["stop_reason"] = execution["stop_reason"] or "run_budget_exhausted"
                    record["runs"][phase] = {
                        "status": "not_started",
                        "reason": execution["stop_reason"],
                    }
                    continue
                try:
                    current, current_files = read_matrix(directory)
                    if current != state or current_files != files:
                        raise ValueError("frozen matrix changed during execution")
                except (Exception, KeyboardInterrupt) as error:
                    record["runs"][phase] = {
                        "status": "not_started",
                        "reason": "matrix_inputs_changed",
                        "type": type(error).__name__,
                    }
                    execution["stop_reason"] = "matrix_inputs_changed"
                    continue
                execution["run_attempts"] += 1
                record["runs"][phase] = {"status": "running"}
                save_json(directory / "execution.json", seal(execution))
                path = "cases/" + case["id"] + "/" + phase
                try:
                    result = validate(
                        target,
                        review,
                        directory / recipe,
                        directory / path,
                        image=case["image"],
                        docker=docker,
                        docker_host=docker_host,
                        poc_review=directory / "poc-review",
                        configuration_id=case["id"],
                    )
                    record["runs"][phase] = {
                        "path": path,
                        "result_sha256": result["identity_sha256"],
                        "status": result["status"],
                    }
                    if result["cleanup"]["status"] == "failed" or (
                        result["execution_attempted"]
                        and (result["exit_code"] is None or result["execution_started"] is not True)
                    ):
                        execution["stop_reason"] = "cleanup_or_execution_unknown"
                except (Exception, KeyboardInterrupt) as error:
                    record["runs"][phase] = {
                        "status": "controller_failed",
                        "type": type(error).__name__,
                    }
                    execution["stop_reason"] = "controller_failed"
                    if isinstance(error, KeyboardInterrupt):
                        execution["status"] = "interrupted"
                        save_json(directory / "execution.json", seal(execution))
                        raise
                save_json(directory / "execution.json", seal(execution))
        execution["status"] = "complete" if execution["stop_reason"] is None else "partial"
        save_json(directory / "execution.json", seal(execution))
    return execution


def judge_matrix(directory, output):
    directory, output = directory.resolve(), output.resolve()
    state, files = read_matrix(directory)
    if output.is_relative_to(directory) or output.is_relative_to(Path(state["target"])):
        raise ValueError("matrix judgment output must be outside target and matrix")
    execution = (
        read_sealed(directory, "execution.json")
        if (directory / "execution.json").exists()
        else None
    )
    if execution and (
        execution.get("matrix_sha256") != state["identity_sha256"]
        or execution.get("status") not in {"complete", "partial", "interrupted"}
        or type(execution.get("run_attempts")) is not int
        or type(execution.get("max_runs")) is not int
        or not 0 <= execution["run_attempts"] <= execution["max_runs"] <= 8
        or [{"id": c["id"], "image": c["image"]} for c in execution["cases"]]
        != files["matrix-input.json"]["cases"]
    ):
        raise ValueError("matrix execution is unfinished or differs from prepared cases")
    with run_lock(output):
        if any(p.name != ".lock" for p in output.iterdir()):
            raise ValueError("matrix judgment output is nonempty; use a new directory")
        report = {
            "schema_version": 1,
            "matrix_sha256": state["identity_sha256"],
            "cases": [],
            "validated_cases": [],
            "coverage_complete": False,
            "candidate": files["poc-review/proposal.json"]["context"]["candidate"],
            "poc_review": files["poc-review/review.json"],
            "execution_sha256": execution["identity_sha256"] if execution else None,
        }
        for number, case in enumerate(files["matrix-input.json"]["cases"]):
            record = {**case, "status": "missing", "verdict": "inconclusive", "judgment": None}
            record["issues"] = poc_issues(files["poc-review/proposal.json"])
            record["declared_configuration"] = next(
                c for c in files["recipe.json"]["configurations"] if c["id"] == case["id"]
            )
            report["cases"].append(record)
            try:
                if not execution:
                    record["reason"] = "matrix_not_executed"
                    continue
                runs = execution["cases"][number]["runs"]
                record["runs"] = runs
                if not all(runs.get(phase, {}).get("path") for phase in ("baseline", "fixed")):
                    record["reason"] = "before_or_after_run_missing"
                    record["runs"] = runs
                    continue
                workers = []
                for phase, recipe in (
                    ("baseline", files["recipe.json"]),
                    ("fixed", files["fixed-recipe.json"]),
                ):
                    relative = "cases/" + case["id"] + "/" + phase
                    if runs[phase]["path"] != relative:
                        raise ValueError("matrix worker path differs from declared case")
                    worker = read_worker(directory / relative)
                    identity = worker["result"].get("identity", {})
                    if (
                        worker["result"]["identity_sha256"] != runs[phase]["result_sha256"]
                        or worker["recipe"] != recipe
                        or worker["result"]["image"] != case["image"]
                        or identity.get("configuration_id") != case["id"]
                        or identity.get("poc_review_sha256")
                        != files["matrix-input.json"]["poc_review_sha256"]
                    ):
                        raise ValueError("matrix worker identity differs from declared inputs")
                    workers.append(worker["result"]["identity_sha256"])
                    del worker
                decision = judge(
                    directory / runs["baseline"]["path"],
                    output / case["id"],
                    fixed=directory / runs["fixed"]["path"],
                )
                if decision["status"] == "complete" and any(
                    decision["identity"][phase]["result_sha256"] != checksum
                    for phase, checksum in zip(("baseline", "fixed"), workers, strict=True)
                ):
                    raise ValueError("matrix worker changed during judgment")
                record.update(status="judged", verdict=decision["verdict"], judgment=decision)
                if decision["promotion"]["eligible"]:
                    report["validated_cases"].append(case["id"])
            except (Exception, KeyboardInterrupt) as error:
                record.update(
                    status="invalid",
                    reason={"type": type(error).__name__, "detail": str(error)[:2000]},
                )
        report["coverage_complete"] = all(
            c["status"] == "judged"
            and c["judgment"]["status"] == "complete"
            and all(
                run["reliable"] and run["configuration"]["applied"]
                for run in c["judgment"]["runs"].values()
            )
            for c in report["cases"]
        )
        report["note"] = (
            "Only observed cases are covered; missing/negative cases never establish safety."
        )
        current, current_files = read_matrix(directory)
        current_execution = read_sealed(directory, "execution.json") if execution else None
        if current != state or current_files != files or current_execution != execution:
            raise ValueError("matrix inputs changed during judgment")
        report = seal(report)
        save_json(output / "matrix-judgment.json", report)
    return report
