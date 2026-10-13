"""Freeze researcher-reviewed impact gates over validated, source-bound inputs."""

import hashlib
import json
import tempfile
from pathlib import Path

from .chain import selected_settings, source_snapshot, verified_primitive
from .chain_experiment import judge_chain, read_chain
from .judgment import check_oracle, source_proof
from .pipeline import RESOURCES, digest, run_lock, save_json, validate_shape
from .poc import poc_issues, verify_review
from .validation import attachment_sources, execution_command, read_regular


def verified_input(kind, path):
    if kind not in {"primitive", "chain"}:
        raise ValueError("impact input must be a validated primitive or connected chain")
    name = "judgment.json" if kind == "primitive" else "chain-judgment.json"
    saved = json.loads(read_regular(path, name))
    if not isinstance(saved, dict) or not isinstance(saved.get("inputs"), dict):
        raise ValueError("impact input judgment is malformed")
    inputs = saved["inputs"]
    worker_reference = inputs.get("baseline" if kind == "primitive" else "worker")
    if not isinstance(worker_reference, str) or not worker_reference:
        raise ValueError("impact input lacks an original worker reference")
    worker_dir = Path(worker_reference)
    if not worker_dir.is_absolute():
        raise ValueError("impact input lacks an absolute original worker reference")
    worker_hint = json.loads(read_regular(worker_dir, "result.json"))
    if not isinstance(worker_hint, dict) or not isinstance(worker_hint.get("target"), str):
        raise ValueError("impact original worker target is malformed")
    target = Path(worker_hint["target"]).resolve()
    if path.is_relative_to(target):
        raise ValueError("impact input artifact must be outside the target")
    with tempfile.TemporaryDirectory(dir=path.parent, prefix="impact-input-") as temporary:
        if kind == "primitive":
            decision, run = verified_primitive(path, Path(temporary) / "judgment")
            runs = [run]
            candidate = run["candidate"]
            identity = run["result"]["identity"]
            base_hash = decision["identity_sha256"]
        else:
            if (
                saved.get("status") != "complete"
                or saved.get("verdict") != "connected"
                or saved.get("connection_observed") is not True
                or saved.get("impact_validated") is not False
            ):
                raise ValueError("impact requires a connected chain with no open issues")
            if any(
                not isinstance(inputs.get(key), str) or not inputs[key]
                for key in ("chain", "review")
            ):
                raise ValueError("impact chain lacks original review references")
            fresh = judge_chain(
                Path(inputs["chain"]),
                Path(inputs["review"]),
                worker_dir,
                Path(temporary) / "judgment",
            )
            if fresh != saved:
                raise ValueError("impact chain judgment differs from original evidence")
            chain, runs = read_chain(Path(inputs["chain"]))
            if saved["chain_sha256"] != chain["identity_sha256"]:
                raise ValueError("impact chain identity differs")
            candidate = runs[-1]["candidate"]
            identity = runs[-1]["result"]["identity"]
            base_hash = saved["identity_sha256"]
    sources = {}
    for run in runs:
        for name, data in source_snapshot(run).items():
            if name in sources and sources[name] != data:
                raise ValueError("impact primitive source snapshots disagree")
            sources[name] = data
    protected = {path, worker_dir}
    if kind == "primitive":
        protected.add(Path(inputs["fixed"]))
    else:
        protected.update(Path(inputs[key]) for key in ("chain", "review"))
        for item in chain["individual_primitives"]:
            judgment = Path(item["judgment"])
            protected.add(judgment)
            original = json.loads(read_regular(judgment, "judgment.json"))["inputs"]
            protected.update(Path(original[key]) for key in ("baseline", "fixed"))
    return {
        "kind": kind,
        "path": str(path),
        "sha256": base_hash,
        "target": str(target),
        "image": runs[-1]["result"]["image"],
        "candidate": candidate,
        "candidate_source_paths": [run["candidate"]["path"] for run in runs],
        "identity": identity,
        "configuration_settings": selected_settings(runs[-1]),
        "sources": sources,
        "protected_paths": sorted(protected),
    }


def checked_stage(stage, base):
    directory = Path(stage["poc_review"])
    if not directory.is_absolute() or directory.resolve().is_relative_to(Path(base["target"])):
        raise ValueError("impact stage PoC review must be absolute and outside the target")
    directory = directory.resolve()
    receipt = json.loads(read_regular(directory, "review.json"))
    proposal = json.loads(read_regular(directory, "proposal.json"))
    recipe = json.loads(read_regular(directory, "recipe.json"))
    if not all(isinstance(item, dict) for item in (receipt, proposal, recipe)):
        raise ValueError("impact stage PoC artifacts are malformed")
    identity = base["identity"]
    verify_review(
        receipt,
        proposal,
        recipe,
        base["candidate"],
        identity["review_sha256"],
        identity["queue_sha256"],
        receipt.get("source_index_sha256"),
    )
    context = proposal["context"]
    if (
        context["target"] != base["target"]
        or context["candidate"] != base["candidate"]
        or receipt["review_sha256"] != identity["review_sha256"]
        or receipt["queue_sha256"] != identity["queue_sha256"]
        or recipe["candidate_id"] != base["candidate"]["id"]
        or recipe.get("replacements")
    ):
        raise ValueError("impact stage differs from validated source and candidate")
    execution_command(recipe, identity.get("configuration_id"))
    selected = identity.get("configuration_id")
    stage_settings = (
        next(
            item["settings"] for item in recipe.get("configurations", []) if item["id"] == selected
        )
        if selected
        else None
    )
    if stage_settings != base["configuration_settings"]:
        raise ValueError("impact stage configuration settings differ from validated input")
    # shortcut: only validated snapshots; use a reviewed source index when new files are needed.
    inputs = {item["path"] for item in recipe["inputs"]}
    if not set(base["candidate_source_paths"]) <= inputs or stage["source"]["path"] not in inputs:
        raise ValueError("impact stage omits primitive or property source")
    for item in recipe["inputs"]:
        data = base["sources"].get(item["path"])
        if data is None or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("impact stage source differs from validated snapshot")
    sources = base["sources"] | attachment_sources(recipe, set(base["sources"]))
    proofs = check_oracle(recipe, base["candidate"], sources, sources, issues=poc_issues(proposal))
    entry = recipe["oracle"]["entrypoint"]
    if entry is None or entry["kind"] != "entrypoint":
        raise ValueError("impact stage must observe a real target entrypoint")
    proofs["property"] = source_proof(stage["source"], base["sources"])
    marker = stage["harness_observation"]
    if (
        marker["path"] != recipe["oracle"]["harness_path"]
        or recipe["oracle"][stage["expected_outcome"]]["line"] not in marker["quote"]
    ):
        raise ValueError("impact gate marker must cite its supplied harness observation")
    proofs["harness_observation"] = source_proof(marker, sources)
    return directory, receipt, proposal, recipe, proofs


def review_impact(kind, input_dir, plan_file, output, *, decision, reviewer, rationale):
    input_dir, plan_file, output = (path.resolve() for path in (input_dir, plan_file, output))
    base = verified_input(kind, input_dir)
    target = Path(base["target"])
    if (
        decision not in {"approve", "reject", "request_changes"}
        or not reviewer.strip()
        or not rationale.strip()
        or output.is_relative_to(target)
        or output.is_relative_to(input_dir)
        or plan_file.is_relative_to(target)
        or any(
            output.is_relative_to(path) or plan_file.is_relative_to(path)
            for path in base["protected_paths"]
        )
    ):
        raise ValueError("invalid impact review decision or artifact boundary")
    raw = read_regular(plan_file.parent, plan_file.name)
    plan = json.loads(raw)
    validate_shape(
        "impact plan",
        plan,
        json.loads((RESOURCES / "schemas/impact-plan.json").read_text()),
    )
    stages = plan["stages"]
    kinds = [item["kind"] for item in stages]
    ids = [item["id"] for item in stages]
    if (
        len(ids) != len(set(ids))
        or kinds[0] != "setup"
        or kinds[1] != "primitive"
        or kinds[-1] != "impact"
        or kinds.count("control") != 1
        or kinds.index("control") < 2
        or any(kind not in {"measurement", "control"} for kind in kinds[2:-1])
        or any(
            item["expected_outcome"]
            != ("not_reproduced" if item["kind"] == "control" else "reproduced")
            for item in stages
        )
    ):
        raise ValueError("impact stages must be ordered setup, primitive, control, impact")
    if plan["security_property"]["source"]["path"] not in base["sources"]:
        raise ValueError("impact security property is outside validated source")
    counter_proofs = [
        source_proof(item["source"], base["sources"]) if item["source"] else None
        for item in plan["counterevidence"]
    ]
    resolutions = plan["resolutions"]
    references = [(item["kind"], item["index"]) for item in resolutions]
    if len(references) != len(set(references)) or any(
        item["index"] >= len(plan[item["kind"]]) or item["stage_id"] not in ids
        for item in resolutions
    ):
        raise ValueError("impact resolution refers to an absent or duplicate claim")
    property_proof = source_proof(plan["security_property"]["source"], base["sources"])
    checked = [checked_stage(stage, base) for stage in stages]
    poc_ids = [receipt["identity_sha256"] for _, receipt, _, _, _ in checked]
    recipes = [digest(recipe) for _, _, _, recipe, _ in checked]
    if len(set(poc_ids)) != len(poc_ids) or len(set(recipes)) != len(recipes):
        raise ValueError("impact stages require distinct approved PoC recipes")
    record = {
        "schema_version": 1,
        "status": "reviewed",
        "decision": decision,
        "reviewer": reviewer,
        "rationale": rationale,
        "input": {key: base[key] for key in ("kind", "path", "sha256", "target", "image")},
        "candidate_id": base["candidate"]["id"],
        "plan_sha256": hashlib.sha256(raw).hexdigest(),
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "schema_sha256": hashlib.sha256(
            (RESOURCES / "schemas/impact-plan.json").read_bytes()
        ).hexdigest(),
        "property_proof": property_proof,
        "counterevidence_proofs": counter_proofs,
        "stages": [
            {
                "id": stage["id"],
                "kind": stage["kind"],
                "poc_review": str(directory),
                "poc_review_sha256": receipt["identity_sha256"],
                "poc_proposal_sha256": proposal["identity_sha256"],
                "recipe_sha256": digest(recipe),
                "source_proofs": proofs,
            }
            for stage, (directory, receipt, proposal, recipe, proofs) in zip(
                stages, checked, strict=True
            )
        ],
    }
    record["identity_sha256"] = digest(record)
    if any(output.is_relative_to(directory) for directory, *_ in checked):
        raise ValueError("impact review output must be outside PoC review artifacts")
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("impact review output is nonempty; use a new directory")
        (output / "plan-input.json").write_bytes(raw)
        for stage, (_, receipt, proposal, recipe, _) in zip(stages, checked, strict=True):
            for name, data in (
                ("review.json", receipt),
                ("proposal.json", proposal),
                ("recipe.json", recipe),
            ):
                save_json(output / "stages" / stage["id"] / "poc-review" / name, data)
        save_json(output / "impact-review.json", record)
    return record
