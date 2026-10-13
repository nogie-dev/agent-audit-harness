"""Review a frozen chain experiment and judge its isolated worker observations."""

import base64
import binascii
import hashlib
import json
import tempfile
from pathlib import Path

from .chain import prepare_chain, source_snapshot
from .judgment import check_oracle, evaluate_run, observe, read_worker, source_proof
from .pipeline import RESOURCES, digest, run_lock, save_json, source_lines, validate_shape
from .poc import poc_issues, verify_review
from .validation import attachment_sources, execution_command, read_regular


def read_chain(directory):
    chain = json.loads(read_regular(directory, "chain.json"))
    if (
        chain.get("status") != "hypothesis"
        or chain.get("connection") != "unobserved"
        or chain.get("identity_sha256")
        != digest({key: value for key, value in chain.items() if key != "identity_sha256"})
    ):
        raise ValueError("chain hypothesis is unfinished or changed")
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix="chain-recheck-") as temporary:
        fresh = prepare_chain(
            *(Path(item["judgment"]) for item in chain["individual_primitives"]),
            directory / "hypothesis-input.json",
            Path(temporary) / "chain",
        )
    if fresh != chain:
        raise ValueError("chain hypothesis differs from independently checked primitives")
    runs = [
        read_worker(
            Path(
                json.loads(read_regular(Path(item["judgment"]), "judgment.json"))["inputs"][
                    "baseline"
                ]
            )
        )
        for item in chain["individual_primitives"]
    ]
    return chain, runs


def checked_experiment(chain, runs, poc_review, plan):
    receipt = json.loads(read_regular(poc_review, "review.json"))
    proposal = json.loads(read_regular(poc_review, "proposal.json"))
    recipe = json.loads(read_regular(poc_review, "recipe.json"))
    second = runs[1]
    identity = second["result"]["identity"]
    context = proposal["context"]
    if (
        context["target"] != second["result"]["target"]
        or context["candidate"] != second["candidate"]
        or receipt["review_sha256"] != identity["review_sha256"]
        or receipt["queue_sha256"] != identity["queue_sha256"]
        or recipe["candidate_id"] != chain["hypothesis"]["sequence"][1]
        or recipe.get("replacements")
    ):
        raise ValueError("chain experiment differs from the second validated primitive")
    verify_review(
        receipt,
        proposal,
        recipe,
        second["candidate"],
        identity["review_sha256"],
        identity["queue_sha256"],
        receipt["source_index_sha256"],
    )
    execution_command(recipe, identity.get("configuration_id"))
    source = source_snapshot(runs[0]) | source_snapshot(second)
    for item in recipe["inputs"]:
        data = source.get(item["path"])
        if data is None or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("chain experiment input differs from validated source")
    first_source = runs[0]["candidate"]["path"]
    if first_source not in {item["path"] for item in recipe["inputs"]}:
        raise ValueError("chain experiment omits the first primitive source")
    sources = source | attachment_sources(recipe, set(source))
    check_oracle(recipe, second["candidate"], sources, sources, issues=poc_issues(proposal))
    oracle = recipe["oracle"]
    if oracle["entrypoint"] is None or oracle["entrypoint"]["kind"] != "entrypoint":
        raise ValueError("chain experiment requires a real second entrypoint oracle")
    observations = plan["observations"]
    stream = oracle["reproduced"]["stream"]
    if (
        any(value["stream"] != stream for value in observations.values())
        or oracle["entrypoint"]["observation"]["stream"] != stream
        or oracle["completed"]["stream"] != stream
        or observations["first_entrypoint"] == oracle["entrypoint"]["observation"]
        or observations["producer_prefix"]["prefix"] == observations["consumer_prefix"]["prefix"]
        or observations["producer_prefix"]["prefix"].startswith(
            observations["consumer_prefix"]["prefix"]
        )
        or observations["consumer_prefix"]["prefix"].startswith(
            observations["producer_prefix"]["prefix"]
        )
    ):
        raise ValueError("chain observations must be distinct and ordered on one stream")
    markers = [
        observations["first_entrypoint"]["line"],
        observations["control_denied"]["line"],
        *(oracle[key]["line"] for key in ("reproduced", "not_reproduced", "completed")),
        oracle["entrypoint"]["observation"]["line"],
    ]
    if len(set(markers)) != len(markers) or any(
        marker.startswith(observations[key]["prefix"])
        for marker in markers
        for key in ("producer_prefix", "consumer_prefix")
    ):
        raise ValueError("chain outcome or entrypoint aliases a transfer observation")
    harness = oracle["harness_path"]
    if any(item["path"] != harness for item in plan["harness"].values()):
        raise ValueError("chain experiment citations must use the unchanged supplied harness")
    proofs = {key: source_proof(item, sources) for key, item in plan["harness"].items()}
    if plan["first_entrypoint_source"]["path"] not in source_snapshot(runs[0]):
        raise ValueError("first entrypoint source is outside its validated snapshot")
    proofs["first_entrypoint_source"] = source_proof(
        plan["first_entrypoint_source"], source_snapshot(runs[0])
    )
    for key, length in (
        ("resolve_unresolved", len(chain["hypothesis"]["unresolved"])),
        ("resolve_prerequisites", len(chain["hypothesis"]["prerequisites"])),
    ):
        indices = [item["index"] for item in plan[key]]
        if len(indices) != len(set(indices)) or any(index >= length for index in indices):
            raise ValueError("chain resolution refers to an absent or duplicate claim")
    return receipt, proposal, recipe, proofs


def review_chain(chain_dir, poc_review, plan_file, output, *, decision, reviewer, rationale):
    chain_dir, poc_review, plan_file, output = (
        path.resolve() for path in (chain_dir, poc_review, plan_file, output)
    )
    chain, runs = read_chain(chain_dir)
    target = Path(runs[0]["result"]["target"])
    if (
        decision not in {"approve", "reject", "request_changes"}
        or not reviewer.strip()
        or not rationale.strip()
        or any(output.is_relative_to(path) for path in (target, chain_dir, poc_review))
        or plan_file.is_relative_to(target)
    ):
        raise ValueError("invalid chain review decision or artifact boundary")
    raw = read_regular(plan_file.parent, plan_file.name)
    plan = json.loads(raw)
    validate_shape(
        "chain experiment",
        plan,
        json.loads((RESOURCES / "schemas/chain-experiment.json").read_text()),
    )
    poc_receipt, proposal, recipe, proofs = checked_experiment(chain, runs, poc_review, plan)
    record = {
        "schema_version": 1,
        "decision": decision,
        "reviewer": reviewer,
        "rationale": rationale,
        "chain_sha256": chain["identity_sha256"],
        "poc_review": str(poc_review),
        "poc_review_sha256": poc_receipt["identity_sha256"],
        "poc_proposal_sha256": proposal["identity_sha256"],
        "recipe_sha256": digest(recipe),
        "plan_sha256": hashlib.sha256(raw).hexdigest(),
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_proofs": proofs,
    }
    record["identity_sha256"] = digest(record)
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("chain review output is nonempty; use a new directory")
        (output / "experiment-input.json").write_bytes(raw)
        for name, data in (
            ("review.json", poc_receipt),
            ("proposal.json", proposal),
            ("recipe.json", recipe),
        ):
            save_json(output / "poc-review" / name, data)
        save_json(output / "chain-review.json", record)
    return record


def read_chain_review(chain_dir, directory):
    saved = json.loads(read_regular(directory, "chain-review.json"))
    if saved.get("identity_sha256") != digest(
        {key: value for key, value in saved.items() if key != "identity_sha256"}
    ):
        raise ValueError("chain researcher review identity is invalid")
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix="review-recheck-") as temporary:
        fresh = review_chain(
            chain_dir,
            Path(saved["poc_review"]),
            directory / "experiment-input.json",
            Path(temporary) / "review",
            decision=saved["decision"],
            reviewer=saved["reviewer"],
            rationale=saved["rationale"],
        )
    if fresh != saved or any(
        json.loads(read_regular(directory / "poc-review", name))
        != json.loads(read_regular(Path(saved["poc_review"]), name))
        for name in ("review.json", "proposal.json", "recipe.json")
    ):
        raise ValueError("chain review differs from approved frozen experiment")
    return saved, json.loads(read_regular(directory, "experiment-input.json"))


def observe_prefix(run, marker):
    path = "logs/execute." + marker["stream"] + ".log"
    data = run["files"][path]
    found = []
    for number, line in enumerate(source_lines(data.decode("utf-8")), 1):
        if not line.endswith("\n") or not line.rstrip("\r\n").startswith(marker["prefix"]):
            continue
        encoded = line.rstrip("\r\n")[len(marker["prefix"]) :]
        try:
            value = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            value = b""
        if not 1 <= len(value) <= 4096 or base64.b64encode(value).decode() != encoded:
            found.append({"line": number, "valid": False})
        else:
            found.append(
                {
                    "line": number,
                    "valid": True,
                    "bytes": len(value),
                    "value_sha256": hashlib.sha256(value).hexdigest(),
                }
            )
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "matches": found,
        "unique": len(found) == 1 and found[0]["valid"],
    }


def judge_chain(chain_dir, review_dir, worker_dir, output):
    chain_dir, review_dir, worker_dir, output = (
        path.resolve() for path in (chain_dir, review_dir, worker_dir, output)
    )
    if any(output.is_relative_to(path) for path in (chain_dir, review_dir, worker_dir)):
        raise ValueError("chain judgment output must be outside all input artifacts")
    worker_hint = json.loads(read_regular(worker_dir, "result.json"))
    if output.is_relative_to(Path(worker_hint["target"]).resolve()):
        raise ValueError("chain judgment output must be outside the target")
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("chain judgment output is nonempty; use a new directory")
        decision = {
            "schema_version": 1,
            "status": "failed",
            "verdict": "inconclusive",
            "connection_observed": False,
            "impact_validated": False,
            "blockers": [],
            "failure": None,
            "inputs": {
                "chain": str(chain_dir),
                "review": str(review_dir),
                "worker": str(worker_dir),
            },
        }
        try:
            chain, primitives = read_chain(chain_dir)
            review, plan = read_chain_review(chain_dir, review_dir)
            if review["decision"] != "approve":
                raise ValueError("chain experiment lacks explicit researcher approval")
            worker = read_worker(worker_dir)
            result = worker["result"]
            identity = result.get("identity", {})
            original = primitives[1]["result"]
            expected = json.loads(read_regular(review_dir / "poc-review", "recipe.json"))
            if (
                worker["candidate"] != primitives[1]["candidate"]
                or worker["recipe"] != expected
                or identity.get("recipe_sha256") != digest(expected)
                or identity.get("poc_review_sha256") != review["poc_review_sha256"]
                or identity.get("poc_proposal_sha256") != review["poc_proposal_sha256"]
                or any(
                    identity.get(key) != original["identity"].get(key)
                    for key in ("review_sha256", "queue_sha256", "configuration_id")
                )
                or result["target"] != original["target"]
                or result["image"] != original["image"]
            ):
                raise ValueError("chain worker differs from reviewed primitive or experiment")
            evaluation = evaluate_run(worker)
            decision.update(
                chain_sha256=chain["identity_sha256"],
                review_sha256=review["identity_sha256"],
                worker={
                    "directory": str(worker_dir),
                    "result_sha256": result["identity_sha256"],
                    "status": result["status"],
                    "failure": result["failure"],
                },
                individual_primitives=chain["individual_primitives"],
                evaluation=evaluation,
                hypothesis=chain["hypothesis"],
            )
            blockers = decision["blockers"]
            blockers.extend(evaluation["blockers"])
            if not evaluation["reliable"] or evaluation["outcome"] != "reproduced":
                blockers.append("combined_reproduction_not_observed")
            if not evaluation["entrypoint_reached"]:
                blockers.append("second_entrypoint_not_observed")
            observations = {}
            if result["status"] in {"completed", "process_failed"}:
                spec = plan["observations"]
                observations = {
                    "first_entrypoint": observe(worker, spec["first_entrypoint"]),
                    "producer": observe_prefix(worker, spec["producer_prefix"]),
                    "consumer": observe_prefix(worker, spec["consumer_prefix"]),
                    "control_denied": observe(worker, spec["control_denied"]),
                }
                second = evaluation["observations"].get("entrypoint", {})
                outcome = evaluation["observations"].get("reproduced", {})
                complete = evaluation["observations"].get("completed", {})
                points = [
                    observations["first_entrypoint"]["lines"],
                    [item["line"] for item in observations["producer"]["matches"]],
                    [item["line"] for item in observations["consumer"]["matches"]],
                    second.get("lines", []),
                    outcome.get("lines", []),
                    complete.get("lines", []),
                ]
                if (
                    not all(len(group) == 1 for group in points)
                    or not observations["producer"]["unique"]
                    or not observations["consumer"]["unique"]
                    or not all(a[0] < b[0] for a, b in zip(points, points[1:], strict=False))
                    or observations["producer"]["matches"][0].get("value_sha256")
                    != observations["consumer"]["matches"][0].get("value_sha256")
                    or observations["producer"]["matches"][0].get("bytes")
                    != observations["consumer"]["matches"][0].get("bytes")
                ):
                    blockers.append("state_transfer_or_order_unverified")
                control = observations["control_denied"]["lines"]
                if (
                    len(control) != 1
                    or len(outcome.get("lines", [])) != 1
                    or len(complete.get("lines", [])) != 1
                    or not outcome["lines"][0] < control[0] < complete["lines"][0]
                ):
                    blockers.append("state_dependence_unverified")
            else:
                blockers.append("combined_worker_did_not_complete")
            decision["observations"] = observations
            transfer = not blockers
            resolutions = {
                key: {item["index"]: item for item in plan[key]}
                for key in ("resolve_unresolved", "resolve_prerequisites")
            }
            decision["issues"] = {
                "unresolved": [
                    {
                        "claim": claim,
                        "resolved": transfer and index in resolutions["resolve_unresolved"],
                        "resolution": resolutions["resolve_unresolved"].get(index),
                    }
                    for index, claim in enumerate(chain["hypothesis"]["unresolved"])
                ],
                "prerequisites": [
                    {
                        **item,
                        "resolved": transfer and index in resolutions["resolve_prerequisites"],
                        "resolution": resolutions["resolve_prerequisites"].get(index),
                    }
                    for index, item in enumerate(chain["hypothesis"]["prerequisites"])
                ],
                "counterevidence": chain["hypothesis"]["counterevidence"],
            }
            if transfer and any(
                not item["resolved"]
                for key in ("unresolved", "prerequisites")
                for item in decision["issues"][key]
            ):
                blockers.append("open_chain_issue")
            if chain["hypothesis"]["counterevidence"]:
                blockers.append("unresolved_chain_counterevidence")
            decision["connection_observed"] = transfer
            decision["verdict"] = (
                "connected"
                if not blockers
                else "observed_with_open_issues"
                if transfer
                else "inconclusive"
                if not evaluation["reliable"]
                else "not_observed"
            )
            decision["status"] = "complete"
        except (Exception, KeyboardInterrupt) as error:
            decision["failure"] = {"type": type(error).__name__, "detail": str(error)[:2000]}
            decision["blockers"].append("invalid_or_incomplete_evidence")
        decision["identity_sha256"] = digest(decision)
        save_json(output / "chain-judgment.json", decision)
        return decision
