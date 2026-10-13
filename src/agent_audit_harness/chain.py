"""Bind two independently validated primitives to a source-backed chain hypothesis."""

import hashlib
import json
import tempfile
from pathlib import Path

from .judgment import judge, read_worker, source_proof
from .pipeline import RESOURCES, digest, run_lock, save_json, validate_shape
from .validation import read_regular


def verified_primitive(path, scratch):
    saved = json.loads(read_regular(path, "judgment.json"))
    if not isinstance(saved, dict) or saved.get("identity_sha256") != digest(
        {key: value for key, value in saved.items() if key != "identity_sha256"}
    ):
        raise ValueError("chain judgment identity is invalid")
    if (
        saved.get("status") != "complete"
        or saved.get("verdict") != "validated"
        or saved.get("validated_findings") != 1
        or saved.get("promotion", {}).get("eligible") is not True
        or any(not issue.get("resolved") for issue in saved.get("issues", []))
    ):
        raise ValueError("chain requires a fully validated primitive")
    inputs = saved["inputs"]
    if not inputs.get("fixed"):
        raise ValueError("chain primitive requires a controlled fix comparison")
    fresh = judge(Path(inputs["baseline"]), scratch, fixed=Path(inputs["fixed"]))
    if fresh != saved:
        raise ValueError("chain judgment differs from independently checked worker evidence")
    run = read_worker(Path(inputs["baseline"]))
    return saved, run


def source_snapshot(run):
    return {item["path"]: run["files"]["input/" + item["path"]] for item in run["recipe"]["inputs"]}


def selected_settings(run):
    selected = run["result"]["identity"].get("configuration_id")
    if selected is None:
        return None
    return next(
        item["settings"]
        for item in run["recipe"].get("configurations", [])
        if item["id"] == selected
    )


def prepare_chain(first, second, spec_file, output):
    first, second, spec_file, output = (
        path.resolve() for path in (first, second, spec_file, output)
    )
    if first == second or any(output.is_relative_to(path) for path in (first, second)):
        raise ValueError("chain output must be separate from both judgments")
    for path in (first, second):
        saved = json.loads(read_regular(path, "judgment.json"))
        baseline = Path(saved["inputs"]["baseline"])
        worker = json.loads(read_regular(baseline, "result.json"))
        target = Path(worker["target"]).resolve()
        if output.is_relative_to(target) or spec_file.is_relative_to(target):
            raise ValueError("chain spec and output must be outside the target")
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("chain output is nonempty; use a new directory")
        state = {"schema_version": 1, "status": "preparing", "connection": "unobserved"}
        save_json(output / "chain.json", state)
        try:
            raw = read_regular(spec_file.parent, spec_file.name)
            (output / "hypothesis-input.json").write_bytes(raw)
            spec = json.loads(raw)
            validate_shape(
                "chain hypothesis",
                spec,
                json.loads((RESOURCES / "schemas/chain-hypothesis.json").read_text()),
            )
            with tempfile.TemporaryDirectory(dir=output, prefix="recheck-") as temporary:
                root = Path(temporary)
                first_decision, first_run = verified_primitive(first, root / "first")
                second_decision, second_run = verified_primitive(second, root / "second")
            runs = (first_run, second_run)
            if spec["sequence"] != [run["candidate"]["id"] for run in runs]:
                raise ValueError("chain sequence differs from validated candidate order")
            identities = [run["result"]["identity"] for run in runs]
            common = ("review_sha256", "queue_sha256", "image", "configuration_id")
            if (
                runs[0]["candidate"]["id"] == runs[1]["candidate"]["id"]
                or runs[0]["result"]["target"] != runs[1]["result"]["target"]
                or any(identities[0].get(key) != identities[1].get(key) for key in common)
                or selected_settings(runs[0]) != selected_settings(runs[1])
            ):
                raise ValueError("chain primitives do not share a target, review, or configuration")
            sources = [source_snapshot(run) for run in runs]
            for path in sources[0].keys() & sources[1].keys():
                if sources[0][path] != sources[1][path]:
                    raise ValueError("chain primitive source snapshots disagree")

            def proof(at, evidence):
                if evidence["path"] not in sources[at]:
                    raise ValueError("chain citation is outside the validated worker snapshot")
                return source_proof(evidence, sources[at])

            proofs = {
                "producer": proof(0, spec["state"]["producer"]),
                "consumer": proof(1, spec["state"]["consumer"]),
                "prerequisites": [
                    proof(0 if item["at"] == "first" else 1, item["source"])
                    if item["source"]
                    else None
                    for item in spec["prerequisites"]
                ],
                "counterevidence": [
                    proof(0 if item["at"] == "first" else 1, item["source"])
                    if item["source"]
                    else None
                    for item in spec["counterevidence"]
                ],
            }
            state = {
                "schema_version": 1,
                "status": "hypothesis",
                "connection": "unobserved",
                "individual_primitives": [
                    {
                        "candidate_id": run["candidate"]["id"],
                        "judgment": str(path),
                        "judgment_sha256": decision["identity_sha256"],
                        "baseline_result_sha256": run["result"]["identity_sha256"],
                        "configuration_id": run["result"]["identity"].get("configuration_id"),
                    }
                    for path, decision, run in zip(
                        (first, second), (first_decision, second_decision), runs, strict=True
                    )
                ],
                "hypothesis": spec,
                "source_proofs": proofs,
                "identity": {
                    "spec_sha256": hashlib.sha256(raw).hexdigest(),
                    "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "schema_sha256": hashlib.sha256(
                        (RESOURCES / "schemas/chain-hypothesis.json").read_bytes()
                    ).hexdigest(),
                },
            }
            state["identity_sha256"] = digest(state)
            save_json(output / "chain.json", state)
            return state
        except (Exception, KeyboardInterrupt) as error:
            state.update(
                status="failed", failure={"type": type(error).__name__, "detail": str(error)[:2000]}
            )
            save_json(output / "chain.json", state)
            raise
