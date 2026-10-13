"""Source-bound PoC proposals and operator review records; code remains data here."""

import hashlib
import json
import time

from .agents import strip_optional_nulls
from .intake import intake_frame
from .judgment import candidate_issues, check_oracle
from .pipeline import (
    RESOURCES,
    digest,
    encode,
    index_target,
    run_lock,
    save_json,
    save_text,
    source_lines,
    validate_evidence,
    validate_shape,
)
from .recon import current_graph
from .static_analysis import read_static
from .triage import checked_evidence, input_gaps
from .validation import attachment_sources, read_regular, read_source, review_candidate


def poc_context(target, review, candidate_id, byte_limit, *, support_paths=()):
    if not 1024 <= byte_limit <= 64000:
        raise ValueError("PoC input bytes must be between 1024 and 64000")
    candidate, manifest, queue, _ = review_candidate(target, review, candidate_id)
    sources, skipped = index_target(target)
    index = [s.metadata() for s in sources]
    if index != manifest["identity"]["source_index"]:
        raise ValueError("PoC source index differs from review")
    artifacts = {}
    if manifest["identity"].get("graph_sha256"):
        artifacts["graph"] = current_graph(target, review / "graph.json", sources)
        if artifacts["graph"]["identity_sha256"] != manifest["identity"]["graph_sha256"]:
            raise ValueError("PoC graph differs from review")
    if manifest["identity"].get("static_sha256"):
        artifacts["static"] = read_static(review / "static.json", artifacts["graph"], sources)
        if artifacts["static"]["identity_sha256"] != manifest["identity"]["static_sha256"]:
            raise ValueError("PoC static evidence differs from review")
    slices = json.loads(read_regular(review, "slices.json", 8 * 1024 * 1024))
    selected = next((s for s in slices if s["id"] == candidate["slice_id"]), None)
    if selected is None:
        raise ValueError("PoC candidate slice is missing")
    fragments = selected.get("fragments", [selected])
    source_map = {s.path: s for s in sources}
    ranges = []
    for item in fragments:
        source = source_map.get(item["path"])
        if source is None or source.sha256 != item["source_sha256"]:
            raise ValueError("PoC saved fragment source hash differs")
        lines = source_lines(source.text)
        if not 1 <= item["first_line"] <= item["last_line"] <= len(lines):
            raise ValueError("PoC saved fragment range is invalid")
        if item["text"] != "".join(lines[item["first_line"] - 1 : item["last_line"]]):
            raise ValueError("PoC saved fragment differs from source")
        ranges.append({k: item[k] for k in ("path", "first_line", "last_line")})
        ranges[-1]["sha256"] = source.sha256
    try:
        validate_evidence(candidate, fragments)
    except ValueError:
        source = source_map[candidate["path"]]
        lines = source_lines(source.text)
        validate_evidence(
            candidate,
            [{"path": source.path, "first_line": 1, "last_line": len(lines), "text": source.text}],
        )
        first = max(1, candidate["line"] - 20)
        last = min(len(lines), candidate["line"] + max(20, len(source_lines(candidate["quote"]))))
        if last - first >= 200:
            raise ValueError("PoC candidate quote exceeds bounded source range") from None
        from .recon import merge_fragments

        merged = merge_fragments(
            [
                {
                    "id": str(i),
                    "path": r["path"],
                    "line": r["first_line"],
                    "end_line": r["last_line"],
                }
                for i, r in enumerate(ranges)
            ]
            + [{"id": "candidate", "path": source.path, "line": first, "end_line": last}],
            source_map,
        )
        ranges = [
            {
                "path": f["path"],
                "first_line": f["first_line"],
                "last_line": f["last_line"],
                "sha256": f["source_sha256"],
            }
            for f in merged
        ]
    bounded = []
    quote_end = candidate["line"] + len(source_lines(candidate["quote"])) - 1
    for item in ranges:
        first = item["first_line"]
        while first <= item["last_line"]:
            last = min(first + 199, item["last_line"])
            if item["path"] == candidate["path"] and first <= candidate["line"] <= last < quote_end:
                last = candidate["line"] - 1
            if last < first:
                raise ValueError("PoC candidate quote exceeds bounded source range")
            bounded.append({**item, "first_line": first, "last_line": last})
            first = last + 1
    if len(bounded) > 32:
        raise ValueError("PoC source context exceeds 32 bounded ranges")
    spec = {"fragments": bounded}
    if "hypothesis_id" in candidate:
        spec["hypothesis_id"] = candidate["hypothesis_id"]
    frame, omissions = intake_frame(spec, sources, byte_limit, artifacts)
    config = []
    for item in artifacts.get("graph", {}).get("input_config", []):
        config.append({**item, "text": read_source(target, item["path"]).decode()})
    files = {
        s.path: s.metadata() for s in sources if s.path in {f["path"] for f in frame["fragments"]}
    }
    for item in config:
        files[item["path"]] = {"path": item["path"], "sha256": item["sha256"]}
    if (
        len(support_paths) > 16
        or any(type(path) is not str for path in support_paths)
        or len(set(support_paths)) != len(support_paths)
    ):
        raise ValueError("PoC support files must be distinct and limited to 16")
    support_bytes = 0
    for path in support_paths:
        source = source_map.get(path)
        if source is None or path in files:
            raise ValueError("PoC support file must be a reviewed source outside the slice")
        support_bytes += len(source.text.encode("utf-8"))
        if support_bytes > 256 * 1024:
            raise ValueError("PoC support files exceed 256 KiB")
        files[path] = source.metadata()
    context = {
        "target": str(target),
        "review_sha256": digest(manifest),
        "queue_sha256": digest(queue),
        "source_index_sha256": digest(index),
        "skipped_sha256": digest(skipped),
        "graph_sha256": artifacts.get("graph", {}).get("identity_sha256"),
        "static_sha256": artifacts.get("static", {}).get("identity_sha256"),
        "candidate": candidate,
        "candidate_issues": candidate_issues(candidate),
        "source_slice": frame,
        "configuration": config,
        "input_files": list(files.values()),
        "byte_limit": byte_limit,
        "omissions": omissions,
        "additional_issues": candidate_issues({"input_gaps": input_gaps(frame, artifacts)}),
    }
    if support_paths:
        context["support_paths"] = list(support_paths)
    if len(encode(context).encode()) > byte_limit:
        raise ValueError("PoC context exceeds input byte budget; use a larger explicit budget")
    contents = {path: read_source(target, path) for path in files}
    return context, contents


def check_reply(data, context, contents):
    schema = json.loads((RESOURCES / "schemas/poc-proposal.json").read_text())
    validate_shape("PoC proposal", data, schema)
    if len(encode(data).encode()) > 128 * 1024:
        raise ValueError("PoC response exceeds 128 KiB")
    candidate, frame, recipe = context["candidate"], context["source_slice"], data["recipe"]
    if data["candidate_id"] != candidate["id"] or recipe["candidate_id"] != candidate["id"]:
        raise ValueError("PoC proposal candidate differs")
    proof = data["evidence"]
    if any(proof[k] != candidate[k] for k in ("path", "line", "quote")):
        raise ValueError("PoC proposal must cite its candidate occurrence")
    checked_evidence(proof, frame)
    if recipe["oracle"]["source"] != proof:
        raise ValueError("PoC oracle must freeze the candidate source evidence")
    for item in data["unresolved"]:
        if item["evidence"] is not None:
            checked_evidence(item["evidence"], frame)
    available = {item["path"]: item["sha256"] for item in context["input_files"]}
    seen = {}
    for item in recipe["inputs"]:
        path = item["path"]
        if path in seen or available.get(path) != item["sha256"]:
            raise ValueError("PoC recipe input is duplicate, unavailable or its hash differs")
        if path not in contents or hashlib.sha256(contents[path]).hexdigest() != item["sha256"]:
            raise ValueError("PoC source contents differ")
        seen[path] = contents[path]
    if candidate["path"] not in seen:
        raise ValueError("PoC recipe must include candidate source")
    seen.update(attachment_sources(recipe, available))
    if recipe["oracle"]["harness_path"] not in {a["path"] for a in recipe["attachments"]}:
        raise ValueError("PoC oracle must use its supplied attachment harness")
    entry = recipe["oracle"]["entrypoint"]
    if entry is not None:
        checked_evidence(entry["source"], frame)
    for item in recipe.get("configurations", []):
        checked_evidence(item["source"], frame)
    if not recipe["command"][0].startswith("/") or any("\0" in arg for arg in recipe["command"]):
        raise ValueError("PoC command must use an absolute container executable without NUL")
    check_oracle(
        recipe, candidate, seen, seen, issues=poc_issues({"context": context, "data": data})
    )
    return data


def poc_issues(proposal):
    context, data = proposal["context"], proposal["data"]
    issues = candidate_issues(context["candidate"]) + context["additional_issues"]
    for item in data["unresolved"]:
        detail = {
            **item,
            "evidence": checked_evidence(item["evidence"], context["source_slice"])
            if item["evidence"] is not None
            else None,
        }
        issue = {"kind": "poc_unresolved", "detail": detail}
        issues.append({"id": "vi-" + digest(issue)[:16], **issue})
    return list({i["id"]: i for i in sorted(issues, key=lambda i: i["id"])}.values())


def verify_proposal(proposal):
    if (
        not isinstance(proposal, dict)
        or set(proposal) != {"schema_version", "identity", "context", "data", "identity_sha256"}
        or not isinstance(proposal["identity"], dict)
        or not isinstance(proposal["context"], dict)
        or proposal["schema_version"] != 1
        or proposal["identity_sha256"]
        != digest({k: v for k, v in proposal.items() if k != "identity_sha256"})
        or proposal["identity"].get("context_sha256") != digest(proposal["context"])
    ):
        raise ValueError("PoC proposal identity is invalid")
    validate_shape(
        "PoC proposal",
        proposal["data"],
        json.loads((RESOURCES / "schemas/poc-proposal.json").read_text()),
    )


def verify_review(receipt, proposal, recipe, candidate, review_hash, queue_hash, source_index_hash):
    validate_shape(
        "PoC researcher review",
        receipt,
        json.loads((RESOURCES / "schemas/poc-review.json").read_text()),
    )
    verify_proposal(proposal)
    context = proposal["context"]
    base = {k: v for k, v in recipe.items() if k not in {"replacements", "poc_review_sha256"}}
    expected = {
        "proposal_sha256": proposal["identity_sha256"],
        "candidate_sha256": digest(candidate),
        "review_sha256": review_hash,
        "queue_sha256": queue_hash,
        "source_index_sha256": source_index_hash,
        "recipe_sha256": digest(base),
    }
    if (
        receipt["decision"] != "approve"
        or receipt["identity_sha256"]
        != digest({k: v for k, v in receipt.items() if k != "identity_sha256"})
        or recipe.get("poc_review_sha256") != receipt["identity_sha256"]
        or any(receipt[key] != value for key, value in expected.items())
        or base != proposal["data"]["recipe"]
        or context["candidate"] != candidate
        or any(
            context[key] != expected[key]
            for key in ("review_sha256", "queue_sha256", "source_index_sha256")
        )
    ):
        raise ValueError(
            "PoC researcher review is unapproved, changed or bound to different inputs"
        )


def read_poc_reply(output, identity, attempts):
    if type(attempts) is not int or not 0 <= attempts <= 16:
        raise ValueError("invalid PoC attempt counter")
    directory = output / "calls/p0001.poc"
    record = json.loads(read_regular(directory, "reply.json"))
    if (
        set(record) != {"input_sha256", "reply_sha256", "data", "attempt", "raw_sha256", "usage"}
        or record["input_sha256"] != identity["prompt_sha256"]
        or record["reply_sha256"] != digest(record["data"])
        or type(record["attempt"]) is not int
        or not 1 <= record["attempt"] <= attempts
    ):
        raise ValueError("invalid cached PoC reply")
    attempt = directory / f"attempt-{record['attempt']:04d}"
    raw = read_regular(attempt, "raw-response.json")
    if (
        hashlib.sha256(raw).hexdigest() != record["raw_sha256"]
        or json.loads(raw) != record["data"]
        or digest(read_regular(attempt, "prompt.txt").decode()) != identity["prompt_sha256"]
    ):
        raise ValueError("cached PoC raw response or prompt changed")
    return record


def propose_poc(
    target,
    review,
    candidate_id,
    output,
    agent,
    *,
    input_bytes=16000,
    max_calls=1,
    resume=False,
    support_paths=(),
):
    target, review, output = target.resolve(), review.resolve(), output.resolve()
    if (
        review.is_relative_to(target)
        or output.is_relative_to(target)
        or output.is_relative_to(review)
    ):
        raise ValueError("PoC review/output must be outside target; output must be outside review")
    if not 1 <= max_calls <= 16:
        raise ValueError("PoC max calls must be between 1 and 16")
    context, contents = poc_context(
        target, review, candidate_id, input_bytes, support_paths=support_paths
    )
    schema = json.loads((RESOURCES / "schemas/poc-proposal.json").read_text())
    prompt = (
        (RESOURCES / "prompts/poc.md").read_text() + "\nUNTRUSTED_INPUT_JSON:\n" + encode(context)
    )
    identity = {
        "context_sha256": digest(context),
        "provider": agent.identity,
        "prompt_sha256": digest(prompt),
        "schema_sha256": digest(schema),
        "tools_sha256": digest(
            {
                name: hashlib.sha256((RESOURCES / name).read_bytes()).hexdigest()
                for name in (
                    "poc.py",
                    "intake.py",
                    "pipeline.py",
                    "triage.py",
                    "recon.py",
                    "graph.py",
                    "static_analysis.py",
                    "validation.py",
                    "judgment.py",
                    "agents.py",
                    "schemas/validation-recipe.json",
                    "schemas/poc-review.json",
                )
            }
        ),
    }
    manifest = output / "manifest.json"
    with run_lock(output):
        if resume:
            state = json.loads(read_regular(output, "manifest.json"))
            if (
                state.get("identity") != identity
                or json.loads(read_regular(output, "context.json")) != context
            ):
                raise ValueError("PoC inputs changed; use a new directory")
            if type(state.get("call_attempts")) is not int or not 0 <= state["call_attempts"] <= 16:
                raise ValueError("invalid PoC attempt counter")
        else:
            if any(p.name != ".lock" for p in output.iterdir()):
                raise ValueError("PoC output is nonempty; use --resume or a new directory")
            state = {"identity": identity, "call_attempts": 0}
            save_json(output / "context.json", context)
        state["status"] = "running"
        save_json(manifest, state)
        checkpoint = output / "calls/p0001.poc/reply.json"
        hit = checkpoint.exists()
        try:
            if hit:
                record = read_poc_reply(output, identity, state["call_attempts"])
                reply = check_reply(record["data"], context, contents)
            else:
                if state["call_attempts"] >= max_calls:
                    raise ValueError("PoC call budget exhausted; resume with higher --max-calls")
                state["call_attempts"] += 1
                save_json(manifest, state)
                attempt = checkpoint.parent / f"attempt-{state['call_attempts']:04d}"
                save_text(attempt / "prompt.txt", prompt)
                started = time.monotonic()
                try:
                    response = agent.call("poc", "p0001", prompt, schema, attempt)
                    if not (attempt / "raw-response.json").exists():
                        save_json(attempt / "raw-response.json", response.data)
                    reply = check_reply(response.data, context, contents)
                    if (
                        strip_optional_nulls(
                            json.loads(read_regular(attempt, "raw-response.json")), schema
                        )
                        != reply
                    ):
                        raise ValueError("PoC raw response differs from structured reply")
                except (Exception, KeyboardInterrupt) as error:
                    save_json(
                        attempt / "failure.json",
                        {
                            "type": type(error).__name__,
                            "elapsed_seconds": time.monotonic() - started,
                        },
                    )
                    raise
                save_json(
                    checkpoint,
                    {
                        "input_sha256": digest(prompt),
                        "reply_sha256": digest(reply),
                        "data": reply,
                        "attempt": state["call_attempts"],
                        "usage": response.usage,
                        "raw_sha256": hashlib.sha256(
                            read_regular(attempt, "raw-response.json")
                        ).hexdigest(),
                    },
                )
            proposal = {
                "schema_version": 1,
                "identity": identity,
                "context": context,
                "data": reply,
            }
            proposal["identity_sha256"] = digest(proposal)
            if state.get("result_sha256") and (
                state["result_sha256"] != proposal["identity_sha256"]
                or json.loads(read_regular(output, "proposal.json")) != proposal
                or json.loads(read_regular(output, "recipe-proposal.json")) != reply["recipe"]
            ):
                raise ValueError("saved PoC result changed")
            current, current_contents = poc_context(
                target, review, candidate_id, input_bytes, support_paths=support_paths
            )
            if current != context or current_contents != contents:
                raise ValueError("PoC input changed during proposal")
            save_json(output / "proposal.json", proposal)
            save_json(output / "recipe-proposal.json", reply["recipe"])
            state.update(
                status="complete",
                cache_hit=hit,
                result_sha256=proposal["identity_sha256"],
                reported_token_usage=record["usage"] if hit else response.usage,
            )
            save_json(manifest, state)
        except (Exception, KeyboardInterrupt) as error:
            state.update(
                status="failed", failure={"type": type(error).__name__, "detail": str(error)[:8000]}
            )
            save_json(manifest, state)
            raise
    return state


def review_poc(target, review, proposal_dir, output, *, decision, reviewer, rationale):
    target, review, proposal_dir, output = (
        p.resolve() for p in (target, review, proposal_dir, output)
    )
    if (
        review.is_relative_to(target)
        or proposal_dir.is_relative_to(target)
        or proposal_dir.is_relative_to(review)
        or output.is_relative_to(target)
        or output.is_relative_to(review)
        or output.is_relative_to(proposal_dir)
    ):
        raise ValueError("PoC researcher artifacts must be outside target/review/proposal")
    proposal = json.loads(read_regular(proposal_dir, "proposal.json"))
    verify_proposal(proposal)
    old = proposal["context"]
    context, contents = poc_context(
        target,
        review,
        old["candidate"]["id"],
        old["byte_limit"],
        support_paths=old.get("support_paths", ()),
    )
    if context != old:
        raise ValueError("PoC proposal inputs changed before researcher review")
    state = json.loads(read_regular(proposal_dir, "manifest.json"))
    if (
        state["status"] != "complete"
        or state["identity"] != proposal["identity"]
        or state["result_sha256"] != proposal["identity_sha256"]
        or read_poc_reply(proposal_dir, state["identity"], state["call_attempts"])["data"]
        != proposal["data"]
    ):
        raise ValueError("PoC proposal is unfinished or changed")
    if json.loads(read_regular(proposal_dir, "recipe-proposal.json")) != proposal["data"]["recipe"]:
        raise ValueError("PoC recipe proposal changed before researcher review")
    check_reply(proposal["data"], context, contents)
    receipt = {
        "schema_version": 1,
        "decision": decision,
        "reviewer": reviewer,
        "rationale": rationale,
        "proposal_sha256": proposal["identity_sha256"],
        "candidate_sha256": digest(context["candidate"]),
        **{key: context[key] for key in ("review_sha256", "queue_sha256", "source_index_sha256")},
        "recipe_sha256": digest(proposal["data"]["recipe"]),
    }
    receipt["identity_sha256"] = digest(receipt)
    validate_shape(
        "PoC researcher review",
        receipt,
        json.loads((RESOURCES / "schemas/poc-review.json").read_text()),
    )
    with run_lock(output):
        if any(p.name != ".lock" for p in output.iterdir()):
            raise ValueError("PoC researcher output is nonempty; use a new directory")
        save_json(output / "proposal.json", proposal)
        save_json(output / "review.json", receipt)
        if decision == "approve":
            save_json(
                output / "recipe.json",
                {**proposal["data"]["recipe"], "poc_review_sha256": receipt["identity_sha256"]},
            )
    return receipt
