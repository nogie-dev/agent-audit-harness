"""PoC code stays data until an explicit, source-bound operator review."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from test_judgment import NEGATIVE, POSITIVE, reseal
from test_validation import IMAGE
from test_validation import engine as shared_engine

from agent_audit_harness.agents import ReplayAgent, Reply
from agent_audit_harness.cli import main
from agent_audit_harness.graph import build_graph
from agent_audit_harness.intake import import_review
from agent_audit_harness.judgment import candidate_issues, judge
from agent_audit_harness.pipeline import digest, encode, index_target
from agent_audit_harness.poc import poc_context, propose_poc, review_poc
from agent_audit_harness.recon import build_recon
from agent_audit_harness.static_analysis import DEFAULT_RULES, build_static
from agent_audit_harness.validation import validate

ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / "examples/poc-replay"
CID = "f-d71ac5092c87347c"


def read(path):
    return json.loads(path.read_text())


def write(path, data):
    path.write_text(encode(data))


class SuppliedAgent:
    identity = {"provider": "offline-test"}

    def __init__(self, change=None):
        self.change = change
        self.calls = 0

    def call(self, stage, slice_id, prompt, schema, directory):
        assert (stage, slice_id) == ("poc", "p0001")
        self.calls += 1
        data = read(REPLAY / "p0001.poc.json")
        if self.change:
            self.change(data, directory)
        return Reply(data, {"input_tokens": 10, "output_tokens": 20})


@pytest.fixture
def job(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(ROOT / "examples/judgment-target", target)
    review = tmp_path / "review"
    import_review(target, ROOT / "examples/candidate-import.json", review)
    return target, review, CID, tmp_path / "proposal"


@pytest.fixture
def engine(monkeypatch):
    return shared_engine.__wrapped__(monkeypatch)


def approve(job, *, agent=None, decision="approve", name="researcher"):
    target, review, _, proposal = job
    propose_poc(*job, agent or ReplayAgent(REPLAY))
    output = proposal.parent / name
    receipt = review_poc(
        target,
        review,
        proposal,
        output,
        decision=decision,
        reviewer="offline-fixture",
        rationale="Synthetic contract review; not an actual security approval.",
    )
    return output, receipt


def execute(job, engine, approved, *, fixed=False, name=None, mutate=None):
    recipe = read(approved / "recipe.json")
    if fixed:
        recipe["replacements"] = read(ROOT / "examples/intake-fixed-recipe.json")["replacements"]
    if mutate:
        mutate(recipe)
    name = name or ("fixed" if fixed else "baseline")
    recipe_file = approved.parent / f"{name}-recipe.json"
    write(recipe_file, recipe)
    output = approved.parent / name
    engine.stdout = NEGATIVE if fixed else POSITIVE
    result = validate(job[0], job[1], recipe_file, output, image=IMAGE, poc_review=approved)
    return output, result


def test_proposal_review_and_resume_preserve_raw_claims_without_host_execution(job, monkeypatch):
    original = {p.name: p.read_bytes() for p in job[0].iterdir()}

    def forbidden(*args, **kwargs):
        raise AssertionError("PoC proposal/review must not start a process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    agent = SuppliedAgent()
    state = propose_poc(*job, agent)
    proposal = read(job[3] / "proposal.json")
    assert state["status"] == "complete" and state["call_attempts"] == 1
    assert proposal["context"]["candidate"] == read(job[1] / "findings.json")[0]
    assert proposal["context"]["candidate"]["verdict"] == "uncertain"
    assert proposal["context"]["candidate_issues"] == candidate_issues(
        proposal["context"]["candidate"]
    )
    assert proposal["data"] == read(REPLAY / "p0001.poc.json")
    assert (job[3] / "calls/p0001.poc/attempt-0001/raw-response.json").exists()
    resumed = propose_poc(*job, agent, resume=True)
    assert resumed["cache_hit"] and agent.calls == 1
    assert resumed["reported_token_usage"] == {"input_tokens": 10, "output_tokens": 20}
    receipt = review_poc(
        job[0],
        job[1],
        job[3],
        job[3].parent / "rejected",
        decision="reject",
        reviewer="offline-fixture",
        rationale="This experiment is insufficient.",
    )
    assert receipt["decision"] == "reject"
    assert not (job[3].parent / "rejected/recipe.json").exists()
    assert original == {p.name: p.read_bytes() for p in job[0].iterdir()}


@pytest.mark.parametrize("paths", [("../secret",), ("app.sh",), ("missing.go",), ("x", "x")])
def test_poc_rejects_unreviewed_or_duplicate_support_file_before_agent_call(job, paths):
    agent = SuppliedAgent()
    with pytest.raises(ValueError, match="PoC support file"):
        propose_poc(*job, agent, support_paths=paths)
    assert agent.calls == 0


@pytest.mark.parametrize(
    "change",
    [
        "candidate",
        "recipe_candidate",
        "quote",
        "column",
        "self_approve",
        "validated",
        "replace",
        "review_hash",
        "input_hash",
        "duplicate_input",
        "unavailable_input",
        "attachment_hash",
        "unsafe_path",
        "credential_path",
        "duplicate_attachment",
        "nul",
        "oversize_bytes",
        "harness",
        "entry_quote",
        "resolution",
        "relative_command",
        "unresolved_quote",
        "raw_mismatch",
    ],
)
def test_untrusted_agent_reply_cannot_change_identity_or_approve_itself(job, change):
    def mutate(data, directory):
        recipe = data["recipe"]
        attachment = recipe["attachments"][0]
        if change == "candidate":
            data["candidate_id"] = "f-" + "0" * 16
        elif change == "recipe_candidate":
            recipe["candidate_id"] = "f-" + "0" * 16
        elif change == "quote":
            data["evidence"]["quote"] = "invented"
        elif change == "column":
            data["evidence"]["column"] = 1
        elif change in {"self_approve", "validated"}:
            data[change] = True
        elif change == "replace":
            recipe["replacements"] = []
        elif change == "review_hash":
            recipe["poc_review_sha256"] = "0" * 64
        elif change == "input_hash":
            recipe["inputs"][0]["sha256"] = "0" * 64
        elif change == "duplicate_input":
            recipe["inputs"].append(recipe["inputs"][0].copy())
        elif change == "unavailable_input":
            recipe["inputs"][0]["path"] = "probe.sh"
        elif change == "attachment_hash":
            attachment["sha256"] = "0" * 64
        elif change == "unsafe_path":
            attachment["path"] = "poc/../host.sh"
        elif change == "credential_path":
            attachment["path"] = "poc/credentials.json"
        elif change == "duplicate_attachment":
            recipe["attachments"].append(attachment.copy())
        elif change in {"nul", "oversize_bytes"}:
            attachment["content"] = "\0" if change == "nul" else "가" * 22000
            attachment["sha256"] = hashlib.sha256(attachment["content"].encode()).hexdigest()
        elif change == "harness":
            recipe["oracle"]["harness_path"] = "app.sh"
        elif change == "entry_quote":
            recipe["oracle"]["entrypoint"]["source"]["quote"] = "fake entrypoint"
        elif change == "resolution":
            recipe["oracle"]["resolutions"][0]["issue_id"] = "vi-" + "0" * 16
        elif change == "relative_command":
            recipe["command"][0] = "sh"
        elif change == "unresolved_quote":
            data["unresolved"] = [
                {"claim": "unknown", "evidence": {**data["evidence"], "quote": "fake"}}
            ]
        else:
            write(directory / "raw-response.json", {"different": "raw"})

    with pytest.raises(ValueError):
        propose_poc(*job, SuppliedAgent(mutate))
    assert read(job[3] / "manifest.json")["status"] == "failed"
    assert read(job[3] / "calls/p0001.poc/attempt-0001/failure.json")["type"] == (
        "CitationError" if change in {"column", "entry_quote", "unresolved_quote"} else "ValueError"
    )
    assert (job[3] / "calls/p0001.poc/attempt-0001/raw-response.json").exists()
    assert not (job[3] / "recipe-proposal.json").exists()


def test_timeout_attempt_and_budget_survive_resume(job):
    def timeout(data, directory):
        (directory / "stderr.log").write_text("bounded fixture timeout")
        raise TimeoutError("fixture timeout")

    agent = SuppliedAgent(timeout)
    with pytest.raises(TimeoutError):
        propose_poc(*job, agent)
    with pytest.raises(ValueError, match="budget exhausted"):
        propose_poc(*job, agent, resume=True)
    assert agent.calls == 1
    agent.change = None
    state = propose_poc(*job, agent, resume=True, max_calls=2)
    assert state["status"] == "complete" and state["call_attempts"] == 2
    assert read(job[3] / "calls/p0001.poc/attempt-0001/failure.json")["type"] == "TimeoutError"
    assert read(job[3] / "calls/p0001.poc/reply.json")["attempt"] == 2


@pytest.mark.parametrize("change", ["provider", "byte_budget"])
def test_changed_call_identity_does_not_reuse_or_overwrite_completed_evidence(job, change):
    agent = SuppliedAgent()
    propose_poc(*job, agent)
    saved = (job[3] / "manifest.json").read_bytes()
    options = {"resume": True}
    if change == "provider":
        agent.identity = {"provider": "different-offline-provider"}
    else:
        options["input_bytes"] = 32000
    with pytest.raises(ValueError, match="inputs changed"):
        propose_poc(*job, agent, **options)
    assert agent.calls == 1 and (job[3] / "manifest.json").read_bytes() == saved


@pytest.mark.parametrize(
    "file",
    [
        "proposal.json",
        "recipe-proposal.json",
        "calls/p0001.poc/reply.json",
        "calls/p0001.poc/attempt-0001/raw-response.json",
        "calls/p0001.poc/attempt-0001/prompt.txt",
    ],
)
def test_resume_and_researcher_review_reject_changed_saved_artifacts(job, file):
    agent = SuppliedAgent()
    propose_poc(*job, agent)
    path = job[3] / file
    path.write_text("changed prompt" if file.endswith(".txt") else "{}")
    with pytest.raises((ValueError, KeyError)):
        review_poc(
            job[0],
            job[1],
            job[3],
            job[3].parent / "receipt",
            decision="approve",
            reviewer="offline-fixture",
            rationale="fixture",
        )
    with pytest.raises((ValueError, KeyError)):
        propose_poc(*job, agent, resume=True)
    assert agent.calls == 1
    assert path.read_text() in {"changed prompt", "{}"}


@pytest.mark.parametrize("change", ["source", "review"])
def test_inputs_changed_during_proposal_cannot_finish(job, change):
    def mutate(data, directory):
        if change == "source":
            with (job[0] / "app.sh").open("a") as stream:
                stream.write("\n# changed during proposal\n")
        else:
            state = read(job[1] / "manifest.json")
            state["fixture_changed"] = True
            write(job[1] / "manifest.json", state)

    with pytest.raises(ValueError):
        propose_poc(*job, SuppliedAgent(mutate))
    assert read(job[3] / "manifest.json")["status"] == "failed"


@pytest.mark.parametrize("decision", ["approve", "reject", "request_changes"])
def test_researcher_decisions_bind_exact_inputs_and_preserve_proposal(job, decision):
    output, receipt = approve(job, decision=decision)
    proposal = read(job[3] / "proposal.json")
    assert receipt["proposal_sha256"] == proposal["identity_sha256"]
    assert receipt["candidate_sha256"] == digest(proposal["context"]["candidate"])
    assert receipt["source_index_sha256"] == proposal["context"]["source_index_sha256"]
    assert read(output / "proposal.json") == proposal
    assert (output / "recipe.json").exists() == (decision == "approve")
    if decision == "approve":
        assert read(output / "recipe.json")["poc_review_sha256"] == receipt["identity_sha256"]


@pytest.mark.parametrize(
    "case", ["unreviewed", "receipt", "code", "oracle", "unexecuted_source", "frozen_harness"]
)
def test_worker_rejects_unreviewed_or_changed_inputs_before_docker(job, engine, case):
    approved, _ = approve(job)
    recipe = read(approved / "recipe.json")
    if case == "receipt":
        receipt = read(approved / "review.json")
        receipt["decision"] = "reject"
        write(approved / "review.json", receipt)
    elif case == "code":
        attachment = recipe["attachments"][0]
        attachment["content"] += "\n# changed\n"
        attachment["sha256"] = hashlib.sha256(attachment["content"].encode()).hexdigest()
    elif case == "oracle":
        recipe["oracle"]["reproduced"]["line"] = "exit zero is enough"
    elif case == "unexecuted_source":
        (job[0] / "probe.sh").write_text("# changed although it is not executed\n")
    elif case == "frozen_harness":
        attachment = recipe["attachments"][0]
        recipe["replacements"] = [
            {
                "path": attachment["path"],
                "before_sha256": attachment["sha256"],
                "after_sha256": hashlib.sha256(b"changed").hexdigest(),
                "content": "changed",
            }
        ]
    file = approved.parent / "modified-recipe.json"
    write(file, recipe)
    result = validate(
        job[0],
        job[1],
        file,
        approved.parent / "worker",
        image=IMAGE,
        poc_review=None if case == "unreviewed" else approved,
    )
    assert result["status"] == "worker_failed" and result["failure"]["stage"] == "prepare"
    assert not result["execution_attempted"] and not engine.calls


def test_attachment_cannot_shadow_unexecuted_target_source(job, engine):
    (job[0] / "poc").mkdir()
    (job[0] / "poc/probe.sh").write_text("# target-owned file outside supplied fragments\n")
    sources, _ = index_target(job[0])
    spec = read(ROOT / "examples/candidate-import.json")
    spec["source_index_sha256"] = digest([s.metadata() for s in sources])
    spec_file, review = job[3].parent / "new-import.json", job[3].parent / "new-review"
    write(spec_file, spec)
    import_review(job[0], spec_file, review)
    updated_job = job[0], review, CID, job[3]

    def compatible_resolutions(data, directory):
        known = {i["id"] for i in candidate_issues(read(review / "findings.json")[0])}
        data["recipe"]["oracle"]["resolutions"] = [
            r for r in data["recipe"]["oracle"]["resolutions"] if r["issue_id"] in known
        ]

    approved, _ = approve(updated_job, agent=SuppliedAgent(compatible_resolutions))
    _, result = execute(updated_job, engine, approved)
    assert result["status"] == "worker_failed" and not result["execution_attempted"]
    assert "collides" in result["failure"]["detail"] and not engine.calls


def test_approved_attachment_reaches_worker_and_controlled_judgment_keeps_original_claim(
    job, engine
):
    original = read(job[1] / "findings.json")[0]
    approved, receipt = approve(job)
    baseline, first = execute(job, engine, approved)
    fixed, second = execute(job, engine, approved, fixed=True)
    assert first["status"] == second["status"] == "completed"
    assert first["confirmed_findings"] == second["confirmed_findings"] == 0
    attachment = read(approved / "recipe.json")["attachments"][0]
    assert (baseline / "input/poc/probe.sh").read_text() == attachment["content"]
    assert (baseline / "input/poc/probe.sh").stat().st_mode & 0o777 == 0o444
    assert read(baseline / "candidate.json") == original
    decision = judge(baseline, approved.parent / "judgment", fixed=fixed)
    assert decision["verdict"] == "validated" and decision["comparison"]["fix_verified"]
    assert decision["poc_review"] == receipt and decision["candidate"] == original
    assert all(issue["resolved"] for issue in decision["issues"])


@pytest.mark.parametrize("entry_kind", [None, "direct_call"])
def test_successful_proposal_run_without_real_entrypoint_is_not_promoted(job, engine, entry_kind):
    def direct(data, directory):
        if entry_kind is None:
            data["recipe"]["oracle"]["entrypoint"] = None
        else:
            data["recipe"]["oracle"]["entrypoint"]["kind"] = entry_kind

    approved, _ = approve(job, agent=SuppliedAgent(direct))
    baseline, _ = execute(job, engine, approved)
    fixed, _ = execute(job, engine, approved, fixed=True)
    decision = judge(baseline, approved.parent / "judgment", fixed=fixed)
    assert not decision["promotion"]["requirements"]["entrypoint"]
    assert not decision["promotion"]["eligible"] and decision["validated_findings"] == 0


@pytest.mark.parametrize("failure", [None, "timeout", "process", "cleanup"])
def test_proposal_unresolved_evidence_survives_comparison_timeout_and_failure(job, engine, failure):
    def unresolved(data, directory):
        data["unresolved"] = [
            {"claim": "Build applicability is unverified.", "evidence": data["evidence"].copy()}
        ]

    approved, receipt = approve(job, agent=SuppliedAgent(unresolved))
    if failure == "timeout":
        engine.reason = "timeout"
    elif failure == "process":
        engine.exit_code = 1
    elif failure == "cleanup":
        engine.fail_stage = "cleanup"
    baseline, result = execute(job, engine, approved)
    fixed = execute(job, engine, approved, fixed=True)[0] if failure is None else None
    decision = judge(baseline, approved.parent / "judgment", fixed=fixed)
    assert decision["status"] == "complete" and not decision["promotion"]["eligible"]
    issue = next(i for i in decision["issues"] if i["kind"] == "poc_unresolved")
    assert not issue["resolved"] and issue["detail"]["evidence"]["source_sha256"]
    assert decision["poc_review"] == receipt
    assert read(baseline / "poc-proposal.json")["data"]["unresolved"]
    if failure == "timeout":
        assert result["status"] == "timeout"
    elif failure == "process":
        assert result["status"] == "process_failed"
    elif failure == "cleanup":
        assert result["cleanup"]["status"] == "failed"
    else:
        assert decision["comparison"]["fix_verified"]


@pytest.mark.parametrize("file", ["poc-review.json", "poc-proposal.json", "input/poc/probe.sh"])
def test_judge_rejects_changed_worker_evidence_even_with_resealed_outer_record(job, engine, file):
    approved, _ = approve(job)
    baseline, _ = execute(job, engine, approved)
    if file.endswith(".sh"):
        (baseline / file).chmod(0o644)
        (baseline / file).write_text("# altered supplied harness\n")
    else:
        data = read(baseline / file)
        data["decision" if file == "poc-review.json" else "schema_version"] = "changed"
        write(baseline / file, data)
    reseal(baseline, lambda result: None)
    decision = judge(baseline, approved.parent / "judgment")
    assert decision["status"] == "failed" and decision["validated_findings"] == 0


def test_a_different_operator_approval_makes_runs_incomparable(job, engine):
    approved, _ = approve(job)
    baseline, _ = execute(job, engine, approved)
    second = approved.parent / "second-review"
    review_poc(
        job[0],
        job[1],
        job[3],
        second,
        decision="approve",
        reviewer="another-fixture",
        rationale="Different review identity.",
    )
    fixed, _ = execute(job, engine, second, fixed=True)
    decision = judge(baseline, approved.parent / "judgment", fixed=fixed)
    assert not decision["comparison"]["comparable"] and not decision["promotion"]["eligible"]


def test_query_discovered_candidate_window_is_verified_and_bounded(job):
    slices = read(job[1] / "slices.json")
    fragment = slices[0]["fragments"][0]
    fragment.update(
        first_line=1, last_line=1, text=(job[0] / "app.sh").read_text().splitlines(True)[0]
    )
    write(job[1] / "slices.json", slices)
    context, _ = poc_context(job[0], job[1], CID, 16000)
    assert any(f["first_line"] <= 5 <= f["last_line"] for f in context["source_slice"]["fragments"])
    fragment["text"] = "forged saved fragment\n"
    write(job[1] / "slices.json", slices)
    with pytest.raises(ValueError, match="fragment differs"):
        propose_poc(*job, SuppliedAgent())


def test_long_verified_review_fragments_are_split_without_silent_source_loss(job):
    long_source = "# source padding\n" * 450
    (job[0] / "long.py").write_text(long_source)
    sources, _ = index_target(job[0])
    spec = read(ROOT / "examples/candidate-import.json")
    spec["source_index_sha256"] = digest([s.metadata() for s in sources])
    source = next(s for s in sources if s.path == "long.py")
    spec["fragments"].append(
        {"path": source.path, "first_line": 1, "last_line": 200, "sha256": source.sha256}
    )
    spec_file, review = job[3].parent / "import-long.json", job[3].parent / "long-review"
    write(spec_file, spec)
    import_review(job[0], spec_file, review)
    slices = read(review / "slices.json")
    fragment = next(f for f in slices[0]["fragments"] if f["path"] == "long.py")
    fragment.update(last_line=450, text=long_source)
    write(review / "slices.json", slices)
    context, _ = poc_context(job[0], review, CID, 64000)
    fragments = [f for f in context["source_slice"]["fragments"] if f["path"] == "long.py"]
    assert [(f["first_line"], f["last_line"]) for f in fragments] == [
        (1, 200),
        (201, 400),
        (401, 450),
    ]
    assert "".join(f["text"] for f in fragments) == long_source


def test_go_context_retains_multiple_files_configuration_and_external_gaps(tmp_path):
    if not shutil.which("go"):
        pytest.skip("Go toolchain required")
    from agent_audit_harness.pipeline import run_pipeline

    target, graph_dir, recon_dir, review = [
        tmp_path / p for p in ("target", "graph", "recon", "review")
    ]
    shutil.copytree(ROOT / "examples/go-http-target", target)
    graph = build_graph(target, graph_dir, language="go")
    build_recon(target, graph_dir / "graph.json", ROOT / "examples/go-http-plan.json", recon_dir)
    run_pipeline(
        target,
        review,
        ReplayAgent(ROOT / "examples/go-http-replay"),
        graph_file=graph_dir / "graph.json",
        recon_file=recon_dir / "recon.json",
    )
    candidate = read(review / "findings.json")[0]
    context, contents = poc_context(target, review, candidate["id"], 64000)
    assert context["graph_sha256"] == graph["identity_sha256"]
    assert "go.mod" in contents and len(context["source_slice"]["fragments"]) > 1
    assert any(i["kind"] == "external_call_ids" for i in context["additional_issues"])
    assert context["configuration"][0]["sha256"] == hashlib.sha256(contents["go.mod"]).hexdigest()
    with (target / "go.mod").open("a") as stream:
        stream.write("\n// changed config\n")
    with pytest.raises(ValueError, match="configuration"):
        poc_context(target, review, candidate["id"], 64000)


def test_partial_python_static_context_preserves_full_owner_gaps_and_omissions(tmp_path):
    if not (ROOT / ".cache/semgrep/semgrep-core").is_file():
        pytest.skip("run make setup-static")
    target = tmp_path / "target"
    shutil.copytree(ROOT / "examples/static-target", target)
    graph_file, static_file, review = (
        tmp_path / "graph/graph.json",
        tmp_path / "static/static.json",
        tmp_path / "review",
    )
    build_graph(target, graph_file.parent, language="python")
    build_static(target, graph_file, DEFAULT_RULES, static_file.parent)
    import_review(
        target,
        ROOT / "examples/static-candidate-import.json",
        review,
        graph_file=graph_file,
        static_file=static_file,
    )
    candidate = read(review / "findings.json")[0]
    context, _ = poc_context(target, review, candidate["id"], 64000)
    assert context["static_sha256"] == read(static_file)["identity_sha256"]
    assert len(context["source_slice"]["fragments"][0]["text"].splitlines()) == 1
    assert context["omissions"] and context["source_slice"]["omitted_counts"]
    assert {i["kind"] for i in context["additional_issues"]} >= {
        "unresolved_call_ids",
        "static_gap_ids",
        "omitted_counts",
    }


def test_cli_proposal_resume_and_explicit_review(job, capsys):
    base = [
        "poc",
        str(job[0]),
        "--run",
        str(job[1]),
        "--candidate",
        CID,
        "--replay",
        str(REPLAY),
        "--output",
        str(job[3]),
    ]
    assert main(base) == main(base + ["--resume"]) == 0
    output = job[3].parent / "cli-review"
    assert (
        main(
            [
                "poc-review",
                str(job[0]),
                "--run",
                str(job[1]),
                "--proposal",
                str(job[3]),
                "--decision",
                "request_changes",
                "--reviewer",
                "offline-fixture",
                "--rationale",
                "Needs source-backed controls",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert read(output / "review.json")["decision"] == "request_changes"
    assert not (output / "recipe.json").exists()
    assert '"cache_hit": true' in capsys.readouterr().out


@pytest.mark.parametrize(
    "case", ["input_budget", "call_budget", "unfinished", "inside", "nonempty"]
)
def test_preflight_limits_prevent_agent_calls_and_preserve_existing_data(job, case):
    agent = SuppliedAgent()
    args, options = list(job), {}
    if case == "input_budget":
        options["input_bytes"] = 1024
    elif case == "call_budget":
        options["max_calls"] = 17
    elif case == "unfinished":
        state = read(job[1] / "manifest.json")
        state["status"] = "failed"
        write(job[1] / "manifest.json", state)
    elif case == "inside":
        args[3] = job[0] / "proposal"
    else:
        job[3].mkdir()
        (job[3] / "sentinel").write_text("preserve")
    with pytest.raises(ValueError):
        propose_poc(*args, agent, **options)
    assert agent.calls == 0
    if case == "nonempty":
        assert (job[3] / "sentinel").read_text() == "preserve"
