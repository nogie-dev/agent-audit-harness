"""One Go HTTP fixture connects the graph, review, worker, and judgment contracts."""

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from test_validation import IMAGE as FIXTURE_IMAGE
from test_validation import engine as shared_engine

from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.cli import main
from agent_audit_harness.graph import build_graph, reachable
from agent_audit_harness.judgment import candidate_issues, judge
from agent_audit_harness.pipeline import encode, run_pipeline
from agent_audit_harness.poc import review_poc
from agent_audit_harness.recon import build_recon
from agent_audit_harness.validation import prepare_inputs, validate

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples/go-http-target"
IMAGE = os.environ.get("AUDIT_GO_VALIDATION_IMAGE")
DOCKER_HOST = os.environ.get("AUDIT_GO_DOCKER_HOST")
pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain is required")


def read(path):
    return json.loads(path.read_text())


@pytest.fixture
def fake_engine(monkeypatch):
    return shared_engine.__wrapped__(monkeypatch)


@pytest.fixture
def scenario(tmp_path, request):
    target = tmp_path / "target"
    shutil.copytree(TARGET, target)
    if getattr(request, "param", None) == "go.sum":
        (target / "go.sum").write_text("")
    graph_dir = tmp_path / "graph"
    graph = build_graph(target, graph_dir, language="go")
    recon_dir = tmp_path / "recon"
    recon = build_recon(
        target, graph_dir / "graph.json", ROOT / "examples/go-http-plan.json", recon_dir
    )
    review = tmp_path / "review"
    first = run_pipeline(
        target,
        review,
        ReplayAgent(ROOT / "examples/go-http-replay"),
        graph_file=graph_dir / "graph.json",
        recon_file=recon_dir / "recon.json",
    )
    resumed = run_pipeline(
        target,
        review,
        ReplayAgent(ROOT / "examples/go-http-replay"),
        graph_file=graph_dir / "graph.json",
        recon_file=recon_dir / "recon.json",
        resume=True,
    )
    return target, graph, recon, review, first, resumed


@pytest.fixture
def reviewed_go_poc(scenario, tmp_path):
    target, graph, _, review, _, _ = scenario
    candidate = read(review / "findings.json")[0]
    proposal = tmp_path / "poc-proposal"
    assert (
        main(
            [
                "poc",
                str(target),
                "--run",
                str(review),
                "--candidate",
                candidate["id"],
                "--replay",
                str(ROOT / "examples/go-http-poc-replay"),
                "--input-bytes",
                "32000",
                "--support-file",
                "cmd/server/main.go",
                "--support-file",
                "probe.sh",
                "--output",
                str(proposal),
            ]
        )
        == 0
    )
    state = read(proposal / "manifest.json")
    assert state["status"] == "complete"
    context = read(proposal / "context.json")
    assert context["graph_sha256"] == graph["identity_sha256"]
    assert context["support_paths"] == ["cmd/server/main.go", "probe.sh"]
    approved = tmp_path / "poc-approved"
    receipt = review_poc(
        target,
        review,
        proposal,
        approved,
        decision="approve",
        reviewer="offline-fixture",
        rationale="Synthetic contract review; no target execution or real approval.",
    )
    assert receipt["decision"] == "approve"
    return target, review, approved


def test_go_graph_to_reviewed_poc_worker_and_judgment_contract(
    reviewed_go_poc, tmp_path, fake_engine
):
    target, review, approved = reviewed_go_poc
    original = (target / "web/handler.go").read_bytes()
    recipe = read(approved / "recipe.json")
    assert recipe["oracle"]["harness_path"] == "poc/probe.sh"
    assert recipe["attachments"][0]["content"] == (target / "probe.sh").read_text()
    limits = recipe["limits"]

    def go_policy(policy):
        host = policy["host"]
        host["Memory"] = host["MemorySwap"] = limits["memory_mb"] * 1024 * 1024
        host["NanoCpus"] = int(limits["cpus"] * 1e9)
        host["PidsLimit"] = limits["pids"]
        host["Tmpfs"]["/work"] = (
            f"rw,exec,nosuid,nodev,size={limits['scratch_mb']}m,uid=65532,gid=65532,mode=700"
        )

    fake_engine.policy_change = go_policy
    jobs = []
    for revision, stdout in (
        (
            "baseline",
            'TARGET guest stdout "ENTRY HTTP /private\\n"\n'
            'HTTP guest status 200\nHTTP guest body "DATA private-record\\n"\n'
            'HTTP admin body "DATA private-record\\n"\nCONTROL admin passed\n'
            "ORACLE unauthorized-read\nCHECK complete\n",
        ),
        (
            "fixed",
            'TARGET guest stdout "ENTRY HTTP /private\\n"\n'
            'HTTP guest status 403\nHTTP guest body "DENIED\\n"\n'
            'HTTP admin body "DATA private-record\\n"\nCONTROL admin passed\n'
            "ORACLE access-denied\nCHECK complete\n",
        ),
    ):
        selected = {**recipe}
        if revision == "fixed":
            selected["replacements"] = read(ROOT / "examples/go-http-fixed-recipe.json")[
                "replacements"
            ]
        recipe_file = tmp_path / f"{revision}-reviewed-recipe.json"
        recipe_file.write_text(encode(selected))
        output = tmp_path / f"reviewed-{revision}"
        fake_engine.stdout = stdout
        result = validate(
            target, review, recipe_file, output, image=FIXTURE_IMAGE, poc_review=approved
        )
        assert result["status"] == "completed" and result["confirmed_findings"] == 0
        assert result["cleanup"]["status"] == "removed"
        jobs.append(output)
    decision = judge(jobs[0], tmp_path / "reviewed-judgment", fixed=jobs[1])
    assert decision["verdict"] == "validated" and decision["promotion"]["eligible"]
    assert decision["candidate"]["verdict"] == "uncertain"
    assert all(issue["resolved"] and issue["evidence_refs"] for issue in decision["issues"])
    assert (target / "web/handler.go").read_bytes() == original


def test_reviewed_go_poc_rejects_changed_source_before_worker(
    reviewed_go_poc, tmp_path, fake_engine
):
    target, review, approved = reviewed_go_poc
    path = target / "cmd/server/main.go"
    path.write_text(path.read_text() + "\n// changed after review\n")
    result = validate(
        target,
        review,
        approved / "recipe.json",
        tmp_path / "stale-worker",
        image=FIXTURE_IMAGE,
        poc_review=approved,
    )
    assert result["status"] == "worker_failed" and not result["execution_attempted"]
    assert not fake_engine.calls


@pytest.mark.skipif(
    not IMAGE, reason="set AUDIT_GO_VALIDATION_IMAGE to a prepared local Go image ID"
)
def test_real_reviewed_go_poc_before_after_and_judgment(reviewed_go_poc, tmp_path):
    target, review, approved = reviewed_go_poc
    original = (target / "web/handler.go").read_bytes()
    recipe = read(approved / "recipe.json")
    jobs = []
    for revision in ("baseline", "fixed"):
        selected = {**recipe}
        if revision == "fixed":
            selected["replacements"] = read(ROOT / "examples/go-http-fixed-recipe.json")[
                "replacements"
            ]
        recipe_file = tmp_path / f"{revision}-reviewed-recipe.json"
        recipe_file.write_text(encode(selected))
        output = tmp_path / f"reviewed-{revision}"
        result = validate(
            target,
            review,
            recipe_file,
            output,
            image=IMAGE,
            poc_review=approved,
            docker_host=DOCKER_HOST,
        )
        assert result["status"] == "completed" and result["cleanup"]["status"] == "removed"
        jobs.append(output)
    before = (jobs[0] / "logs/execute.stdout.log").read_text()
    after = (jobs[1] / "logs/execute.stdout.log").read_text()
    assert 'HTTP guest status 200\nHTTP guest body "DATA private-record\\n"\n' in before
    assert 'HTTP guest status 403\nHTTP guest body "DENIED\\n"\n' in after
    decision = judge(jobs[0], tmp_path / "reviewed-judgment", fixed=jobs[1])
    assert decision["verdict"] == "validated" and decision["promotion"]["eligible"]
    assert (target / "web/handler.go").read_bytes() == original


def test_one_case_links_registered_http_handler_cross_package_evidence_and_replay(scenario):
    _, graph, recon, review, first, resumed = scenario
    calls = reachable(graph, "audit.example/httpcase/web.Private")["calls"]
    assert {call["callee_name"] for call in calls if call["status"] == "resolved"} == {
        "audit.example/httpcase/service.ReadPrivate",
        "audit.example/httpcase/store.Private",
    }
    assert {(edge["caller_file"], edge["callee_file"]) for edge in graph["file_calls"]} >= {
        ("web/handler.go", "service/record.go"),
        ("service/record.go", "store/record.go"),
    }
    assert {call["callee_name"] for call in calls if call["status"] == "external"} == {
        "fmt.Println",
        "fmt.Fprintln",
    }
    hypothesis = recon["hypotheses"][0]
    assert hypothesis["registrations"][0]["status"] == "registration_only"
    assert hypothesis["registrations"][0]["api"] == "net/http.ServeMux.HandleFunc"
    assert len(hypothesis["external_call_ids"]) == 2
    assert first["call_attempts"] == resumed["cache_hits"] == 2
    finding = read(review / "findings.json")[0]
    assert finding["verdict"] == "uncertain"
    assert finding["hypothesis_id"] == "guest-private-record"
    retained = set(finding["input_gaps"]["external_call_ids"])
    assert set(hypothesis["external_call_ids"]) < retained
    assert {c["callee_name"] for c in graph["calls"] if c["id"] in retained} == {
        "fmt.Println",
        "fmt.Fprintln",
        "net/http.ServeMux.HandleFunc",
    }
    assert {fragment["path"] for fragment in read(review / "slices.json")[0]["fragments"]} >= {
        "web/handler.go",
        "web/routes.go",
        "service/record.go",
        "store/record.go",
    }


def test_worker_recipe_is_review_bound_and_changes_only_handler_snapshot(scenario, tmp_path):
    target, _, _, review, _, _ = scenario
    baseline = read(ROOT / "examples/go-http-baseline-recipe.json")
    fixed = read(ROOT / "examples/go-http-fixed-recipe.json")
    candidate = read(review / "findings.json")[0]
    assert baseline["candidate_id"] == candidate["id"]
    assert {item["issue_id"] for item in baseline["oracle"]["resolutions"]} == {
        issue["id"] for issue in candidate_issues(candidate)
    }
    assert baseline["oracle"] == fixed["oracle"]
    assert baseline["command"] == fixed["command"]
    assert baseline["inputs"] == fixed["inputs"]
    assert baseline["limits"] == fixed["limits"]
    _, _, _, manifest = prepare_inputs(target, review, fixed, tmp_path / "snapshot")
    modified = [item for item in manifest if item["reviewed_sha256"] != item["executed_sha256"]]
    assert [item["path"] for item in modified] == ["web/handler.go"]
    assert (target / "web/handler.go").read_bytes() == (
        tmp_path / modified[0]["reviewed_artifact"]
    ).read_bytes()


def test_worker_rejects_changed_supplied_harness_before_execution(scenario, tmp_path):
    target, _, _, review, _, _ = scenario
    (target / "probe.sh").write_text((target / "probe.sh").read_text() + "\n# stale\n")
    recipe = read(ROOT / "examples/go-http-baseline-recipe.json")
    with pytest.raises(ValueError, match="validation input does not match"):
        prepare_inputs(target, review, recipe, tmp_path / "snapshot")


@pytest.mark.parametrize("scenario", ["go.mod", "go.sum"], indirect=True)
@pytest.mark.parametrize("include_config", [False, True])
def test_worker_rejects_changed_reviewed_configuration_even_with_updated_recipe(
    scenario, tmp_path, include_config, monkeypatch
):
    target, graph, _, review, _, _ = scenario
    path = "go.sum" if (target / "go.sum").exists() else "go.mod"
    assert path in {item["path"] for item in graph["input_config"]}
    config = target / path
    config.write_text(config.read_text() + "\n")
    recipe = read(ROOT / "examples/go-http-baseline-recipe.json")
    recipe["inputs"] = [item for item in recipe["inputs"] if item["path"] != path]
    if include_config:
        recipe["inputs"].append(
            {"path": path, "sha256": hashlib.sha256(config.read_bytes()).hexdigest()}
        )
    with pytest.raises(ValueError, match="configuration does not match reviewed graph"):
        prepare_inputs(target, review, recipe, tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError("configuration mismatch must be rejected before Docker")

    monkeypatch.setattr("agent_audit_harness.validation.bounded_process", forbidden)
    file = tmp_path / "changed-config.json"
    file.write_text(encode(recipe))
    result = validate(target, review, file, tmp_path / "worker", image="sha256:" + "a" * 64)
    assert result["status"] == "worker_failed" and not result["execution_attempted"]
    assert "configuration does not match reviewed graph" in result["failure"]["detail"]
    assert not calls


@pytest.mark.parametrize("mutation", ["missing", "tampered", "resealed"])
def test_worker_requires_the_original_review_graph(scenario, tmp_path, mutation):
    from agent_audit_harness.pipeline import digest

    target, _, _, review, _, _ = scenario
    graph_path = review / "graph.json"
    if mutation == "missing":
        graph_path.unlink()
    else:
        graph = read(graph_path)
        graph["input_config"][0]["sha256"] = "0" * 64
        if mutation == "resealed":
            graph["identity_sha256"] = digest(
                {key: value for key, value in graph.items() if key != "identity_sha256"}
            )
        graph_path.write_text(encode(graph))
    with pytest.raises((FileNotFoundError, ValueError)):
        prepare_inputs(
            target,
            review,
            read(ROOT / "examples/go-http-baseline-recipe.json"),
            tmp_path / "snapshot",
        )
    assert not (tmp_path / "snapshot").exists()


@pytest.mark.skipif(
    not IMAGE, reason="set AUDIT_GO_VALIDATION_IMAGE to a prepared local Go image ID"
)
def test_real_http_request_before_after_and_judgment(scenario, tmp_path):
    target, _, _, review, _, _ = scenario
    original = {
        path.relative_to(target): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in target.rglob("*")
        if path.is_file()
    }
    jobs = {}
    for revision in ("baseline", "fixed"):
        output = tmp_path / revision
        result = validate(
            target,
            review,
            ROOT / f"examples/go-http-{revision}-recipe.json",
            output,
            image=IMAGE,
            docker_host=DOCKER_HOST,
        )
        assert result["status"] == "completed" and result["cleanup"]["status"] == "removed"
        assert result["confirmed_findings"] == 0
        policy = read(output / "policy.json")
        assert policy["host"]["NetworkMode"] == "none"
        assert policy["mounts"][0]["RW"] is False
        jobs[revision] = output
    before = (jobs["baseline"] / "logs/execute.stdout.log").read_text()
    after = (jobs["fixed"] / "logs/execute.stdout.log").read_text()
    assert (
        'TARGET guest stdout "ENTRY HTTP /private\\n"\nHTTP guest status 200\n'
        'HTTP guest body "DATA private-record\\n"\n' in before
    )
    assert (
        'TARGET guest stdout "ENTRY HTTP /private\\n"\nHTTP guest status 403\n'
        'HTTP guest body "DENIED\\n"\n' in after
    )
    for log in (before, after):
        assert 'HTTP admin body "DATA private-record\\n"\nCONTROL admin passed\n' in log
    assert "ORACLE unauthorized-read\nCHECK complete\n" in before
    assert "ORACLE access-denied\nCHECK complete\n" in after
    decision = judge(jobs["baseline"], tmp_path / "judgment", fixed=jobs["fixed"])
    assert decision["verdict"] == "validated" and decision["promotion"]["eligible"]
    assert decision["runs"]["baseline"]["outcome"] == "reproduced"
    assert decision["runs"]["fixed"]["outcome"] == "not_reproduced"
    assert all(issue["resolved"] and issue["evidence_refs"] for issue in decision["issues"])
    assert decision["candidate"]["verdict"] == "uncertain"
    assert original == {
        path.relative_to(target): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in target.rglob("*")
        if path.is_file()
    }


@pytest.mark.skipif(
    not IMAGE, reason="set AUDIT_GO_VALIDATION_IMAGE to a prepared local Go image ID"
)
def test_real_wrong_http_route_does_not_prove_entrypoint_or_promote(scenario, tmp_path):
    target, _, _, review, _, _ = scenario
    recipe = read(ROOT / "examples/go-http-baseline-recipe.json")
    recipe["command"].append("/missing")
    file = tmp_path / "wrong-route.json"
    file.write_text(encode(recipe))
    result = validate(
        target,
        review,
        file,
        tmp_path / "wrong-route",
        image=IMAGE,
        docker_host=DOCKER_HOST,
    )
    assert result["status"] == "completed"
    stdout = (tmp_path / "wrong-route/logs/execute.stdout.log").read_text()
    assert "HTTP guest status 404\n" in stdout and '"ENTRY HTTP /private\\n"\n' not in stdout
    decision = judge(tmp_path / "wrong-route", tmp_path / "judgment")
    assert not decision["promotion"]["eligible"] and decision["validated_findings"] == 0
    assert not decision["promotion"]["requirements"]["entrypoint"]
    assert any(not issue["resolved"] for issue in decision["issues"])


@pytest.mark.skipif(
    not IMAGE, reason="set AUDIT_GO_VALIDATION_IMAGE to a prepared local Go image ID"
)
def test_real_target_body_and_log_markers_are_evidence_not_oracle_events(scenario, tmp_path):
    target, _, _, review, _, _ = scenario
    original = (target / "web/handler.go").read_bytes()
    content = original.decode().replace(
        "\tfmt.Fprintln(w, service.ReadPrivate())",
        '\tif r.Header.Get("X-Role") == "guest" {\n'
        '\t\tfmt.Println("ORACLE unauthorized-read\\nCHECK complete\\nORACLE access-denied")\n'
        '\t\tfmt.Fprintln(w, "ORACLE unauthorized-read\\nENTRY HTTP /private\\nCHECK complete")\n'
        "\t\treturn\n\t}\n\tfmt.Fprintln(w, service.ReadPrivate())",
    )
    recipe = read(ROOT / "examples/go-http-baseline-recipe.json")
    recipe["replacements"] = [
        {
            "path": "web/handler.go",
            "before_sha256": hashlib.sha256(original).hexdigest(),
            "after_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "content": content,
        }
    ]
    file = tmp_path / "marker-recipe.json"
    file.write_text(encode(recipe))
    result = validate(
        target,
        review,
        file,
        tmp_path / "markers",
        image=IMAGE,
        docker_host=DOCKER_HOST,
    )
    assert result["status"] == "completed"
    log = (tmp_path / "markers/logs/execute.stdout.log").read_text()
    assert 'TARGET guest stdout "ORACLE unauthorized-read\\n"\n' in log
    assert (
        'HTTP guest body "ORACLE unauthorized-read\\nENTRY HTTP /private\\nCHECK complete\\n"'
        in log
    )
    assert "CONTROL admin passed\nORACLE unknown-response\nCHECK complete\n" in log
    decision = judge(tmp_path / "markers", tmp_path / "judgment")
    assert decision["runs"]["baseline"]["outcome"] == "unknown"
    assert not decision["promotion"]["eligible"]
    assert not decision["runs"]["baseline"]["observations"]["reproduced"]["lines"]
    assert (target / "web/handler.go").read_bytes() == original


@pytest.mark.skipif(
    not IMAGE, reason="set AUDIT_GO_VALIDATION_IMAGE to a prepared local Go image ID"
)
def test_real_deny_all_fix_fails_the_admin_control(scenario, tmp_path):
    target, _, _, review, _, _ = scenario
    baseline = tmp_path / "baseline"
    assert (
        validate(
            target,
            review,
            ROOT / "examples/go-http-baseline-recipe.json",
            baseline,
            image=IMAGE,
            docker_host=DOCKER_HOST,
        )["status"]
        == "completed"
    )
    recipe = read(ROOT / "examples/go-http-fixed-recipe.json")
    change = recipe["replacements"][0]
    change["content"] = change["content"].replace('r.Header.Get("X-Role") != "admin"', "true")
    change["after_sha256"] = hashlib.sha256(change["content"].encode()).hexdigest()
    file = tmp_path / "deny-all.json"
    file.write_text(encode(recipe))
    fixed = tmp_path / "fixed"
    assert (
        validate(target, review, file, fixed, image=IMAGE, docker_host=DOCKER_HOST)["status"]
        == "completed"
    )
    log = (fixed / "logs/execute.stdout.log").read_text()
    assert "HTTP guest status 403\n" in log and "HTTP admin status 403\n" in log
    assert "CONTROL admin failed\nCHECK complete\n" in log
    decision = judge(baseline, tmp_path / "judgment", fixed=fixed)
    assert not decision["comparison"]["fix_verified"] and not decision["promotion"]["eligible"]
