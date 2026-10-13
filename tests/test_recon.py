import copy
import json
import shutil
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.cli import main
from agent_audit_harness.graph import build_graph, reachable, read_graph, resolve
from agent_audit_harness.pipeline import (
    candidates_for_slice,
    digest,
    encode,
    index_target,
    make_slices,
    run_pipeline,
    validate_evidence,
)
from agent_audit_harness.recon import (
    build_recon,
    make_graph_slices,
    make_recon,
    read_recon,
    reviewed_lines,
)
from agent_audit_harness.triage import input_gaps

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples" / "go-review-target"
SPEC = ROOT / "examples" / "go-review-plan.json"
REPLAY = ROOT / "examples" / "go-review-replay"
pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="Go not installed")


def read(path):
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def graph_file(tmp_path_factory):
    output = tmp_path_factory.mktemp("review-graph")
    build_graph(TARGET, output, language="go")
    return output / "graph.json"


@pytest.fixture
def review(graph_file, tmp_path):
    graph = read_graph(graph_file)
    sources, _ = index_target(TARGET)
    output = tmp_path / "recon"
    recon = build_recon(TARGET, graph_file, SPEC, output)
    return graph, sources, recon, output / "recon.json"


def test_types_fields_globals_and_callback_registration_are_not_call_edges(review):
    graph, _, recon, _ = review
    functions = {node["qualified_name"]: node for node in graph["functions"]}
    contexts = {node["name"]: node for node in graph["contexts"]}
    request = contexts["Request"]
    assert request["kind"] == "type" and request["path"] == "model/request.go"
    assert request["id"] in functions["audit.example/review/service.Raw"]["context_ids"]
    dynamic = functions["audit.example/review/web.Dynamic"]
    assert {contexts[name]["id"] for name in ("engine", "callback")} <= set(dynamic["context_ids"])
    assert contexts["Engine"]["id"] in contexts["engine"]["references"]
    route = reachable(graph, "Register")
    assert len(route["functions"]) == 1
    assert all(call["status"] == "external" for call in route["calls"])
    assert all(call["function_arguments"][0]["status"] == "resolved" for call in route["calls"])
    for hypothesis in recon["hypotheses"]:
        assert hypothesis["entry_status"] == "provided_hypothesis"
        assert len(hypothesis["registrations"]) == 1
        assert hypothesis["registrations"][0]["status"] == "registration_only"
    assert len(recon["hypotheses"][2]["unknown_call_ids"]) == 2
    model = next(c for c in recon["components"] if c["scope"] == "audit.example/review/model")
    assert not model["function_ids"] and model["context_ids"]
    for selector in ("model/request.go", "audit.example/review/model", request["id"]):
        result = resolve(graph, selector)
        assert not result["functions"] and request in result["contexts"]
    assert "Request" in {
        c["name"] for c in reachable(graph, "audit.example/review/web.Raw")["contexts"]
    }


def test_typed_mux_alias_shadowed_api_literal_and_blank_declaration_identity(tmp_path):
    from agent_audit_harness.extractors.golang import entry_registrations

    target = tmp_path / "target"
    target.mkdir()
    (target / "go.mod").write_text("module test.example/routes\n\ngo 1.23.0\n")
    (target / "routes.go").write_text(
        'package routes\nimport h "net/http"\n'
        "var (_ = 1; _ = 2)\n"
        "func Handler(w h.ResponseWriter, r *h.Request) {}\n"
        "func Other(w h.ResponseWriter, r *h.Request) {}\n"
        "func HandleFunc(s string, fn func(h.ResponseWriter, *h.Request)) {}\n"
        "func Bind() {\n"
        ' mux := h.NewServeMux(); mux.HandleFunc("/real", Handler)\n'
        ' HandleFunc("/fake", Other)\n'
        ' var cb func(h.ResponseWriter, *h.Request); h.HandleFunc("/unknown", cb)\n'
        ' h.HandleFunc("/literal", func(w h.ResponseWriter, r *h.Request) { Handler(w,r) })\n'
        "}\n"
    )
    graph = build_graph(target, tmp_path / "graph", language="go")
    nodes = {node["name"]: node for node in graph["functions"]}
    assert len({c["id"] for c in graph["contexts"]}) == len(graph["contexts"])
    assert len(entry_registrations(graph, nodes["Handler"]["id"])) == 1
    assert not entry_registrations(graph, nodes["Other"]["id"])
    literal = next(node for node in graph["functions"] if node["kind"] == "lambda")
    assert len(entry_registrations(graph, literal["id"])) == 1
    assert {node["name"] for node in reachable(graph, "Bind")["functions"]} == {
        "Bind",
        "HandleFunc",
    }
    assert any(
        arg["status"] == "unresolved" for c in graph["calls"] for arg in c["function_arguments"]
    )


def test_hypothesis_slices_include_controls_fields_registration_and_unknowns(review):
    graph, sources, recon, _ = review
    slices, gaps = make_graph_slices(graph, recon, sources, 16000)
    assert not gaps and len(slices) == 3
    raw, checked, dynamic = slices
    raw_text = "\n".join(part["text"] for part in raw["fragments"])
    checked_text = "\n".join(part["text"] for part in checked["fragments"])
    dynamic_text = "\n".join(part["text"] for part in dynamic["fragments"])
    assert {part["path"] for part in raw["fragments"]} == {
        "web/handlers.go",
        "web/routes.go",
        "service/flow.go",
        "runner/execute.go",
        "model/request.go",
    }
    assert "Program string" in raw_text and "exec.Command" in raw_text
    assert 'http.HandleFunc("/raw", Raw)' in raw_text
    assert "if !allowed(req.Program)" in checked_text
    assert 'return program == "date"' in checked_text and "exec.Command" in checked_text
    assert "type Engine interface" in dynamic_text and "var callback" in dynamic_text
    assert len([c for c in dynamic["calls"] if c["status"] == "unresolved"]) == 2
    assert all(len(encode(source_slice).encode()) <= 16000 for source_slice in slices)
    assert make_graph_slices(graph, recon, sources, 16000) == (slices, gaps)


def test_byte_budget_preserves_gaps_and_unique_line_coverage(review):
    graph, sources, recon, _ = review
    slices, gaps = make_graph_slices(graph, recon, sources, 2200)
    assert slices and gaps
    assert all(len(encode(source_slice).encode()) <= 2200 for source_slice in slices)
    assert any(item["reason"] == "slice_byte_budget" for item in gaps)
    assert any(item.get("status") == "unresolved" for item in gaps)
    assert any(sum(s["omitted_counts"].values()) for s in slices)
    for source_slice in slices:
        full = next(h for h in recon["hypotheses"] if h["id"] == source_slice["hypothesis"]["id"])
        retained = input_gaps(source_slice, {"graph": graph, "recon": recon})
        assert retained["unresolved_call_ids"] == full["unknown_call_ids"]
        assert retained["external_call_ids"] == full["external_call_ids"]
        assert retained["unlinked_annotation_ids"] == full["unlinked_annotation_ids"]
        assert retained["omitted_counts"] == source_slice["omitted_counts"]
    dynamic = slices[2]
    assert not any(c["status"] == "unresolved" for c in dynamic["calls"])
    assert len(input_gaps(dynamic, {"graph": graph, "recon": recon})["unresolved_call_ids"]) == 2
    large, _ = make_graph_slices(graph, recon, sources, 16000)
    naive_count = sum(
        part["last_line"] - part["first_line"] + 1 for s in large for part in s["fragments"]
    )
    assert reviewed_lines(large) < naive_count
    assert reviewed_lines(large) <= sum(len(source.text.splitlines()) for source in sources)


def test_same_budget_first_lexical_slice_misses_cross_file_evidence(review):
    graph, sources, recon, _ = review
    relation = make_graph_slices(graph, recon, sources, 16000)[0][0]
    lexical = make_slices(sources, 16000)[0][0]
    assert len(encode(lexical).encode()) <= 16000
    assert len(encode(relation).encode()) <= 16000
    for quote in ("service.Raw(req)", "runner.Execute(req.Program)", "exec.Command(program)"):
        assert quote in "\n".join(part["text"] for part in relation["fragments"])
        assert quote not in lexical["text"]


@pytest.mark.parametrize(
    "change",
    [
        {"path": "../outside.go"},
        {"line": 1},
        {"quote": "invented source"},
    ],
)
def test_recon_annotation_must_match_its_function_source(review, change):
    graph, sources, _, _ = review
    spec = read(SPEC)
    spec["hypotheses"][0]["annotations"][0]["evidence"].update(change)
    with pytest.raises(ValueError):
        make_recon(graph, sources, spec)


def test_wrong_function_duplicate_hypothesis_and_extra_fields_are_rejected(review):
    graph, sources, _, _ = review
    spec = read(SPEC)
    spec["hypotheses"][0]["annotations"][0]["function"] = "audit.example/review/service.Raw"
    with pytest.raises(ValueError, match="outside"):
        make_recon(graph, sources, spec)
    spec = read(SPEC)
    spec["hypotheses"][1]["id"] = spec["hypotheses"][0]["id"]
    with pytest.raises(ValueError, match="duplicate"):
        make_recon(graph, sources, spec)
    spec = read(SPEC)
    spec["run_command"] = "not executable"
    with pytest.raises(ValueError, match="invalid research plan"):
        make_recon(graph, sources, spec)


def test_same_line_function_annotation_cannot_cite_neighbor(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "go.mod").write_text("module test.example/spans\n\ngo 1.23.0\n")
    (target / "span.go").write_text("package spans\nfunc A() { }; func B() { panic(1) }\n")
    graph = build_graph(target, tmp_path / "graph", language="go")
    sources, _ = index_target(target)
    spec = {
        "schema_version": 1,
        "hypotheses": [
            {
                "id": "span",
                "entry": "A",
                "question": "Check A",
                "assumptions": [],
                "annotations": [
                    {
                        "role": "sink",
                        "function": "A",
                        "claim": "Check this operation",
                        "evidence": {
                            "path": "span.go",
                            "line": 2,
                            "quote": "panic(1)",
                        },
                    }
                ],
            }
        ],
    }
    with pytest.raises(ValueError, match="quote"):
        make_recon(graph, sources, spec)
    spec["hypotheses"][0]["annotations"][0]["function"] = "B"
    recon = make_recon(graph, sources, spec)
    assert recon["hypotheses"][0]["unlinked_annotation_ids"]
    assert recon["hypotheses"][0]["annotations"][0]["call_relation"] == "not_linked_by_direct_calls"
    bad = copy.deepcopy(graph)
    next(f for f in bad["functions"] if f["name"] == "B")["end_column"] = 99999
    with pytest.raises(ValueError, match="actual source"):
        make_recon(bad, sources, spec)


def test_unicode_separator_in_comment_keeps_native_go_line_identity(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "go.mod").write_text("module test.example/lines\n\ngo 1.23.0\n")
    path = target / "line.go"
    path.write_text(
        "package lines\n// separator: \u2028 still a comment\nfunc Entry() { panic(1) }\n"
    )
    graph = build_graph(target, tmp_path / "graph", language="go")
    sources, _ = index_target(target)
    assert sources[0].metadata()["lines"] == 3
    spec = {
        "schema_version": 1,
        "hypotheses": [
            {
                "id": "physical-line",
                "entry": "Entry",
                "question": "Check this operation",
                "assumptions": [],
                "annotations": [
                    {
                        "function": "Entry",
                        "role": "sink",
                        "claim": "panic appears here",
                        "evidence": {"path": "line.go", "line": 3, "quote": "panic(1)"},
                    }
                ],
            }
        ],
    }
    recon = make_recon(graph, sources, spec)
    fragments = make_graph_slices(graph, recon, sources, 16000)[0][0]["fragments"]
    assert validate_evidence(spec["hypotheses"][0]["annotations"][0]["evidence"], fragments)
    path.write_bytes(b"package lines\rfunc Entry() {}\r")
    with pytest.raises(ValueError, match="bare CR"):
        build_graph(target, tmp_path / "cr-graph", language="go")


def test_multifile_evidence_checks_and_hypothesis_identity(review):
    graph, sources, recon, _ = review
    raw = make_graph_slices(graph, recon, sources, 16000)[0][0]
    data = read(REPLAY / "s0001.analysis.json")
    candidates = candidates_for_slice(data, raw)
    assert candidates[0]["path"] == "runner/execute.go"
    assert candidates[0]["hypothesis_id"] == "raw-command"
    another = copy.deepcopy(raw)
    another["hypothesis"]["id"] = "different-question"
    assert candidates_for_slice(data, another)[0]["id"] != candidates[0]["id"]
    for change in ({"path": "service/flow.go"}, {"line": 1}, {"quote": "fake"}):
        changed = copy.deepcopy(data)
        changed["candidates"][0].update(change)
        with pytest.raises(ValueError):
            candidates_for_slice(changed, raw)
    with pytest.raises(ValueError):
        validate_evidence({"path": "runner/execute.go", "line": 6, "quote": "exec.Command"}, [])


def test_tampered_recon_and_graph_context_argument_references_are_rejected(review, tmp_path):
    graph, sources, recon, recon_file = review
    changed = copy.deepcopy(recon)
    changed["hypotheses"][0]["function_ids"] = []
    changed.pop("identity_sha256")
    changed["identity_sha256"] = digest(changed)
    recon_file.write_text(encode(changed))
    with pytest.raises(ValueError, match="recon changed"):
        read_recon(recon_file, graph, sources)
    mutations = [
        lambda g: g["contexts"][0].update(references=["unknown"]),
        lambda g: g["contexts"][0].update(end_line=99999),
        lambda g: g["functions"][0].update(context_ids=["unknown"]),
        lambda g: next(c for c in g["calls"] if c["function_arguments"])["function_arguments"][
            0
        ].update(function="unknown", status="resolved"),
    ]
    for mutate in mutations:
        changed = copy.deepcopy(graph)
        mutate(changed)
        changed.pop("identity_sha256")
        changed["identity_sha256"] = digest(changed)
        path = tmp_path / "bad-graph.json"
        path.write_text(encode(changed))
        with pytest.raises(ValueError):
            read_graph(path)


@pytest.mark.parametrize("config", [False, True])
def test_changed_target_or_config_refuses_review_before_agent_call(tmp_path, config):
    target = tmp_path / "target"
    shutil.copytree(TARGET, target)
    graph_file = tmp_path / "graph" / "graph.json"
    build_graph(target, graph_file.parent, language="go")
    recon_file = tmp_path / "recon" / "recon.json"
    build_recon(target, graph_file, SPEC, recon_file.parent)
    changed = target / ("go.mod" if config else "model/request.go")
    changed.write_text(changed.read_text() + "\n// changed snapshot\n")
    with pytest.raises(ValueError, match="configuration changed" if config else "source changed"):
        run_pipeline(
            target,
            tmp_path / "run",
            ReplayAgent(REPLAY),
            graph_file=graph_file,
            recon_file=recon_file,
        )
    assert not (tmp_path / "run").exists()


def test_replay_graph_review_and_resume_no_calls_and_changed_plan_refused(
    review, graph_file, tmp_path
):
    graph, sources, recon, recon_file = review
    output = tmp_path / "run"
    agent = ReplayAgent(REPLAY)
    first = run_pipeline(TARGET, output, agent, graph_file=graph_file, recon_file=recon_file)
    assert first["call_attempts"] == 6
    assert first["verdict_counts"] == {"needs_validation": 1, "rejected": 1, "uncertain": 1}
    assert first["confirmed_findings"] == first["validation_executions"] == 0
    assert first["cluster_count"] == 2
    findings = read(output / "findings.json")
    clusters = read(output / "clusters.json")
    shared = next(c for c in clusters if c["status"] == "mixed")
    raw, checked, dynamic = findings
    assert raw["cluster_id"] == checked["cluster_id"] == shared["id"]
    assert raw["slice_id"] != checked["slice_id"]
    assert shared["candidate_ids"] == sorted([raw["id"], checked["id"]])
    assert checked["verdict"] == "rejected" and len(checked["counterevidence"]) == 2
    assert dynamic["verdict"] == "uncertain" and dynamic["root_cause"] is None
    assert (
        dynamic["input_gaps"]["unresolved_call_ids"] == recon["hypotheses"][2]["unknown_call_ids"]
    )
    assert {f["id"] for f in read(output / "validation-queue.json")} == {raw["id"], dynamic["id"]}
    coverage = read(output / "coverage.json")
    assert coverage["input_mode"] == "graph_hypotheses"
    assert len(coverage["hypotheses"][2]["unknown_call_ids"]) == 2
    assert read(output / "graph.json") == graph and read(output / "recon.json") == recon
    agent.call = lambda *args: pytest.fail("resume called the agent")
    second = run_pipeline(
        TARGET, output, agent, graph_file=graph_file, recon_file=recon_file, resume=True
    )
    assert second["cache_hits"] == 6 and second["call_attempts"] == 6
    assert read(output / "clusters.json") == clusters
    assert read(output / "findings.json") == findings
    spec = read(SPEC)
    spec["hypotheses"][0]["assumptions"].append("new context")
    recon_file.write_text(encode(make_recon(graph, sources, spec)))
    with pytest.raises(ValueError, match="inputs changed"):
        run_pipeline(
            TARGET, output, agent, graph_file=graph_file, recon_file=recon_file, resume=True
        )


def test_cli_recon_plan_without_source_text_and_required_pair(
    graph_file, tmp_path, capsys, monkeypatch
):
    output = tmp_path / "recon"
    assert (
        main(
            [
                "recon",
                str(TARGET),
                "--graph",
                str(graph_file),
                "--spec",
                str(SPEC),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["hypotheses"] == 3
    monkeypatch.chdir(ROOT)
    assert (
        main(
            [
                "plan",
                "examples/go-review-target",
                "--graph",
                str(graph_file),
                "--recon",
                str(output / "recon.json"),
                "--max-slices",
                "1",
            ]
        )
        == 0
    )
    plan = json.loads(capsys.readouterr().out)
    assert plan["selected_slices"][0]["hypothesis_id"] == "raw-command"
    assert '"text"' not in json.dumps(plan)
    assert plan["selected_slices"][0]["input_bytes"] <= 16000
    assert main(["plan", str(TARGET), "--graph", str(graph_file)]) == 1
    assert "supplied together" in capsys.readouterr().err
    with pytest.raises(ValueError, match="nonempty"):
        build_recon(TARGET, graph_file, SPEC, output)
    with pytest.raises(ValueError, match="outside"):
        build_recon(TARGET, graph_file, SPEC, TARGET / "output")


def test_entry_larger_than_budget_is_deferred_and_has_no_agent_call(review, graph_file, tmp_path):
    graph, sources, recon, recon_file = review
    slices, gaps = make_graph_slices(graph, recon, sources, 1024)
    assert not slices
    assert any(gap["reason"] == "entry_definition_exceeds_budget" for gap in gaps)
    with pytest.raises(ValueError, match="no source slices"):
        run_pipeline(
            TARGET,
            tmp_path / "run",
            ReplayAgent(REPLAY),
            slice_bytes=1024,
            graph_file=graph_file,
            recon_file=recon_file,
        )
    assert not (tmp_path / "run").exists()
