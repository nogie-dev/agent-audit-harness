import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent, Reply
from agent_audit_harness.benchmark import checked_truth
from agent_audit_harness.cli import main
from agent_audit_harness.go_value_flow import MAX_STATES, go_value_flows
from agent_audit_harness.graph import build_graph
from agent_audit_harness.judgment import candidate_issues
from agent_audit_harness.pipeline import digest, encode, index_target, run_pipeline
from agent_audit_harness.recon import build_recon, make_graph_slices, make_recon, read_recon
from agent_audit_harness.recon_proposal import propose_recon, recon_context
from agent_audit_harness.static_analysis import DEFAULT_RULES, build_static

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(
    not (ROOT / ".cache/semgrep/semgrep-core").is_file(), reason="run make setup-static"
)
def test_python_value_flow_cross_module_and_constant_control(tmp_path):
    target = ROOT / "examples/static-target"
    graph_file = tmp_path / "graph/graph.json"
    graph = build_graph(target, graph_file.parent, language="python")
    static = build_static(target, graph_file, DEFAULT_RULES, tmp_path / "static")
    sources, _ = index_target(target)
    flows, gaps = go_value_flows(graph, static)
    calls = {call["id"]: call for call in graph["calls"]}
    assert [[calls[ref]["callee_name"] for ref in flow["call_ids"]] for flow in flows] == [
        ["builtins.input", "os.system"],
        ["builtins.input", "worker.execute", "os.system"],
    ]
    assert gaps
    recon = build_recon(
        target, graph_file, ROOT / "examples/python-value-plan.json", tmp_path / "recon"
    )
    slices, _ = make_graph_slices(graph, recon, sources, 20000, static)
    by_hypothesis = {item["hypothesis"]["id"]: item for item in slices}
    assert len(by_hypothesis["cross-module-shell"]["value_flows"]) == 1
    assert not by_hypothesis["constant-shell-control"]["value_flows"]


def read(path):
    return json.loads(path.read_text())


@pytest.fixture(scope="module", params=["python", "go"])
def case(request, tmp_path_factory):
    if not (ROOT / ".cache/semgrep/semgrep-core").is_file():
        pytest.skip("run make setup-static")
    language = request.param
    if language == "go" and not shutil.which("go"):
        pytest.skip("Go toolchain required")
    root = tmp_path_factory.mktemp("recon-" + language)
    target = root / "target"
    shutil.copytree(
        ROOT / "examples" / ("static-target" if language == "python" else "go-review-target"),
        target,
    )
    sentinel = root / "target-executed"
    if language == "python":
        (target / "trap.py").write_text(
            f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n"
        )
    graph_file = root / "graph/graph.json"
    graph = build_graph(target, graph_file.parent, language=language)
    static_file = root / "static/static.json"
    static = build_static(target, graph_file, DEFAULT_RULES, static_file.parent)
    sources, _ = index_target(target.resolve())
    replay = ROOT / f"examples/recon-{language}-replay"
    return {
        "target": target,
        "graph_file": graph_file,
        "graph": graph,
        "static_file": static_file,
        "static": static,
        "sources": sources,
        "replay": replay,
        "sentinel": sentinel,
    }


def propose(case, output, agent=None, **kwargs):
    return propose_recon(
        case["target"],
        case["graph_file"],
        case["static_file"],
        output,
        agent or ReplayAgent(case["replay"]),
        **kwargs,
    )


@pytest.fixture(scope="module")
def solidity_case(tmp_path_factory):
    if (
        shutil.which("node") is None
        or not (ROOT / ".cache/solidity-extractor/node_modules/solc/soljson.js").is_file()
    ):
        pytest.skip("Node/pinned solc unavailable; run make setup-solidity")
    root = tmp_path_factory.mktemp("recon-solidity")
    target = root / "target"
    shutil.copytree(ROOT / "examples/solidity-benchmark-target", target)
    graph_file = root / "graph/graph.json"
    graph = build_graph(target, graph_file.parent, language="solidity")
    sources, _ = index_target(target)
    return target, graph_file, graph, sources


def test_solidity_visibility_recon_preserves_unverified_deployment(solidity_case, tmp_path):
    target, graph_file, graph, sources = solidity_case
    context = recon_context(graph, sources, None, 16000)
    facts = context["data"]["facts"]
    names = {f["id"]: f["qualified_name"] for f in graph["functions"]}
    assert {names[fact["function"]] for fact in facts} == {
        "Vault.sol:Vault.receive",
        "Vault.sol:Vault.releaseA",
        "Vault.sol:Vault.releaseB",
    }
    assert all(
        fact["kind"] == "entry_visibility" and fact["status"] == "visibility_only" for fact in facts
    )
    assert all(fact["evidence"]["quote"] for fact in facts)
    assert "deployment_unverified" in {gap["reason"] for gap in context["gaps"]}
    assert not context["omissions"]
    omitted = recon_context(graph, sources, None, 1024)["omissions"]
    assert len(omitted) == len(facts)
    assert {item["line"] for item in omitted} == {7, 9, 13}
    assert all(item["path"] == "Vault.sol" and item["function"] in names for item in omitted)
    assert all(
        item["source_sha256"] == next(s.sha256 for s in sources if s.path == "Vault.sol")
        for item in omitted
    )
    output = tmp_path / "proposal"
    agent = ReplayAgent(ROOT / "examples/recon-solidity-replay")
    state = propose_recon(
        target,
        graph_file,
        None,
        output,
        agent,
    )
    assert state["status"] == "complete"
    recon = read_recon(output / "recon.json", graph, sources)
    assert [item["id"] for item in recon["hypotheses"]] == [
        "release-a-access",
        "release-b-control",
    ]
    assert {gap["reason"] for gap in recon["spec"]["proposal_origin"]["gaps"]} >= {
        "deployment_unverified",
        "unselected_recon_entries",
    }
    slices, gaps = make_graph_slices(graph, recon, sources, 16000)
    assert not gaps and slices[1]["modifier_flows"]
    review = tmp_path / "review"
    metrics = run_pipeline(
        target,
        review,
        ReplayAgent(ROOT / "examples/solidity-benchmark-replay"),
        graph_file=graph_file,
        recon_file=output / "recon.json",
    )
    assert metrics["verdict_counts"] == {"needs_validation": 1}
    assert read(review / "recon-context.json") == context
    agent.call = lambda *args: pytest.fail("cached Solidity proposal invoked the agent")
    assert propose_recon(target, graph_file, None, output, agent, resume=True)["cache_hit"]


def test_solidity_recon_rejects_visibility_fact_for_other_entry(solidity_case, tmp_path):
    target, graph_file, graph, sources = solidity_case
    context = recon_context(graph, sources, None, 16000)
    receive = next(f for f in context["data"]["facts"] if f["evidence"]["quote"] == "receive")
    reply = read(ROOT / "examples/recon-solidity-replay/r0001.recon.json")
    reply["hypotheses"][0]["selection"]["fact_ids"] = [receive["id"]]
    replay = tmp_path / "replay"
    replay.mkdir()
    (replay / "r0001.recon.json").write_text(json.dumps(reply))
    output = tmp_path / "proposal"
    with pytest.raises(ValueError, match="registration, visibility or source fact"):
        propose_recon(target, graph_file, None, output, ReplayAgent(replay))
    assert read(output / "manifest.json")["status"] == "failed"
    assert read(output / "calls/r0001.recon/attempt-0001/raw-response.json") == reply
    assert not (output / "recon.json").exists()


class SuppliedAgent(ReplayAgent):
    def __init__(self, case, data=None):
        super().__init__(case["replay"])
        self.data = data or read(case["replay"] / "r0001.recon.json")
        self.error = None

    def call(self, *args, **kwargs):
        if self.error:
            raise self.error
        return Reply(self.data)


def test_proposal_connects_to_recon_slices_triage_and_resume(case, tmp_path):
    output = tmp_path / "proposal"
    before = case["static_file"].read_bytes()
    state = propose(case, output)
    assert state["status"] == "complete" and state["call_attempts"] == 1
    assert case["static_file"].read_bytes() == before
    recon = read_recon(output / "recon.json", case["graph"], case["sources"])
    hypotheses = recon["hypotheses"]
    assert [h["selection"]["priority"] for h in hypotheses] == list(range(1, len(hypotheses) + 1))
    assert all(
        h["recon_gaps"] and h["selection"]["entry_evidence"]["source_sha256"] for h in hypotheses
    )
    assert all(h["entry_status"] == "provided_hypothesis" for h in hypotheses)
    context = read(output / "context.json")
    assert context["payload_bytes"] <= context["byte_limit"] == 16000
    if case["graph"]["language"] == "go":
        assert all(h["registrations"][0]["status"] == "registration_only" for h in hypotheses)
    else:
        assert any(
            g["reason"] == "unselected_recon_entries"
            for g in recon["spec"]["proposal_origin"]["gaps"]
        )
    slices, _ = make_graph_slices(case["graph"], recon, case["sources"], 32000, case["static"])
    assert slices[0]["hypothesis"]["selection"]["rationale"]
    assert slices[0]["hypothesis"]["recon_gaps"]
    run = tmp_path / "review"
    metrics = run_pipeline(
        case["target"],
        run,
        ReplayAgent(case["replay"]),
        graph_file=case["graph_file"],
        recon_file=output / "recon.json",
        static_file=case["static_file"],
        slice_bytes=32000,
    )
    findings = read(run / "findings.json")
    assert findings and metrics["confirmed_findings"] == 0
    assert all(f["input_gaps"]["recon_gap_ids"] for f in findings)
    assert read(run / "recon-context.json") == context
    assert all(f["input_gaps"]["recon_context_ref"] == "recon-context.json" for f in findings)
    assert all("recon_gap_ids" in {i["kind"] for i in candidate_issues(f)} for f in findings)
    agent = SuppliedAgent(case)
    agent.error = AssertionError("cached proposal invoked the agent")
    resumed = propose(case, output, agent, resume=True)
    assert resumed["cache_hit"] and resumed["call_attempts"] == 1
    assert read(output / "recon.json") == recon
    assert not case["sentinel"].exists()


@pytest.mark.parametrize("case", ["go", "python"], indirect=True, scope="module")
def test_recon_call_context_is_bounded_and_keeps_missing_calls(case):
    full = recon_context(case["graph"], case["sources"], case["static"], 16000)
    supplied = {function["id"] for function in full["data"]["functions"]}
    graph_calls = {call["id"]: call for call in case["graph"]["calls"]}
    assert full["data"]["calls"]
    assert all(
        call["caller"] in supplied
        and call["id"] in graph_calls
        and call["status"] == graph_calls[call["id"]]["status"]
        and call["callee"] == graph_calls[call["id"]]["callee"]
        for call in full["data"]["calls"]
    )
    if case["graph"]["language"] == "python":
        assert any(
            call["status"] == "unresolved" and call["callee"] is None
            for call in full["data"]["calls"]
        )
    first = full["data"]["calls"][0]
    assert first["status"] == "resolved"
    fact_only = {**full["data"], "calls": []}
    limit = len(encode({**fact_only, "calls": [first]}).encode())
    partial = recon_context(case["graph"], case["sources"], case["static"], limit)
    assert partial["payload_bytes"] <= limit
    assert partial["data"]["calls"][0] == first
    omitted = [item for item in partial["omissions"] if item["kind"] == "call"]
    assert omitted and all(item["reason"] == "recon_input_byte_budget" for item in omitted)
    assert all(item["source_sha256"] for item in omitted)
    assert "recon_input_byte_budget" in {gap["reason"] for gap in partial["gaps"]}


def test_recon_relationships_are_bounded_structural_paths(case):
    context = recon_context(case["graph"], case["sources"], case["static"], 16000)
    facts = {fact["id"]: fact for fact in context["data"]["facts"]}
    calls = {call["id"]: call for call in case["graph"]["calls"]}
    supplied = {call["id"] for call in context["data"]["calls"]}
    relationships = context["data"]["relationships"]
    assert all(
        relation["entry_fact_id"] in facts
        and relation["role_fact_id"] in facts
        and facts[relation["role_fact_id"]]["role"] == relation["role"]
        and all(
            call_id in supplied
            and calls[call_id]["status"] == "resolved"
            and calls[call_id]["dispatch"] == "direct"
            for call_id in relation["call_ids"]
        )
        for relation in relationships
    )
    if case["graph"]["language"] == "python":
        functions = {f["id"]: f for f in case["graph"]["functions"]}
        assert any(
            functions[facts[relation["entry_fact_id"]]["function"]]["name"] == "across_files"
            and functions[facts[relation["role_fact_id"]]["function"]]["name"] == "execute"
            and len(relation["call_ids"]) == 1
            for relation in relationships
        )
        assert any(item["reason"] == "no_resolved_direct_path" for item in context["omissions"])
        no_relations = {**context["data"], "relationships": [], "value_flows": []}
        limited = recon_context(
            case["graph"], case["sources"], case["static"], len(encode(no_relations).encode())
        )
        assert not limited["data"]["relationships"]
        assert any(
            item["kind"] == "relationship" and item["reason"] == "recon_input_byte_budget"
            for item in limited["omissions"]
        )


def test_go_http_file_roles_link_across_packages_without_claiming_taint(tmp_path):
    target = ROOT / "examples/model-eval-prospective-go-target"
    graph_file = tmp_path / "graph/graph.json"
    graph = build_graph(target, graph_file.parent, language="go")
    static = build_static(target, graph_file, DEFAULT_RULES, tmp_path / "static")
    sources, _ = index_target(target)
    context = recon_context(graph, sources, static, 16000)
    facts = {fact["id"]: fact for fact in context["data"]["facts"]}
    functions = {function["id"]: function for function in graph["functions"]}
    calls = {call["id"]: call for call in graph["calls"]}
    assert not static["taint_results"]
    assert {fact["role"] for fact in facts.values() if fact["kind"] == "static_role"} == {
        "source",
        "sink",
    }
    selected = [
        relationship
        for relationship in context["data"]["relationships"]
        if relationship["role"] == "sink"
        and facts[relationship["entry_fact_id"]]["kind"] == "static_role"
        and functions[facts[relationship["entry_fact_id"]]["function"]]["name"] == "Selected"
        and functions[facts[relationship["role_fact_id"]]["function"]]["name"] == "ReadSelected"
    ]
    assert len(selected) == 1 and len(selected[0]["call_ids"]) == 1
    assert len(context["data"]["value_flows"]) == 1
    flow = context["data"]["value_flows"][0]
    assert [calls[ref]["callee_name"].split(".")[-1] for ref in flow["call_ids"]] == [
        "Get",
        "ReadSelected",
        "ReadFile",
    ]
    assert flow["status"] == "bounded_syntax_value_path"
    recon = build_recon(
        target,
        graph_file,
        ROOT / "examples/model-eval-prospective-go-plan.json",
        tmp_path / "researcher-recon",
    )
    slices, slice_gaps = make_graph_slices(graph, recon, sources, 16000, static)
    assert len(slices[0]["value_flows"]) == 1
    assert slices[0]["omitted_counts"]["value_flows"] == 0
    assert not any(
        gap["kind"] == "value_flow" for gap in slice_gaps if gap["hypothesis_id"] == "selected-file"
    )
    transfer = calls[selected[0]["call_ids"][0]]["metadata"]["argument_transfers"][0]
    assert (transfer["expression"], transfer["parameter_name"], transfer["kind"]) == (
        "name",
        "name",
        "identifier",
    )
    assert any(
        functions[facts[relationship["entry_fact_id"]]["function"]]["name"] == "Public"
        and functions[facts[relationship["role_fact_id"]]["function"]]["name"] == "ReadPublic"
        and relationship["role"] == "sink"
        for relationship in context["data"]["relationships"]
    )
    assert 'os.ReadFile("public.txt")' in (target / "store/files.go").read_text()
    assert "no_resolved_direct_path" in {item["reason"] for item in context["omissions"]}


@pytest.mark.parametrize(
    "change", ["reassign", "conditional", "address_escape", "conversion", "forward"]
)
def test_go_value_flow_keeps_controls_and_multihop_distinct(tmp_path, change):
    target = tmp_path / "target"
    shutil.copytree(ROOT / "examples/model-eval-prospective-go-target", target)
    handler = target / "web/handlers.go"
    text = handler.read_text()
    if change == "reassign":
        text = text.replace(
            "\tdata, err := store.ReadSelected(name)",
            '\tname = "public.txt"\n\tdata, err := store.ReadSelected(name)',
        )
    elif change == "conditional":
        text = text.replace(
            "\tdata, err := store.ReadSelected(name)",
            '\tif name == "" { return }\n\tdata, err := store.ReadSelected(name)',
        )
    elif change == "address_escape":
        text = text.replace(
            "\tdata, err := store.ReadSelected(name)",
            '\tp := &name\n\t*p = "public.txt"\n\tdata, err := store.ReadSelected(name)',
        )
    elif change == "conversion":
        text = text.replace(
            "\tdata, err := store.ReadSelected(name)",
            "\tconverted := string([]byte(name))\n\tdata, err := store.ReadSelected(converted)",
        )
    else:
        text = text.replace("store.ReadSelected(name)", "store.Forward(name)")
        with (target / "store/files.go").open("a") as stream:
            stream.write(
                "\nfunc Forward(name string) ([]byte, error) { return ReadSelected(name) }\n"
            )
    handler.write_text(text)
    graph_file = tmp_path / "graph/graph.json"
    graph = build_graph(target, graph_file.parent, language="go")
    static = build_static(target, graph_file, DEFAULT_RULES, tmp_path / "static")
    sources, _ = index_target(target)
    context = recon_context(graph, sources, static, 16000)
    flows = context["data"]["value_flows"]
    if change == "forward":
        assert len(flows) == 1
        calls = {call["id"]: call for call in graph["calls"]}
        assert [calls[ref]["callee_name"].split(".")[-1] for ref in flows[0]["call_ids"]] == [
            "Get",
            "Forward",
            "ReadSelected",
            "ReadFile",
        ]
    else:
        assert not flows
        assert "no_supported_value_path" in {gap["reason"] for gap in context["gaps"]}


def test_new_go_fixture_freezes_sink_site_and_separates_constant_control(tmp_path):
    target = ROOT / "examples/go-eval-next-target"
    labels, _, skipped, _ = checked_truth(target, ROOT / "examples/go-eval-next-truth.json")
    assert {item["path"] for item in skipped} == {"go.mod"}
    assert [(case["id"], case["line"], case["expected"]) for case in labels] == [
        ("request-selected-export", 6, "positive"),
        ("fixed-notice-control", 10, "negative"),
    ]
    graph_file = tmp_path / "graph/graph.json"
    graph = build_graph(target, graph_file.parent, language="go")
    static = build_static(target, graph_file, DEFAULT_RULES, tmp_path / "static")
    recon = build_recon(
        target, graph_file, ROOT / "examples/go-eval-next-plan.json", tmp_path / "recon"
    )
    sources, _ = index_target(target)
    slices, gaps = make_graph_slices(graph, recon, sources, 20000, static)
    calls = {call["id"]: call for call in graph["calls"]}
    positive = next(
        item for item in slices if item["hypothesis"]["id"] == "request-selected-export"
    )
    negative = next(item for item in slices if item["hypothesis"]["id"] == "fixed-notice-control")
    assert len(positive["value_flows"]) == 1
    assert [
        calls[ref]["callee_name"].split(".")[-1] for ref in positive["value_flows"][0]["call_ids"]
    ] == ["Get", "Fetch", "Open", "ReadFile"]
    assert not negative["value_flows"]
    assert any(
        gap["kind"] == "value_flow" and gap["hypothesis_id"] == "fixed-notice-control"
        for gap in gaps
    )
    limited, limited_gaps = make_graph_slices(graph, recon, sources, 16000, static)
    assert not limited[0]["value_flows"]
    assert limited[0]["omitted_counts"]["value_flows"] == 1
    assert any(gap["reason"] == "value_flow_input_omitted" for gap in limited_gaps)


def test_go_value_flow_state_budget_retains_unknown_pair():
    source_call = {
        "id": "source",
        "caller": "entry",
        "path": "entry.go",
        "line": 1,
        "column": 1,
        "dispatch": "direct",
        "status": "external",
        "metadata": {"call_end_line": 1, "call_end_column": 8},
    }
    sink_call = {
        "id": "sink",
        "caller": "other",
        "path": "other.go",
        "line": 1,
        "column": 1,
        "dispatch": "direct",
        "status": "external",
        "metadata": {"call_end_line": 1, "call_end_column": 8},
    }
    branches = [
        {
            "id": f"branch-{i}",
            "caller": "entry",
            "callee": f"function-{i}",
            "path": "entry.go",
            "line": i + 2,
            "column": 1,
            "dispatch": "direct",
            "status": "resolved",
            "metadata": {
                "argument_origins": [
                    {
                        "argument_index": 0,
                        "kind": "call_result",
                        "path": "entry.go",
                        "line": 1,
                        "column": 1,
                        "end_line": 1,
                        "end_column": 8,
                    }
                ],
                "argument_transfers": [{"argument_index": 0, "parameter_index": 0}],
            },
        }
        for i in range(MAX_STATES + 1)
    ]
    graph = {"language": "go", "calls": [source_call, *branches, sink_call]}
    static = {
        "observations": [
            {
                "id": "source-role",
                "role": "source",
                "rule_id": "r",
                "evidence": {
                    "function_id": "entry",
                    "call_ids": ["source"],
                    "line": 1,
                    "column": 1,
                    "end_line": 1,
                    "end_column": 8,
                },
            },
            {
                "id": "sink-role",
                "role": "sink",
                "rule_id": "r",
                "evidence": {
                    "function_id": "other",
                    "call_ids": ["sink"],
                    "line": 1,
                    "column": 1,
                    "end_line": 1,
                    "end_column": 8,
                },
            },
        ]
    }
    flows, gaps = go_value_flows(graph, static)
    assert not flows
    assert gaps == [
        {
            "source_observation_id": "source-role",
            "sink_observation_id": "sink-role",
            "reason": "value_flow_state_budget",
        }
    ]


@pytest.mark.parametrize(
    "change",
    [
        "unknown_entry",
        "false_quote",
        "byte_column",
        "wrong_function",
        "unknown_fact",
        "wrong_fact",
        "exposure",
        "annotation",
    ],
)
def test_invalid_proposals_preserve_raw_failure_without_plan(case, tmp_path, change):
    data = read(case["replay"] / "r0001.recon.json")
    item = data["hypotheses"][-1]
    if change == "unknown_entry":
        item["entry"] = "guessed-function"
    elif change == "false_quote":
        item["selection"]["entry_evidence"]["quote"] = "invented exposure proof"
    elif change == "byte_column":
        item["selection"]["entry_evidence"]["column"] = 2
    elif change == "wrong_function":
        item["selection"]["entry_evidence"]["line"] += 10
    elif change == "unknown_fact":
        item["selection"]["fact_ids"] = ["rf-" + "0" * 24]
    elif change == "wrong_fact":
        context = recon_context(case["graph"], case["sources"], case["static"], 16000)
        other = next(f for f in context["data"]["facts"] if f["function"] != item["entry"])
        item["selection"]["fact_ids"] = [other["id"]]
    elif change == "exposure":
        item["exposure"] = "verified"
    else:
        item["annotations"] = [
            {
                "role": "boundary",
                "function": "unprovided-function",
                "claim": "Claimed control",
                "evidence": item["selection"]["entry_evidence"],
            }
        ]
    output = tmp_path / "invalid"
    with pytest.raises(ValueError):
        propose(case, output, SuppliedAgent(case, data))
    assert read(output / "manifest.json")["status"] == "failed"
    attempt = output / "calls/r0001.recon/attempt-0001"
    assert read(attempt / "raw-response.json") == data and (attempt / "failure.json").is_file()
    assert not (output / "recon.json").exists()
    assert not case["sentinel"].exists()


def test_budget_omissions_empty_reply_and_changed_budget(case, tmp_path):
    agent = SuppliedAgent(case, {"hypotheses": [], "unresolved": ["No adequate supplied entry."]})
    output = tmp_path / "small"
    state = propose(case, output, agent, input_bytes=1024)
    context = read(output / "context.json")
    assert context["payload_bytes"] <= 1024 and context["omissions"]
    assert all(
        {"kind", "function", "path", "line", "column", "source_sha256"} <= item.keys()
        for item in context["omissions"]
    )
    assert not context["data"]["facts"]
    assert state["status"] == "no_hypotheses" and not (output / "recon.json").exists()
    prompt = (output / "calls/r0001.recon/attempt-0001/prompt.txt").read_text()
    packet = json.loads(prompt.split("UNTRUSTED_INPUT_JSON:\n")[1])
    assert "omissions" not in packet and packet["omissions_ref"] == "coverage.json"
    assert propose(case, output, agent, input_bytes=1024, resume=True)["cache_hit"]
    with pytest.raises(ValueError, match="inputs changed"):
        propose(case, output, agent, input_bytes=16000, resume=True)


def test_timeout_retry_and_global_attempt_cap(case, tmp_path):
    output = tmp_path / "retry"
    agent = SuppliedAgent(case)
    agent.error = subprocess.TimeoutExpired("recorded recon", 1)
    with pytest.raises(subprocess.TimeoutExpired):
        propose(case, output, agent)
    failure = output / "calls/r0001.recon/attempt-0001/failure.json"
    assert read(failure)["type"] == "TimeoutExpired"
    agent.error = None
    with pytest.raises(ValueError, match="call budget exhausted"):
        propose(case, output, agent, resume=True)
    state = propose(case, output, agent, resume=True, max_calls=2)
    assert state["status"] == "complete" and state["call_attempts"] == 2
    assert (
        failure.is_file()
        and (output / "calls/r0001.recon/attempt-0002/raw-response.json").is_file()
    )


@pytest.mark.parametrize(
    "name", ["context", "graph", "static", "research-plan", "recon", "raw", "reply"]
)
def test_changed_saved_evidence_rejected_repeatedly(case, tmp_path, name):
    output = tmp_path / "changed"
    propose(case, output)
    if name == "raw":
        path = output / "calls/r0001.recon/attempt-0001/raw-response.json"
    elif name == "reply":
        path = output / "calls/r0001.recon/reply.json"
    else:
        path = output / f"{name}.json"
    data = read(path)
    data["altered"] = True
    path.write_text(encode(data))
    for _ in range(2):
        with pytest.raises(ValueError):
            propose(case, output, resume=True)
        assert read(path) == data


def test_imported_plan_checks_quotes_identity_and_original_static(case, tmp_path):
    output = tmp_path / "proposal"
    propose(case, output)
    plan = read(output / "research-plan.json")
    changed = copy.deepcopy(plan)
    changed["proposal_origin"]["graph_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="identity differs"):
        make_recon(case["graph"], case["sources"], changed)
    changed = copy.deepcopy(plan)
    changed["hypotheses"][0]["selection"]["entry_evidence"]["column"] += 1
    with pytest.raises(ValueError, match="byte column"):
        make_recon(case["graph"], case["sources"], changed)
    with pytest.raises(ValueError, match="original --static"):
        run_pipeline(
            case["target"],
            tmp_path / "missing-static",
            ReplayAgent(case["replay"]),
            graph_file=case["graph_file"],
            recon_file=output / "recon.json",
        )


def test_cli_recon_proposal_and_resume(case, tmp_path, capsys):
    output = tmp_path / "cli"
    args = [
        "recon",
        str(case["target"]),
        "--graph",
        str(case["graph_file"]),
        "--static",
        str(case["static_file"]),
        "--replay",
        str(case["replay"]),
        "--output",
        str(output),
    ]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["hypotheses"]
    assert main([*args, "--resume"]) == 0
    assert json.loads(capsys.readouterr().out)["cache_hit"]
    assert main([*args, "--model", "unused"]) == 1
    assert "only used with --codex" in capsys.readouterr().err


def test_annotation_byte_column_and_source_identity_remain_checked(case, tmp_path):
    data = read(case["replay"] / "r0001.recon.json")
    item = data["hypotheses"][-1]
    item["annotations"] = [
        {
            "role": "boundary",
            "function": item["entry"],
            "claim": "Investigate this supplied entry.",
            "evidence": dict(item["selection"]["entry_evidence"]),
        }
    ]
    output = tmp_path / "annotation"
    propose(case, output, SuppliedAgent(case, data))
    item["annotations"][0]["evidence"]["column"] += 1
    with pytest.raises(ValueError):
        propose(case, tmp_path / "bad-annotation", SuppliedAgent(case, data))
    with pytest.raises(ValueError, match="outside the target"):
        propose(case, case["target"] / "output")


def test_resealed_reply_and_raw_cannot_change_saved_plan(case, tmp_path):
    output = tmp_path / "resealed"
    propose(case, output)
    checkpoint = output / "calls/r0001.recon/reply.json"
    raw = output / "calls/r0001.recon/attempt-0001/raw-response.json"
    data = read(checkpoint)
    data["data"]["hypotheses"][0]["selection"]["rationale"] += " Changed conclusion."
    data["reply_sha256"] = digest(data["data"])
    raw.write_text(encode(data["data"]))
    data["raw_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
    checkpoint.write_text(encode(data))
    original = (output / "recon.json").read_bytes()
    for _ in range(2):
        with pytest.raises(ValueError, match="result identity changed"):
            propose(case, output, resume=True)
        assert (output / "recon.json").read_bytes() == original


def test_partial_input_omission_survives_into_candidate_issues(case, tmp_path):
    full = recon_context(case["graph"], case["sources"], case["static"], 64000)
    fact_bytes = len(encode({**full["data"], "calls": []}).encode())
    data = read(case["replay"] / "r0001.recon.json")
    data["hypotheses"] = [data["hypotheses"][-1]]
    data["unresolved"] = []
    data["hypotheses"][0]["selection"]["unresolved"] = []
    output = tmp_path / "partial"
    propose(case, output, SuppliedAgent(case, data), input_bytes=fact_bytes - 1)
    recon = read_recon(output / "recon.json", case["graph"], case["sources"])
    assert any(
        g["reason"] == "recon_input_byte_budget" for g in recon["hypotheses"][0]["recon_gaps"]
    )
    review = tmp_path / "review"
    run_pipeline(
        case["target"],
        review,
        ReplayAgent(case["replay"]),
        graph_file=case["graph_file"],
        recon_file=output / "recon.json",
        static_file=case["static_file"],
        slice_bytes=32000,
    )
    assert read(review / "findings.json")[0]["input_gaps"]["recon_gap_ids"]


def test_source_change_during_proposal_preserves_response_and_failure(case, tmp_path):
    output = tmp_path / "changed-source"
    path = case["target"] / (
        "entry.py" if case["graph"]["language"] == "python" else "web/handlers.go"
    )
    original = path.read_bytes()
    agent = SuppliedAgent(case)
    call = agent.call

    def mutate(*args, **kwargs):
        reply = call(*args, **kwargs)
        path.write_bytes(
            original + (b"\n# changed\n" if path.suffix == ".py" else b"\n// changed\n")
        )
        return reply

    agent.call = mutate
    try:
        with pytest.raises(ValueError, match="source changed during proposal"):
            propose(case, output, agent)
    finally:
        path.write_bytes(original)
    assert read(output / "manifest.json")["status"] == "failed"
    assert (output / "calls/r0001.recon/attempt-0001/raw-response.json").is_file()
    assert not (output / "recon.json").exists()


def test_different_static_models_cannot_replace_proposal_input(case, tmp_path):
    output = tmp_path / "proposal"
    propose(case, output)
    rules = read(DEFAULT_RULES)
    rules["rules"][0]["assumptions"].append("A different declared model revision.")
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(encode(rules))
    alternative = tmp_path / "alternative/static.json"
    build_static(case["target"], case["graph_file"], rules_file, alternative.parent)
    with pytest.raises(ValueError, match="original --static"):
        run_pipeline(
            case["target"],
            tmp_path / "wrong-static",
            ReplayAgent(case["replay"]),
            graph_file=case["graph_file"],
            recon_file=output / "recon.json",
            static_file=alternative,
        )


def test_rebuilt_import_with_wrong_fact_binding_is_rejected(case, tmp_path):
    output = tmp_path / "proposal"
    propose(case, output)
    plan = read(output / "research-plan.json")
    facts = read(output / "context.json")["data"]["facts"]
    item = plan["hypotheses"][0]
    other = next(f for f in facts if f["function"] != item["entry"])
    item["selection"]["fact_ids"] = [other["id"]]
    imported = tmp_path / "recon.json"
    imported.write_text(encode(make_recon(case["graph"], case["sources"], plan)))
    with pytest.raises(ValueError, match="entry needs its registration, visibility or source fact"):
        run_pipeline(
            case["target"],
            tmp_path / "review",
            ReplayAgent(case["replay"]),
            graph_file=case["graph_file"],
            recon_file=imported,
            static_file=case["static_file"],
        )


@pytest.mark.parametrize("case", ["go"], indirect=True, scope="module")
def test_plan_without_static_keeps_original_gap_when_new_evidence_is_added(case, tmp_path):
    output = tmp_path / "registration-only"
    propose_recon(case["target"], case["graph_file"], None, output, ReplayAgent(case["replay"]))
    review = tmp_path / "review"
    run_pipeline(
        case["target"],
        review,
        ReplayAgent(case["replay"]),
        graph_file=case["graph_file"],
        recon_file=output / "recon.json",
        static_file=case["static_file"],
    )
    assert read(review / "recon-context.json")["data"]["static_sha256"] is None
    assert "static_not_supplied" in {
        g["reason"] for g in read(review / "recon.json")["hypotheses"][0]["recon_gaps"]
    }
