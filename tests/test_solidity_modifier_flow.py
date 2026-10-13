import copy
import shutil
from collections import defaultdict
from pathlib import Path

import pytest

from agent_audit_harness.extractors import solidity_flow
from agent_audit_harness.graph import build_graph, reachable, read_graph, resolve, validate_graph
from agent_audit_harness.investigation import answer_requests, evidence_slice
from agent_audit_harness.pipeline import encode, index_target
from agent_audit_harness.recon import make_graph_slices, make_recon
from agent_audit_harness.triage import input_gaps

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples/solidity-modifier-target"
pytestmark = pytest.mark.skipif(
    shutil.which("node") is None
    or not (ROOT / ".cache/solidity-extractor/node_modules/solc/soljson.js").is_file(),
    reason="Node/pinned solc unavailable; run make setup-solidity",
)


@pytest.fixture(scope="module")
def graph(tmp_path_factory):
    result = build_graph(FIXTURE, tmp_path_factory.mktemp("modifier-flow"))
    assert result["coverage"]["status"] == "parsed", result["coverage"]
    return result


def function(graph, name):
    return next(node for node in graph["functions"] if node["name"] == name)


def flow(graph, name):
    return function(graph, name)["metadata"]["modifier_flow"]


def traces(model, choices=None, terminal="exit"):
    """Walk a bounded, branch-selected fixture path; never execute Solidity."""
    nodes = {node["id"]: node for node in model["nodes"]}
    edges = defaultdict(list)
    for edge in model["edges"]:
        edges[edge["from"]].append(edge)
    pending, results = [(model["entry"], [])], []
    while pending:
        current, path = pending.pop()
        assert len(path) < 100, "Use bounds assertions for cyclic fixtures"
        node = nodes[current]
        path = [*path, node]
        if current == model[terminal]:
            results.append(path)
        for edge in edges[current]:
            if node["kind"] == "branch" and choices and node["snippet"] in choices:
                if edge["kind"] != ("true" if choices[node["snippet"]] else "false"):
                    continue
            pending.append((edge["to"], path))
    return [
        [
            "BODY" if node["kind"] == "body" else node["snippet"]
            for node in path
            if node["kind"] == "body"
            or (node["kind"] == "statement" and node["snippet"].startswith("step("))
        ]
        for path in results
    ]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("combined", ["step(1)", "step(3)", "BODY", "step(4)", "BODY", "step(5)", "step(2)"]),
        (
            "swapped",
            [
                "step(3)",
                "step(1)",
                "BODY",
                "step(2)",
                "step(4)",
                "step(1)",
                "BODY",
                "step(2)",
                "step(5)",
            ],
        ),
        ("returnsValue", ["step(1)", "BODY", "step(2)"]),
    ],
)
def test_before_body_after_and_nested_modifier_order(graph, name, expected):
    model = flow(graph, name)
    assert model["complete"] and traces(model) == [expected]
    assert (
        model["body_execution"]["min"] == model["body_execution"]["max"] == expected.count("BODY")
    )
    assert function(graph, name) in resolve(graph, name)["functions"]


def test_conditional_omission_and_dead_placeholders(graph):
    conditional = flow(graph, "conditional")
    assert traces(conditional, {"allowed": True}) == [["step(6)", "BODY", "step(7)"]]
    assert traces(conditional, {"allowed": False}) == [["step(8)"]]
    assert conditional["body_execution"] == {
        "min": 0,
        "max": 1,
        "unbounded": False,
        "normal_exit_reachable": True,
    }
    omitted = flow(graph, "omitted")
    assert traces(omitted) == [["step(11)"]]
    assert omitted["body_execution"]["min"] == omitted["body_execution"]["max"] == 0
    assert not any(node["kind"] == "body" for node in omitted["nodes"])
    assert function(graph, "constantSkip")["metadata"]["placeholder_count"] == 1
    # The common call graph keeps syntax dependencies, even when the CFG omits the body.
    assert any(
        call["metadata"]["expression"] == "step(99)"
        for call in reachable(graph, "omitted")["calls"]
    )


def test_modifier_return_resumes_outer_postlude_and_can_skip_second_body(graph):
    assert traces(flow(graph, "skippedInner"), {"skip": True}) == [["step(1)", "step(2)"]]
    assert traces(flow(graph, "skippedInner"), {"skip": False}) == [
        ["step(1)", "BODY", "step(9)", "step(2)"]
    ]
    model = flow(graph, "partialReturn")
    assert traces(model, {"skip": True}) == [["step(1)", "BODY", "step(2)"]]
    assert traces(model, {"skip": False}) == [["step(1)", "BODY", "BODY", "step(2)"]]
    assert model["body_execution"]["min"] == 1 and model["body_execution"]["max"] == 2


def test_repetition_multiplies_and_inner_arguments_are_reevaluated(graph):
    model = flow(graph, "fourTimes")
    assert model["body_execution"]["min"] == model["body_execution"]["max"] == 4
    assert traces(model)[0].count("BODY") == 4
    arguments = flow(graph, "arguments")
    calls = {call["id"]: call for call in graph["calls"]}
    argument_call = next(
        call["id"]
        for call in graph["calls"]
        if call["caller"] == function(graph, "arguments")["id"]
        and call["metadata"]["expression"] == "value()"
    )
    inner = [
        node
        for node in arguments["nodes"]
        if node["kind"] == "modifier_enter" and node["modifier_index"] == 1
    ]
    assert len(inner) == 2 and all(argument_call in node["call_ids"] for node in inner)
    assert [calls[ref]["callee_name"] for ref in model["applications"]] == [
        "Guards.sol:Guards.twice"
    ] * 2


def test_require_assert_revert_and_no_normal_exit_are_distinct_from_omission(graph):
    checked = flow(graph, "checked")
    assert {node["guard"] for node in checked["nodes"] if "guard" in node} == {"require", "assert"}
    assert traces(checked, {"allowed": True}) == [["BODY"]]
    assert traces(checked, {"allowed": False}) == []
    assert traces(checked, {"allowed": False}, terminal="revert") == [[]]
    assert checked["body_execution"]["min"] == checked["body_execution"]["max"] == 1
    rejected = flow(graph, "rejected")
    assert traces(rejected, {"blocked": True}, terminal="revert") == [[]]
    assert traces(rejected, {"blocked": False}) == [["BODY"]]
    failed = flow(graph, "fails")
    assert failed["complete"] and failed["body_execution"] == {
        "min": None,
        "max": None,
        "unbounded": False,
        "normal_exit_reachable": False,
    }
    assert not traces(failed) and traces(failed, terminal="revert") == [[]]


def test_loop_repetition_break_and_continue_bounds(graph):
    assert flow(graph, "looped")["body_execution"] == {
        "min": 0,
        "max": None,
        "unbounded": True,
        "normal_exit_reachable": True,
    }
    assert (
        flow(graph, "once")["body_execution"]["min"]
        == flow(graph, "once")["body_execution"]["max"]
        == 1
    )
    assert flow(graph, "continued")["body_execution"] == {
        "min": 0,
        "max": 1,
        "unbounded": False,
        "normal_exit_reachable": True,
    }
    assert any(edge["kind"] == "continue" for edge in flow(graph, "continued")["edges"])
    assert any(edge["kind"] == "break" for edge in flow(graph, "once")["edges"])


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("unknown", "virtual_dispatch_requires_runtime_contract"),
        ("short", "expression_control_flow_not_expanded"),
        ("assemblyBoundary", "unsupported_modifier_statement:InlineAssembly"),
    ],
)
def test_unknown_and_opaque_flow_never_claims_body_counts(graph, name, reason):
    model = flow(graph, name)
    assert not model["complete"] and any(gap["reason"] == reason for gap in model["gaps"])
    assert model["body_execution"] == {
        "min": None,
        "max": None,
        "unbounded": False,
        "normal_exit_reachable": None,
    }
    sources, _ = index_target(FIXTURE)
    recon = make_recon(
        graph,
        sources,
        {
            "schema_version": 1,
            "hypotheses": [
                {
                    "id": "flow-gap",
                    "entry": name,
                    "question": "Inspect missing flow semantics.",
                    "assumptions": [],
                    "annotations": [],
                }
            ],
        },
    )
    source_slice = make_graph_slices(graph, recon, sources, 2200)[0][0]
    assert source_slice["omitted_counts"]["modifier_flows"] > 0
    gaps = input_gaps(source_slice, {"graph": graph, "recon": recon})
    assert function(graph, name)["id"] in gaps["modifier_gap_function_ids"]
    assert gaps["omitted_counts"] == source_slice["omitted_counts"]
    if name == "unknown":
        assert reachable(graph, name)["unresolved_calls"]
        assert not any(
            call["status"] == "resolved" and call["dispatch"] == "modifier"
            for call in reachable(graph, name)["calls"]
        )


def test_partial_source_query_retains_modifier_gap_outside_initial_hypothesis(graph):
    sources, _ = index_target(FIXTURE)
    spec = {
        "schema_version": 1,
        "hypotheses": [
            {
                "id": "order",
                "entry": "combined",
                "question": "Inspect wrapper order.",
                "assumptions": [],
                "annotations": [],
            }
        ],
    }
    recon = make_recon(graph, sources, spec)
    initial = make_graph_slices(graph, recon, sources, 64000)[0][0]
    node = function(graph, "short")
    assert (
        node["id"]
        not in input_gaps(initial, {"graph": graph, "recon": recon})["modifier_gap_function_ids"]
    )
    request = {
        "operation": "source",
        "path": node["path"],
        "first_line": node["line"],
        "last_line": node["line"],
        "reason": "Inspect another function without requesting its entire flow.",
    }
    history = {"responses": [], "budget": {"remaining_queries": 4, "remaining_bytes": 64000}}
    history.update(answer_requests(graph, sources, [request], history, "s0001"))
    assert history["responses"][0]["status"] == "provided"
    data = history["responses"][0]["data"]
    assert node["id"] in data["input_gaps"]["modifier_gap_function_ids"]
    assert {"function_id": node["id"], "gaps": flow(graph, "short")["gaps"]} in data[
        "modifier_gaps"
    ]
    assert "functions" not in data["structure"]
    supplied = evidence_slice(initial, history)
    assert (
        node["id"]
        in input_gaps(supplied, {"graph": graph, "recon": recon})["modifier_gap_function_ids"]
    )


def test_graph_round_trip_schema_compatibility_and_agent_slice_flow(graph, tmp_path):
    path = tmp_path / "graph.json"
    path.write_text(encode(graph))
    assert read_graph(path) == graph
    assert build_graph(FIXTURE, tmp_path / "again") == graph
    old = copy.deepcopy(graph)
    for node in old["functions"]:
        node["metadata"].pop("modifier_flow", None)
    validate_graph(old)  # Previous v2 artifacts do not need the optional extension.
    sources, _ = index_target(FIXTURE)
    spec = {
        "schema_version": 1,
        "hypotheses": [
            {
                "id": "order",
                "entry": "combined",
                "question": "Does the body repeat and what surrounds it?",
                "assumptions": [],
                "annotations": [],
            }
        ],
    }
    recon = make_recon(graph, sources, spec)
    slices, gaps = make_graph_slices(graph, recon, sources, 64000)
    assert not gaps
    assert slices[0]["modifier_flows"] == [
        {"function_id": function(graph, "combined")["id"], "flow": flow(graph, "combined")}
    ]
    assert slices[0]["omitted_counts"]["modifier_flows"] == 0
    small, gaps = make_graph_slices(graph, recon, sources, 5500)
    assert small and gaps and len(encode(small[0]).encode()) <= 5500
    assert small[0]["omitted_counts"]["modifier_flows"] == 1 and not small[0]["modifier_flows"]
    assert any(gap["kind"] == "modifier_flow" for gap in gaps)


@pytest.mark.parametrize("change", ["edge", "source", "call", "order", "bounds", "gap", "kind"])
def test_invalid_flow_evidence_and_summary_are_rejected(graph, change):
    changed = copy.deepcopy(graph)
    model = flow(changed, "combined")
    if change == "edge":
        model["edges"][0]["to"] = "missing"
    elif change == "source":
        model["nodes"][0]["path"] = "outside.sol"
    elif change == "call":
        model["nodes"][0]["call_ids"] = ["missing-call"]
    elif change == "order":
        model["applications"].reverse()
    elif change == "bounds":
        model["body_execution"]["max"] = 1
    elif change == "gap":
        model["complete"] = False
    else:
        model["nodes"][0]["kind"] = "invented"
    with pytest.raises(ValueError, match="modifier flow"):
        validate_graph(changed)


def test_expansion_budget_becomes_explicit_partial_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(solidity_flow, "MAX_FLOW_NODES", 8)
    limited = build_graph(FIXTURE, tmp_path / "limited")
    model = flow(limited, "fourTimes")
    assert not model["complete"] and model["gaps"][0]["reason"] == "modifier_flow_node_budget"
    assert len(model["nodes"]) == 4 and model["body_execution"]["max"] is None
    assert limited["coverage"]["status"] == "parsed"  # Parse success is separate from flow gaps.
