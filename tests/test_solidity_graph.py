import copy
import json
import shutil
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.cli import main
from agent_audit_harness.extractors import solidity
from agent_audit_harness.graph import build_graph, reachable, read_graph, resolve, validate_graph
from agent_audit_harness.pipeline import candidates_for_slice, encode, index_target, run_pipeline
from agent_audit_harness.recon import build_recon, make_graph_slices, make_recon

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "solidity-target"
CACHE = ROOT / ".cache" / "solidity-extractor"
pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not (CACHE / "node_modules/solc/soljson.js").is_file(),
    reason="Node/pinned solc unavailable; run make setup-solidity",
)


@pytest.fixture(scope="module")
def graph_file(tmp_path_factory):
    output = tmp_path_factory.mktemp("solidity-graph")
    build_graph(FIXTURE, output)
    return output / "graph.json"


def spec():
    return {
        "schema_version": 1,
        "hypotheses": [
            {
                "id": "external-boundary",
                "entry": "Wallet.sol:Wallet.entry",
                "question": "What checks and external boundaries occur on this path?",
                "assumptions": [],
                "annotations": [
                    {
                        "function": "Base.sol:Base.onlyOwner",
                        "role": "barrier_candidate",
                        "claim": "Owner comparison exists; effectiveness needs investigation.",
                        "evidence": {
                            "path": "Base.sol",
                            "line": 7,
                            "quote": 'require(msg.sender == owner, "owner");',
                        },
                    }
                ],
            }
        ],
    }


def test_common_contract_inheritance_modifier_and_cross_file_queries(graph_file, tmp_path):
    graph = read_graph(graph_file)
    assert graph["schema_version"] == 2 and graph["language"] == "solidity"
    validate_graph(graph)
    nodes = {n["qualified_name"]: n for n in graph["functions"]}
    types = {n["name"]: n for n in graph["contexts"] if n["kind"] == "type"}
    entry = nodes["Wallet.sol:Wallet.entry"]
    assert entry["metadata"]["base_contract_ids"] == [types["Base"]["id"]]
    assert entry["metadata"]["linearized_base_ids"] == [types["Wallet"]["id"], types["Base"]["id"]]
    assert types["Base"]["id"] in types["Wallet"]["references"]
    assert nodes["Wallet.sol:Wallet.hook"]["metadata"]["overrides"] == [
        nodes["Base.sol:Base.hook"]["id"]
    ]
    result = reachable(graph, entry["id"])
    assert {n["name"] for n in result["functions"]} == {
        "entry",
        "onlyOwner",
        "helper",
        "bump",
        "stage",
    }
    modifier = next(c for c in result["calls"] if c["dispatch"] == "modifier")
    assert modifier["callee"] == nodes["Base.sol:Base.onlyOwner"]["id"]
    assert modifier["metadata"]["modifier_index"] == 0
    assert nodes["Base.sol:Base.onlyOwner"]["metadata"]["placeholder_count"] == 1
    assert any(
        c["callee_name"] == "require" and c["caller"] == modifier["callee"] for c in result["calls"]
    )
    assert {(e["caller_file"], e["callee_file"]) for e in graph["file_calls"]} == {
        ("Wallet.sol", "Base.sol"),
        ("Wallet.sol", "Ops.sol"),
    }
    assert len(resolve(graph, "Wallet.sol:Wallet")["functions"]) == 6
    assert len(resolve(graph, "ITarget.sol")["functions"]) == 1
    assert build_graph(FIXTURE, tmp_path / "again") == graph


def test_external_library_contract_self_and_low_level_boundaries(graph_file):
    graph = read_graph(graph_file)
    result = reachable(graph, "entry")
    external = {c["callee_name"]: c for c in result["calls"] if c["status"] == "external"}
    for name in ("ITarget.sol:ITarget.ping", "Wallet.sol:Wallet.echo", "Ops.sol:Ops.linked"):
        assert external[name]["callee"] is None and external[name]["metadata"]["declaration_id"]
        assert external[name]["reason"] == "runtime_contract_binding"
    assert external["Ops.sol:Ops.linked"]["dispatch"] == "library_external"
    assert "gas: 100000" in external["ITarget.sol:ITarget.ping"]["metadata"]["expression"]
    assert not {"ping", "echo", "linked"} & {n["name"] for n in result["functions"]}
    low = next(c for c in result["calls"] if c["dispatch"] == "low_level")
    assert low["status"] == "unresolved" and low["callee"] is None
    assert low["reason"] == "runtime_address_and_selector"
    assert low in result["unresolved_calls"]
    assert all(c["provenance"] == "solc_ast" for c in graph["calls"])


def test_direct_parameter_facts_do_not_resolve_external_or_virtual_calls(graph_file):
    graph = read_graph(graph_file)
    helper = next(
        call
        for call in graph["calls"]
        if call["callee_name"] == "Base.sol:Base.helper"
        and call["caller"]
        == next(node["id"] for node in graph["functions"] if node["name"] == "entry")
    )
    assert helper["status"] == "resolved" and helper["dispatch"] == "direct"
    assert helper["metadata"]["argument_origins"] == [
        {"argument_index": 0, "kind": "parameter", "parameter_index": 2}
    ]
    assert helper["metadata"]["argument_transfers"][0]["parameter_name"] == "n"
    assert helper["metadata"]["argument_transfers"][0]["expression"] == "n"
    bump = next(call for call in graph["calls"] if call["callee_name"] == "Ops.sol:Ops.bump")
    assert bump["metadata"]["argument_transfers"][0]["expression"] == "helper(n)"
    assert bump["metadata"]["argument_origins"] == [
        {"argument_index": 0, "kind": "unknown", "reason": "unsupported_expression"}
    ]
    assert all(
        "argument_transfers" not in call["metadata"]
        for call in graph["calls"]
        if call["status"] != "resolved" or call["dispatch"] != "direct"
    )
    changed = copy.deepcopy(graph)
    next(call for call in changed["calls"] if call["id"] == helper["id"])["metadata"][
        "argument_transfers"
    ][0]["parameter_name"] = "invented"
    with pytest.raises(ValueError, match="argument transfer"):
        validate_graph(changed)


def test_virtual_super_and_function_values_do_not_invent_edges(graph_file):
    graph = read_graph(graph_file)
    virtual = reachable(graph, "invokeVirtual")
    assert {n["name"] for n in virtual["functions"]} == {"invokeVirtual", "viaVirtual"}
    assert virtual["unresolved_calls"][0]["dispatch"] == "virtual"
    assert virtual["unresolved_calls"][0]["metadata"]["declaration_id"]
    hook = reachable(graph, "Wallet.sol:Wallet.hook")
    assert len(hook["functions"]) == 1 and hook["calls"][0]["dispatch"] == "super"
    dynamic = reachable(graph, "dynamic")
    assert len(dynamic["functions"]) == 1
    assert dynamic["calls"][0]["reason"] == "function_value"
    assert all(c["callee"] is None for c in hook["calls"] + dynamic["calls"])


def test_solidity_graph_recon_multifile_slicing_replay_resume_and_cli(graph_file, tmp_path, capsys):
    spec_file = tmp_path / "plan.json"
    spec_file.write_text(encode(spec()))
    recon = build_recon(FIXTURE, graph_file, spec_file, tmp_path / "recon")
    graph = read_graph(graph_file)
    sources, _ = index_target(FIXTURE)
    slices, gaps = make_graph_slices(graph, recon, sources, 24000)
    assert not gaps and len(slices) == 1
    text = "\n".join(f["text"] for f in slices[0]["fragments"])
    assert 'require(msg.sender == owner, "owner")' in text and "address public owner" in text
    assert "function bump" in text and "contract Wallet is Base" in text
    assert any(c["dispatch"] == "low_level" for c in slices[0]["calls"])
    assert len(encode(slices[0]).encode()) <= 24000
    assert slices[0]["modifier_flows"][0]["flow"]["body_execution"]["min"] == 1
    bounded, bounded_gaps = make_graph_slices(graph, recon, sources, 16000)
    assert bounded_gaps and len(encode(bounded[0]).encode()) <= 16000
    replay = tmp_path / "replay"
    replay.mkdir()
    external = next(c for c in slices[0]["calls"] if c["callee_name"] == "ITarget.sol:ITarget.ping")
    analysis = {
        "candidates": [
            {
                "path": external["path"],
                "line": external["line"],
                "cwe": "CWE-20",
                "title": "External implementation requires binding evidence",
                "reasoning": "Declared signature does not establish deployed code or controls.",
                "quote": external["metadata"]["expression"],
                "validation_plan": "Obtain deployment and control evidence.",
            }
        ]
    }
    candidate = candidates_for_slice(analysis, slices[0])[0]
    (replay / "s0001.analysis.json").write_text(encode(analysis))
    (replay / "s0001.triage.json").write_text(
        encode(
            {
                "groups": [
                    {
                        "root_cause": None,
                        "decisions": [
                            {
                                "candidate_id": candidate["id"],
                                "verdict": "uncertain",
                                "counterevidence": [],
                                "unresolved": [
                                    {"claim": "Runtime binding is unknown.", "evidence": None}
                                ],
                                "rationale": "Declaration known; runtime binding unknown.",
                            }
                        ],
                    }
                ]
            }
        )
    )
    options = {
        "graph_file": graph_file,
        "recon_file": tmp_path / "recon/recon.json",
        "slice_bytes": 24000,
    }
    first = run_pipeline(FIXTURE, tmp_path / "run", ReplayAgent(replay), **options)
    resumed = run_pipeline(FIXTURE, tmp_path / "run", ReplayAgent(replay), resume=True, **options)
    assert first["call_attempts"] == resumed["call_attempts"] == resumed["cache_hits"] == 2
    assert first["confirmed_findings"] == first["validation_executions"] == 0
    assert first["verdict_counts"] == {"uncertain": 1}
    assert (
        main(
            [
                "graph",
                "build",
                str(FIXTURE),
                "--language",
                "solidity",
                "--output",
                str(tmp_path / "cli"),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["graph", "resolve", str(graph_file), "Wallet.sol:Wallet"]) == 0
    assert json.loads(capsys.readouterr().out)["functions"]


@pytest.mark.parametrize("invalid", ["type_error", "pragma", "missing_import"])
def test_invalid_compilation_excludes_all_partial_ast(tmp_path, invalid):
    target = tmp_path / "target"
    target.mkdir()
    (target / "Good.sol").write_text(
        "pragma solidity ^0.8.20; contract Good {function ok() public {}}"
    )
    contents = {
        "type_error": (
            "pragma solidity ^0.8.20; contract Bad {function broken() public {absent();}}"
        ),
        "pragma": "pragma solidity 0.8.19; contract Bad {}",
        "missing_import": 'pragma solidity ^0.8.20; import "../outside.sol"; contract Bad {}',
    }
    (target / "Bad.sol").write_text(contents[invalid])
    (tmp_path / "outside.sol").write_text("pragma solidity ^0.8.20; contract Outside {}")
    graph = build_graph(target, tmp_path / "graph")
    assert graph["coverage"]["status"] == "partial"
    assert not graph["functions"] and not graph["calls"] and not graph["contexts"]
    assert all(u["status"] == "failed" and u["errors"] for u in graph["coverage"]["units"])
    if invalid == "missing_import":
        assert "Import outside supplied sources is disabled" in str(graph["coverage"]["units"])


def test_alias_using_overloads_computed_functions_getters_assembly_and_utf8(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "Lib.sol").write_text(
        "pragma solidity ^0.8.20; library Lib {"
        "function f(uint n) internal pure returns(uint) {return n;}}"
    )
    (target / "Edge.sol").write_text("""pragma solidity ^0.8.20;
import {Lib as Alias} from "./Lib.sol";
// 한글 comments have byte offsets, not character offsets.
contract Edge {
    using Alias for uint;
    uint public value;
    function leaf(uint n) internal pure returns(uint) {return n;}
    function leaf(address a) internal pure returns(address) {return a;}
    function chosen(uint n) internal pure returns(uint) {return n;}
    function factory() internal pure
        returns(function(uint) internal pure returns(uint)) {return chosen;}
    function entry(uint n, bool choose) public returns(uint) {
        uint v = n.f();
        v = leaf(v);
        v = factory()(v);
        v = (choose ? chosen : chosen)(v);
        v = this.value();
        assembly { mstore(0, v) }
        return v;
    }
    function first() public pure {revert();} /* 한 */ function second() public pure {assert(true);}
    function externalValue(function(uint) external returns(uint) cb, uint n)
        public returns(uint) {return cb(n);}
    function low(address target, bytes memory data) public {
        target.delegatecall(data); target.staticcall(data);
        payable(target).send(1); payable(target).transfer(1);
    }
}
""")
    graph = build_graph(target, tmp_path / "graph")
    assert graph["coverage"]["status"] == "parsed", graph["coverage"]
    result = reachable(graph, "entry")
    assert {n["name"] for n in result["functions"]} == {"entry", "f", "leaf", "factory"}
    assert len([c for c in result["calls"] if c["reason"] == "function_value"]) == 2
    assert len([c for c in result["calls"] if c["dispatch"] == "assembly"]) == 1
    getter = next(c for c in result["calls"] if c["metadata"]["expression"] == "this.value()")
    assert getter["status"] == "external" and getter["dispatch"] == "external"
    assert reachable(graph, "externalValue")["calls"][0]["reason"] == "function_value"
    low = reachable(graph, "low")["calls"]
    assert len([c for c in low if c["status"] == "unresolved"]) == 2
    assert len([c for c in low if c["reason"] == "runtime_recipient"]) == 2
    with pytest.raises(ValueError, match="match once"):
        reachable(graph, "leaf")
    sources, _ = index_target(target)
    wrong = spec()
    wrong["hypotheses"][0].update(entry="second")
    wrong["hypotheses"][0]["annotations"][0].update(
        function="second",
        evidence={
            "path": "Edge.sol",
            "line": next(n["line"] for n in graph["functions"] if n["name"] == "second"),
            "quote": "revert();",
        },
    )
    with pytest.raises(ValueError, match="quote|columns"):
        make_recon(graph, sources, wrong)
    wrong["hypotheses"][0]["annotations"][0]["evidence"]["quote"] = "assert(true);"
    assert make_recon(graph, sources, wrong)["hypotheses"]


def test_multiple_inheritance_linearization_and_modifier_order(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "Multi.sol").write_text("""pragma solidity ^0.8.20;
contract A { modifier one() virtual {_ ;} function f() internal virtual returns(uint) {return 1;} }
contract B is A {
    modifier two(uint n) {require(n > 0); _; _;}
    function f() internal virtual override returns(uint) {return super.f();}
}
contract C is A, B {
    modifier one() override {_ ;}
    function f() internal override(A,B) returns(uint) {return A.f();}
    function entry(uint n) public one two(n) returns(uint) {return f();}
}
""")
    graph = build_graph(target, tmp_path / "graph")
    assert graph["coverage"]["status"] == "parsed", graph["coverage"]
    nodes = {n["qualified_name"]: n for n in graph["functions"]}
    types = {n["id"]: n["name"] for n in graph["contexts"] if n["kind"] == "type"}
    entry = nodes["Multi.sol:C.entry"]
    assert [types[i] for i in entry["metadata"]["linearized_base_ids"]] == ["C", "B", "A"]
    assert len(nodes["Multi.sol:C.f"]["metadata"]["overrides"]) == 2
    result = reachable(graph, entry["id"])
    modifiers = sorted(
        (c for c in result["calls"] if c["dispatch"] == "modifier"),
        key=lambda c: c["metadata"]["modifier_index"],
    )
    assert [c["callee_name"] for c in modifiers] == ["Multi.sol:C.one", "Multi.sol:B.two"]
    assert nodes["Multi.sol:B.two"]["metadata"]["placeholder_count"] == 2
    assert nodes["Multi.sol:A.f"] in result["functions"]  # Explicit A.f bypasses virtual dispatch.
    assert nodes["Multi.sol:B.f"] not in result["functions"]


def test_source_boundaries_node_preload_and_target_scripts_are_not_executed(tmp_path, monkeypatch):
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    marker = tmp_path / "executed"
    script = tmp_path / "preload.cjs"
    script.write_text(f'require("node:fs").writeFileSync({json.dumps(str(marker))}, "bad");')
    monkeypatch.setenv("NODE_OPTIONS", f"--require={script}")
    (target / "hardhat.config.js").write_text(script.read_text())
    (target / "package.json").write_text('{"scripts":{"compile":"touch unsafe"}}')
    (target / "Outside.sol").symlink_to(FIXTURE / "Ops.sol")
    graph = build_graph(target, tmp_path / "graph", language="solidity")
    assert not marker.exists()
    assert any(
        s["path"] == "Outside.sol" and s["reason"] == "symlink"
        for s in graph["coverage"]["skipped"]
    )
    assert graph["coverage"]["metadata"]["network"] is False
    assert "hardhat.config.js" in graph["coverage"]["unvisited_sources"]
    with pytest.raises(ValueError, match="database"):
        build_graph(
            FIXTURE,
            tmp_path / "db",
            database=tmp_path / "compile_commands.json",
            language="solidity",
        )
    with pytest.raises(ValueError, match="outside"):
        solidity.extract(target, index_target(target)[0], cache=target / "cache")
    with pytest.raises(ValueError, match="dependencies missing"):
        solidity.extract(target, index_target(target)[0], cache=tmp_path / "empty-cache")


def test_unknown_context_and_duplicate_ast_locations_are_rejected(graph_file, tmp_path):
    graph = read_graph(graph_file)
    changed = copy.deepcopy(graph)
    changed["contexts"][0]["references"].append("missing-context")
    with pytest.raises(ValueError, match="context"):
        validate_graph(changed)
    sources, _ = index_target(FIXTURE)
    selected = [sources[0]]
    malformed = {
        selected[0].path: {
            "id": 0,
            "ast": {
                "nodeType": "SourceUnit",
                "id": 1,
                "src": "0:999999:0",
                "nodes": [
                    {
                        "nodeType": "FunctionDefinition",
                        "id": 2,
                        "src": "0:999999:0",
                        "name": "bad",
                        "kind": "function",
                        "parameters": {"parameters": []},
                    }
                ],
            },
        }
    }
    with pytest.raises(ValueError, match="location"):
        solidity.ast_graph(malformed, selected)
    with pytest.raises(ValueError, match="256"):
        solidity.extract(FIXTURE, selected * 257, cache=CACHE)
