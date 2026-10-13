import copy
import json
from pathlib import Path

import pytest

from agent_audit_harness.agents import ReplayAgent
from agent_audit_harness.cli import main
from agent_audit_harness.extractors import python
from agent_audit_harness.graph import build_graph, reachable, read_graph, resolve, validate_graph
from agent_audit_harness.pipeline import candidates_for_slice, encode, index_target, run_pipeline
from agent_audit_harness.recon import build_recon, make_graph_slices

FIXTURE = Path(__file__).resolve().parents[1] / "examples/python-target"


@pytest.fixture(scope="module")
def graph_file(tmp_path_factory):
    output = tmp_path_factory.mktemp("python-graph")
    build_graph(FIXTURE, output)
    return output / "graph.json"


def target_files(tmp_path, files):
    target = tmp_path / "target"
    target.mkdir()
    for name, text in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return target


def test_package_directory_requires_its_parent_as_import_root(tmp_path):
    root = target_files(
        tmp_path,
        {
            "package/__init__.py": "from .worker import run\n",
            "package/worker.py": "def run(): return 1\n",
            "entry.py": "from package import run\ndef entry(): return run()\n",
        },
    )
    bad_output = tmp_path / "bad-graph"
    with pytest.raises(ValueError, match="package parent/import root"):
        build_graph(root / "package", bad_output, language="python")
    assert not (bad_output / "graph.json").exists()
    graph = build_graph(root, tmp_path / "good-graph", language="python")
    assert graph["coverage"]["status"] == "parsed"
    names = {item["qualified_name"] for item in reachable(graph, "entry.entry")["functions"]}
    assert "package.worker.run" in names


def test_straight_line_argument_origins_and_uncertain_boundaries(tmp_path):
    target = target_files(
        tmp_path,
        {
            "entry.py": (
                "import os\nfrom worker import execute\n"
                "def selected():\n    value = input()\n    execute(value)\n"
                "def constant():\n    value = input()\n    os.system('fixed')\n"
                "def branch(flag):\n    value = input()\n    if flag: pass\n    execute(value)\n"
                "def rebound():\n    value = input()\n    value = 'fixed'\n    execute(value)\n"
            ),
            "worker.py": "import os\ndef execute(value):\n    os.system(value)\n",
        },
    )
    graph = build_graph(target, tmp_path / "graph", language="python")
    by_id = {function["id"]: function["qualified_name"] for function in graph["functions"]}
    calls = {(by_id[call["caller"]], call["callee_name"]): call for call in graph["calls"]}
    selected = calls["entry.selected", "worker.execute"]
    assert selected["metadata"]["argument_origins"][0]["kind"] == "call_result"
    assert selected["metadata"]["argument_transfers"][0]["parameter_name"] == "value"
    assert calls["worker.execute", "os.system"]["metadata"]["argument_origins"] == [
        {"argument_index": 0, "kind": "parameter", "parameter_index": 0}
    ]
    assert calls["entry.constant", "os.system"]["metadata"]["argument_origins"] == [
        {"argument_index": 0, "kind": "constant"}
    ]
    for name in ("entry.branch", "entry.rebound"):
        assert calls[name, "worker.execute"]["metadata"]["argument_origins"][0]["kind"] == "unknown"
    tampered = copy.deepcopy(graph)
    next(call for call in tampered["calls"] if call["id"] == selected["id"])["metadata"][
        "argument_origins"
    ][0]["path"] = "worker.py"
    with pytest.raises(ValueError, match="argument origin"):
        validate_graph(tampered)


def test_shared_contract_multifile_modules_alias_reexport_and_queries(graph_file, tmp_path):
    graph = read_graph(graph_file)
    assert graph["schema_version"] == 2 and graph["language"] == "python"
    validate_graph(graph)
    assert graph["coverage"]["status"] == "parsed"
    assert graph["coverage"]["configuration_verified"] is False
    result = reachable(graph, "app.entry")
    assert {node["qualified_name"] for node in result["functions"]} == {
        "app.entry",
        "auditpkg.ops.stage",
        "auditpkg.shared.normalize",
        "auditpkg.worker.run",
        "auditpkg.worker.helper",
    }
    assert result["files"] == [
        "app.py",
        "auditpkg/ops.py",
        "auditpkg/shared.py",
        "auditpkg/worker.py",
    ]
    assert {(edge["caller_file"], edge["callee_file"]) for edge in graph["file_calls"]} == {
        ("app.py", "auditpkg/ops.py"),
        ("app.py", "auditpkg/shared.py"),
        ("app.py", "auditpkg/worker.py"),
        ("auditpkg/ops.py", "auditpkg/shared.py"),
        ("auditpkg/worker.py", "auditpkg/shared.py"),
    }
    assert {(edge["caller_scope"], edge["callee_scope"]) for edge in graph["scope_calls"]} == {
        ("app", "auditpkg.ops"),
        ("app", "auditpkg.shared"),
        ("app", "auditpkg.worker"),
        ("auditpkg.ops", "auditpkg.shared"),
        ("auditpkg.worker", "auditpkg.shared"),
    }
    assert len(resolve(graph, "auditpkg.worker")["functions"]) == 2
    assert resolve(graph, "auditpkg/worker.py")["functions"]
    assert resolve(graph, "auditpkg")["contexts"]  # Context-only re-export module.
    recursion = reachable(graph, "auditpkg.shared.recurse")
    assert len(recursion["functions"]) == 1 and recursion["calls"][0]["status"] == "resolved"
    assert all(call["provenance"] == "python_ast" for call in graph["calls"])
    assert build_graph(FIXTURE, tmp_path / "again") == graph


def test_unknown_callbacks_methods_dynamic_expressions_and_external_boundaries(graph_file):
    graph = read_graph(graph_file)
    result = reachable(graph, "dynamic")
    assert len(result["functions"]) == 1
    unknown = {call["metadata"]["expression"]: call for call in result["unresolved_calls"]}
    for name in ("callback", "obj.run", "getattr(obj, name)"):
        assert unknown[name]["status"] == "unresolved" and unknown[name]["callee"] is None
        assert unknown[name]["reason"]
    assert unknown["getattr"]["callee_name"] == "builtins.getattr"
    assert unknown["getattr"]["status"] == "external"
    assert reachable(graph, "normalize")["calls"][0]["status"] == "unresolved"


def test_nested_functions_async_src_layout_relative_parents_and_namespace_packages(tmp_path):
    target = target_files(
        tmp_path,
        {
            "src/pkg/shared.py": "def leaf(value):\n    return value\n",
            "src/pkg/deep/entry.py": (
                "from ..shared import leaf as imported\n"
                "async def entry(value):\n"
                "    def inner(item):\n        return imported(item)\n"
                "    return await inner(value)\n"
            ),
        },
    )
    graph = build_graph(target, tmp_path / "graph")
    result = reachable(graph, "pkg.deep.entry.entry")
    assert {node["qualified_name"] for node in result["functions"]} == {
        "pkg.deep.entry.entry",
        "pkg.deep.entry.entry.<locals>.inner",
        "pkg.shared.leaf",
    }
    assert next(node for node in result["functions"] if node["name"] == "entry")["metadata"][
        "async"
    ]
    assert any(call["metadata"]["awaited"] for call in result["calls"])
    assert not result["unresolved_calls"]


@pytest.mark.parametrize(
    "statement, expected",
    [
        ("leaf = callback", "multiple_bindings"),
        ("if enabled:\n    def leaf(value): return value", "conditional_binding"),
        ("@decorate\ndef leaf(value): return value", "decorated_function"),
        ("from local import *", "wildcard_import"),
    ],
)
def test_rebinding_conditionals_decorators_and_star_imports_are_not_resolved(
    tmp_path, statement, expected
):
    prefix = "def leaf(value): return value\n" if statement == "leaf = callback" else ""
    target = target_files(
        tmp_path,
        {
            "entry.py": prefix + statement + "\ndef entry(value): return leaf(value)\n",
            "local.py": "def leaf(value): return value\n",
        },
    )
    result = reachable(build_graph(target, tmp_path / "graph"), "entry.entry")
    assert len(result["functions"]) == 1
    assert result["calls"][0]["callee"] is None and result["calls"][0]["reason"] == expected


def test_lexical_shadowing_comprehensions_global_nonlocal_and_attribute_writes(tmp_path):
    target = target_files(
        tmp_path,
        {
            "entry.py": (
                "import other\ndef leaf(value): return value\n"
                "def parameter(leaf, value): return leaf(value)\n"
                "def assigned(value):\n    leaf(value)\n    leaf = value\n"
                "def comp(items):\n    [leaf(1) for leaf in items]\n    return leaf(2)\n"
                "def gen(items): return ([leaf(item) for item in items] for outer in items)\n"
                "def global_write(callback):\n    global leaf\n    leaf = callback\n"
                "def outer(value):\n    def inner(): return value\n"
                "    def write(callback):\n        nonlocal inner\n        inner = callback\n"
                "    return inner()\n"
                "def mutate(callback): other.work = callback\n"
                "def imported(value): return other.work(value)\n"
            ),
            "other.py": "def work(value): return value\n",
        },
    )
    graph = build_graph(target, tmp_path / "graph")
    for name in ("parameter", "assigned", "outer", "imported"):
        result = reachable(graph, "entry." + name)
        assert len(result["functions"]) == 1 and result["unresolved_calls"]
    assert reachable(graph, "imported")["calls"][0]["reason"] == "attribute_rebinding"
    assert all(call["callee"] is None for call in reachable(graph, "comp")["calls"])
    assert reachable(graph, "gen")["calls"][0]["execution"] == "deferred"


def test_comprehension_targets_do_not_leak_into_function_scope(tmp_path):
    target = target_files(
        tmp_path,
        {
            "entry.py": (
                "def leaf(value): return value\n"
                "def entry(items):\n    [leaf(1) for leaf in items]\n    return leaf(2)\n"
            )
        },
    )
    result = reachable(build_graph(target, tmp_path / "graph"), "entry.entry")
    assert [call["status"] for call in result["calls"]] == ["unresolved", "resolved"]


def test_local_imports_dynamic_imports_alias_values_and_nonpackage_parent(tmp_path):
    target = target_files(
        tmp_path,
        {
            "entry.py": (
                "import importlib\nfrom pkg.worker import work\n"
                "def leaf(value): return value\n"
                "def entry(value):\n    from other import work as local\n    local(value)\n"
                "    module = importlib.import_module('other')\n    module.work(value)\n"
                "    alias = leaf\n    alias(value)\n    work(value)\n"
            ),
            "other.py": "def work(value): return value\n",
            "pkg.py": "def placeholder(): return 1\n",
            "pkg/worker.py": "def work(value): return value\n",
        },
    )
    result = reachable(build_graph(target, tmp_path / "graph"), "entry.entry")
    assert {node["qualified_name"] for node in result["functions"]} == {
        "entry.entry",
        "other.work",
    }
    by_expression = {call["metadata"]["expression"]: call for call in result["calls"]}
    assert by_expression["local"]["status"] == "resolved"
    assert by_expression["importlib.import_module"]["status"] == "external"
    for name in ("module.work", "alias", "work"):
        assert by_expression[name]["status"] == "unresolved"
    assert by_expression["work"]["reason"] == "parent_module_is_not_a_parsed_package"


def test_nested_global_directive_does_not_capture_outer_local_function(tmp_path):
    target = target_files(
        tmp_path,
        {
            "entry.py": (
                "def outer():\n    def leaf(): return 1\n"
                "    def middle():\n        global leaf\n"
                "        def inner(): return leaf()\n        return inner()\n"
                "    return middle()\n"
            )
        },
    )
    result = reachable(build_graph(target, tmp_path / "graph"), "entry.outer")
    assert {node["name"] for node in result["functions"]} == {"outer", "middle", "inner"}
    assert result["unresolved_calls"][0]["reason"] == "name_not_bound"


def test_definition_time_assignment_does_not_leave_a_false_direct_edge(tmp_path):
    target = target_files(
        tmp_path,
        {
            "entry.py": (
                "def leaf(value): return value\n"
                "def defined(value=(leaf := None)): return value\n"
                "def entry(value): return leaf(value)\n"
            )
        },
    )
    result = reachable(build_graph(target, tmp_path / "graph"), "entry.entry")
    assert len(result["functions"]) == 1
    assert result["calls"][0]["status"] == "ambiguous"
    assert result["calls"][0]["reason"] == "multiple_bindings"


def test_failed_local_modules_import_cycles_duplicate_paths_and_unknown_imports(tmp_path):
    target = target_files(
        tmp_path,
        {
            "entry.py": (
                "from broken import work\nfrom cycle_a import loop\n"
                "from same import chosen\nfrom external_library import api\n"
                "def entry(value):\n    work(value)\n    loop(value)\n"
                "    chosen(value)\n    api(value)\n"
            ),
            "broken.py": "def work(:\n    pass\n",
            "cycle_a.py": "from cycle_b import loop\n",
            "cycle_b.py": "from cycle_a import loop\n",
            "same.py": "def chosen(value): return value\n",
            "src/same.py": "def chosen(value): return value\n",
        },
    )
    graph = build_graph(target, tmp_path / "graph")
    assert graph["coverage"]["status"] == "partial"
    assert "broken.py" in graph["coverage"]["unvisited_sources"]
    assert any(unit["errors"] for unit in graph["coverage"]["units"])
    result = reachable(graph, "entry.entry")
    assert len(result["functions"]) == 1
    assert [call["reason"] for call in result["calls"]] == [
        "local_module_parse_failed",
        "cyclic_or_deep_import",
        "multiple_module_paths",
        "outside_source_snapshot",
    ]
    assert result["calls"][2]["status"] == "ambiguous"
    assert result["calls"][3]["status"] == "external"


def test_utf8_crlf_nested_call_ids_methods_and_definition_time_omissions(tmp_path):
    target = target_files(
        tmp_path,
        {
            "entry.py": (
                "def leaf(value): return value\r\n"
                "def factory(): return leaf\r\n"
                "class C:\r\n    def method(self, value): return leaf(value)\r\n"
                "def entry(value=leaf(0)):\r\n"
                "    label = '한글'; leaf(label)\r\n"
                "    factory()(value)\r\n"
                "    delayed = lambda: leaf(value)\r\n"
                "    C().method(value)\r\n"
            )
        },
    )
    graph = build_graph(target, tmp_path / "graph")
    result = reachable(graph, "entry.entry")
    assert len(result["calls"]) == 5
    assert len({call["id"] for call in graph["calls"]}) == len(graph["calls"])
    direct = next(call for call in result["calls"] if call["line"] == 6)
    assert direct["column"] == len("    label = '한글'; ".encode()) + 1
    assert all(call["line"] not in (5, 8) for call in result["calls"])
    assert "method" not in {node["name"] for node in result["functions"]}
    assert reachable(graph, "method")["calls"][0]["status"] == "resolved"


def test_no_target_import_execution_pythonpath_or_build_configuration(tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    payload = f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
    target = target_files(
        tmp_path,
        {
            "entry.py": payload + "from package import leaf\ndef entry(): return leaf()\n",
            "package/__init__.py": payload + "def leaf(): return 1\n",
            "sitecustomize.py": payload,
            "setup.py": payload,
        },
    )
    (target / "pyproject.toml").write_text("[build-system]\nrequires = ['malicious']\n")
    (target / "outside.py").symlink_to(tmp_path / "external.py")
    (tmp_path / "external.py").write_text(payload)
    monkeypatch.setenv("PYTHONPATH", str(target))
    monkeypatch.setenv("PYTHONSTARTUP", str(target / "setup.py"))
    graph = build_graph(target, tmp_path / "graph")
    assert not marker.exists()
    assert graph["coverage"]["metadata"]["target_execution"] is False
    assert {"path": "outside.py", "reason": "symlink"} in graph["coverage"]["skipped"]


def test_cli_selection_mixed_sources_and_extractor_failure_boundaries(
    tmp_path, capsys, monkeypatch
):
    assert (
        main(
            [
                "graph",
                "build",
                str(FIXTURE),
                "--language",
                "python",
                "--output",
                str(tmp_path / "cli"),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["graph", "resolve", str(tmp_path / "cli/graph.json"), "app.entry"]) == 0
    assert json.loads(capsys.readouterr().out)["outgoing_calls"]
    assert main(["graph", "reachable", str(tmp_path / "cli/graph.json"), "dynamic"]) == 0
    assert json.loads(capsys.readouterr().out)["unresolved_calls"]
    target = target_files(
        tmp_path, {"entry.py": "def entry(): return 1\n", "other.go": "package other\n"}
    )
    with pytest.raises(ValueError, match="select --language"):
        build_graph(target, tmp_path / "mixed")
    graph = build_graph(target, tmp_path / "python", language="python")
    assert graph["coverage"]["status"] == "partial"
    assert "other.go" in graph["coverage"]["unvisited_sources"]
    with pytest.raises(ValueError, match="only to c_cpp"):
        build_graph(FIXTURE, tmp_path / "db", database=Path("compile_commands.json"))
    sources, _ = index_target(FIXTURE)
    with pytest.raises(ValueError, match="256"):
        python.extract(FIXTURE, sources * 257)

    def timeout(*args, **kwargs):
        raise ValueError("Python AST timeout after 1s")

    monkeypatch.setattr("agent_audit_harness.extractors.process.run_tool", timeout)
    assert main(["graph", "build", str(FIXTURE), "--output", str(tmp_path / "timeout")]) == 1
    assert "timeout" in capsys.readouterr().err


def test_python_recon_multifile_slicing_replay_and_resume(graph_file, tmp_path):
    spec = {
        "schema_version": 1,
        "hypotheses": [
            {
                "id": "python-path",
                "entry": "app.entry",
                "question": "Which imported functions and unknown boundaries are on this path?",
                "assumptions": [],
                "annotations": [],
            }
        ],
    }
    spec_file = tmp_path / "plan.json"
    spec_file.write_text(encode(spec))
    recon = build_recon(FIXTURE, graph_file, spec_file, tmp_path / "recon")
    sources, _ = index_target(FIXTURE)
    slices, gaps = make_graph_slices(read_graph(graph_file), recon, sources, 16000)
    assert not gaps and len(slices) == 1
    assert {fragment["path"] for fragment in slices[0]["fragments"]} == {
        "app.py",
        "auditpkg/__init__.py",
        "auditpkg/ops.py",
        "auditpkg/shared.py",
        "auditpkg/worker.py",
    }
    assert any(call["status"] == "unresolved" for call in slices[0]["calls"])
    assert "from .shared import normalize" in "\n".join(f["text"] for f in slices[0]["fragments"])
    replay = tmp_path / "replay"
    replay.mkdir()
    analysis = {
        "candidates": [
            {
                "path": "auditpkg/shared.py",
                "line": 2,
                "cwe": "CWE-20",
                "title": "Input type remains unknown",
                "reasoning": "Method dispatch is not proven by source-level imports.",
                "quote": "return value.strip()",
                "validation_plan": "Check input type and caller controls.",
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
                                "rationale": (
                                    "Call structure alone does not establish a vulnerability."
                                ),
                            }
                        ],
                    }
                ]
            }
        )
    )
    options = {"graph_file": graph_file, "recon_file": tmp_path / "recon/recon.json"}
    first = run_pipeline(FIXTURE, tmp_path / "run", ReplayAgent(replay), **options)
    resumed = run_pipeline(FIXTURE, tmp_path / "run", ReplayAgent(replay), resume=True, **options)
    assert first["call_attempts"] == resumed["cache_hits"] == 2
    assert first["verdict_counts"] == {"uncertain": 1}
    assert first["confirmed_findings"] == first["validation_executions"] == 0
