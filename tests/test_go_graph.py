import copy
import json
import shutil
from pathlib import Path

import pytest

from agent_audit_harness.cli import main
from agent_audit_harness.graph import build_graph, reachable, read_graph, resolve
from agent_audit_harness.pipeline import digest

FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "go-target"
requires_go = pytest.mark.skipif(shutil.which("go") is None, reason="Go not installed")


@requires_go
def test_typed_go_cross_file_package_queries_recursion_and_stable_output(tmp_path):
    graph = build_graph(FIXTURE, tmp_path / "graph")
    assert graph["schema_version"] == 2 and graph["language"] == "go"
    assert read_graph(tmp_path / "graph" / "graph.json") == graph
    result = reachable(graph, "Entry")
    assert result["files"] == [
        "app/entry.go",
        "app/stage.go",
        "parser/parse.go",
        "shared/normalize.go",
    ]
    assert result["scopes"] == [
        f"audit.example/graph/{name}" for name in ("app", "parser", "shared")
    ]
    assert {node["name"] for node in result["functions"]} == {
        "Entry",
        "stage",
        "Parse",
        "Run",
        "Normalize",
    }
    assert not result["unresolved_calls"]
    assert {(edge["caller_scope"], edge["callee_scope"]) for edge in graph["scope_calls"]} == {
        ("audit.example/graph/app", "audit.example/graph/parser"),
        ("audit.example/graph/app", "audit.example/graph/shared"),
        ("audit.example/graph/parser", "audit.example/graph/shared"),
    }
    assert ("app/entry.go", "app/stage.go") in {
        (edge["caller_file"], edge["callee_file"]) for edge in graph["file_calls"]
    }
    package = resolve(graph, "audit.example/graph/parser")
    assert {node["name"] for node in package["functions"]} == {"Parse", "Run"}
    assert {call["callee_name"] for call in package["incoming_calls"]} == {
        "audit.example/graph/parser.Parse",
        "audit.example/graph/parser.Decoder.Run",
    }
    assert len(resolve(graph, "app/stage.go")["functions"]) == 2
    assert all(call["provenance"] == "go_types" for call in graph["calls"])
    assert all(
        "symbol" not in node and "translation_units" not in node for node in graph["functions"]
    )
    recursive = reachable(graph, "Recurse")
    assert len(recursive["functions"]) == 1
    assert recursive["calls"][0]["callee"] == recursive["entry"]
    assert build_graph(FIXTURE, tmp_path / "again") == graph


@requires_go
def test_interface_and_function_values_do_not_invent_edges(tmp_path):
    graph = build_graph(FIXTURE, tmp_path / "graph")
    result = reachable(graph, "Dynamic")
    assert len(result["functions"]) == 1
    assert len(result["unresolved_calls"]) == 2
    assert {call["dispatch"] for call in result["calls"]} == {"interface", "function_value"}
    assert {call["reason"] for call in result["calls"]} == {"interface_dispatch", "function_value"}
    assert all(
        call["status"] == "unresolved" and call["callee"] is None for call in result["calls"]
    )
    assert "interface_dispatch" in (tmp_path / "graph" / "report.md").read_text()


@requires_go
def test_go_direct_argument_transfer_across_files_and_packages(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(
        Path(__file__).resolve().parents[1] / "examples/model-eval-prospective-go-target", target
    )
    with (target / "web/handlers.go").open("a") as stream:
        stream.write('\nfunc Constant() { _, _ = store.ReadSelected("public.txt") }\n')
    graph = build_graph(target, tmp_path / "graph")
    by_name = {f["id"]: f for f in graph["functions"]}
    transfers = {
        by_name[call["caller"]]["name"]: call["metadata"]["argument_transfers"]
        for call in graph["calls"]
        if call["callee_name"].endswith("store.ReadSelected")
    }
    selected = transfers["Selected"][0]
    assert selected == {
        "argument_index": 0,
        "parameter_index": 0,
        "parameter_name": "name",
        "parameter_type": "string",
        "path": "web/handlers.go",
        "line": 11,
        "column": 34,
        "end_line": 11,
        "end_column": 38,
        "expression": "name",
        "kind": "identifier",
        "source_sha256": next(
            source["sha256"]
            for source in graph["source_index"]
            if source["path"] == "web/handlers.go"
        ),
    }
    assert transfers["Constant"][0]["expression"] == '"public.txt"'
    assert transfers["Constant"][0]["kind"] == "constant"
    calls = {call["id"]: call for call in graph["calls"]}
    selected_call = next(
        call
        for call in calls.values()
        if by_name[call["caller"]]["name"] == "Selected"
        and call["callee_name"].endswith("store.ReadSelected")
    )
    source_origin = selected_call["metadata"]["argument_origins"][0]
    assert source_origin["kind"] == "call_result"
    assert (source_origin["path"], source_origin["line"]) == ("web/handlers.go", 10)
    sink_call = next(
        call
        for call in calls.values()
        if call["callee_name"] == "os.ReadFile" and call["line"] == 6
    )
    assert sink_call["metadata"]["argument_origins"] == [
        {"argument_index": 0, "kind": "parameter", "parameter_index": 0}
    ]
    assert all(
        not call.get("metadata", {}).get("argument_transfers")
        for call in graph["calls"]
        if call["status"] != "resolved" or call["dispatch"] != "direct"
    )
    assert read_graph(tmp_path / "graph/graph.json") == graph
    edited = copy.deepcopy(graph)
    changed = next(
        call for call in edited["calls"] if call.get("metadata", {}).get("argument_transfers")
    )
    changed["metadata"]["argument_transfers"][0]["source_sha256"] = "0" * 64
    edited["identity_sha256"] = digest(
        {key: value for key, value in edited.items() if key != "identity_sha256"}
    )
    altered = tmp_path / "altered.json"
    altered.write_text(json.dumps(edited))
    with pytest.raises(ValueError, match="argument transfer"):
        read_graph(altered)
    edited = copy.deepcopy(graph)
    changed = next(call for call in edited["calls"] if call["id"] == selected_call["id"])
    changed["metadata"]["argument_origins"][0]["end_column"] += 1
    edited["identity_sha256"] = digest(
        {key: value for key, value in edited.items() if key != "identity_sha256"}
    )
    altered.write_text(json.dumps(edited))
    with pytest.raises(ValueError, match="argument origin"):
        read_graph(altered)


@requires_go
def test_generics_methods_literals_shadowing_and_execution_kinds(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "go.mod").write_text("module test.example/edge\n\ngo 1.23.0\n")
    (target / "edge.go").write_text(
        'package edge\nimport "unsafe"\n'
        "func leaf(n int) int { return n }\n"
        "func Generic[T any](n T) T { return n }\n"
        "type Box[T any] struct { value T }\n"
        "func (b *Box[T]) Get() T { return b.value }\n"
        "func Entry() int {\n"
        " b := Box[int]{}; _ = b.Get(); _ = (*Box[int]).Get(&b)\n"
        " go leaf(1); defer leaf(2)\n"
        " return Generic[int](int(func() int { return leaf(3) }()))\n"
        "}\n"
        "func Shadow() int { leaf := func() int { return 7 }; return leaf() }\n"
        "func Unevaluated() uintptr { return unsafe.Sizeof(leaf(9)) }\n"
        "func Builtin() { panic(1) }\n"
    )
    graph = build_graph(target, tmp_path / "graph")
    result = reachable(graph, "Entry")
    assert {node["name"] for node in result["functions"] if node["kind"] != "lambda"} == {
        "Entry",
        "leaf",
        "Generic",
        "Get",
    }
    assert len([node for node in result["functions"] if node["kind"] == "lambda"]) == 1
    assert not result["unresolved_calls"]
    assert {call["execution"] for call in result["calls"]} == {"normal", "concurrent", "deferred"}
    assert len(result["calls"]) == 7  # Two methods, go/defer, generic, literal, literal's leaf.
    assert len(resolve(graph, "Get")["incoming_calls"]) == 2
    shadow = reachable(graph, "Shadow")
    assert len(shadow["functions"]) == 1 and shadow["unresolved_calls"][0]["callee"] is None
    assert shadow["unresolved_calls"][0]["dispatch"] == "function_value"
    assert not reachable(graph, "Unevaluated")["calls"]
    builtin = reachable(graph, "Builtin")["unresolved_calls"][0]
    assert builtin["status"] == "external" and builtin["dispatch"] == "builtin"


@requires_go
def test_partial_packages_excluded_files_and_no_target_execution(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "go.mod").write_text("module test.example/partial\n\ngo 1.23.0\n")
    marker = tmp_path / "executed"
    (target / "ok").mkdir()
    (target / "ok" / "ok.go").write_text(
        'package ok\nimport "os"\n'
        f"//go:generate touch {marker}\n"
        f"func init() {{ _ = os.WriteFile({json.dumps(str(marker))}, nil, 0600) }}\n"
        "func Entry() int { return leaf() }\nfunc leaf() int { return 1 }\n"
    )
    (target / "ok" / "excluded.go").write_text(
        "//go:build audit_never_enabled\n\npackage ok\nfunc Excluded() {}\n"
    )
    (target / "ok" / "ok_test.go").write_text("package ok\nfunc TestOnly() {}\n")
    (target / "bad").mkdir()
    (target / "bad" / "bad.go").write_text("package bad\nfunc Broken() { absent() }\n")
    driver = tmp_path / "driver"
    driver.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
    driver.chmod(0o700)
    monkeypatch.setenv("GOPACKAGESDRIVER", str(driver))
    monkeypatch.setenv("GOFLAGS", "-tags=audit_never_enabled")
    monkeypatch.setenv("GOTOOLCHAIN", "go99.0.0")
    graph = build_graph(target, tmp_path / "graph")
    assert not marker.exists()
    assert graph["coverage"]["status"] == "partial"
    assert not graph["coverage"]["configuration_verified"]
    assert {node["name"] for node in graph["functions"]} == {"init", "Entry", "leaf"}
    assert reachable(graph, "Entry")["unresolved_calls"] == []
    failed = next(unit for unit in graph["coverage"]["units"] if unit["status"] == "failed")
    assert failed["path"] == "test.example/partial/bad"
    assert any("absent" in error for error in failed["errors"])
    assert not any(call["path"].startswith("bad/") for call in graph["calls"])
    assert {
        item["path"]
        for item in graph["coverage"]["skipped"]
        if item["reason"] == "not_selected_by_go_build"
    } == {"ok/excluded.go", "ok/ok_test.go"}
    assert graph["coverage"]["metadata"]["network"] is False


@requires_go
@pytest.mark.parametrize(
    "configuration", ["local_replace", "workspace", "nested_module", "symlink_mod"]
)
def test_module_boundaries_are_explicit(tmp_path, configuration):
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    expected = "unsupported"
    if configuration == "local_replace":
        with (target / "go.mod").open("a") as stream:
            stream.write("\nreplace other.example/module => /tmp/outside\n")
    elif configuration == "workspace":
        (target / "go.work").write_text("go 1.23.0\nuse .\n")
    elif configuration == "nested_module":
        (target / "app" / "go.mod").write_text("module nested.example/app\n")
    else:
        (target / "go.mod").unlink()
        (target / "go.mod").symlink_to(FIXTURE / "go.mod")
        expected = "outside target"
    with pytest.raises((ValueError, OSError), match=expected):
        build_graph(target, tmp_path / "graph")
    assert not (tmp_path / "graph" / "graph.json").exists()


@requires_go
def test_uncached_dependency_is_partial_without_download(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "go.mod").write_text(
        "module test.example/missing\n\ngo 1.23.0\nrequire missing.invalid/pkg v0.0.1\n"
    )
    (target / "entry.go").write_text(
        'package missing\nimport "missing.invalid/pkg"\nfunc Entry() { pkg.Run() }\n'
    )
    graph = build_graph(target, tmp_path / "graph")
    assert graph["coverage"]["status"] == "partial"
    assert not graph["functions"] and not graph["calls"]
    assert any(
        "missing.invalid/pkg" in error
        for unit in graph["coverage"]["units"]
        for error in unit["errors"]
    )


@requires_go
def test_cli_go_auto_and_package_queries_and_mixed_target(tmp_path, capsys):
    output = tmp_path / "graph"
    assert main(["graph", "build", str(FIXTURE), "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["scope_edges"] == 3
    graph_file = str(output / "graph.json")
    assert main(["graph", "resolve", graph_file, "audit.example/graph/parser"]) == 0
    assert len(json.loads(capsys.readouterr().out)["functions"]) == 2
    assert main(["graph", "reachable", graph_file, "Dynamic", "--files"]) == 0
    result = capsys.readouterr()
    assert result.out.strip() == "app/stage.go" and "unresolved" in result.err
    target = tmp_path / "mixed"
    shutil.copytree(FIXTURE, target)
    (target / "extra.c").write_text("int example(void) { return 0; }\n")
    with pytest.raises(ValueError, match="--language"):
        build_graph(target, tmp_path / "mixed-auto")
    graph = build_graph(target, tmp_path / "mixed-go", language="go")
    assert {"path": "extra.c", "reason": "unsupported_graph_language"} in graph["coverage"][
        "skipped"
    ]
    with pytest.raises(ValueError, match="only to c_cpp"):
        build_graph(FIXTURE, tmp_path / "bad-config", database=Path("compile_commands.json"))


@requires_go
def test_common_graph_contract_rejects_tampered_relationships_even_with_new_checksum(tmp_path):
    graph = build_graph(FIXTURE, tmp_path / "graph")
    path = tmp_path / "edited.json"
    for field, value, expected in (
        ("file_calls", [], "summaries"),
        ("scope_calls", [], "summaries"),
        ("source_index", graph["source_index"] * 2, "duplicate source"),
        ("language", "python", "language differs"),
    ):
        edited = copy.deepcopy(graph)
        edited[field] = value
        edited.pop("identity_sha256")
        edited["identity_sha256"] = digest(edited)
        path.write_text(json.dumps(edited))
        with pytest.raises(ValueError, match=expected):
            read_graph(path)
    edited = copy.deepcopy(graph)
    edited["calls"][0]["line"] = 999
    edited.pop("identity_sha256")
    edited["identity_sha256"] = digest(edited)
    path.write_text(json.dumps(edited))
    with pytest.raises(ValueError, match="location outside"):
        read_graph(path)


@requires_go
def test_config_change_during_extraction_rejects_stale_graph(tmp_path, monkeypatch):
    from agent_audit_harness.extractors import golang

    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    extract = golang.extract

    def changing(*args, **kwargs):
        result = extract(*args, **kwargs)
        with (target / "go.mod").open("a") as stream:
            stream.write("\n// changed during extraction\n")
        return result

    monkeypatch.setattr(golang, "extract", changing)
    with pytest.raises(ValueError, match="configuration changed"):
        build_graph(target, tmp_path / "graph")
    assert not (tmp_path / "graph" / "graph.json").exists()


@requires_go
def test_identical_names_in_different_packages_keep_separate_identities(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    path = target / "app" / "stage.go"
    path.write_text(
        path.read_text().replace("return shared.Normalize(value)", "return Normalize(value)")
        + "\nfunc Normalize(value string) string { return shared.Normalize(value) }\n"
    )
    graph = build_graph(target, tmp_path / "graph")
    functions = [
        node for node in reachable(graph, "Entry")["functions"] if node["name"] == "Normalize"
    ]
    assert {node["qualified_name"] for node in functions} == {
        "audit.example/graph/app.Normalize",
        "audit.example/graph/shared.Normalize",
    }
    assert len({node["id"] for node in functions}) == 2
    with pytest.raises(ValueError, match="match once"):
        resolve(graph, "Normalize")
    assert len(resolve(graph, "audit.example/graph/app.Normalize")["outgoing_calls"]) == 1


@requires_go
def test_dotted_package_path_cannot_alias_a_receiver_symbol(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    package = target / "parser.Decoder"
    package.mkdir()
    (package / "run.go").write_text(
        "package other\nfunc Run(value string) string { return value }\n"
    )
    (target / "app" / "collision.go").write_text(
        'package app\nimport other "audit.example/graph/parser.Decoder"\n'
        'func Collision() string { return other.Run("ok") }\n'
    )
    graph = build_graph(target, tmp_path / "graph")
    assert not reachable(graph, "Entry")["unresolved_calls"]
    result = reachable(graph, "Collision")
    assert not result["unresolved_calls"]
    assert result["files"] == ["app/collision.go", "parser.Decoder/run.go"]
    duplicates = [
        node
        for node in graph["functions"]
        if node["qualified_name"] == "audit.example/graph/parser.Decoder.Run"
    ]
    assert len(duplicates) == 2 and len({node["id"] for node in duplicates}) == 2
