import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from agent_audit_harness.cli import main
from agent_audit_harness.extractors.clang import compile_flags
from agent_audit_harness.graph import (
    build_graph,
    reachable,
    read_graph,
    resolve,
)

FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "graph-target"
requires_clang = pytest.mark.skipif(shutil.which("clang") is None, reason="Clang not installed")


@requires_clang
def test_real_clang_cross_file_static_identity_recursion_and_indirect(tmp_path):
    output = tmp_path / "graph"
    graph = build_graph(FIXTURE, output)
    assert read_graph(output / "graph.json") == graph
    path = reachable(graph, "entry")
    assert path["files"] == ["entry.c", "parser.c"]
    assert {node["name"] for node in path["functions"]} == {"entry", "parse", "helper"}
    assert len([node for node in path["functions"] if node["name"] == "helper"]) == 2
    assert not path["unresolved_calls"]
    assert graph["file_calls"][0]["caller_file"] == "entry.c"
    assert graph["file_calls"][0]["callee_file"] == "parser.c"
    entry_call = resolve(graph, "entry")["outgoing_calls"]
    assert {call["line"] for call in entry_call} == {5}
    assert all(call["provenance"] == "clang_ast" for call in graph["calls"])
    callback = reachable(graph, "callback_entry")["unresolved_calls"][0]
    assert callback["status"] == "unresolved" and callback["dispatch"] == "indirect"
    recursive = reachable(graph, "recurse")
    assert len(recursive["functions"]) == 1
    assert recursive["calls"][0]["callee"] == recursive["entry"]
    with pytest.raises(ValueError, match="match once"):
        resolve(graph, "helper")
    assert len(resolve(graph, "parser.c")["functions"]) == 3
    assert build_graph(FIXTURE, tmp_path / "again") == graph


@requires_clang
def test_cpp_overloads_and_virtual_dispatch_remain_distinct(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "api.cpp").write_text(
        "int pick(int x) { return x; }\n"
        "int pick(double x) { return (int)x; }\n"
        "struct Base { virtual int run(int x) { return pick(x); } };\n"
        "int entry(Base &b) { return b.run(pick(1) + pick(1.0)); }\n"
    )
    graph = build_graph(target, tmp_path / "graph")
    result = reachable(graph, "entry")
    assert len([node for node in result["functions"] if node["name"] == "pick"]) == 2
    assert result["unresolved_calls"][0]["status"] == "unresolved"
    assert result["unresolved_calls"][0]["dispatch"] == "virtual"
    assert not any(node["name"] == "run" for node in result["functions"])


@requires_clang
def test_compile_database_flags_and_partial_parse_are_visible(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "ok.c").write_text("#ifdef ENABLED\nint enabled(void) { return 1; }\n#endif\n")
    (target / "broken.c").write_text('#include "absent.h"\nint broken(void) { return 0; }\n')
    (target / "not-in-build.c").write_text("int excluded(void) { return 1; }\n")
    (target / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(target),
                    "file": "ok.c",
                    "arguments": [
                        "never-executed-compiler",
                        "-DENABLED",
                        "-c",
                        "ok.c",
                        "-o",
                        "ok.o",
                    ],
                },
                {"directory": str(target), "file": "broken.c", "command": "clang -c broken.c"},
            ]
        )
    )
    graph = build_graph(target, tmp_path / "graph")
    assert {node["name"] for node in graph["functions"]} == {"enabled"}
    assert graph["coverage"]["status"] == "partial"
    assert any(
        unit["status"] == "failed" and "absent.h" in unit["error"]
        for unit in graph["coverage"]["units"]
    )
    assert {"path": "not-in-build.c", "reason": "missing_compile_command"} in graph["coverage"][
        "skipped"
    ]
    assert not list(target.glob("*.o"))


def test_compile_flags_never_replay_plugins_commands_or_response_files(tmp_path):
    flags, ignored = compile_flags(
        [
            "malicious-compiler",
            "-I",
            ".",
            "-DGOOD=1",
            "-std=c11",
            "-Xclang",
            "-load",
            "evil.so",
            "@flags",
            "-fplugin=evil.so",
            ";",
            "touch",
            "marker",
            "-c",
            "file.c",
            "-o",
            "file.o",
        ],
        tmp_path,
        tmp_path,
    )
    assert flags == ["-I", str(tmp_path), "-D", "GOOD=1", "-std=c11"]
    assert "-fplugin=evil.so" in ignored and "@flags" in ignored
    with pytest.raises(ValueError, match="outside target"):
        compile_flags(["clang", "-I", "/etc"], tmp_path, tmp_path)


def test_parse_timeout_is_recorded_and_process_is_stopped(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "input.c").write_text("int entry(void) { return 0; }\n")
    pid_file = tmp_path / "pid"
    compiler = tmp_path / "fake-clang"
    compiler.write_text(
        f"#!{sys.executable}\n"
        "import os, sys, time\n"
        "from pathlib import Path\n"
        "if '--version' in sys.argv:\n"
        "    print('clang timeout fixture')\n"
        "else:\n"
        f"    Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
        "    time.sleep(10)\n"
    )
    compiler.chmod(0o700)
    graph = build_graph(target, tmp_path / "graph", compiler=str(compiler), timeout=1)
    unit = graph["coverage"]["units"][0]
    assert unit["status"] == "failed" and "timeout" in unit["error"]
    assert graph["coverage"]["status"] == "partial"
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)


@requires_clang
def test_duplicate_definitions_do_not_invent_a_unique_edge(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "entry.c").write_text(
        "int duplicate(void); int entry(void) { return duplicate(); }\n"
    )
    for name in ("a.c", "b.c"):
        (target / name).write_text("int duplicate(void) { return 1; }\n")
    graph = build_graph(target, tmp_path / "graph")
    result = reachable(graph, "entry")
    assert result["files"] == ["entry.c"]
    assert result["unresolved_calls"][0]["status"] == "ambiguous"


@requires_clang
def test_header_macro_locations_and_unevaluated_calls(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "api.h").write_text(
        "static int leaf(int x) { return x; }\n"
        "static inline int helper(int x) { return leaf(x); }\n"
        "#define WRAPPED(x) helper(x)\n"
    )
    (target / "entry.c").write_text(
        '#include "api.h"\n'
        "int hidden(void);\n"
        "int entry(void) { return WRAPPED(1) + sizeof(hidden()); }\n"
    )
    graph = build_graph(target, tmp_path / "graph")
    path = reachable(graph, "entry")
    assert path["files"] == ["api.h", "entry.c"]
    assert not path["unresolved_calls"]
    assert resolve(graph, "entry")["outgoing_calls"][0]["line"] == 3
    assert resolve(graph, "helper")["outgoing_calls"][0]["path"] == "api.h"
    assert resolve(graph, "helper")["outgoing_calls"][0]["line"] == 2


@requires_clang
def test_out_of_line_cpp_virtual_definition_does_not_become_direct(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "api.cpp").write_text(
        "struct Base { virtual int run(); };\n"
        "int Base::run() { return 1; }\n"
        "int entry(Base &b) { return b.run(); }\n"
    )
    graph = build_graph(target, tmp_path / "graph")
    assert resolve(graph, "Base::run")["functions"][0]["line"] == 2
    call = reachable(graph, "entry")["unresolved_calls"][0]
    assert call["status"] == "unresolved" and call["dispatch"] == "virtual"


@requires_clang
def test_cli_graph_queries_and_preserve_existing_output(tmp_path, capsys):
    output = tmp_path / "graph"
    assert main(["graph", "build", str(FIXTURE), "--output", str(output)]) == 0
    capsys.readouterr()
    assert main(["graph", "reachable", str(output / "graph.json"), "entry", "--files"]) == 0
    assert capsys.readouterr().out.splitlines() == ["entry.c", "parser.c"]
    before = (output / "graph.json").read_bytes()
    assert main(["graph", "build", str(FIXTURE), "--output", str(output)]) == 1
    assert "nonempty" in capsys.readouterr().err
    assert (output / "graph.json").read_bytes() == before
    data = json.loads(before)
    data["calls"][0]["callee"] = "invented-endpoint"
    (output / "graph.json").write_text(json.dumps(data))
    assert main(["graph", "reachable", str(output / "graph.json"), "entry"]) == 1
    assert "unknown call endpoint" in capsys.readouterr().err
