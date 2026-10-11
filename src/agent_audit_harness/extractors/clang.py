"""Clang-specific extraction; kept separate from shared graph queries."""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

from ..pipeline import digest
from .process import run_tool

UNIT_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
HEADER_SUFFIXES = {".h", ".hpp", ".hh", ".hxx"}
FUNCTION_KINDS = {"FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl"}
CALL_KINDS = {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr", "CXXConstructExpr"}


def compile_flags(arguments: list[str], directory: Path, target: Path) -> tuple[list, list]:
    """Copy only parsing inputs; never replay executables, plugins or response files."""
    if (
        not arguments
        or len(arguments) > 4096
        or any(not isinstance(arg, str) or len(arg) > 4096 for arg in arguments)
    ):
        raise ValueError("invalid compilation arguments")
    flags, ignored = [], []
    iterator = iter(arguments[1:])
    for argument in iterator:
        if argument in {"-c", "-S", "-fsyntax-only"}:
            continue
        if argument == "-o":
            next(iterator, None)
            continue
        if argument in {"-I", "-isystem", "-iquote", "-D", "-U", "-x"}:
            option, value = argument, next(iterator, None)
        elif argument.startswith(("-I", "-D", "-U")) and len(argument) > 2:
            option, value = argument[:2], argument[2:]
        elif argument.startswith("-std="):
            option, value = "-std=", argument[5:]
        else:
            if argument.startswith("-") or argument.startswith("@"):
                ignored.append(argument)
            continue
        if not value or value.startswith("-"):
            raise ValueError(f"missing/invalid value for {option}")
        if option in {"-I", "-isystem", "-iquote"}:
            path = (directory / value).resolve()
            if not path.is_relative_to(target):
                raise ValueError(f"include directory outside target: {value}")
            flags.extend([option, str(path)])
        elif option == "-x":
            if value not in {"c", "c++"}:
                raise ValueError("only C and C++ compilation languages are supported")
            flags.extend([option, value])
        elif option == "-std=":
            if not re.fullmatch(r"[a-z0-9+]+", value):
                raise ValueError("invalid language standard")
            flags.append(option + value)
        else:
            flags.extend([option, value])
    return flags, ignored


def compilation_units(target: Path, sources: list, database: Path | None) -> tuple[list, list]:
    paths = {source.path for source in sources if Path(source.path).suffix in UNIT_SUFFIXES}
    if database is None and (target / "compile_commands.json").is_file():
        database = target / "compile_commands.json"
    if database is None:
        return [
            {"path": path, "flags": [], "ignored_flags": [], "configuration": "defaults"}
            for path in sorted(paths)
        ], []
    if database.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("compilation database exceeds 8 MiB")
    entries = json.loads(database.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("compilation database must be an array")
    units = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise ValueError("invalid compilation database entry")
        directory = entry.get("directory")
        if not isinstance(directory, str) or not Path(directory).is_absolute():
            raise ValueError("compilation directory must be absolute")
        directory = Path(directory).resolve()
        path = (directory / entry["file"]).resolve()
        if not path.is_relative_to(target) or path.relative_to(target).as_posix() not in paths:
            continue
        relative = path.relative_to(target).as_posix()
        if relative in units:
            raise ValueError(f"multiple build configurations for {relative}; select one")
        arguments = entry.get("arguments")
        if arguments is None and isinstance(entry.get("command"), str):
            arguments = shlex.split(entry["command"])
        if not isinstance(arguments, list):
            raise ValueError("compilation entry needs arguments or command")
        flags, ignored = compile_flags(arguments, directory, target)
        units[relative] = {
            "path": relative,
            "flags": flags,
            "ignored_flags": ignored,
            "configuration": "compilation_database",
        }
    missing = [
        {"path": path, "reason": "missing_compile_command"} for path in sorted(paths - units.keys())
    ]
    return [units[path] for path in sorted(units)], missing


def clang_ast(compiler: str, target: Path, unit: dict, timeout: int) -> tuple[dict, str]:
    command = [
        compiler,
        "--no-default-config",
        *unit["flags"],
        "-fno-modules",
        "-fno-implicit-modules",
        "-fno-implicit-module-maps",
        "-fsyntax-only",
        "-Xclang",
        "-ast-dump=json",
        "--",
        str(target / unit["path"]),
    ]
    environment = {key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG") if key in os.environ}
    with tempfile.TemporaryDirectory(prefix="audit-graph-") as scratch:
        output, diagnostics = run_tool("Clang parse", command, Path(scratch), environment, timeout)
        return json.loads(output), diagnostics


def extract_unit(root: dict, target: Path, sources: list, unit: str) -> tuple[list, list, set]:
    contents = {source.path: source.text.encode() for source in sources}
    declarations, definitions, pending, visited = {}, [], [], set()
    line_starts, contexts = {}, {}
    last_file = str(target / unit)

    def location(point: dict) -> dict | None:
        nonlocal last_file
        point = point.get("expansionLoc", point)
        if "file" in point:
            last_file = point["file"]
        path = Path(last_file)
        if not path.is_absolute():
            path = target / path
        path = path.resolve()
        if not path.is_relative_to(target):
            return None
        relative = path.relative_to(target).as_posix()
        if relative not in contents or "offset" not in point:
            return None
        content, offset = contents[relative], point["offset"]
        if not 0 <= offset <= len(content):
            return None
        visited.add(relative)
        if relative not in line_starts:
            line_starts[relative] = [0, *[match.end() for match in re.finditer(b"\n", content)]]
        line = bisect_right(line_starts[relative], offset)
        return {
            "path": relative,
            "line": line,
            "column": offset - line_starts[relative][line - 1] + 1,
            "offset": offset,
        }

    def visit(node: dict, scope: tuple = (), owner: str | None = None, unevaluated=False):
        kind = node.get("kind")
        position = location(node.get("loc", {}))
        begin = location(node.get("range", {}).get("begin", {}))
        end = location(node.get("range", {}).get("end", {}))
        children = node.get("inner", [])
        if kind in {"NamespaceDecl", "CXXRecordDecl"}:
            scope = (*scope, node.get("name", "(anonymous)"))
            contexts[node.get("id")] = scope
        if kind in FUNCTION_KINDS:
            scope = contexts.get(node.get("parentDeclContextId"), scope)
            symbol = node.get("mangledName")
            internal = (
                kind == "FunctionDecl" and node.get("storageClass") == "static"
            ) or "(anonymous)" in scope
            key = digest([symbol, unit if internal else None]) if symbol else None
            declaration = {
                "key": key,
                "name": node.get("name", ""),
                "virtual": node.get("virtual", False)
                or any(child.get("kind") == "OverrideAttr" for child in children),
            }
            declarations[node.get("id")] = declaration
            body = any(child.get("kind") in {"CompoundStmt", "CXXTryStmt"} for child in children)
            owner = None
            if (
                body
                and position
                and end
                and position["path"] == end["path"]
                and key
                and not node.get("isImplicit")
            ):
                owner = "fn-" + digest([key, position["path"], position["offset"]])[:20]
                definitions.append(
                    {
                        "id": owner,
                        "key": key,
                        "name": declaration["name"],
                        "qualified_name": "::".join((*scope, declaration["name"])),
                        "symbol": symbol,
                        "signature": node.get("type", {}).get("qualType", ""),
                        "path": position["path"],
                        "line": position["line"],
                        "end_line": end["line"],
                        "internal": internal,
                        "parameters": [
                            {
                                "name": child.get("name", ""),
                                "type": child.get("type", {}).get("qualType", ""),
                            }
                            for child in children
                            if child.get("kind") == "ParmVarDecl"
                        ],
                        "translation_units": [unit],
                    }
                )
        if kind in {"UnaryExprOrTypeTraitExpr", "CXXNoexceptExpr", "TypeTraitExpr"}:
            unevaluated = True
        if kind in CALL_KINDS and owner and begin and not unevaluated:
            callee = children[0] if children and kind != "CXXConstructExpr" else {}
            while (
                callee.get("kind")
                in {"ImplicitCastExpr", "ParenExpr", "CStyleCastExpr", "UnaryOperator"}
                and len(callee.get("inner", [])) == 1
            ):
                callee = callee["inner"][0]
            reference = callee.get("referencedDecl", {})
            decl_id = (
                reference.get("id")
                if reference.get("kind") in FUNCTION_KINDS
                else callee.get("referencedMemberDecl")
            )
            pending.append(
                {
                    "caller": owner,
                    "path": begin["path"],
                    "line": begin["line"],
                    "column": begin["column"],
                    "offset": begin["offset"],
                    "decl_id": decl_id,
                    "callee_name": reference.get("name") or callee.get("name", ""),
                    "kind": kind,
                    "translation_units": [unit],
                }
            )
        for child in children:
            child_owner = owner
            if kind in FUNCTION_KINDS and child.get("kind") not in {"CompoundStmt", "CXXTryStmt"}:
                child_owner = None
            visit(child, scope, child_owner, unevaluated)

    visit(root)
    virtual_keys = {
        declaration["key"]
        for declaration in declarations.values()
        if declaration["virtual"] and declaration["key"]
    }
    for call in pending:
        declaration = declarations.get(call.pop("decl_id"), {})
        call["key"] = declaration.get("key")
        call["status"] = (
            "virtual"
            if declaration.get("key") in virtual_keys
            else (
                "direct"
                if call["key"]
                else "constructor"
                if call["kind"] == "CXXConstructExpr"
                else "indirect"
            )
        )
        call["callee_name"] = declaration.get("name") or call["callee_name"]
    return definitions, pending, visited


def assemble_graph(functions: list, pending: list) -> tuple[list, list]:
    nodes, by_key = {}, defaultdict(set)
    for function in functions:
        if function["id"] in nodes:
            nodes[function["id"]]["translation_units"] = sorted(
                set(nodes[function["id"]]["translation_units"] + function["translation_units"])
            )
        else:
            nodes[function["id"]] = function
        by_key[function["key"]].add(function["id"])
    calls = {}
    for pending_call in pending:
        call = dict(pending_call)
        matches = sorted(by_key.get(call.pop("key"), []))
        call["callee"] = None
        if call["status"] == "direct":
            call["status"] = (
                "resolved" if len(matches) == 1 else "ambiguous" if matches else "external"
            )
            if len(matches) == 1:
                call["callee"] = matches[0]
        call["id"] = (
            "call-"
            + digest(
                [
                    call["caller"],
                    call["path"],
                    call.pop("offset"),
                    call["column"],
                    call["kind"],
                    call["callee_name"],
                    call["callee"],
                    call["status"],
                ]
            )[:20]
        )
        call["provenance"] = "clang_ast"
        if call["id"] in calls:
            calls[call["id"]]["translation_units"] = sorted(
                set(calls[call["id"]]["translation_units"] + call["translation_units"])
            )
        else:
            calls[call["id"]] = call
    return (
        sorted(nodes.values(), key=lambda row: (row["path"], row["line"], row["id"])),
        sorted(calls.values(), key=lambda row: (row["path"], row["line"], row["id"])),
    )


def extract(
    target: Path,
    sources: list,
    *,
    database: Path | None = None,
    compiler: str = "clang",
    timeout: int = 30,
) -> dict:
    executable = shutil.which(compiler)
    if not executable:
        raise ValueError("Clang is required for call graph extraction")
    versions = subprocess.run(
        [executable, "--version"], capture_output=True, text=True, timeout=5, check=True
    ).stdout.splitlines()
    if not versions or "clang" not in versions[0].lower():
        raise ValueError("graph compiler must be Clang")
    units, missing = compilation_units(target, sources, database)
    if not units:
        raise ValueError(
            "no C/C++ translation units; select a supported subtree/build configuration"
        )
    if len(units) > 256:
        raise ValueError("more than 256 translation units; select a smaller subtree")
    functions, pending, seen, results = [], [], set(), []
    for unit in units:
        result = dict(unit)
        try:
            ast, diagnostics = clang_ast(executable, target, unit, timeout)
            definitions, calls, visited = extract_unit(ast, target, sources, unit["path"])
            functions.extend(definitions)
            pending.extend(calls)
            seen.update(visited)
            result.update(status="parsed", diagnostics=diagnostics)
        except (ValueError, OSError, RecursionError) as error:
            result.update(status="failed", error=str(error))
        results.append(result)
    nodes, calls = assemble_graph(functions, pending)
    # Native symbol keys and translation units belong to the extractor, not the shared contract.
    for node in nodes:
        native = {key: node.pop(key) for key in ("key", "symbol", "internal", "translation_units")}
        node.update(
            language="c_cpp",
            scope=node["qualified_name"].rpartition("::")[0],
            kind="function",
            metadata=native,
        )
    for call in calls:
        native = {key: call.pop(key) for key in ("kind", "translation_units")}
        status = call["status"]
        call.update(
            language="c_cpp",
            kind="call",
            dispatch=status if status in {"virtual", "constructor", "indirect"} else "direct",
            execution="normal",
            reason=status if status != "resolved" else "",
            metadata=native,
        )
        if status in {"virtual", "constructor", "indirect"}:
            call["status"] = "unresolved"
    unsupported = [
        {"path": source.path, "reason": "unsupported_graph_language"}
        for source in sources
        if Path(source.path).suffix not in UNIT_SUFFIXES | HEADER_SUFFIXES
    ]
    unvisited = sorted(
        source.path
        for source in sources
        if Path(source.path).suffix in HEADER_SUFFIXES and source.path not in seen
    )
    partial = (
        missing
        or unsupported
        or unvisited
        or any(unit["status"] == "failed" or unit["ignored_flags"] for unit in results)
    )
    return {
        "engine": {"name": "clang_ast", "executable": executable, "version": versions[0]},
        "functions": nodes,
        "calls": calls,
        "input_config": [],
        "coverage": {
            "status": "partial" if partial else "parsed",
            "units": results,
            "skipped": missing + unsupported,
            "unvisited_sources": unvisited,
            "configuration_verified": all(
                unit["status"] == "parsed"
                and unit["configuration"] == "compilation_database"
                and not unit["ignored_flags"]
                for unit in results
            ),
        },
        "limitations": [
            "direct calls only; pointers and virtual dispatch remain unresolved",
            "constructors, implicit destructors, templates and linkage are incomplete",
            "syntax reachability is not data flow or attacker reachability",
            "system headers depend on the local toolchain",
        ],
    }
