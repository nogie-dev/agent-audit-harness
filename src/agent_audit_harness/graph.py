"""Shared graph contract, persistence and queries; no language-specific parsing."""

import json
from collections import Counter, defaultdict, deque
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .extractors.inputs import read_input
from .pipeline import digest, index_target, run_lock, save_json, save_text

MAX_GRAPH_BYTES = 64 * 1024 * 1024
GRAPH_SCHEMA = Path(__file__).parent / "schemas" / "graph.json"


def graph_report(graph: dict) -> str:
    # Untrusted paths/names remain literal text, including HTML and Markdown links.
    def plain(value):
        return (
            json.dumps(value, ensure_ascii=False)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("`", "\\u0060")
        )

    rows = [
        "# Call structure",
        "",
        "Static structure extraction; no model, build script or target program execution.",
        "",
        f"Parse coverage: {graph['coverage']['status']}",
        f"Function definitions: {len(graph['functions'])}",
        "Call sites: " + plain(dict(Counter(call["status"] for call in graph["calls"]))),
        "",
        "Reachability follows resolved direct calls only; it does not establish input/data flow.",
        "",
        "## File calls",
        "",
    ]
    for edge in graph["file_calls"]:
        rows.append(
            f"- `{plain(edge['caller_file'])}` → `{plain(edge['callee_file'])}` "
            f"({len(edge['call_ids'])} call sites)"
        )
    rows.extend(["", "## Package / scope calls", ""])
    for edge in graph.get("scope_calls", []):
        rows.append(
            f"- `{plain(edge['caller_scope'])}` → `{plain(edge['callee_scope'])}` "
            f"({len(edge['call_ids'])} call sites)"
        )
    rows.extend(["", "## Function definitions", ""])
    for function in graph["functions"]:
        rows.append(
            f"- `{plain(function['qualified_name'])}` — "
            f"`{plain(function['path'])}`:{function['line']} — `{function['id']}`"
        )
    rows.extend(["", "## Unresolved calls", ""])
    for call in graph["calls"]:
        if call["status"] != "resolved":
            rows.append(
                f"- {call['status']}: `{plain(call['callee_name'])}` "
                f"at `{plain(call['path'])}`:{call['line']} "
                f"({plain(call.get('reason', call['status']))})"
            )
    rows.extend(
        [
            "",
            "Coverage, parse failures and reduced flags are preserved in graph.json.",
            "",
        ]
    )
    return "\n".join(rows)


def validate_v1(graph: dict):
    try:
        if (
            type(graph["schema_version"]) is not int
            or graph["schema_version"] != 1
            or not isinstance(graph["functions"], list)
            or not isinstance(graph["calls"], list)
        ):
            raise ValueError("unsupported graph format")
        if (
            graph["coverage"]["status"] not in {"parsed", "partial"}
            or type(graph["coverage"]["configuration_verified"]) is not bool
        ):
            raise ValueError("invalid graph coverage")
        nodes = {node["id"]: node for node in graph["functions"]}
        if len(nodes) != len(graph["functions"]):
            raise ValueError("duplicate function IDs")
        for node in nodes.values():
            if any(
                not isinstance(node[key], str)
                for key in ("id", "name", "qualified_name", "path", "signature")
            ):
                raise ValueError("invalid function fields")
            if any(type(node[key]) is not int or node[key] < 1 for key in ("line", "end_line")):
                raise ValueError("invalid function location")
        call_ids = set()
        for call in graph["calls"]:
            if any(
                not isinstance(call[key], str)
                for key in ("id", "caller", "status", "path", "callee_name")
            ):
                raise ValueError("invalid call fields")
            if call["status"] not in {
                "resolved",
                "external",
                "ambiguous",
                "virtual",
                "constructor",
                "indirect",
            }:
                raise ValueError("invalid call status")
            if any(type(call[key]) is not int or call[key] < 1 for key in ("line", "column")):
                raise ValueError("invalid call location")
            if call["id"] in call_ids:
                raise ValueError("duplicate call IDs")
            call_ids.add(call["id"])
            if call["caller"] not in nodes or (
                call["callee"] is not None and call["callee"] not in nodes
            ):
                raise ValueError("unknown call endpoint")
            if (call["status"] == "resolved") != (call["callee"] is not None):
                raise ValueError("invalid resolved call")
    except (KeyError, TypeError) as error:
        raise ValueError("invalid graph format") from error


def summarize_calls(functions: list, calls: list) -> tuple[list, list]:
    nodes = {node["id"]: node for node in functions}
    files, scopes = defaultdict(list), defaultdict(list)
    for call in calls:
        if call["status"] != "resolved":
            continue
        caller, callee = nodes[call["caller"]], nodes[call["callee"]]
        if caller["path"] != callee["path"]:
            files[(caller["path"], callee["path"])].append(call["id"])
        if caller["scope"] != callee["scope"]:
            scopes[(caller["scope"], callee["scope"])].append(call["id"])
    return (
        [
            {"caller_file": left, "callee_file": right, "call_ids": sorted(ids)}
            for (left, right), ids in sorted(files.items())
        ],
        [
            {"caller_scope": left, "callee_scope": right, "call_ids": sorted(ids)}
            for (left, right), ids in sorted(scopes.items())
        ],
    )


def validate_graph(graph: dict):
    if graph.get("schema_version") == 1:
        validate_v1(graph)
        return
    schema = json.loads(GRAPH_SCHEMA.read_text(encoding="utf-8"))
    try:
        Draft202012Validator(schema).validate(graph)
    except ValidationError as error:
        raise ValueError(f"invalid graph contract: {error.message}") from error
    nodes = {node["id"]: node for node in graph["functions"]}
    if len(nodes) != len(graph["functions"]):
        raise ValueError("duplicate function IDs")
    source_index = {source["path"]: source for source in graph["source_index"]}
    if len(source_index) != len(graph["source_index"]):
        raise ValueError("duplicate source paths")
    for item in graph["source_index"] + graph["input_config"]:
        path = Path(item["path"])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("graph input path is outside target")
    contexts = {item["id"]: item for item in graph.get("contexts", [])}
    if len(contexts) != len(graph.get("contexts", [])):
        raise ValueError("duplicate context IDs")
    if set(contexts) & set(nodes):
        raise ValueError("context and function IDs must be distinct")
    for item in contexts.values():
        if item["language"] != graph["language"]:
            raise ValueError("context language differs from graph")
        if (
            item["path"] not in source_index
            or not 1 <= item["line"] <= item["end_line"] <= source_index[item["path"]]["lines"]
            or any(ref not in contexts for ref in item["references"])
        ):
            raise ValueError("invalid context location or reference")
    for node in nodes.values():
        if ("column" in node) != ("end_column" in node) or (
            "column" in node
            and node["line"] == node["end_line"]
            and node["column"] > node["end_column"]
        ):
            raise ValueError("invalid function column range")
        if any(ref not in contexts for ref in node.get("context_ids", [])):
            raise ValueError("unknown function context")
        if (
            node["path"] not in source_index
            or not 1 <= node["line"] <= node["end_line"] <= source_index[node["path"]]["lines"]
        ):
            raise ValueError("function location outside indexed source")
        if node["language"] != graph["language"]:
            raise ValueError("function language differs from graph")
    call_ids = set()
    for call in graph["calls"]:
        argument_indices = set()
        for argument in call.get("function_arguments", []):
            if (
                argument["index"] in argument_indices
                or (argument["status"] == "resolved") != (argument["function"] is not None)
                or (argument["function"] is not None and argument["function"] not in nodes)
                or (argument["status"] != "resolved" and not argument["reason"])
            ):
                raise ValueError("invalid function argument reference")
            argument_indices.add(argument["index"])
        if call["id"] in call_ids:
            raise ValueError("duplicate call IDs")
        call_ids.add(call["id"])
        if call["caller"] not in nodes or (
            call["callee"] is not None and call["callee"] not in nodes
        ):
            raise ValueError("unknown call endpoint")
        if (call["status"] == "resolved") != (call["callee"] is not None):
            raise ValueError("invalid resolved call")
        if (
            call["path"] not in source_index
            or not 1 <= call["line"] <= source_index[call["path"]]["lines"]
        ):
            raise ValueError("call location outside indexed source")
        if call["language"] != nodes[call["caller"]]["language"]:
            raise ValueError("call language differs from caller")
        caller = nodes[call["caller"]]
        if "column" in caller and (
            (call["line"] == caller["line"] and call["column"] < caller["column"])
            or (call["line"] == caller["end_line"] and call["column"] > caller["end_column"])
        ):
            raise ValueError("call location outside caller columns")
        if (
            call["path"] != caller["path"]
            or not caller["line"] <= call["line"] <= caller["end_line"]
        ):
            raise ValueError("call location outside caller")
        if call["status"] != "resolved" and not call["reason"]:
            raise ValueError("unresolved call requires a reason")
    if summarize_calls(graph["functions"], graph["calls"]) != (
        graph["file_calls"],
        graph["scope_calls"],
    ):
        raise ValueError("call summaries do not match resolved edges")


def build_graph(
    target: Path,
    output: Path,
    *,
    database: Path | None = None,
    compiler: str = "clang",
    timeout: int = 30,
    language: str = "auto",
    go: str = "go",
    node: str = "node",
) -> dict:
    target, output = target.resolve(), output.resolve()
    if output.is_relative_to(target):
        raise ValueError("output must be outside the target directory")
    if timeout < 1:
        raise ValueError("timeout must be positive")
    sources, skipped = index_target(target)
    from .extractors import clang, golang, solidity

    if language == "auto":
        detected = set()
        for source in sources:
            suffix = Path(source.path).suffix
            if suffix == ".go":
                detected.add("go")
            elif suffix == ".sol":
                detected.add("solidity")
            elif suffix in clang.UNIT_SUFFIXES:
                detected.add("c_cpp")
        if len(detected) != 1:
            raise ValueError(
                "select --language go, c_cpp or solidity for a mixed/unsupported target"
            )
        language = detected.pop()
    if language not in {"go", "c_cpp", "solidity"}:
        raise ValueError("unsupported graph language")
    if language != "c_cpp" and database is not None:
        raise ValueError("compilation database applies only to c_cpp")
    cache = Path.cwd() / ".cache" / "go-extractor"
    if cache.resolve().is_relative_to(target):
        cache = output.parent / ".go-extractor-cache"
    with run_lock(output):
        if any(path.name != ".lock" for path in output.iterdir()):
            raise ValueError("graph output is nonempty; use a new output directory")
        if language == "go":
            result = golang.extract(target, sources, compiler=go, timeout=timeout, cache=cache)
        elif language == "solidity":
            solidity_cache = Path.cwd() / ".cache" / "solidity-extractor"
            result = solidity.extract(
                target, sources, compiler=node, timeout=timeout, cache=solidity_cache
            )
        else:
            result = clang.extract(
                target, sources, database=database, compiler=compiler, timeout=timeout
            )
        current, current_skipped = index_target(target)
        if [source.metadata() for source in sources] != [
            source.metadata() for source in current
        ] or skipped != current_skipped:
            raise ValueError(
                "target changed during graph extraction; retry with a stable source tree"
            )
        for item in result["input_config"]:
            if read_input(target, item["path"]).metadata() != item:
                raise ValueError("target configuration changed during graph extraction")
        functions = sorted(
            result["functions"], key=lambda node: (node["path"], node["line"], node["id"])
        )
        calls = sorted(result["calls"], key=lambda call: (call["path"], call["line"], call["id"]))
        files, scopes = summarize_calls(functions, calls)
        graph = {
            "schema_version": 2,
            "language": language,
            "target": str(target),
            "source_index": [source.metadata() for source in sources],
            **result,
            "functions": functions,
            "calls": calls,
            "file_calls": files,
            "scope_calls": scopes,
        }
        config_paths = {item["path"] for item in graph["input_config"]}
        graph["coverage"]["skipped"] = [
            item for item in skipped if item["path"] not in config_paths
        ] + result["coverage"]["skipped"]
        graph["identity_sha256"] = digest(graph)
        validate_graph(graph)
        save_json(output / "graph.json", graph)
        save_text(output / "report.md", graph_report(graph))
    return graph


def read_graph(path: Path) -> dict:
    if path.stat().st_size > MAX_GRAPH_BYTES:
        raise ValueError("graph exceeds 64 MiB")
    graph = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(graph, dict):
        raise ValueError("invalid graph format")
    validate_graph(graph)
    expected = dict(graph)
    checksum = expected.pop("identity_sha256", None)
    if checksum != digest(expected):
        raise ValueError("graph checksum mismatch; rebuild the graph")
    return graph


def select_function(graph: dict, selector: str) -> dict:
    matches = [
        node
        for node in graph["functions"]
        if selector in {node["id"], node["name"], node["qualified_name"]}
    ]
    if len(matches) != 1:
        choices = [
            {"id": node["id"], "signature": node["signature"], "path": node["path"]}
            for node in matches
        ]
        raise ValueError(f"function must match once; use its ID: {choices}")
    return matches[0]


def resolve(graph: dict, selector: str) -> dict:
    nodes = [
        node
        for node in graph["functions"]
        if node["path"] == selector or (node.get("scope") and node["scope"] == selector)
    ]
    context_ids = [
        item["id"]
        for item in graph.get("contexts", [])
        if selector in {item["id"], item["path"], item["scope"]}
    ]
    if not nodes and not context_ids:
        nodes = [select_function(graph, selector)]
    ids = {node["id"] for node in nodes}
    return {
        "functions": nodes,
        "contexts": referenced_contexts(graph, nodes, context_ids),
        "parse_coverage": graph["coverage"]["status"],
        "build_configuration_verified": graph["coverage"]["configuration_verified"],
        "incoming_calls": [call for call in graph["calls"] if call["callee"] in ids],
        "outgoing_calls": [call for call in graph["calls"] if call["caller"] in ids],
    }


def reachable(graph: dict, selector: str) -> dict:
    entry = select_function(graph, selector)
    outgoing = defaultdict(list)
    for call in graph["calls"]:
        outgoing[call["caller"]].append(call)
    seen, queue, calls = {entry["id"]}, deque([entry["id"]]), []
    while queue:
        for call in outgoing[queue.popleft()]:
            calls.append(call)
            if call["status"] == "resolved" and call["callee"] not in seen:
                seen.add(call["callee"])
                queue.append(call["callee"])
    functions = [node for node in graph["functions"] if node["id"] in seen]
    return {
        "entry": entry["id"],
        "parse_coverage": graph["coverage"]["status"],
        "build_configuration_verified": graph["coverage"]["configuration_verified"],
        "functions": functions,
        "contexts": referenced_contexts(graph, functions),
        "files": sorted({node["path"] for node in functions}),
        "scopes": sorted({node.get("scope", "") for node in functions} - {""}),
        "calls": calls,
        "unresolved_calls": [call for call in calls if call["status"] != "resolved"],
        "note": "Direct-call reachability only; unresolved calls can hide additional paths.",
    }


def referenced_contexts(graph: dict, functions: list, context_ids=()) -> list[dict]:
    contexts = {item["id"]: item for item in graph.get("contexts", [])}
    pending = [
        *context_ids,
        *[ref for function in functions for ref in function.get("context_ids", [])],
    ]
    seen = set()
    while pending:
        ref = pending.pop()
        if ref not in seen:
            seen.add(ref)
            pending.extend(contexts[ref]["references"])
    return [item for item in contexts.values() if item["id"] in seen]
