"""Typed Solidity AST extraction; external and runtime dispatch are explicit boundaries."""

import hashlib
import json
import os
import shutil
import tempfile
from bisect import bisect_right
from pathlib import Path

from ..pipeline import digest, source_lines
from .process import run_tool

HELPER = Path(__file__).parent / "solidity_helper"


def walk(node):
    if isinstance(node, dict):
        if "nodeType" in node:
            yield node
        for value in node.values():
            if isinstance(value, (dict, list)):
                yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def extract(target: Path, sources: list, *, compiler: str = "node", timeout: int = 30, cache: Path):
    executable = shutil.which(compiler)
    if not executable:
        raise ValueError("Node.js is required for Solidity extraction; run make setup-solidity")
    selected = [source for source in sources if Path(source.path).suffix == ".sol"]
    if not selected or len(selected) > 256:
        raise ValueError("Solidity extraction requires between 1 and 256 source files")
    cache = cache.resolve()
    if cache.is_relative_to(target):
        raise ValueError("Solidity compiler cache must be outside target")
    soljson = cache / "node_modules" / "solc" / "soljson.js"
    if not soljson.is_file():
        raise ValueError("Solidity compiler dependencies missing; run make setup-solidity")
    environment = {key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG") if key in os.environ}
    helper_hash = hashlib.sha256()
    for name in ("main.cjs", "package.json", "package-lock.json"):
        helper_hash.update((HELPER / name).read_bytes())
    with tempfile.TemporaryDirectory(prefix="audit-solidity-") as scratch:
        root = Path(scratch)
        command = [executable, str(HELPER / "main.cjs")]
        version, _ = run_tool(
            "Solidity compiler", [*command, "--version", str(cache)], root, environment, timeout
        )
        if not version.startswith("0.8.30+"):
            raise ValueError(
                "Solidity extractor requires pinned solc 0.8.30; run make setup-solidity"
            )
        request = {
            "language": "Solidity",
            "sources": {source.path: {"content": source.text} for source in selected},
            "settings": {"outputSelection": {"*": {"": ["ast"]}}},
        }
        input_path = root / "input.json"
        input_path.write_text(json.dumps(request), encoding="utf-8")
        raw, _ = run_tool(
            "Solidity AST", [*command, str(input_path), str(cache)], root, environment, timeout
        )
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("invalid Solidity compiler JSON output")
    errors = [item["message"] for item in result.get("errors", []) if item["severity"] == "error"]
    # Type errors can leave partially annotated ASTs; never consume them as resolved structure.
    parsed = {} if errors else result.get("sources", {})
    if not errors and set(parsed) != {source.path for source in selected}:
        raise ValueError("Solidity AST sources differ from supplied source snapshot")
    try:
        functions, calls, contexts = ast_graph(parsed, selected) if not errors else ([], [], [])
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise ValueError("invalid Solidity AST output") from error
    unvisited = [source.path for source in sources if source.path not in parsed]
    return {
        "engine": {
            "name": "solc-js typed AST",
            "version": version,
            "helper_sha256": helper_hash.hexdigest(),
            "compiler_sha256": hashlib.sha256(soljson.read_bytes()).hexdigest(),
        },
        "input_config": [],
        "functions": functions,
        "calls": calls,
        "contexts": contexts,
        "coverage": {
            "status": "partial" if errors or unvisited else "parsed",
            "units": [
                {"path": source.path, "status": "failed" if errors else "parsed", "errors": errors}
                for source in selected
            ],
            "skipped": [],
            "unvisited_sources": unvisited,
            "configuration_verified": False,
            "metadata": {
                "network": False,
                "bytecode": False,
                "diagnostics": result.get("errors", []),
            },
        },
        "limitations": [
            "Pinned solc 0.8.30 defaults; no Foundry/Hardhat build configuration.",
            "Supplied .sol imports only; no remappings, filesystem fallback or downloads.",
            "Internal non-virtual calls and modifier applications are static dependencies.",
            "Virtual/super targets require a runtime contract; candidates are not edges.",
            "External declarations do not prove deployed contract/library implementations.",
            "Modifier order/placeholders do not prove control flow or effective authorization.",
            "Function values/low-level calls remain unresolved; assembly is opaque.",
            "Initializer execution, implicit base constructors and modifier flow are not expanded.",
            "No bytecode, deployment, EVM execution, taint or attacker reachability analysis.",
        ],
    }


def ast_graph(parsed: dict, sources: list) -> tuple[list, list, list]:
    by_path = {source.path: source for source in sources}
    source_ids, line_starts = {}, {}
    declarations, owners, contracts = {}, {}, {}
    for path, unit in parsed.items():
        if type(unit["id"]) is not int or unit["id"] in source_ids:
            raise ValueError("invalid Solidity source ID")
        source_ids[unit["id"]] = path
        offsets, offset = [], 0
        for line in source_lines(by_path[path].text):
            offsets.append(offset)
            offset += len(line.encode())
        line_starts[path] = offsets
        pending = [(unit["ast"], None)]
        while pending:
            node, owner = pending.pop()
            if not isinstance(node, dict):
                continue
            if node.get("nodeType", "").startswith("Yul"):
                continue
            if "nodeType" in node:
                if node["id"] in declarations:
                    raise ValueError("duplicate Solidity AST declaration ID")
                declarations[node["id"]] = node
                if node["nodeType"] == "ContractDefinition":
                    owner = node["id"]
                    contracts[owner] = node
                owners[node["id"]] = owner
            for value in node.values():
                if isinstance(value, dict):
                    pending.append((value, owner))
                elif isinstance(value, list):
                    pending.extend((item, owner) for item in value if isinstance(item, dict))

    def span(node):
        start, length, file_id = map(int, node["src"].split(":"))
        path = source_ids.get(file_id)
        if (
            path is None
            or start < 0
            or length < 1
            or start + length > len(by_path[path].text.encode())
        ):
            raise ValueError("Solidity AST location outside supplied source")
        return path, start, length

    def location(node):
        path, start, length = span(node)
        starts = line_starts[path]
        first, last = bisect_right(starts, start) - 1, bisect_right(starts, start + length - 1) - 1
        return {
            "path": path,
            "line": first + 1,
            "end_line": last + 1,
            "column": start - starts[first] + 1,
            "end_column": start + length - starts[last],
        }

    def scope(node):
        path, _, _ = span(node)
        owner = owners[node["id"]]
        return f"{path}:{contracts[owner]['name']}" if owner is not None else path

    def identity(node, kind):
        path, start, _ = span(node)
        return digest(
            {
                "language": "solidity",
                "kind": kind,
                "path": path,
                "offset": start,
                "length": span(node)[2],
            }
        )

    contexts, file_contexts = {}, {}
    for ast_id, node in declarations.items():
        typ = node["nodeType"]
        if typ not in {
            "ContractDefinition",
            "StructDefinition",
            "EnumDefinition",
            "UserDefinedValueTypeDefinition",
            "PragmaDirective",
            "ImportDirective",
        } and not (
            typ == "VariableDeclaration" and (node.get("stateVariable") or owners[ast_id] is None)
        ):
            continue
        if (
            typ == "VariableDeclaration"
            and not node.get("constant")
            and not node.get("stateVariable")
        ):
            continue
        where = node
        if typ == "ContractDefinition":
            path, start, _ = span(node)
            _, name_start, name_len = span({"src": node["nameLocation"]})
            end = max(
                [name_start + name_len, *[s + n for _, s, n in map(span, node["baseContracts"])]]
            )
            where = {"src": f"{start}:{end - start}:{parsed[path]['id']}"}
        loc = location(where)
        preamble = typ in {"PragmaDirective", "ImportDirective"}
        contexts[ast_id] = {
            "id": identity(node, "context"),
            "language": "solidity",
            "scope": scope(node),
            "kind": "preamble" if preamble else "value" if typ == "VariableDeclaration" else "type",
            "name": node.get("name")
            or node.get("file")
            or "pragma " + " ".join(node.get("literals", [])),
            "path": loc["path"],
            "line": loc["line"],
            "end_line": loc["end_line"],
            "references": [],
        }
        if preamble:
            file_contexts.setdefault(loc["path"], []).append(contexts[ast_id]["id"])
    for ast_id, context in contexts.items():
        node = declarations[ast_id]
        # Header dependencies exclude unrelated contract bodies from a slice.
        children = (
            node.get("baseContracts", []) if node["nodeType"] == "ContractDefinition" else node
        )
        refs = {n.get("referencedDeclaration") for n in walk(children)} & contexts.keys()
        context["references"] = sorted(
            {contexts[ref]["id"] for ref in refs if ref != ast_id}
            | (set(file_contexts.get(context["path"], [])) - {context["id"]})
        )
    functions = {}
    for ast_id, node in declarations.items():
        if node["nodeType"] not in {"FunctionDefinition", "ModifierDefinition"}:
            continue
        owner = owners[ast_id]
        name = node.get("name") or node.get("kind", "constructor")
        parameters = [
            {"name": p["name"], "type": p["typeDescriptions"]["typeString"]}
            for p in node["parameters"]["parameters"]
        ]
        refs = {n.get("referencedDeclaration") for n in walk(node)} & contexts.keys()
        if owner is not None:
            refs.add(owner)
        contract = contracts.get(owner, {})
        functions[ast_id] = {
            "id": identity(node, "function"),
            "language": "solidity",
            "scope": scope(node),
            "kind": "modifier" if node["nodeType"] == "ModifierDefinition" else node["kind"],
            "name": name,
            "qualified_name": f"{scope(node)}.{name}",
            "signature": name + "(" + ",".join(p["type"] for p in parameters) + ")",
            **location(node),
            "parameters": parameters,
            "context_ids": sorted(
                {contexts[ref]["id"] for ref in refs}
                | set(file_contexts.get(location(node)["path"], []))
            ),
            "metadata": {
                "ast_id": ast_id,
                "visibility": node.get("visibility", "internal"),
                "state_mutability": node.get("stateMutability"),
                "virtual": node.get("virtual", False),
                "implemented": node.get("body") is not None,
                "contract_kind": contract.get("contractKind"),
                "base_contract_ids": [
                    contexts[b["baseName"]["referencedDeclaration"]]["id"]
                    for b in contract.get("baseContracts", [])
                ],
                "linearized_base_ids": [
                    contexts[b]["id"] for b in contract.get("linearizedBaseContracts", [])
                ],
                "placeholder_count": sum(
                    n["nodeType"] == "PlaceholderStatement" for n in walk(node)
                ),
            },
        }
    calls = []
    for ast_id, function in functions.items():
        node = declarations[ast_id]
        function["metadata"]["overrides"] = [
            functions[ref]["id"] for ref in node.get("baseFunctions", node.get("baseModifiers", []))
        ]
        modifier_indices = {m["id"]: i for i, m in enumerate(node.get("modifiers", []))}
        for item in walk(node):
            typ = item["nodeType"]
            if typ not in {"FunctionCall", "ModifierInvocation", "InlineAssembly"}:
                continue
            if typ == "FunctionCall" and item["kind"] != "functionCall":
                continue
            exp = item.get("expression", item.get("modifierName", {}))
            while exp.get("nodeType") == "FunctionCallOptions":
                exp = exp["expression"]
            ref = exp.get("referencedDeclaration")
            declaration = declarations.get(ref, {})
            if declaration.get("nodeType") in {"EventDefinition", "ErrorDefinition"}:
                continue
            target_function = functions.get(ref)
            type_id = exp.get("typeDescriptions", {}).get("typeIdentifier", "")
            receiver = exp.get("expression", {})
            name = (
                target_function["qualified_name"]
                if target_function
                else exp.get("name", exp.get("memberName", "dynamic call"))
            )
            status, dispatch, reason, callee = "unresolved", "indirect", "unknown_declaration", None
            if typ == "InlineAssembly":
                dispatch, reason, name = "assembly", "opaque_assembly", "inline assembly boundary"
            elif (
                declaration.get("typeDescriptions", {})
                .get("typeIdentifier", "")
                .startswith("t_function_")
                or exp.get("nodeType") == "FunctionCall"
                or (
                    type_id.startswith("t_function_external_")
                    and exp.get("nodeType") != "MemberAccess"
                )
            ):
                dispatch, reason = "function_value", "function_value"
            elif any(
                type_id.startswith(f"t_function_{kind}_")
                for kind in ("barecall", "baredelegatecall", "barestaticcall")
            ):
                dispatch, reason = "low_level", "runtime_address_and_selector"
            elif type_id.startswith(("t_function_external_", "t_function_delegatecall_")):
                status, dispatch, reason = (
                    "external",
                    "library_external"
                    if type_id.startswith("t_function_delegatecall_")
                    else "external",
                    "runtime_contract_binding",
                )
            elif exp.get("nodeType") == "NewExpression":
                is_contract = exp["typeName"]["nodeType"] == "UserDefinedTypeName"
                status, dispatch, reason, name = (
                    ("external", "constructor", "contract_creation", "new contract")
                    if is_contract
                    else ("external", "builtin", "memory_allocation", "new array")
                )
            elif typ == "ModifierInvocation" and ref in contracts:
                dispatch, reason = "constructor", "base_constructor_not_expanded"
            elif type_id.startswith(("t_function_send_", "t_function_transfer_")):
                status, dispatch, reason = "external", "external", "runtime_recipient"
            elif target_function:
                qualified = receiver.get("referencedDeclaration") in contracts
                if receiver.get("name") == "super":
                    dispatch, reason = "super", "super_dispatch_requires_runtime_contract"
                elif not declaration.get("body") or (declaration.get("virtual") and not qualified):
                    dispatch, reason = "virtual", "virtual_dispatch_requires_runtime_contract"
                else:
                    status, dispatch, reason, callee = (
                        "resolved",
                        "modifier" if typ == "ModifierInvocation" else "direct",
                        "",
                        target_function["id"],
                    )
            elif type_id.startswith("t_function_internal_"):
                dispatch, reason = "function_value", "function_value"
            elif type_id.startswith("t_function_"):
                status, dispatch, reason = "external", "builtin", "compiler_builtin"
            loc = location(item)
            calls.append(
                {
                    "id": identity(item, "call"),
                    "language": "solidity",
                    "caller": function["id"],
                    "callee": callee,
                    "callee_name": name,
                    "path": loc["path"],
                    "line": loc["line"],
                    "column": loc["column"],
                    "kind": "call",
                    "dispatch": dispatch,
                    "execution": "normal",
                    "status": status,
                    "reason": reason,
                    "provenance": "solc_ast",
                    "metadata": {
                        "ast_id": item["id"],
                        "declaration_id": target_function["id"] if target_function else None,
                        "modifier_index": modifier_indices.get(item["id"]),
                        "expression": by_path[loc["path"]]
                        .text.encode()[span(item)[1] : span(item)[1] + span(item)[2]]
                        .decode(),
                    },
                }
            )
    return (
        list(functions.values()),
        calls,
        sorted(contexts.values(), key=lambda c: (c["path"], c["line"], c["id"])),
    )
