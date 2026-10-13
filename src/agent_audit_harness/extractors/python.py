"""Python AST bindings from supplied source; never import or execute the target."""

import ast
import builtins
import hashlib
import json
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
MAX_FILES = 256
MAX_AST_NODES = 100_000


def extract(target: Path, sources: list, *, timeout: int = 30) -> dict:
    from .process import run_tool

    selected = [source for source in sources if Path(source.path).suffix == ".py"]
    if not 1 <= len(selected) <= MAX_FILES:
        raise ValueError("Python extraction requires between 1 and 256 source files")
    if any(source.path in {"__init__.py", "src/__init__.py"} for source in selected):
        raise ValueError("select the package parent/import root, not the package directory")
    environment = {key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG") if key in os.environ}
    with tempfile.TemporaryDirectory(prefix="audit-python-") as scratch:
        root = Path(scratch)
        request = root / "sources.json"
        request.write_text(
            json.dumps({source.path: source.text for source in selected}), encoding="utf-8"
        )
        raw, _ = run_tool(
            "Python AST",
            [sys.executable, "-I", str(Path(__file__).resolve()), str(request)],
            root,
            environment,
            timeout,
        )
        result = json.loads(raw)
    skipped = [
        {"path": source.path, "reason": "unsupported_graph_language"}
        for source in sources
        if Path(source.path).suffix != ".py"
    ]
    unvisited = [unit["path"] for unit in result["units"] if unit["status"] != "parsed"]
    return {
        "engine": {
            "name": "python_ast",
            "version": sys.version.split()[0],
            "helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "functions": result["functions"],
        "calls": result["calls"],
        "contexts": result["contexts"],
        "input_config": [],
        "coverage": {
            "status": "partial" if unvisited or skipped else "parsed",
            "units": result["units"],
            "skipped": skipped,
            "unvisited_sources": sorted([*unvisited, *[item["path"] for item in skipped]]),
            "configuration_verified": False,
            "metadata": {
                "import_roots": [".", "src"],
                "target_execution": False,
                "network": False,
                "pythonpath_used": False,
            },
        },
        "limitations": [
            "static lexical/import bindings only; resolved edges are not runtime proof",
            "target is the import root (or a project with src/); project config is not executed",
            "ambiguous module paths, conditional/rebound/decorated symbols remain unresolved",
            "object dispatch/constructors and dynamic/function-value calls stay unresolved",
            "wildcard imports, global/nonlocal writes and direct attribute writes are conservative",
            "no points-to, inheritance, descriptor, sys.path, import-hook or monkey-patch analysis",
            "module/class initialization, definition-time calls and lambda bodies are omitted",
            "async/generator calls are syntactic dependencies, not proof of body execution",
            "parser uses the harness Python version and indexed UTF-8 source only",
        ],
    }


def identity(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()[:24]


def module_name(path: str) -> str:
    parts = list(Path(path).with_suffix("").parts)
    if parts[0] == "src" and len(parts) > 1:
        parts.pop(0)
    if parts[-1] == "__init__":
        parts.pop()
    if not parts or not all(part.isidentifier() for part in parts):
        raise ValueError("select the package parent/import root; module path must be identifiers")
    return ".".join(parts)


class Scope:
    def __init__(self, module, node=None, parent=None, kind="module", qualified=""):
        self.module, self.node, self.parent, self.kind = module, node, parent, kind
        self.qualified = qualified or module
        self.bindings = defaultdict(list)
        self.globals, self.nonlocals = set(), set()
        self.wildcard = False
        self.calls, self.writes, self.contexts = [], [], []
        self.function = None


def call_location(node, path):
    return {
        "path": path,
        "line": node.lineno,
        "column": node.col_offset + 1,
        "end_line": node.end_lineno,
        "end_column": node.end_col_offset + 1,
    }


def simple_argument_origins(node, path):
    """Track only straight-line local names; any control or rebinding drops the path."""
    if not isinstance(node, FUNCTIONS) or isinstance(node, ast.AsyncFunctionDef):
        return {}
    parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    parameters += [arg for arg in (node.args.vararg, node.args.kwarg) if arg]
    names = {arg.arg for arg in parameters}
    for statement in node.body:
        if isinstance(statement, ast.Assign):
            if (
                len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
                or not isinstance(statement.value, (ast.Call, ast.Name, ast.Constant))
                or statement.targets[0].id in names
            ):
                return {}
            names.add(statement.targets[0].id)
        elif isinstance(statement, ast.Expr):
            if not isinstance(statement.value, (ast.Call, ast.Constant)):
                return {}
        elif isinstance(statement, ast.Return):
            if statement.value is not None and not isinstance(
                statement.value, (ast.Call, ast.Name, ast.Constant)
            ):
                return {}
        elif not isinstance(statement, ast.Pass):
            return {}
        if any(
            isinstance(child, (ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom))
            for child in ast.walk(statement)
        ):
            return {}

    current = {
        arg.arg: {"kind": "parameter", "parameter_index": index}
        for index, arg in enumerate(parameters)
    }
    origins = {}

    def origin(expression):
        if isinstance(expression, ast.Name):
            return current.get(
                expression.id, {"kind": "unknown", "reason": "unsupported_expression"}
            )
        if isinstance(expression, ast.Constant):
            return {"kind": "constant"}
        if isinstance(expression, ast.Call):
            return {"kind": "call_result", **call_location(expression, path)}
        return {"kind": "unknown", "reason": "unsupported_expression"}

    for statement in node.body:
        for child in ast.walk(statement):
            if isinstance(child, ast.Call):
                origins[id(child)] = [
                    {"argument_index": index, **origin(argument)}
                    for index, argument in enumerate(child.args)
                ]
        if isinstance(statement, ast.Assign):
            current[statement.targets[0].id] = origin(statement.value)
    return origins


def ast_graph(sources: dict[str, str]) -> dict:
    modules, scopes, functions, contexts, units = defaultdict(list), [], [], [], []
    function_nodes = {}
    import_contexts = []
    paths, packages = {}, {}
    for path, text in sorted(sources.items()):
        try:
            module = module_name(path)
            tree = ast.parse(text, filename=path)
            if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
                raise ValueError("Python AST exceeds 100,000 nodes per file")
        except (SyntaxError, ValueError, RecursionError) as error:
            units.append({"path": path, "status": "failed", "errors": [str(error)]})
            # Preserve known local module boundaries even when their syntax failed.
            try:
                modules[module_name(path)].append(None)
            except ValueError:
                pass
            continue
        scope = Scope(module, tree)
        modules[module].append(scope)
        scopes.append(scope)
        paths[id(scope)] = path
        packages[module] = module if Path(path).name == "__init__.py" else module.rpartition(".")[0]
        units.append({"path": path, "module": module, "status": "parsed", "errors": []})
    for module in list(modules):
        parts = module.split(".")
        for end in range(1, len(parts)):
            modules.setdefault(".".join(parts[:end]), [])

    def root_scope(scope):
        while scope.parent:
            scope = scope.parent
        return scope

    def context(scope, node, kind, name, header=False):
        path = paths[id(root_scope(scope))]
        item = {
            "id": identity(path, node.lineno, node.col_offset, "context"),
            "language": "python",
            "scope": scope.module,
            "kind": kind,
            "name": name,
            "path": path,
            "line": min([node.lineno, *[d.lineno for d in getattr(node, "decorator_list", [])]]),
            "end_line": max(node.lineno, node.body[0].lineno - 1) if header else node.end_lineno,
            "references": [],
        }
        contexts.append(item)
        scope.contexts.append(item["id"])
        return item

    def imported_module(scope, node):
        if not node.level:
            return node.module or ""
        package = packages[scope.module].split(".") if packages[scope.module] else []
        if node.level > len(package):
            return None
        base = package[: len(package) - node.level + 1]
        return ".".join([*base, *([node.module] if node.module else [])])

    def header_writes(scope, expressions):
        for expression in expressions:
            if expression is None:
                continue
            for node in ast.walk(expression):
                if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    scope.bindings[node.id].append(("unknown", "definition_time_assignment"))
                if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    scope.writes.append(node)

    def scan(scope, node, conditional=False, awaited=False):
        if isinstance(node, FUNCTIONS):
            qualified = scope.qualified + (".<locals>." if scope.kind == "function" else ".")
            qualified += node.name
            path = paths[id(root_scope(scope))]
            child = Scope(scope.module, node, scope, "function", qualified)
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            arguments += [arg for arg in (node.args.vararg, node.args.kwarg) if arg]
            header_writes(
                scope,
                [
                    *node.args.defaults,
                    *node.args.kw_defaults,
                    *node.decorator_list,
                    *[arg.annotation for arg in arguments],
                    node.returns,
                ],
            )
            function = {
                "id": identity(path, node.lineno, node.col_offset, qualified),
                "language": "python",
                "scope": scope.module,
                "kind": "method" if scope.kind == "class" else "function",
                "name": node.name,
                "qualified_name": qualified,
                "signature": ("async " if isinstance(node, ast.AsyncFunctionDef) else "")
                + f"def {node.name}({ast.unparse(node.args)})"
                + (f" -> {ast.unparse(node.returns)}" if node.returns else ""),
                "parameters": [
                    {"name": arg.arg, "type": ast.unparse(arg.annotation) if arg.annotation else ""}
                    for arg in arguments
                ],
                "path": path,
                "line": min([node.lineno, *[d.lineno for d in node.decorator_list]]),
                "end_line": node.end_lineno,
                "column": node.col_offset + 1,
                "end_column": node.end_col_offset,
                "metadata": {
                    "async": isinstance(node, ast.AsyncFunctionDef),
                    "decorators": [ast.unparse(d) for d in node.decorator_list],
                    "binding": "static_lexical",
                },
            }
            child.function = function
            function_nodes[function["id"]] = node
            functions.append(function)
            scopes.append(child)
            reason = "conditional_binding" if conditional else "decorated_function"
            scope.bindings[node.name].append(
                ("unknown", reason)
                if conditional or node.decorator_list
                else ("function", function)
            )
            for arg in arguments:
                child.bindings[arg.arg].append(("unknown", "parameter_or_function_value"))
            for statement in node.body:
                scan(child, statement)
            return
        if isinstance(node, ast.ClassDef):
            header_writes(
                scope,
                [
                    *node.bases,
                    *[keyword.value for keyword in node.keywords],
                    *node.decorator_list,
                ],
            )
            scope.bindings[node.name].append(("unknown", "class_constructor_or_descriptor"))
            child = Scope(scope.module, node, scope, "class", scope.qualified + "." + node.name)
            scopes.append(child)
            context(child, node, "type", node.name, header=True)
            for statement in node.body:
                scan(child, statement)
            return
        if isinstance(node, ast.Lambda):
            return  # No implicit invocation edge from the enclosing function to lambda bodies.
        if isinstance(node, COMPREHENSIONS):
            scan(scope, node.generators[0].iter, conditional)
            child = Scope(scope.module, node, scope, "comprehension")
            scopes.append(child)
            for index, generator in enumerate(node.generators):
                if index:
                    scan(child, generator.iter, conditional)
                scan(child, generator.target, conditional)
                for condition in generator.ifs:
                    scan(child, condition, conditional)
            for field in ("elt", "key", "value"):
                if hasattr(node, field):
                    scan(child, getattr(node, field), conditional)
            return
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            (scope.globals if isinstance(node, ast.Global) else scope.nonlocals).update(node.names)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            item = context(scope, node, "preamble", ast.unparse(node))
            import_contexts.append((scope, node, item))
            for alias in node.names:
                if alias.name == "*":
                    scope.wildcard = True
                    continue
                if isinstance(node, ast.Import):
                    name = alias.asname or alias.name.split(".")[0]
                    value = ("module", alias.name if alias.asname else name)
                else:
                    name = alias.asname or alias.name
                    module = imported_module(scope, node)
                    value = (
                        ("import", module, alias.name)
                        if module
                        else ("unknown", "relative_import_outside_snapshot")
                    )
                scope.bindings[name].append(
                    ("unknown", "conditional_binding") if conditional else value
                )
            return
        if isinstance(node, ast.ExceptHandler) and node.name:
            scope.bindings[node.name].append(("unknown", "exception_binding"))
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            scope.bindings[node.name].append(("unknown", "pattern_binding"))
        if isinstance(node, ast.MatchMapping) and node.rest:
            scope.bindings[node.rest].append(("unknown", "pattern_binding"))
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                scope.bindings[node.id].append(("unknown", "assigned_or_deleted_name"))
        if isinstance(node, ast.NamedExpr) and scope.kind == "comprehension":
            owner = scope.parent
            while owner.kind == "comprehension":
                owner = owner.parent
            if isinstance(node.target, ast.Name):
                owner.bindings[node.target.id].append(("unknown", "assignment_expression"))
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            scope.writes.append(node)
        if isinstance(node, ast.Call):
            scope.calls.append((node, awaited))
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and scope.kind == "module":
            context(scope, node, "value", ast.unparse(node).split("=", 1)[0].strip())
        conditional |= isinstance(
            node, (ast.If, ast.Try, ast.TryStar, ast.For, ast.AsyncFor, ast.While, ast.Match)
        )
        for child in ast.iter_child_nodes(node):
            scan(scope, child, conditional, isinstance(node, ast.Await))

    for members in modules.values():
        for scope in members:
            if scope:
                for statement in scope.node.body:
                    scan(scope, statement)

    def enclosing(scope, name):
        scope = scope.parent
        while scope:
            if scope.kind == "function" and name in scope.bindings:
                return scope
            scope = scope.parent
        return None

    # Import/re-export evidence is a context dependency, never an initialization call edge.
    for scope, node, item in import_contexts:
        if isinstance(node, ast.Import):
            dependencies = [alias.name for alias in node.names]
        else:
            module = imported_module(scope, node)
            dependencies = [module, *[module + "." + a.name for a in node.names]] if module else []
        refs = set()
        for dependency in dependencies:
            parts = dependency.split(".")
            for end in range(1, len(parts) + 1):
                for member in modules.get(".".join(parts[:end]), []):
                    if member:
                        refs.update(member.contexts)
        item["references"] = sorted(refs - {item["id"]})

    for scope in scopes:
        for name in scope.globals | scope.nonlocals:
            if name in scope.bindings:
                destination = root_scope(scope) if name in scope.globals else enclosing(scope, name)
                if destination:
                    destination.bindings[name].append(("unknown", "global_or_nonlocal_write"))
                del scope.bindings[name]

    def module_symbol(module, name, seen):
        if (module, name) in seen or len(seen) >= 64:
            return ("unknown", "cyclic_or_deep_import")
        seen = seen | {(module, name)}
        parts = module.split(".")
        for end in range(1, len(parts)):
            parent = ".".join(parts[:end])
            members = modules.get(parent, [])
            if len(members) > 1:
                return ("ambiguous", "multiple_module_paths")
            if members and (members[0] is None or packages[parent] != parent):
                return ("unknown", "parent_module_is_not_a_parsed_package")
        if module not in modules:
            if any(module.startswith(local + ".") for local in modules):
                return ("unknown", "local_module_not_indexed")
            return ("external", module + "." + name)
        members = modules[module]
        if len(members) > 1:
            return ("ambiguous", "multiple_module_paths")
        if members and members[0] is None:
            return ("unknown", "local_module_parse_failed")
        if members and (name in members[0].bindings or members[0].wildcard):
            return binding(members[0], name, seen)
        if module + "." + name in modules and (not members or packages[module] == module):
            return ("module", module + "." + name)
        return ("unknown", "local_export_not_found")

    def binding(scope, name, seen):
        if scope.wildcard:
            return ("unknown", "wildcard_import")
        values = scope.bindings.get(name, [])
        if len(values) != 1:
            return ("ambiguous", "multiple_bindings")
        value = values[0]
        if value[0] == "import":
            return module_symbol(value[1], value[2], seen)
        return value

    # shortcut: no dynamic target/type propagation, add an analyzer for callbacks or methods.
    def lookup(scope, name):
        if name in scope.globals:
            scope = root_scope(scope)
        elif name in scope.nonlocals:
            scope = enclosing(scope, name)
            if scope is None:
                return ("unknown", "nonlocal_binding_not_found")
        while scope:
            if scope.kind != "module" and name in scope.globals:
                scope = root_scope(scope)
                continue
            if scope.kind != "class":
                if scope.kind == "module" and len(modules[scope.module]) > 1:
                    return ("ambiguous", "multiple_module_paths")
                if name in scope.bindings or scope.wildcard:
                    return binding(scope, name, set())
            scope = scope.parent
        if hasattr(builtins, name):
            return ("external", "builtins." + name)
        return ("unknown", "name_not_bound")

    def expression(scope, node):
        if isinstance(node, ast.Name):
            return lookup(scope, node.id)
        if isinstance(node, ast.Attribute):
            base = expression(scope, node.value)
            if base[0] == "module":
                return module_symbol(base[1], node.attr, set())
            if base[0] == "external":
                return ("external", base[1] + "." + node.attr)
            if base[0] in {"unknown", "ambiguous"}:
                return base
            return ("unknown", "object_attribute_or_descriptor")
        return ("unknown", "dynamic_callable_expression")

    mutated = set()
    for scope in scopes:
        for write in scope.writes:
            value = expression(scope, write)
            if value[0] == "function":
                mutated.add(value[1]["id"])
            elif value[0] in {"module", "external"}:
                mutated.add(value[1])

    calls = []
    functions_by_id = {function["id"]: function for function in functions}
    origin_cache = {}
    for scope in scopes:
        owner = scope
        deferred = False
        while owner and owner.kind == "comprehension":
            deferred |= isinstance(owner.node, ast.GeneratorExp)
            owner = owner.parent
        if not owner or not owner.function:
            continue
        if owner.function["id"] not in origin_cache:
            origin_cache[owner.function["id"]] = simple_argument_origins(
                function_nodes[owner.function["id"]], owner.function["path"]
            )
        for node, awaited in scope.calls:
            value = expression(scope, node.func)
            status, callee, reason = "unresolved", None, ""
            spelling = ast.unparse(node.func)
            name = spelling
            if value[0] == "function":
                name = value[1]["qualified_name"]
                if value[1]["id"] in mutated or any(
                    value[1]["scope"] == item or value[1]["scope"].startswith(item + ".")
                    for item in mutated
                ):
                    reason = "attribute_rebinding"
                else:
                    status, callee = "resolved", value[1]["id"]
            elif value[0] == "external":
                name = value[1]
                status, reason = (
                    ("unresolved", "attribute_rebinding")
                    if name in mutated
                    else ("external", "outside_source_snapshot")
                )
            elif value[0] == "ambiguous":
                status, reason = "ambiguous", value[1]
            elif value[0] == "module":
                reason = "module_is_not_a_function"
            else:
                reason = value[1]
            path = owner.function["path"]
            metadata = {
                "expression": spelling,
                "awaited": awaited,
                "call_end_line": node.end_lineno,
                "call_end_column": node.end_col_offset + 1,
            }
            if scope is owner and status in {"resolved", "external"}:
                metadata["argument_origins"] = origin_cache[owner.function["id"]].get(
                    id(node),
                    [
                        {
                            "argument_index": index,
                            "kind": "unknown",
                            "reason": "conditional_or_prior_control",
                        }
                        for index in range(len(node.args))
                    ],
                )
            if status == "resolved" and scope is owner:
                destination = function_nodes[callee]
                positional = [*destination.args.posonlyargs, *destination.args.args]
                if (
                    destination.args.vararg
                    or destination.args.kwarg
                    or destination.args.kwonlyargs
                    or destination.args.defaults
                    or any(value is not None for value in destination.args.kw_defaults)
                    or node.keywords
                    or len(node.args) != len(positional)
                    or any(isinstance(argument, ast.Starred) for argument in node.args)
                ):
                    metadata["argument_transfer_gap"] = "unsupported_signature_or_arity"
                else:
                    transfers = []
                    for index, argument in enumerate(node.args):
                        expression_text = ast.get_source_segment(sources[path], argument)
                        if not expression_text or len(expression_text.encode()) > 256:
                            metadata["argument_transfer_gap"] = "argument_expression_outside_limit"
                            break
                        transfers.append(
                            {
                                "argument_index": index,
                                "parameter_index": index,
                                "parameter_name": positional[index].arg,
                                "parameter_type": functions_by_id[callee]["parameters"][index][
                                    "type"
                                ],
                                "kind": "identifier"
                                if isinstance(argument, ast.Name)
                                else "constant"
                                if isinstance(argument, ast.Constant)
                                else "expression",
                                "expression": expression_text,
                                **call_location(argument, path),
                                "source_sha256": hashlib.sha256(sources[path].encode()).hexdigest(),
                            }
                        )
                    else:
                        metadata["argument_transfers"] = transfers
            calls.append(
                {
                    "id": identity(
                        path,
                        node.lineno,
                        node.col_offset,
                        node.end_lineno,
                        node.end_col_offset,
                        owner.function["id"],
                    ),
                    "language": "python",
                    "caller": owner.function["id"],
                    "callee": callee,
                    "callee_name": name,
                    "path": path,
                    "line": node.lineno,
                    "column": node.col_offset + 1,
                    "kind": "call",
                    "dispatch": "direct" if status in {"resolved", "external"} else "dynamic",
                    "execution": "deferred" if deferred else "normal",
                    "status": status,
                    "reason": reason,
                    "provenance": "python_ast",
                    "metadata": metadata,
                }
            )
        parent, refs = owner, set()
        while parent:
            refs.update(parent.contexts)
            parent = parent.parent
        owner.function.setdefault("context_ids", []).extend(sorted(refs))
        owner.function["context_ids"] = sorted(set(owner.function["context_ids"]))
    return {"functions": functions, "calls": calls, "contexts": contexts, "units": units}


if __name__ == "__main__":
    print(json.dumps(ast_graph(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))))
