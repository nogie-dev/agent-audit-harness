"""Bounded modifier CFGs in Solidity metadata; call-graph dependencies stay unchanged."""

from collections import defaultdict, deque

MAX_FLOW_NODES = 384
MAX_TOTAL_FLOW_NODES = 8192
MAX_FLOW_DEPTH = 64
NODE_KINDS = {
    "entry",
    "exit",
    "revert",
    "branch",
    "statement",
    "placeholder",
    "body",
    "continuation",
    "modifier_enter",
    "modifier_exit",
    "return",
    "break",
    "continue",
    "opaque",
}
EDGE_KINDS = {
    "next",
    "true",
    "false",
    "invoke",
    "resume",
    "return",
    "revert",
    "break",
    "continue",
    "unknown",
}
NOTE = (
    "Modifier control only. Branches are symbolic, not proven feasible; bounds describe "
    "syntactic normal-exit paths. Expressions, callees and the function body are atomic; "
    "call IDs are syntax references, not evaluation-order or successful-return proofs."
)


def walk(node):
    if isinstance(node, dict):
        if node.get("nodeType", "").startswith("Yul"):
            return
        if "nodeType" in node:
            yield node
        for value in node.values():
            if isinstance(value, (dict, list)):
                yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def body_bounds(flow):
    unknown = {"min": None, "max": None, "unbounded": False, "normal_exit_reachable": None}
    if not flow["complete"]:
        return unknown
    nodes = {node["id"]: node for node in flow["nodes"]}
    outgoing, incoming = defaultdict(list), defaultdict(list)
    for edge in flow["edges"]:
        outgoing[edge["from"]].append(edge["to"])
        incoming[edge["to"]].append(edge["from"])
    relevant, pending = {flow["exit"]}, [flow["exit"]]
    while pending:
        for previous in incoming[pending.pop()]:
            if previous not in relevant:
                relevant.add(previous)
                pending.append(previous)
    if flow["entry"] not in relevant:
        return {**unknown, "normal_exit_reachable": False}
    weights = {key: int(node["kind"] in {"body", "continuation"}) for key, node in nodes.items()}
    minimum = {flow["entry"]: 0}
    queue = deque([flow["entry"]])
    while queue:
        source = queue.popleft()
        for target in outgoing[source]:
            distance = minimum[source] + weights[target]
            if target in relevant and distance < minimum.get(target, float("inf")):
                minimum[target] = distance
                queue.append(target)
    maximum = {flow["entry"]: 0}
    # A positive-weight cycle on a path to exit gives an unbounded structural count.
    for _ in range(len(relevant)):
        changed = False
        for edge in flow["edges"]:
            source, target = edge["from"], edge["to"]
            if source in maximum and target in relevant:
                distance = maximum[source] + weights[target]
                if distance > maximum.get(target, -1):
                    maximum[target] = distance
                    changed = True
        if not changed:
            break
    return {
        "min": minimum[flow["exit"]],
        "max": None if changed else maximum[flow["exit"]],
        "unbounded": changed,
        "normal_exit_reachable": True,
    }


class FlowLimit(Exception):
    pass


class ModifierFlow:
    def __init__(self, ast_id, functions, declarations, calls, location, text, budget):
        self.ast_id, self.functions, self.declarations = ast_id, functions, declarations
        self.location, self.text, self.budget = location, text, budget
        self.calls = {call["metadata"]["ast_id"]: call for call in calls}
        self.nodes, self.edges, self.gaps = [], [], []
        self.applications = [
            self.calls[item["id"]] for item in declarations[ast_id].get("modifiers", [])
        ]
        self.exit = self.add("exit", declarations[ast_id], ast_id)
        self.revert = self.add("revert", declarations[ast_id], ast_id)

    def add(self, kind, node, owner, **extra):
        if len(self.nodes) >= self.budget:
            raise FlowLimit("modifier_flow_node_budget")
        node_id = f"n{len(self.nodes)}"
        structural = kind in {"entry", "exit", "revert", "modifier_exit", "continuation"}
        snippet = (self.functions[owner]["name"] if structural else self.text(node)).encode()
        self.nodes.append(
            {
                "id": node_id,
                "kind": kind,
                "function_id": self.functions[owner]["id"],
                **self.location(node),
                "ast_id": node["id"],
                "snippet": snippet[:512].decode(errors="ignore"),
                "snippet_truncated": len(snippet) > 512,
                "call_ids": []
                if structural
                else sorted(
                    {self.calls[n["id"]]["id"] for n in walk(node) if n["id"] in self.calls}
                ),
                **extra,
            }
        )
        return node_id

    def edge(self, source, target, kind="next"):
        self.edges.append({"from": source, "to": target, "kind": kind})

    def gap(self, node_id, reason):
        self.gaps.append({"node": node_id, "reason": reason})

    def expression(self, kind, node, owner):
        result = self.add(kind, node, owner)
        if any(
            n["nodeType"] == "Conditional"
            or (n["nodeType"] == "BinaryOperation" and n.get("operator") in {"&&", "||"})
            for n in walk(node)
        ):
            self.gap(result, "expression_control_flow_not_expanded")
        return result

    def branch(self, node, owner, yes, no):
        branch = self.expression("branch", node, owner)
        literal = node.get("value") if node.get("kind") == "bool" else None
        if literal != "false":
            self.edge(branch, yes, "true")
        if literal != "true":
            self.edge(branch, no, "false")
        return branch

    def wrap(self, index, resume, depth):
        if depth > MAX_FLOW_DEPTH:
            raise FlowLimit("modifier_flow_depth_budget")
        declaration = self.declarations[self.ast_id]
        if index == len(self.applications):
            # shortcut: bodies are atomic; expand when whole-function execution proofs are needed.
            body = self.add("body", declaration["body"], self.ast_id)
            self.edge(body, resume, "resume")
            return body
        call = self.applications[index]
        invocation = self.declarations[call["metadata"]["ast_id"]]
        target_id = invocation["modifierName"].get("referencedDeclaration")
        target = self.declarations.get(target_id, {})
        enter = self.add(
            "modifier_enter",
            invocation,
            self.ast_id,
            application_id=call["id"],
            modifier_index=index,
        )
        if call["status"] != "resolved" or target.get("nodeType") != "ModifierDefinition":
            opaque = self.add("opaque", invocation, self.ast_id)
            self.gap(opaque, call["reason"] or "unknown_modifier")
            self.edge(enter, opaque)
            self.edge(opaque, resume, "unknown")
            self.edge(opaque, self.wrap(index + 1, resume, depth + 1), "unknown")
            return enter
        leave = self.add("modifier_exit", target, target_id, application_id=call["id"])
        self.edge(leave, resume, "resume")
        entry = self.statement(
            target["body"],
            leave,
            target_id,
            leave,
            lambda after: self.wrap(index + 1, after, depth + 1),
            depth + 1,
        )
        self.edge(enter, entry)
        # Modifier arguments are evaluated on entry, once per invocation of this wrapper.
        if any(
            n["nodeType"] == "Conditional"
            or (n["nodeType"] == "BinaryOperation" and n.get("operator") in {"&&", "||"})
            for argument in invocation.get("arguments", [])
            for n in walk(argument)
        ):
            self.gap(enter, "expression_control_flow_not_expanded")
        return enter

    def statement(self, node, after, owner, leave, continuation, depth, loop=None):
        if depth > MAX_FLOW_DEPTH:
            raise FlowLimit("modifier_flow_depth_budget")
        typ = node["nodeType"]
        if typ in {"Block", "UncheckedBlock"}:
            for child in reversed(node["statements"]):
                after = self.statement(child, after, owner, leave, continuation, depth + 1, loop)
            return after
        if typ == "PlaceholderStatement":
            placeholder = self.add("placeholder", node, owner)
            self.edge(placeholder, continuation(after), "invoke")
            return placeholder
        if typ == "IfStatement":
            yes = self.statement(
                node["trueBody"], after, owner, leave, continuation, depth + 1, loop
            )
            no = (
                self.statement(
                    node["falseBody"], after, owner, leave, continuation, depth + 1, loop
                )
                if node.get("falseBody")
                else after
            )
            return self.branch(node["condition"], owner, yes, no)
        if typ in {"ForStatement", "WhileStatement", "DoWhileStatement"}:
            condition = node.get("condition")
            branch = self.expression("branch", condition or node, owner)
            increment = node.get("loopExpression")
            repeat = (
                self.statement(increment, branch, owner, leave, continuation, depth + 1, loop)
                if increment
                else branch
            )
            body = self.statement(
                node["body"], repeat, owner, leave, continuation, depth + 1, (after, repeat)
            )
            literal = (
                condition.get("value")
                if condition and condition.get("kind") == "bool"
                else "true"
                if condition is None
                else None
            )
            if literal != "false":
                self.edge(branch, body, "true")
            if literal != "true":
                self.edge(branch, after, "false")
            entry = body if typ == "DoWhileStatement" else branch
            initial = node.get("initializationExpression")
            return (
                self.statement(initial, entry, owner, leave, continuation, depth + 1, loop)
                if initial
                else entry
            )
        if typ in {"Break", "Continue"}:
            current = self.add(typ.lower(), node, owner)
            if loop is None:
                raise ValueError("Solidity loop control outside loop")
            self.edge(current, loop[0 if typ == "Break" else 1], typ.lower())
            return current
        if typ == "Return":
            current = self.expression("return", node, owner)
            self.edge(current, leave, "return")
            return current
        if typ == "RevertStatement":
            current = self.expression("statement", node, owner)
            self.edge(current, self.revert, "revert")
            return current
        exp = node.get("expression", {})
        type_id = exp.get("expression", {}).get("typeDescriptions", {}).get("typeIdentifier", "")
        if typ == "ExpressionStatement" and type_id.startswith(
            ("t_function_require_", "t_function_assert_")
        ):
            branch = self.branch(exp["arguments"][0], owner, after, self.revert)
            self.nodes[-1]["guard"] = (
                "require" if type_id.startswith("t_function_require_") else "assert"
            )
            self.nodes[-1]["call_ids"] = sorted(
                {self.calls[n["id"]]["id"] for n in walk(node) if n["id"] in self.calls}
            )
            return branch
        current = self.expression("statement", node, owner)
        if typ == "ExpressionStatement" and type_id.startswith("t_function_revert_"):
            self.edge(current, self.revert, "revert")
        elif typ in {"ExpressionStatement", "VariableDeclarationStatement", "EmitStatement"}:
            self.edge(current, after)
        else:
            self.nodes[-1]["kind"] = "opaque"
            self.gap(current, "unsupported_modifier_statement:" + typ)
            self.edge(current, after, "unknown")
        return current

    def build(self):
        declaration = self.declarations[self.ast_id]
        start = self.add("entry", declaration, self.ast_id)
        if declaration["nodeType"] == "ModifierDefinition":

            def continuation(after):
                body = self.add("continuation", declaration, self.ast_id)
                self.edge(body, after, "resume")
                return body

            if declaration.get("body"):
                first = self.statement(
                    declaration["body"], self.exit, self.ast_id, self.exit, continuation, 0
                )
            else:
                first = self.add("opaque", declaration, self.ast_id)
                self.gap(first, "modifier_without_implementation")
                self.edge(first, self.exit, "unknown")
        else:
            first = self.wrap(0, self.exit, 0)
        self.edge(start, first)
        return self.result(start)

    def result(self, start):
        outgoing = defaultdict(list)
        for edge in self.edges:
            outgoing[edge["from"]].append(edge["to"])
        live, pending = {start}, [start]
        while pending:
            for target in outgoing[pending.pop()]:
                if target not in live:
                    live.add(target)
                    pending.append(target)
        # Keep terminal nodes even when no path reaches them, but discard dead statements.
        kept = live | {self.exit, self.revert}
        gaps = [gap for gap in self.gaps if gap["node"] in live]
        flow = {
            "version": 1,
            "scope": "modifier_control",
            "provenance": "solc_ast",
            "entry": start,
            "exit": self.exit,
            "revert": self.revert,
            "nodes": [node for node in self.nodes if node["id"] in kept],
            "edges": [edge for edge in self.edges if edge["from"] in live],
            "applications": [call["id"] for call in self.applications],
            "complete": not gaps,
            "gaps": gaps,
            "note": NOTE,
            "execution_unit": "continuation"
            if self.functions[self.ast_id]["kind"] == "modifier"
            else "function_body",
        }
        flow["body_execution"] = body_bounds(flow)
        return flow


def add_modifier_flows(functions, declarations, calls, location, text):
    total = 0
    for ast_id, function in sorted(functions.items()):
        if function["kind"] != "modifier" and not declarations[ast_id].get("modifiers"):
            continue
        budget = max(4, min(MAX_FLOW_NODES, MAX_TOTAL_FLOW_NODES - total))
        builder = ModifierFlow(ast_id, functions, declarations, calls, location, text, budget)
        try:
            if total >= MAX_TOTAL_FLOW_NODES:
                raise FlowLimit("modifier_flow_total_budget")
            flow = builder.build()
        except FlowLimit as error:
            builder.nodes, builder.edges, builder.gaps = builder.nodes[:2], [], []
            builder.budget = 4
            start = builder.add("entry", declarations[ast_id], ast_id)
            opaque = builder.add("opaque", declarations[ast_id], ast_id)
            builder.gap(opaque, str(error))
            builder.edge(start, opaque)
            builder.edge(opaque, builder.exit, "unknown")
            flow = builder.result(start)
        function["metadata"]["modifier_flow"] = flow
        total += len(flow["nodes"])


def validate_modifier_flows(graph):
    """Validate the optional extension without changing the common v2 schema."""
    functions = {node["id"]: node for node in graph["functions"]}
    calls = {call["id"]: call for call in graph["calls"]}
    required = {
        "version",
        "scope",
        "provenance",
        "entry",
        "exit",
        "revert",
        "nodes",
        "edges",
        "applications",
        "complete",
        "gaps",
        "note",
        "execution_unit",
        "body_execution",
    }
    node_fields = {
        "id",
        "kind",
        "function_id",
        "path",
        "line",
        "end_line",
        "column",
        "end_column",
        "ast_id",
        "snippet",
        "snippet_truncated",
        "call_ids",
    }
    try:
        for function in functions.values():
            flow = function.get("metadata", {}).get("modifier_flow")
            if flow is None:
                continue
            if (
                graph["language"] != "solidity"
                or not isinstance(flow, dict)
                or set(flow) != required
                or type(flow["version"]) is not int
                or flow["version"] != 1
                or flow["scope"] != "modifier_control"
                or flow["provenance"] != "solc_ast"
                or type(flow["complete"]) is not bool
                or flow["note"] != NOTE
                or flow["execution_unit"]
                != ("continuation" if function["kind"] == "modifier" else "function_body")
                or not isinstance(flow["nodes"], list)
                or not 3 <= len(flow["nodes"]) <= MAX_FLOW_NODES
                or not isinstance(flow["edges"], list)
                or len(flow["edges"]) > 3 * MAX_FLOW_NODES
                or not isinstance(flow["gaps"], list)
                or not isinstance(flow["applications"], list)
            ):
                raise ValueError("invalid modifier flow shape")
            nodes = {node["id"]: node for node in flow["nodes"]}
            if len(nodes) != len(flow["nodes"]):
                raise ValueError("duplicate modifier flow node")
            for key in ("entry", "exit", "revert"):
                if nodes[flow[key]]["kind"] != key:
                    raise ValueError("invalid modifier flow terminal")
            expected = sorted(
                (
                    call
                    for call in calls.values()
                    if call["caller"] == function["id"]
                    and call.get("metadata", {}).get("modifier_index") is not None
                ),
                key=lambda call: call["metadata"]["modifier_index"],
            )
            if flow["applications"] != [call["id"] for call in expected]:
                raise ValueError("modifier flow application order differs from calls")
            for node in nodes.values():
                if (
                    not node_fields <= set(node)
                    or set(node) - node_fields - {"guard", "application_id", "modifier_index"}
                    or not isinstance(node["id"], str)
                    or not node["id"].startswith("n")
                    or not node["id"][1:].isdigit()
                    or node["kind"] not in NODE_KINDS
                    or type(node["ast_id"]) is not int
                    or not isinstance(node["snippet"], str)
                    or len(node["snippet"].encode()) > 512
                    or type(node["snippet_truncated"]) is not bool
                    or not isinstance(node["call_ids"], list)
                    or len(set(node["call_ids"])) != len(node["call_ids"])
                    or any(
                        type(node[key]) is not int or node[key] < 1
                        for key in ("line", "end_line", "column", "end_column")
                    )
                ):
                    raise ValueError("invalid modifier flow node fields")
                owner = functions[node["function_id"]]
                if (
                    node["path"] != owner["path"]
                    or not owner["line"] <= node["line"] <= node["end_line"] <= owner["end_line"]
                    or (node["line"] == owner["line"] and node["column"] < owner["column"])
                    or (
                        node["end_line"] == owner["end_line"]
                        and node["end_column"] > owner["end_column"]
                    )
                    or (node["line"] == node["end_line"] and node["column"] > node["end_column"])
                    or any(calls[ref]["caller"] != owner["id"] for ref in node["call_ids"])
                ):
                    raise ValueError("invalid modifier flow source or call reference")
                if "guard" in node and (
                    node["kind"] != "branch" or node["guard"] not in {"require", "assert"}
                ):
                    raise ValueError("invalid modifier flow guard")
                if "application_id" in node:
                    if node["application_id"] not in flow["applications"]:
                        raise ValueError("unknown modifier flow application")
                    call = calls[node["application_id"]]
                    if "modifier_index" in node and (
                        type(node["modifier_index"]) is not int
                        or node["modifier_index"] != call["metadata"]["modifier_index"]
                    ):
                        raise ValueError("invalid modifier flow index")
            for edge in flow["edges"]:
                if (
                    set(edge) != {"from", "to", "kind"}
                    or edge["from"] not in nodes
                    or edge["to"] not in nodes
                    or edge["kind"] not in EDGE_KINDS
                    or edge["from"] in {flow["exit"], flow["revert"]}
                ):
                    raise ValueError("invalid modifier flow edge")
            for gap in flow["gaps"]:
                if (
                    set(gap) != {"node", "reason"}
                    or gap["node"] not in nodes
                    or not isinstance(gap["reason"], str)
                    or not gap["reason"]
                ):
                    raise ValueError("invalid modifier flow gap")
            if flow["complete"] != (not flow["gaps"]) or any(
                node["kind"] == "opaque"
                and not any(gap["node"] == node["id"] for gap in flow["gaps"])
                for node in nodes.values()
            ):
                raise ValueError("modifier flow coverage mismatch")
            bounds = flow["body_execution"]
            if (
                not isinstance(bounds, dict)
                or bounds != body_bounds(flow)
                or any(
                    value is not None and type(value) is not int
                    for key, value in bounds.items()
                    if key in {"min", "max"}
                )
                or type(bounds["unbounded"]) is not bool
                or (
                    bounds["normal_exit_reachable"] is not None
                    and type(bounds["normal_exit_reachable"]) is not bool
                )
            ):
                raise ValueError("modifier flow body bounds mismatch")
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise ValueError(f"invalid Solidity modifier flow: {error}") from error
