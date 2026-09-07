"""JS AST data-flow analysis (Phase 43, DalFox-v3-style).

Replaces regex-only DOM taint analysis with a real ESTree walk (esprima):
parse each <script> block, track tainted identifiers through declarations
and assignments, and confirm sink calls/assignments that consume tainted
data.  Regex analysis cannot do this: it matches PATTERNS near sinks, which
misses cross-line variable chains and misfires on minified/renamed code.

Scope decisions (conservative on purpose):
  * Taint propagates through var/let/const declarations, plain assignments,
    and binary/concatenation expressions.
  * Function bodies are analyzed in the SAME taint scope (cheap and
    false-negative-averse; cross-function paths are marked medium
    confidence via a flag).
  * Object members (``cfg.x = source``) taint the whole object name.

Any parse failure (minified syntax variants esprima can't handle) returns
None so the caller falls back to the regex channel — never crash a scan.
"""
from __future__ import annotations

# Sources that are attacker-controllable without server round-trips.
_SOURCE_PATHS = {
    "location.hash": "location.hash",
    "location.search": "location.search",
    "location.href": "location.href",
    "document.referrer": "document.referrer",
    "document.cookie": "document.cookie",
    "window.name": "window.name",
    "localStorage.getItem": "localStorage.getItem",
    "sessionStorage.getItem": "sessionStorage.getItem",
}

# Sinks that execute markup/code when fed tainted data.
_SINK_PROPS = {
    "innerHTML", "outerHTML", "insertAdjacentHTML", "srcdoc",
    "document.write", "document.writeln", "eval", "setTimeout",
    "setInterval", "location.assign", "location.replace", "open",
}

try:
    import esprima  # type: ignore
    _AVAILABLE = True
except ImportError:  # pragma: no cover - env-dependent
    _AVAILABLE = False


def available() -> bool:
    """Whether the AST channel can run (esprima installed)."""
    return _AVAILABLE


def _member_name(node) -> str | None:
    """Resolve a MemberExpression chain to a dotted path string."""
    parts = []
    while node is not None and getattr(node, "type", None) == "MemberExpression":
        prop = node.property
        if getattr(prop, "type", None) == "Identifier":
            parts.append(prop.name)
        elif getattr(prop, "type", None) == "Literal":
            parts.append(str(prop.value))
        else:
            return None
        node = node.object
    if node is None or getattr(node, "type", None) != "Identifier":
        return None
    parts.append(node.name)
    parts.reverse()
    return ".".join(parts)


def _sources_in(node, tainted: set[str]) -> list[str]:
    """Collect attacker-controlled sources used inside an expression."""
    found: list[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n is None or not hasattr(n, "type"):
            continue
        t = n.type
        if t == "Identifier":
            if n.name in tainted:
                found.append(f"var:{n.name}")
        elif t == "MemberExpression":
            path = _member_name(n)
            if path in _SOURCE_PATHS:
                found.append(_SOURCE_PATHS[path])
            elif path and path.endswith(".data"):
                # postMessage event.data (any receiver named e/event/message).
                base = path.rsplit(".data", 1)[0]
                if base in ("e", "ev", "event", "msg", "message", "evt"):
                    found.append("postMessage event.data")
        elif t == "CallExpression":
            path = _member_name(n.callee)
            if path in _SOURCE_PATHS:
                found.append(_SOURCE_PATHS[path])
            stack.extend(n.arguments)
        else:
            # Recurse into common expression containers.
            for attr in ("left", "right", "argument", "test", "consequent",
                         "alternate", "init", "value", "callee"):
                child = getattr(n, attr, None)
                if child is not None and hasattr(child, "type"):
                    stack.append(child)
            for attr in ("elements", "expressions", "arguments"):
                children = getattr(n, attr, None)
                if children:
                    stack.extend(c for c in children if hasattr(c, "type"))
    return found


def _sink_name(node) -> str | None:
    """Name of the sink when ``node`` is a sink-bearing call/member."""
    if getattr(node, "type", None) == "CallExpression":
        return _member_name(node.callee) or (
            node.callee.name if getattr(node.callee, "type", None) == "Identifier"
            else None)
    if getattr(node, "type", None) == "MemberExpression":
        return _member_name(node)
    return None


def _is_sink_assignment(node) -> str | None:
    """AssignmentExpression whose left side is a dangerous DOM property."""
    if getattr(node, "type", None) != "AssignmentExpression":
        return None
    path = _member_name(node.left)
    if not path:
        return None
    leaf = path.rsplit(".", 1)[-1]
    if leaf in _SINK_PROPS:
        return path
    return None


def _is_sink_call(node) -> str | None:
    """CallExpression whose callee is a dangerous function/property."""
    if getattr(node, "type", None) != "CallExpression":
        return None
    name = _sink_name(node)
    if not name:
        return None
    if name in _SINK_PROPS:
        return name
    leaf = name.rsplit(".", 1)[-1]
    # jQuery .html()/.append() etc.
    if leaf in ("html", "append", "prepend", "before", "after", "replaceWith"):
        return name
    return None


def _all_functions(node) -> list:
    """Collect every function body anywhere in the AST (postMessage
    handlers, event callbacks, IIFEs...).  Their statements are walked
    with the SHARED taint scope so an event.data sink inside a callback
    is still caught."""
    fns = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n is None or not hasattr(n, "type"):
            continue
        if n.type in ("FunctionDeclaration", "FunctionExpression",
                      "ArrowFunctionExpression"):
            fns.append(n)
            # Keep descending INTO the body so nested functions (callback
            # inside callback) are collected too.  Double reporting is
            # impossible: _walk_body never recurses into function nodes.
            fb = getattr(n, "body", None)
            if fb is not None:
                stack.append(fb)
            continue
        # Generic descent: child attributes may be nodes OR node lists --
        # flatten lists element-by-element (Script.body, arguments, ...).
        for attr in ("body", "expression", "init", "test", "update", "left",
                     "right", "argument", "consequent", "alternate", "callee",
                     "object", "property", "id", "declarations", "elements",
                     "expressions", "arguments", "params", "block", "handler",
                     "finalizer"):
            child = getattr(n, attr, None)
            if child is None:
                continue
            if isinstance(child, list):
                stack.extend(child)
            else:
                stack.append(child)
    return fns


def _walk_expression_stmt(expr, tainted: set[str], findings: list,
                          code: str, cross_function: bool) -> None:
    """Apply taint/sink rules to a single expression (shared by
    ExpressionStatement bodies and arrow-function expression bodies)."""
    sink_path = _is_sink_assignment(expr)
    if sink_path:
        srcs = _sources_in(expr.right, tainted)
        if srcs:
            _report(findings, code, expr, sink_path, srcs, cross_function)
    sink_call = _is_sink_call(expr)
    if sink_call:
        srcs = []
        for arg in expr.arguments:
            srcs.extend(_sources_in(arg, tainted))
        if srcs:
            _report(findings, code, expr, sink_call, srcs, cross_function)
    # Plain assignment taint propagation: x = location.hash.
    if (getattr(expr, "type", None) == "AssignmentExpression"
            and not sink_path):
        name = (expr.left.name
                if getattr(expr.left, "type", None) == "Identifier"
                else None)
        srcs = _sources_in(expr.right, tainted)
        if name and srcs:
            tainted.add(name)


def _walk_body(body: list, tainted: set[str], findings: list,
               code: str, cross_function: bool) -> None:
    """Walk a statement list: propagate taint, confirm sink hits."""
    for stmt in body:
        t = getattr(stmt, "type", None)
        if t == "VariableDeclaration":
            for decl in stmt.declarations:
                name = getattr(decl.id, "name", None)
                srcs = _sources_in(decl.init, tainted)
                if name and srcs:
                    tainted.add(name)
        elif t == "ExpressionStatement":
            _walk_expression_stmt(stmt.expression, tainted, findings,
                                  code, cross_function)
        elif t in ("IfStatement", "ForStatement", "ForInStatement",
                   "ForOfStatement", "WhileStatement", "DoWhileStatement",
                   "TryStatement", "SwitchStatement", "BlockStatement"):
            # Recurse into structured blocks, keeping the shared taint scope.
            for attr in ("consequent", "alternate", "body", "block", "handler",
                         "finalizer"):
                sub = getattr(stmt, attr, None)
                if sub is None:
                    continue
                if getattr(sub, "type", None) == "BlockStatement":
                    _walk_body(sub.body, tainted, findings, code,
                               cross_function)
                elif isinstance(getattr(sub, "body", None), list):
                    _walk_body(sub.body, tainted, findings, code,
                               cross_function)
        # FunctionDeclaration bodies are handled by the top-level
        # _all_functions pass (shared taint scope) -- no recursion here.


def _report(findings: list, code: str, node, sink: str, srcs: list[str],
            cross_function: bool) -> None:
    # esprima-python fills range only when parsing with range=True; fall
    # back to 0 for line/snippet when position data is absent.
    rng = getattr(node, "range", None) or getattr(node, "start", None)
    if isinstance(rng, (list, tuple)) and rng:
        start = rng[0]
    elif isinstance(rng, int):
        start = rng
    else:
        start = 0
    line = code.count("\n", 0, start) + 1
    snippet = code[max(0, start - 40): start + 120].replace("\n", " ").strip()
    key = (line, sink, tuple(sorted(srcs)))
    if any((f["line"], f["sink"], tuple(sorted(f.get("_srcs", [])))) == key
           for f in findings):
        return
    findings.append({
        "type": "dom_sink",
        "line": line,
        "sink": sink,
        "source": srcs[0],
        "snippet": snippet[:160],
        "confidence": "high" if not cross_function else "medium",
        "detail": (f"[AST] sink '{sink}' fed by {', '.join(sorted(set(srcs)))}"
                   + (" (cross-function)" if cross_function else "")),
        "_srcs": srcs,
    })


def analyze_script(code: str) -> list[dict] | None:
    """AST data-flow analysis of one <script> body.

    Returns a list of finding dicts (same shape as dom.py), or None when
    parsing fails (caller should fall back to the regex channel).  Each
    finding carries a ``_srcs`` internal key for dedup; callers may strip it.
    """
    if not _AVAILABLE or not code or not code.strip():
        return None
    try:
        # range=True -> node.range populated for line/snippet reporting.
        ast = esprima.parseScript(code, options={"range": True},
                                  tolerant=True)
    except Exception:
        return None
    findings: list[dict] = []
    tainted: set[str] = set()
    try:
        _walk_body(ast.body, tainted, findings, code, False)
        # Every nested function body shares the taint scope: postMessage /
        # event handlers are the dominant real-world DOM-XSS shape.
        for fn in _all_functions(ast):
            fn_body = getattr(fn, "body", None)
            if fn_body is None:
                continue
            if getattr(fn_body, "type", None) == "BlockStatement":
                _walk_body(fn_body.body, tainted, findings, code, True)
            else:
                # Arrow-function expression body: body itself is the expr.
                _walk_expression_stmt(fn_body, tainted, findings, code, True)
    except Exception:
        # Partial results are still useful.
        return findings if findings else None
    return findings
