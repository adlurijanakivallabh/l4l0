"""Value-derivation sandbox (Build Order 2b — CAI's CodeAct, narrowly scoped).

Closes a real gap named in this session's reference-project audit: a target
needing a bespoke runtime-computed value (an HMAC/JWT-style signature, a
custom token derivation, an encoded field) that no pre-built payload/
resolver anticipated. CAI's CodeAct answers this with a general Python
interpreter (~1500 lines: an AST walker over the full statement grammar,
an import allowlist, ~40 node handlers) whose own shipped instance sets
``additional_authorized_imports=["*"]`` — silently defeating its own
sandbox.

This module deliberately does much less, because the actual need is much
smaller than "run arbitrary Python": compute ONE derived value from a
handful of inputs using a fixed set of pure computation functions. Two
structural choices make that safe by construction rather than by
allowlist-policing alone:

  * ``ast.parse(code, mode="eval")`` accepts only a single expression.
    Assignment, loops, ``def``, ``import``, conditionals — none of these can
    even PARSE in "eval" mode; they are SyntaxErrors before any node-walking
    logic runs at all. There is no loop or recursion construct in this
    grammar, so there is no way to express an infinite loop or unbounded
    blowup in the first place — no RLIMIT/timeout is needed the way a real
    subprocess needs one.
  * Calls are restricted to a **bare name** in a fixed function table
    (``sha256(x)``, never ``hashlib.sha256(x)``). Attribute access
    (``ast.Attribute``) is not implemented AT ALL — not allowlisted, not
    denylisted, simply absent from the walker — which eliminates the
    classic Python sandbox-escape route through dunder-attribute chains
    (``().__class__.__bases__[0].__subclasses__()`` and its relatives)
    structurally, not by pattern-matching against known escapes.

The function table itself never touches a socket, the filesystem, or a
subprocess — every entry is pure computation (hash/hmac/encode/decode/
string manipulation). ``derive_value``'s return is inert data: a plain
str/int/float/bool/list/dict/None, handed by the CALLER to the existing
``RequestFirer`` (still ``ScopeGuard``-gated) or into a candidate for
``run_oracle`` — this module itself never fires a request, never calls
``run_oracle``/``write_finding``, and cannot be dynamically widened at
runtime (the function table and allowed node types are both fixed at
import time, not configurable).
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac as _hmac
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime

_MAX_CODE_LENGTH = 2_000
_MAX_STRING_LENGTH = 100_000
_MAX_CALL_DEPTH = 10
_MAX_COLLECTION_ITEMS = 200


class SandboxError(ValueError):
    """The submitted code is outside the allowed expression grammar."""


def _as_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise SandboxError(f"expected str or bytes, got {type(value).__name__}")


def _sha256(data: object) -> str:
    return hashlib.sha256(_as_bytes(data)).hexdigest()


def _sha1(data: object) -> str:
    return hashlib.sha1(_as_bytes(data)).hexdigest()  # noqa: S324 — token derivation, not a security boundary


def _md5(data: object) -> str:
    return hashlib.md5(_as_bytes(data)).hexdigest()  # noqa: S324 — token derivation, not a security boundary


def _hmac_sha256(key: object, data: object) -> str:
    return _hmac.new(_as_bytes(key), _as_bytes(data), hashlib.sha256).hexdigest()


def _hmac_sha1(key: object, data: object) -> str:
    return _hmac.new(_as_bytes(key), _as_bytes(data), hashlib.sha1).hexdigest()


def _b64encode(data: object) -> str:
    return base64.b64encode(_as_bytes(data)).decode("ascii")


def _b64decode(data: object) -> str:
    return base64.b64decode(_as_bytes(data)).decode("utf-8", errors="replace")


def _urlsafe_b64encode(data: object) -> str:
    return base64.urlsafe_b64encode(_as_bytes(data)).decode("ascii").rstrip("=")


def _hex(data: object) -> str:
    return _as_bytes(data).hex()


def _json_dumps(obj: object) -> str:
    return json.dumps(obj, sort_keys=True)


def _json_loads(text: object) -> object:
    return json.loads(_as_bytes(text))


def _now_unix() -> str:
    return str(int(datetime.now(UTC).timestamp()))


def _regex_sub(pattern: object, repl: object, text: object) -> str:
    if not isinstance(pattern, str) or not isinstance(repl, str) or not isinstance(text, str):
        raise SandboxError("regex_sub requires three strings")
    return re.sub(pattern, repl, text)


def _concat(*parts: object) -> str:
    return "".join(str(p) for p in parts)


def _upper(text: object) -> str:
    if not isinstance(text, str):
        raise SandboxError("upper requires a string")
    return text.upper()


def _lower(text: object) -> str:
    if not isinstance(text, str):
        raise SandboxError("lower requires a string")
    return text.lower()


# Closed at import time — never mutated, never extended at runtime. This is
# the entire "what can this code do" surface; there is no import mechanism
# in the grammar to reach anything outside this table.
_FUNCTIONS: dict[str, Callable[..., object]] = {
    "sha256": _sha256,
    "sha1": _sha1,
    "md5": _md5,
    "hmac_sha256": _hmac_sha256,
    "hmac_sha1": _hmac_sha1,
    "b64encode": _b64encode,
    "b64decode": _b64decode,
    "urlsafe_b64encode": _urlsafe_b64encode,
    "hex": _hex,
    "json_dumps": _json_dumps,
    "json_loads": _json_loads,
    "now_unix": _now_unix,
    "regex_sub": _regex_sub,
    "concat": _concat,
    "upper": _upper,
    "lower": _lower,
}


def _check_str_len(value: object) -> None:
    if isinstance(value, str) and len(value) > _MAX_STRING_LENGTH:
        raise SandboxError("string literal exceeds the sandbox size limit")


def _eval_node(node: ast.AST, inputs: dict[str, object], depth: int) -> object:
    if depth > _MAX_CALL_DEPTH:
        raise SandboxError("expression nesting exceeds the sandbox depth limit")
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None or isinstance(value, (str, int, float, bool)):
            _check_str_len(value)
            return value
        raise SandboxError(f"unsupported constant type: {type(value).__name__}")
    if isinstance(node, ast.Name):
        if node.id in inputs:
            return inputs[node.id]
        raise SandboxError(f"unknown name {node.id!r} — not a provided input")
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            # No ast.Attribute support anywhere in this walker — a call
            # target that isn't a bare Name (e.g. `x.sha256()`) cannot be
            # evaluated at all, not just "isn't allowlisted".
            raise SandboxError("calls must target a bare function name")
        name = node.func.id
        if name not in _FUNCTIONS:
            raise SandboxError(f"function not in the sandbox table: {name!r}")
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                raise SandboxError("*args expansion is not allowed")
        for kw in node.keywords:
            if kw.arg is None:
                raise SandboxError("**kwargs expansion is not allowed")
        args = [_eval_node(a, inputs, depth + 1) for a in node.args]
        kwargs = {str(kw.arg): _eval_node(kw.value, inputs, depth + 1) for kw in node.keywords}
        try:
            return _FUNCTIONS[name](*args, **kwargs)
        except SandboxError:
            raise
        except Exception as exc:  # noqa: BLE001 — a function's own error surfaces as a sandbox error
            raise SandboxError(f"{name} failed: {type(exc).__name__}: {exc}") from exc
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_node(node.left, inputs, depth + 1)
        right = _eval_node(node.right, inputs, depth + 1)
        if isinstance(left, str) and isinstance(right, str):
            result = left + right
            _check_str_len(result)
            return result
        raise SandboxError("+ is only supported between two strings")
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > _MAX_COLLECTION_ITEMS:
            raise SandboxError("collection literal exceeds the sandbox size limit")
        return [_eval_node(e, inputs, depth + 1) for e in node.elts]
    if isinstance(node, ast.Dict):
        if len(node.keys) > _MAX_COLLECTION_ITEMS:
            raise SandboxError("collection literal exceeds the sandbox size limit")
        result: dict[object, object] = {}
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            if key_node is None:
                raise SandboxError("dict unpacking (**) is not allowed")
            key = _eval_node(key_node, inputs, depth + 1)
            result[key] = _eval_node(value_node, inputs, depth + 1)
        return result
    raise SandboxError(f"unsupported expression: {type(node).__name__}")


def derive_value(code: str, inputs: dict[str, object] | None = None) -> object:
    """Evaluate one bounded expression against the closed function table.

    ``code`` must be a single Python expression (``mode="eval"`` rejects
    anything else as a SyntaxError before any node is walked). ``inputs``
    are the only names the expression may reference — there is no global,
    builtin, or module namespace reachable from inside the sandbox.

    Raises :class:`SandboxError` on anything outside the allowed grammar —
    never silently substitutes a default; the caller decides what a
    rejected derivation means for its own flow.
    """
    if len(code) > _MAX_CODE_LENGTH:
        raise SandboxError("code exceeds the sandbox length limit")
    try:
        tree = ast.parse(code, mode="eval")
    except SyntaxError as exc:
        raise SandboxError(f"not a single valid expression: {exc}") from exc
    return _eval_node(tree.body, dict(inputs or {}), depth=0)
