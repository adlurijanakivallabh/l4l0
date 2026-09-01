"""Value-derivation sandbox — hermetic + adversarial tests (Build Order 2b).

Safety-critical module: covers both the happy path (the actual use case —
deriving a bespoke signature/token) and real Python sandbox-escape patterns,
confirming each is structurally rejected, not merely denylisted.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from reachagent.sandbox.derive_value import SandboxError, derive_value

# === Happy path: the actual use case ==========================================


def test_sha256_of_a_literal() -> None:
    assert derive_value('sha256("hello")') == hashlib.sha256(b"hello").hexdigest()


def test_hmac_sha256_matches_stdlib() -> None:
    result = derive_value("hmac_sha256(key, data)", {"key": "secret", "data": "payload"})
    expected = hmac.new(b"secret", b"payload", hashlib.sha256).hexdigest()
    assert result == expected


def test_nested_calls_compose_without_variable_assignment() -> None:
    # hmac-sign the hash of the body concatenated with a timestamp — exactly
    # the "bespoke runtime-computed signature" use case, expressed as one
    # nested expression instead of needing multi-statement assignment.
    result = derive_value(
        "hmac_sha256(key, sha256(body) + timestamp)",
        {"key": "k", "body": "b", "timestamp": "123"},
    )
    inner = hashlib.sha256(b"b").hexdigest()
    expected = hmac.new(b"k", (inner + "123").encode(), hashlib.sha256).hexdigest()
    assert result == expected


def test_b64_round_trip() -> None:
    encoded = derive_value('b64encode("hello world")')
    assert derive_value("b64decode(x)", {"x": encoded}) == "hello world"


def test_concat_multiple_parts() -> None:
    assert derive_value('concat(a, "-", b)', {"a": "x", "b": "y"}) == "x-y"


def test_dict_and_list_literals() -> None:
    assert derive_value('{"a": 1, "b": [1, 2, 3]}') == {"a": 1, "b": [1, 2, 3]}


def test_json_dumps_and_loads_round_trip() -> None:
    dumped = derive_value('json_dumps({"a": 1})')
    assert derive_value("json_loads(x)", {"x": dumped}) == {"a": 1}


def test_inputs_are_the_only_reachable_names() -> None:
    assert derive_value("x", {"x": "value"}) == "value"


# === Structural rejections — statements can't even parse =====================


@pytest.mark.parametrize(
    "code",
    [
        "x = 1",
        "import os",
        "from os import system",
        "def f(): pass",
        "for i in range(10): pass",
        "while True: pass",
        "if True: pass",
        "x = 1; y = 2",
        "class Foo: pass",
        "lambda: 1",
    ],
)
def test_statements_are_rejected_as_syntax_errors(code: str) -> None:
    with pytest.raises(SandboxError):
        derive_value(code)


# === Classic Python sandbox-escape patterns — must be structurally unreachable
#
# Every string below is inert test DATA fed to derive_value() to assert it
# gets rejected — none of it is ever executed as real code by this test file.
# derive_value() parses with ast.parse(mode="eval") and walks a closed node
# set with no ast.Attribute/exec/eval/os support at all, so a string like
# "os.system('id')" or "eval('1')" can only ever raise SandboxError here.


@pytest.mark.parametrize(
    "code",
    [
        '"".__class__',
        "().__class__.__bases__",
        "[].__class__.__bases__[0].__subclasses__()",
        '"".__class__.__mro__[1].__subclasses__()',
        "hashlib.sha256",  # attribute access on any name, allowlisted or not
        "os.system('id')",  # data only — the sandbox has no os/system access to reach
        "__import__('os')",
        "__builtins__",
        "globals()",
        "locals()",
        "open('/etc/passwd')",
        "eval('1')",  # data only — the sandbox never calls eval()/exec() itself
        "exec('1')",
        "compile('1', '<s>', 'eval')",
        "(1).__add__(2)",
    ],
)
def test_classic_sandbox_escapes_are_rejected(code: str) -> None:
    with pytest.raises(SandboxError):
        derive_value(code)


def test_unknown_function_name_is_rejected() -> None:
    with pytest.raises(SandboxError):
        derive_value("not_a_real_function(1)")


def test_unknown_variable_name_is_rejected() -> None:
    with pytest.raises(SandboxError):
        derive_value("undeclared_name")


def test_star_args_expansion_is_rejected() -> None:
    with pytest.raises(SandboxError):
        derive_value("concat(*parts)", {"parts": ["a", "b"]})


def test_double_star_kwargs_expansion_is_rejected() -> None:
    with pytest.raises(SandboxError):
        derive_value("hmac_sha256(**kwargs)", {"kwargs": {"key": "a", "data": "b"}})


def test_dict_unpacking_is_rejected() -> None:
    with pytest.raises(SandboxError):
        derive_value("{**other}", {"other": {"a": 1}})


def test_starred_list_element_is_rejected() -> None:
    with pytest.raises(SandboxError):
        derive_value("[*items]", {"items": [1, 2]})


def test_arithmetic_beyond_string_concat_is_rejected() -> None:
    with pytest.raises(SandboxError):
        derive_value("1 + 2")


def test_subscript_is_rejected() -> None:
    with pytest.raises(SandboxError):
        derive_value("x[0]", {"x": [1, 2, 3]})


# === Bounds ====================================================================


def test_code_length_limit_enforced() -> None:
    with pytest.raises(SandboxError):
        derive_value("concat(" + '"a",' * 5000 + '"z")')


def test_string_literal_length_limit_enforced() -> None:
    with pytest.raises(SandboxError):
        derive_value('"' + "a" * 200_000 + '"')


def test_call_depth_limit_enforced() -> None:
    # sha256(sha256(sha256(...("x")...))) nested past the depth cap.
    code = "x"
    for _ in range(30):
        code = f"sha256({code})"
    with pytest.raises(SandboxError):
        derive_value(code, {"x": "seed"})


def test_reasonable_nesting_within_depth_limit_succeeds() -> None:
    code = "x"
    for _ in range(3):
        code = f"sha256({code})"
    assert derive_value(code, {"x": "seed"}) is not None


def test_collection_size_limit_enforced() -> None:
    with pytest.raises(SandboxError):
        derive_value("[" + ",".join("1" for _ in range(500)) + "]")


# === Function table is closed and never mutated at runtime ===================


def test_function_table_cannot_be_widened_at_runtime() -> None:
    from reachagent.sandbox import derive_value as module

    original = dict(module._FUNCTIONS)
    with pytest.raises(SandboxError):
        derive_value("evil_new_function(1)")
    # Confirm the module never mutated its own table as a side effect of the
    # rejected call above (there is no code path that would, but this is the
    # regression guard against ever adding one).
    assert module._FUNCTIONS == original
