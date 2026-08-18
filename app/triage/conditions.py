"""Condition DSL evaluator (§6.2). Rule conditions are data, never eval()'d as code."""
import ipaddress
import re

_UNSAFE_REGEX_RE = re.compile(r"\([^)]*[+*][^)]*\)[+*]")
_REGEX_CACHE = {}
_MAX_PATTERN_LENGTH = 500


class ConditionError(ValueError):
    pass


def _compile_regex(pattern):
    if pattern in _REGEX_CACHE:
        return _REGEX_CACHE[pattern]
    if len(pattern) > _MAX_PATTERN_LENGTH:
        raise ConditionError("regex pattern too long")
    if _UNSAFE_REGEX_RE.search(pattern):
        raise ConditionError("regex pattern rejected: possible catastrophic backtracking")
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ConditionError(f"invalid regex: {exc}") from exc
    _REGEX_CACHE[pattern] = compiled
    return compiled


def _in_cidr(value, cidr_list):
    if not value:
        return False
    if isinstance(cidr_list, str):
        cidr_list = [cidr_list]
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    for cidr in cidr_list:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _op_eq(v, target):
    return v == target


def _op_neq(v, target):
    return v != target


def _op_gt(v, target):
    return v is not None and v > target


def _op_gte(v, target):
    return v is not None and v >= target


def _op_lt(v, target):
    return v is not None and v < target


def _op_lte(v, target):
    return v is not None and v <= target


def _op_in(v, target):
    return v in target


def _op_not_in(v, target):
    return v not in target


def _op_contains(v, target):
    return v is not None and target in v


def _op_not_contains(v, target):
    return v is None or target not in v


def _op_startswith(v, target):
    return isinstance(v, str) and v.startswith(target)


def _op_endswith(v, target):
    return isinstance(v, str) and v.endswith(target)


def _op_regex(v, target):
    return isinstance(v, str) and _compile_regex(target).search(v) is not None


def _op_in_cidr(v, target):
    return _in_cidr(v, target)


def _op_not_in_cidr(v, target):
    return not _in_cidr(v, target)


def _op_exists(v, target):
    return (v is not None) == bool(target)


def _op_is_null(v, target):
    return (v is None) == bool(target)


OPERATORS = {
    "eq": _op_eq,
    "neq": _op_neq,
    "gt": _op_gt,
    "gte": _op_gte,
    "lt": _op_lt,
    "lte": _op_lte,
    "in": _op_in,
    "not_in": _op_not_in,
    "contains": _op_contains,
    "not_contains": _op_not_contains,
    "startswith": _op_startswith,
    "endswith": _op_endswith,
    "regex": _op_regex,
    "in_cidr": _op_in_cidr,
    "not_in_cidr": _op_not_in_cidr,
    "exists": _op_exists,
    "is_null": _op_is_null,
}


def evaluate(node, event):
    """Evaluate a condition (sub)tree against `event` (a dict). Ignores a top-level 'correlation' key."""
    if node is None:
        return True
    if "all" in node:
        return all(evaluate(child, event) for child in node["all"])
    if "any" in node:
        return any(evaluate(child, event) for child in node["any"])
    if "none" in node:
        return not any(evaluate(child, event) for child in node["none"])
    if "field" in node:
        op = node.get("op")
        func = OPERATORS.get(op)
        if func is None:
            raise ConditionError(f"unknown operator: {op}")
        value = event.get(node["field"])
        return bool(func(value, node.get("value")))
    raise ConditionError(f"unrecognised condition node: {node!r}")


def evaluate_base_condition(condition, event):
    """Evaluate everything in a rule's condition except the 'correlation' key."""
    if not condition:
        return True
    base = {k: v for k, v in condition.items() if k != "correlation"}
    if not base:
        return True
    return evaluate(base, event)
