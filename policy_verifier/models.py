"""Data model: statements, policies, calls, verification reports, JSON I/O."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Characters allowed in concrete action/resource names.
NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/_.-"
)
# Pattern characters: name characters plus the two wildcards.
PATTERN_CHARS = NAME_CHARS | frozenset("*?")

MAX_STATEMENTS_PER_POLICY = 24
MAX_PATTERNS_PER_POLICY = 64
MAX_PATTERN_LENGTH = 64
MAX_CALLS = 10000


@dataclass(frozen=True)
class Statement:
    effect: str  # "Allow" or "Deny"
    actions: Tuple[str, ...]
    resources: Tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    statements: Tuple[Statement, ...] = ()


@dataclass(frozen=True)
class Call:
    action: str
    resource: str


@dataclass
class VerificationReport:
    """Result of verifying a candidate policy against an original policy."""

    preserves_calls: bool = True
    no_new_permissions: bool = True
    lost_calls: List[Call] = field(default_factory=list)
    # (action, resource) allowed by candidate but denied by original, if any.
    new_permission_example: Optional[Tuple[str, str]] = None

    @property
    def adoptable(self) -> bool:
        return self.preserves_calls and self.no_new_permissions


def _validate_pattern(pattern: str, where: str) -> None:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"{where}: pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError(
            f"{where}: pattern longer than {MAX_PATTERN_LENGTH} characters"
        )
    bad = set(pattern) - PATTERN_CHARS
    if bad:
        raise ValueError(f"{where}: illegal characters {sorted(bad)!r}")


def _validate_name(name: str, where: str) -> None:
    if not isinstance(name, str) or not name:
        raise ValueError(f"{where}: name must be a non-empty string")
    bad = set(name) - NAME_CHARS
    if bad:
        raise ValueError(f"{where}: illegal characters {sorted(bad)!r}")


def validate_policy(policy: Policy) -> None:
    if len(policy.statements) > MAX_STATEMENTS_PER_POLICY:
        raise ValueError(
            f"policy has more than {MAX_STATEMENTS_PER_POLICY} statements"
        )
    total_patterns = 0
    for i, stmt in enumerate(policy.statements):
        where = f"statement[{i}]"
        if stmt.effect not in ("Allow", "Deny"):
            raise ValueError(f"{where}: effect must be 'Allow' or 'Deny'")
        if not stmt.actions:
            raise ValueError(f"{where}: actions list must be non-empty")
        if not stmt.resources:
            raise ValueError(f"{where}: resources list must be non-empty")
        for pattern in stmt.actions:
            _validate_pattern(pattern, where + ".actions")
        for pattern in stmt.resources:
            _validate_pattern(pattern, where + ".resources")
        total_patterns += len(stmt.actions) + len(stmt.resources)
    if total_patterns > MAX_PATTERNS_PER_POLICY:
        raise ValueError(
            f"policy has more than {MAX_PATTERNS_PER_POLICY} patterns"
        )


def validate_calls(calls: List[Call]) -> None:
    if len(calls) > MAX_CALLS:
        raise ValueError(f"more than {MAX_CALLS} calls")
    for i, call in enumerate(calls):
        _validate_name(call.action, f"call[{i}].action")
        _validate_name(call.resource, f"call[{i}].resource")


def _parse_statement(raw: object, where: str) -> Statement:
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: statement must be an object")
    effect = raw.get("effect")
    actions = raw.get("actions")
    resources = raw.get("resources")
    if not isinstance(actions, list) or not all(
        isinstance(a, str) for a in actions
    ):
        raise ValueError(f"{where}: 'actions' must be a list of strings")
    if not isinstance(resources, list) or not all(
        isinstance(r, str) for r in resources
    ):
        raise ValueError(f"{where}: 'resources' must be a list of strings")
    return Statement(
        effect=effect, actions=tuple(actions), resources=tuple(resources)
    )


def policy_from_json(data: object) -> Policy:
    if isinstance(data, dict):
        data = data.get("statements")
    if not isinstance(data, list):
        raise ValueError("policy JSON must be a list of statements")
    policy = Policy(
        statements=tuple(
            _parse_statement(raw, f"statement[{i}]")
            for i, raw in enumerate(data)
        )
    )
    validate_policy(policy)
    return policy


def calls_from_json(data: object) -> List[Call]:
    if isinstance(data, dict):
        data = data.get("calls")
    if not isinstance(data, list):
        raise ValueError("calls JSON must be a list of calls")
    calls = []
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            raise ValueError(f"call[{i}]: must be an object")
        action = raw.get("action")
        resource = raw.get("resource")
        calls.append(Call(action=action, resource=resource))
    validate_calls(calls)
    return calls


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as handle:
        return policy_from_json(json.load(handle))


def load_calls(path: str) -> List[Call]:
    with open(path, "r", encoding="utf-8") as handle:
        return calls_from_json(json.load(handle))
