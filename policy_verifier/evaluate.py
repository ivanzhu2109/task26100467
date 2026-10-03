"""逐语句授权计算。

一个调用只有在至少一条 Allow 匹配且没有任何 Deny 匹配时才被允许；
没有匹配的 Allow 时默认拒绝。
"""
from __future__ import annotations

from .matching import is_valid_name, match_pattern
from .model import Effect, Policy, Statement


def statement_matches(stmt: Statement, action: str, resource: str) -> bool:
    return any(match_pattern(p, action) for p in stmt.actions) and any(
        match_pattern(p, resource) for p in stmt.resources
    )


def authorize(policy: Policy, action: str, resource: str) -> bool:
    if not is_valid_name(action) or not is_valid_name(resource):
        raise ValueError("动作名与资源名须为非空合法名称")
    allowed = False
    for stmt in policy.statements:
        if statement_matches(stmt, action, resource):
            if stmt.effect is Effect.DENY:
                return False
            allowed = True
    return allowed
