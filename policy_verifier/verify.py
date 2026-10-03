"""候选策略核验。

两项独立结论：
1. 已用权限保留：候选策略仍允许观察期内的全部成功调用。
2. 未扩大权限：候选策略允许的每个动作/资源组合都被原策略允许。
   该判定在整个名称域上精确进行——用等价类自动机把名称域划分为
   有限类，逐格比较两份策略的授权结果，发现扩大即给出具体反例。
"""
from __future__ import annotations

from .automata import compute_classes
from .evaluate import authorize
from .model import Call, Effect, Policy, VerificationResult


def _find_lost_call(candidate: Policy, observed_calls: list[Call]) -> Call | None:
    for call in observed_calls:
        if not authorize(candidate, call.action, call.resource):
            return call
    return None


def _policy_vectors(policy: Policy, action_index: dict[str, int],
                    resource_index: dict[str, int]):
    """把每份策略编译为 (效果, 动作位掩码, 资源位掩码) 列表。"""
    out = []
    for stmt in policy.statements:
        amask = 0
        for p in stmt.actions:
            amask |= 1 << action_index[p]
        rmask = 0
        for p in stmt.resources:
            rmask |= 1 << resource_index[p]
        out.append((stmt.effect, amask, rmask))
    return out


def _allowed_by(compiled, avec: int, rvec: int) -> bool:
    allowed = False
    for effect, amask, rmask in compiled:
        if amask & avec and rmask & rvec:
            if effect is Effect.DENY:
                return False
            allowed = True
    return allowed


def _find_escalation(original: Policy, candidate: Policy) -> Call | None:
    action_patterns: list[str] = []
    resource_patterns: list[str] = []
    for policy in (original, candidate):
        for stmt in policy.statements:
            action_patterns.extend(stmt.actions)
            resource_patterns.extend(stmt.resources)

    action_classes = compute_classes(action_patterns)
    resource_classes = compute_classes(resource_patterns)

    action_index = {p: i for i, p in enumerate(dict.fromkeys(action_patterns))}
    resource_index = {p: i for i, p in enumerate(dict.fromkeys(resource_patterns))}
    orig = _policy_vectors(original, action_index, resource_index)
    cand = _policy_vectors(candidate, action_index, resource_index)

    for avec_tuple, arep in action_classes.items():
        avec = sum(1 << i for i, b in enumerate(avec_tuple) if b)
        for rvec_tuple, rrep in resource_classes.items():
            rvec = sum(1 << i for i, b in enumerate(rvec_tuple) if b)
            if _allowed_by(cand, avec, rvec) and not _allowed_by(orig, avec, rvec):
                return Call(action=arep, resource=rrep)
    return None


def verify_candidate(
    original: Policy,
    candidate: Policy,
    observed_calls: list[Call],
) -> VerificationResult:
    lost_call = _find_lost_call(candidate, observed_calls)
    witness = _find_escalation(original, candidate)
    return VerificationResult(
        preserves_observed=lost_call is None,
        lost_call=lost_call,
        no_escalation=witness is None,
        escalation_witness=witness,
    )
