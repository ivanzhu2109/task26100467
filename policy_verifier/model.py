"""核心数据类型：策略、语句、调用与核验结果。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Effect(Enum):
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass(frozen=True)
class Statement:
    """一条无条件策略语句。

    动作匹配任一动作模式且资源匹配任一资源模式时，语句匹配；
    两份列表表达所有组合，不按位置配对。
    """

    effect: Effect
    actions: tuple[str, ...]
    resources: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.actions:
            raise ValueError("语句的动作模式列表不能为空")
        if not self.resources:
            raise ValueError("语句的资源模式列表不能为空")


@dataclass(frozen=True)
class Policy:
    statements: tuple[Statement, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Call:
    """一次成功调用：具体动作名与资源名（非模式）。"""

    action: str
    resource: str


@dataclass(frozen=True)
class VerificationResult:
    """两项独立的核验结果。

    preserves_observed: 候选策略保留了观察期内的全部成功调用。
    lost_call: 被候选策略拒绝的成功调用（存在丢失时给出一条）。
    no_escalation: 候选策略允许的每个动作/资源组合都被原策略允许。
    escalation_witness: 原策略拒绝而候选策略允许的具体 (动作, 资源) 对。
    """

    preserves_observed: bool
    lost_call: Call | None
    no_escalation: bool
    escalation_witness: Call | None

    @property
    def adoptable(self) -> bool:
        return self.preserves_observed and self.no_escalation
