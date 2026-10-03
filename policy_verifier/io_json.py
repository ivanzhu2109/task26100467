"""从本地 JSON 文件读取策略与成功调用清单。

策略文件格式（IAM 风格）：
    {"Statement": [{"Effect": "Allow", "Action": [...], "Resource": [...]}, ...]}
也接受顶层直接为语句列表。

调用清单文件格式：
    [{"action": "svc:read", "resource": "arn:a"}, ...]
也接受 {"calls": [...]} 包装。
"""
from __future__ import annotations

import json
from typing import Any

from .matching import is_valid_name, is_valid_pattern
from .model import Call, Effect, Policy, Statement


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _parse_statement(raw: Any, where: str) -> Statement:
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: 语句必须是对象")
    try:
        effect = Effect(raw["Effect"])
    except KeyError:
        raise ValueError(f"{where}: 缺少 Effect 字段") from None
    except ValueError:
        raise ValueError(f"{where}: Effect 必须是 'Allow' 或 'Deny'") from None
    actions = raw.get("Action")
    resources = raw.get("Resource")
    for field_name, value in (("Action", actions), ("Resource", resources)):
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(p, str) for p in value)
        ):
            raise ValueError(f"{where}: {field_name} 必须是非空字符串列表")
        for p in value:
            if not is_valid_pattern(p):
                raise ValueError(f"{where}: 非法模式 {p!r}")
    return Statement(
        effect=effect, actions=tuple(actions), resources=tuple(resources)
    )


def load_policy(path: str) -> Policy:
    data = _load_json(path)
    if isinstance(data, dict):
        data = data.get("Statement", data.get("statements"))
    if not isinstance(data, list):
        raise ValueError("策略文件须包含语句列表")
    statements = tuple(
        _parse_statement(raw, f"语句[{i}]") for i, raw in enumerate(data)
    )
    return Policy(statements=statements)


def load_calls(path: str) -> list[Call]:
    data = _load_json(path)
    if isinstance(data, dict):
        data = data.get("calls")
    if not isinstance(data, list):
        raise ValueError("调用清单文件须包含调用列表")
    calls: list[Call] = []
    for i, raw in enumerate(data):
        where = f"调用[{i}]"
        if not isinstance(raw, dict):
            raise ValueError(f"{where}: 调用必须是对象")
        action, resource = raw.get("action"), raw.get("resource")
        if not is_valid_name(action):
            raise ValueError(f"{where}: 非法动作名 {action!r}")
        if not is_valid_name(resource):
            raise ValueError(f"{where}: 非法资源名 {resource!r}")
        calls.append(Call(action=action, resource=resource))
    return calls
