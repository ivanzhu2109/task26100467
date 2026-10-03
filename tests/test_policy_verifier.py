"""policy_verifier 自动化测试。

所有反例（扩大权限的见证对、丢失权限的调用）都用测试内独立的
逐语句授权实现（基于正则翻译的另一套匹配器）复核，确保与库结论一致。
"""
from __future__ import annotations

import json
import random
import re
import string

import pytest

from policy_verifier import (
    Call,
    Effect,
    Policy,
    Statement,
    authorize,
    load_calls,
    load_policy,
    verify_candidate,
)

A, D = Effect.ALLOW, Effect.DENY


# ---------- 独立的参照实现（与库内实现完全分开） ----------

def _ref_match(pattern: str, name: str) -> bool:
    regex = "".join(
        ".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern
    )
    return re.fullmatch(regex, name) is not None


def _ref_authorize(policy: Policy, action: str, resource: str) -> bool:
    allowed = False
    for stmt in policy.statements:
        if any(_ref_match(p, action) for p in stmt.actions) and any(
            _ref_match(p, resource) for p in stmt.resources
        ):
            if stmt.effect is D:
                return False
            allowed = True
    return allowed


def _check_result_consistent(orig, cand, result, calls):
    """库结论与参照实现交叉一致。"""
    assert result.preserves_observed == (result.lost_call is None)
    assert result.no_escalation == (result.escalation_witness is None)
    assert result.adoptable == (result.preserves_observed and result.no_escalation)
    if result.lost_call is not None:
        c = result.lost_call
        assert c in calls
        assert _ref_authorize(orig, c.action, c.resource)  # 题设：原策略允许
        assert not _ref_authorize(cand, c.action, c.resource)
    if result.escalation_witness is not None:
        w = result.escalation_witness
        assert w.action and w.resource  # 名称非空
        assert not _ref_authorize(orig, w.action, w.resource)
        assert _ref_authorize(cand, w.action, w.resource)


# ---------- 验收场景 1：语句合并产生交叉组合 ----------

def test_merge_statements_grants_cross_product():
    orig = Policy((
        Statement(A, ("svc:read",), ("arn:a",)),
        Statement(A, ("svc:write",), ("arn:b",)),
    ))
    cand = Policy((
        Statement(A, ("svc:read", "svc:write"), ("arn:a", "arn:b")),
    ))
    result = verify_candidate(orig, cand, [])
    assert not result.adoptable
    assert not result.no_escalation
    assert result.preserves_observed
    _check_result_consistent(orig, cand, result, [])
    w = result.escalation_witness
    # 反例必须是交叉组合之一
    assert (w.action, w.resource) in {
        ("svc:read", "arn:b"),
        ("svc:write", "arn:a"),
    }


# ---------- 验收场景 2：删除限制私有资源的 Deny ----------

def test_removed_deny_escalates_even_with_public_only_logs():
    orig = Policy((
        Statement(A, ("svc:*",), ("arn:*",)),
        Statement(D, ("svc:*",), ("arn:private/*",)),
    ))
    cand = Policy((
        Statement(A, ("svc:*",), ("arn:*",)),
    ))
    calls = [
        Call("svc:read", "arn:public/x"),
        Call("svc:write", "arn:public/y"),
    ]
    result = verify_candidate(orig, cand, calls)
    assert result.preserves_observed  # 成功调用全来自公开资源，未丢失
    assert not result.no_escalation
    _check_result_consistent(orig, cand, result, calls)
    w = result.escalation_witness
    assert _ref_match("arn:private/*", w.resource)


# ---------- 验收场景 3：拆分等价，随后删分支丢权限 ----------

def _split_setup():
    orig = Policy((
        Statement(A, ("svc:read*",), ("arn:*",)),
        Statement(D, ("svc:readSecret",), ("arn:*",)),
    ))
    split = Policy((
        Statement(A, ("svc:read",), ("arn:*",)),
        Statement(A, ("svc:read?*",), ("arn:*",)),
        Statement(D, ("svc:readSecret",), ("arn:*",)),
    ))
    calls = [Call("svc:readItems", "arn:z"), Call("svc:read", "arn:z")]
    return orig, split, calls


def test_split_pattern_is_equivalent():
    orig, split, calls = _split_setup()
    result = verify_candidate(orig, split, calls)
    assert result.adoptable
    _check_result_consistent(orig, split, result, calls)


def test_removed_branch_loses_observed_permission_without_escalation():
    orig, split, calls = _split_setup()
    # 移除覆盖已观察调用 svc:readItems 的分支 svc:read?*
    shrunk = Policy((
        Statement(A, ("svc:read",), ("arn:*",)),
        Statement(D, ("svc:readSecret",), ("arn:*",)),
    ))
    result = verify_candidate(split, shrunk, calls)
    assert result.no_escalation  # 严格收窄，未扩大权限
    assert not result.preserves_observed
    assert result.lost_call == Call("svc:readItems", "arn:z")
    _check_result_consistent(split, shrunk, result, calls)


# ---------- 单调用授权 ----------

def test_authorize_deny_overrides_allow():
    pol = Policy((
        Statement(A, ("svc:*",), ("arn:*",)),
        Statement(D, ("svc:delete",), ("arn:*",)),
    ))
    assert authorize(pol, "svc:get", "arn:1")
    assert not authorize(pol, "svc:delete", "arn:1")


def test_authorize_default_deny_and_empty_policy():
    assert not authorize(Policy(()), "svc:get", "arn:1")
    pol = Policy((Statement(A, ("svc:get",), ("arn:1",)),))
    assert not authorize(pol, "svc:put", "arn:1")
    assert not authorize(pol, "svc:get", "arn:2")


def test_authorize_rejects_invalid_names():
    pol = Policy((Statement(A, ("*",), ("*",)),))
    with pytest.raises(ValueError):
        authorize(pol, "", "arn:1")
    with pytest.raises(ValueError):
        authorize(pol, "bad name", "arn:1")


def test_wildcard_semantics():
    pol = Policy((Statement(A, ("a?c",), ("r*",)),))
    assert authorize(pol, "abc", "r")
    assert not authorize(pol, "ac", "r")
    assert not authorize(pol, "abbc", "r")
    assert authorize(pol, "a/c", "r:x/y")  # 通配符可匹配冒号斜杠


def test_matching_is_case_sensitive():
    pol = Policy((Statement(A, ("Svc:Read",), ("arn:*",)),))
    assert authorize(pol, "Svc:Read", "arn:x")
    assert not authorize(pol, "svc:read", "arn:x")


# ---------- 等价与边界 ----------

def test_identical_policies_are_equivalent():
    pol = Policy((
        Statement(A, ("svc:*",), ("arn:pub/*",)),
        Statement(D, ("svc:rm",), ("arn:pub/private/*",)),
    ))
    result = verify_candidate(pol, pol, [])
    assert result.adoptable
    _check_result_consistent(pol, pol, result, [])


def test_both_empty_policies_equivalent():
    result = verify_candidate(Policy(()), Policy(()), [])
    assert result.adoptable


def test_empty_original_any_candidate_allow_escalates():
    cand = Policy((Statement(A, ("svc:x",), ("arn:y",)),))
    result = verify_candidate(Policy(()), cand, [])
    assert not result.no_escalation
    _check_result_consistent(Policy(()), cand, result, [])


def test_empty_candidate_loses_calls_but_never_escalates():
    orig = Policy((Statement(A, ("svc:x",), ("arn:y",)),))
    result = verify_candidate(orig, Policy(()), [Call("svc:x", "arn:y")])
    assert result.no_escalation
    assert not result.preserves_observed
    assert result.lost_call == Call("svc:x", "arn:y")


def test_both_problems_reported_together():
    orig = Policy((
        Statement(A, ("svc:a",), ("arn:1",)),
        Statement(D, ("svc:b",), ("arn:2",)),
    ))
    cand = Policy((Statement(A, ("svc:b",), ("arn:2",)),))
    calls = [Call("svc:a", "arn:1")]
    result = verify_candidate(orig, cand, calls)
    assert not result.preserves_observed and not result.no_escalation
    assert result.lost_call is not None and result.escalation_witness is not None
    _check_result_consistent(orig, cand, result, calls)


def test_witness_may_be_longer_than_all_patterns():
    # 原策略只覆盖长度 1-3 的动作名；候选用 "?*" 覆盖任意长度。
    # 唯一的反例空间是长度 >= 4 的动作名，长于所有输入模式。
    orig = Policy((Statement(A, ("?", "??", "???"), ("r",)),))
    cand = Policy((Statement(A, ("?*",), ("r",)),))
    result = verify_candidate(orig, cand, [])
    assert not result.no_escalation
    w = result.escalation_witness
    assert len(w.action) > 3  # 反例长于所有输入模式
    _check_result_consistent(orig, cand, result, [])


def test_equivalence_despite_different_pattern_syntax():
    orig = Policy((Statement(A, ("svc:get*",), ("arn:*",)),))
    cand = Policy((
        Statement(A, ("svc:get",), ("arn:*",)),
        Statement(A, ("svc:get?*",), ("arn:*",)),
    ))
    assert verify_candidate(orig, cand, []).adoptable
    assert verify_candidate(cand, orig, []).adoptable


def test_question_mark_not_droppable():
    orig = Policy((Statement(A, ("svc:a?",), ("r",)),))
    cand = Policy((Statement(A, ("svc:a*",), ("r",)),))
    result = verify_candidate(orig, cand, [])
    assert not result.no_escalation
    _check_result_consistent(orig, cand, result, [])


# ---------- JSON 读取 ----------

def test_load_policy_and_calls(tmp_path):
    pf = tmp_path / "policy.json"
    pf.write_text(json.dumps({"Statement": [
        {"Effect": "Allow", "Action": ["svc:read*"], "Resource": ["arn:pub/*"]},
        {"Effect": "Deny", "Action": ["svc:*"], "Resource": ["arn:sec/*"]},
    ]}))
    cf = tmp_path / "calls.json"
    cf.write_text(json.dumps({"calls": [
        {"action": "svc:read", "resource": "arn:pub/a"},
    ]}))
    pol = load_policy(str(pf))
    calls = load_calls(str(cf))
    assert authorize(pol, calls[0].action, calls[0].resource)
    assert not authorize(pol, "svc:read", "arn:sec/a")


def test_load_policy_validation_errors(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"Statement": [
        {"Effect": "Maybe", "Action": ["a"], "Resource": ["r"]},
    ]}))
    with pytest.raises(ValueError):
        load_policy(str(bad))
    bad.write_text(json.dumps({"Statement": [
        {"Effect": "Allow", "Action": [], "Resource": ["r"]},
    ]}))
    with pytest.raises(ValueError):
        load_policy(str(bad))
    bad.write_text(json.dumps({"Statement": [
        {"Effect": "Allow", "Action": ["a b"], "Resource": ["r"]},
    ]}))
    with pytest.raises(ValueError):
        load_policy(str(bad))


def test_load_calls_validation_errors(tmp_path):
    bad = tmp_path / "bad_calls.json"
    bad.write_text(json.dumps([{"action": "", "resource": "r"}]))
    with pytest.raises(ValueError):
        load_calls(str(bad))


def test_end_to_end_from_files(tmp_path):
    orig_f = tmp_path / "orig.json"
    cand_f = tmp_path / "cand.json"
    calls_f = tmp_path / "calls.json"
    orig_f.write_text(json.dumps({"Statement": [
        {"Effect": "Allow", "Action": ["svc:*"], "Resource": ["arn:*"]},
        {"Effect": "Deny", "Action": ["svc:*"], "Resource": ["arn:private/*"]},
    ]}))
    cand_f.write_text(json.dumps({"Statement": [
        {"Effect": "Allow", "Action": ["svc:*"], "Resource": ["arn:*"]},
    ]}))
    calls_f.write_text(json.dumps([
        {"action": "svc:get", "resource": "arn:public/a"},
    ]))
    result = verify_candidate(
        load_policy(str(orig_f)), load_policy(str(cand_f)),
        load_calls(str(calls_f)),
    )
    assert result.preserves_observed and not result.no_escalation


# ---------- 随机化性质测试：与参照实现交叉验证 ----------

def _random_pattern(rng):
    alphabet = "ab:"
    n = rng.randint(1, 5)
    return "".join(rng.choice(alphabet + "*?") for _ in range(n)) or "a"


def _random_policy(rng):
    stmts = []
    for _ in range(rng.randint(0, 4)):
        stmts.append(Statement(
            rng.choice([A, D]),
            tuple({_random_pattern(rng) for _ in range(rng.randint(1, 2))}),
            tuple({_random_pattern(rng) for _ in range(rng.randint(1, 2))}),
        ))
    return Policy(tuple(stmts))


def test_randomized_cross_check():
    rng = random.Random(20261004)
    names = [
        "".join(rng.choice("ab:") for _ in range(rng.randint(1, 6)))
        for _ in range(60)
    ]
    for _ in range(120):
        orig = _random_policy(rng)
        cand = _random_policy(rng)
        calls = [
            Call(a, r) for a in names[:10] for r in names[:10]
            if _ref_authorize(orig, a, r)
        ][:50]
        result = verify_candidate(orig, cand, calls)
        _check_result_consistent(orig, cand, result, calls)
        # 库判定无扩大时，抽样确认参照实现也找不到反例（仅作健全性抽查）
        if result.no_escalation:
            for a in names:
                for r in names:
                    if _ref_authorize(cand, a, r):
                        assert _ref_authorize(orig, a, r), (a, r)
        # 库判定保留调用时，参照实现逐条确认
        if result.preserves_observed:
            for c in calls:
                assert _ref_authorize(cand, c.action, c.resource)


def test_scale_smoke():
    # 规模上限：两份策略合计 24 语句 / 64 模式 / 模式长 64，调用 10000 条。
    stmts_o, stmts_c = [], []
    for i in range(12):
        stmts_o.append(Statement(
            A, (f"svc:op{i}*".ljust(8, "x"),), (f"arn:res{i}/*",)))
        stmts_c.append(Statement(
            A, (f"svc:op{i}*".ljust(8, "x"),), (f"arn:res{i}/*",)))
    orig = Policy(tuple(stmts_o))
    cand = Policy(tuple(stmts_c))
    calls = [Call(f"svc:op{i % 12}do", f"arn:res{i % 12}/item{i}")
             for i in range(10000)]
    result = verify_candidate(orig, cand, calls)
    assert result.adoptable
