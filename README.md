# policy_verifier — 最小权限建议核验库

由上层调用：策略与成功调用清单从本地 JSON 文件读取，分析状态全部保存在内存中。
本组件只负责核验，不负责生成建议。

## 功能

- `authorize(policy, action, resource)`：判断一个具体调用是否被策略授权
  （至少一条 Allow 匹配且无任何 Deny 匹配；Deny 覆盖 Allow；默认拒绝）。
- `verify_candidate(original, candidate, observed_calls)`：核验候选策略，返回
  `VerificationResult`，两项结论独立给出：
  - `preserves_observed` / `lost_call`：是否保留全部成功调用；丢失时给出一条
    被候选策略拒绝的已观察调用。
  - `no_escalation` / `escalation_witness`：候选允许的每个动作/资源组合是否都被
    原策略允许；扩大时给出一对具体动作名与资源名作为反例。
  - 两个条件同时满足时 `adoptable` 为真。

“未扩大权限”在整个名称域上精确判定：把每个维度（动作/资源）的全部模式编译为
乘积自动机，按“匹配哪些模式”的布尔向量把名称域划分为有限等价类，逐格比较两份
策略的授权结果。不是抽样，也没有名称长度上限或搜索预算。

## 规则

- 只处理无条件策略；语句含 `Effect`（`Allow`/`Deny`）、非空 `Action` 与
  `Resource` 模式列表；同一语句内动作与资源是笛卡尔组合，不按位置配对。
- 名称字符域：英文字母、数字、`:` `/` `_` `.` `-`，区分大小写，非空。
- 模式额外支持 `*`（任意长度序列，含空）与 `?`（恰好一个字符）；通配符可匹配
  `:` 和 `/`，无目录边界与转义。

## JSON 格式

策略文件（也接受顶层直接为语句数组）：

```json
{"Statement": [{"Effect": "Allow", "Action": ["svc:read*"], "Resource": ["arn:public/*"]}]}
```

调用清单（也接受 `{"calls": [...]}` 包装）：

```json
[{"action": "svc:read", "resource": "arn:public/a"}]
```

## 用法

```python
from policy_verifier import load_policy, load_calls, verify_candidate

orig = load_policy("original.json")
cand = load_policy("candidate.json")
calls = load_calls("observed.json")
result = verify_candidate(orig, cand, calls)
if not result.no_escalation:
    print("扩大权限:", result.escalation_witness)
if not result.preserves_observed:
    print("丢失已用权限:", result.lost_call)
```

## 测试

```bash
python3 -m pytest tests/ -q
```
