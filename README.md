# policy_verifier

最小权限建议核验库（纯 Python，无第三方依赖）。由上层调用：在交付精简后的
候选策略前，核验它相对原策略既没有丢失已用权限，也没有引入新权限。

## 能力

- `is_authorized(policy, action, resource)`：对一次具体调用做逐语句授权判定
  （至少一条 Allow 匹配且没有任何 Deny 匹配才允许；Deny 覆盖 Allow；默认拒绝）。
- `verify_candidate(original, candidate, successful_calls)`：核验候选策略，返回
  `VerificationReport`，两项结果独立给出：
  - `preserves_calls` / `lost_calls`：观察期内的成功调用是否全部被保留；
    丢失时逐条列出被候选策略拒绝的调用。
  - `no_new_permissions` / `new_permission_example`：候选策略是否在整个名称域上
    没有超出原策略的权限；超权时给出一对具体的 `(action, resource)` 反例
    （原策略拒绝、候选策略允许）。反例可能长于所有输入模式。
  - 两类问题同时存在时，两类证据都会返回；`report.adoptable` 为两者皆通过。
- `find_new_permission(original, candidate)`：只做权限包含核验。

包含核验是精确判定而非抽样：把名称按“被哪些模式匹配”的签名划分，用模式 NFA
乘积上的 BFS 枚举全部可实现签名（每个签名都保留一个具体见证串），再逐对检查。
名称域无限也能在有限步内给出确定结论，包括策略等价与完全拒绝的情形。

## 策略与调用 JSON 格式

策略文件：

```json
{
  "statements": [
    {"effect": "Allow", "actions": ["svc:read*"], "resources": ["arn:public/*"]},
    {"effect": "Deny",  "actions": ["svc:readSecret"], "resources": ["arn:public/*"]}
  ]
}
```

- `effect` 只能是 `"Allow"` 或 `"Deny"`；`actions` / `resources` 为非空模式列表，
  同一语句内两组模式是笛卡尔组合（任一动作模式匹配且任一资源模式匹配即匹配）。
- 名称字符域：英文字母、数字、`:` `/` `_` `.` `-`，匹配区分大小写。
- 模式额外支持 `*`（任意长度，含零个字符）和 `?`（恰好一个字符）；通配符可
  跨越 `:` 和 `/`，无目录边界与转义语法。

调用清单文件：

```json
[
  {"action": "svc:read", "resource": "arn:public/item1"}
]
```

## 用法

```python
from policy_verifier import load_policy, load_calls, verify_candidate

original = load_policy("original.json")
candidate = load_policy("candidate.json")
calls = load_calls("successful_calls.json")

report = verify_candidate(original, candidate, calls)
if report.adoptable:
    print("候选策略可采用")
else:
    print("丢失的已用权限:", report.lost_calls)
    print("新增权限反例:", report.new_permission_example)
```

输入约束（超出会抛出 `ValueError`）：每份策略至多 24 条语句、64 个模式，
单个模式最长 64 字符，调用清单至多 10000 条；调用方需保证原策略允许清单中
的所有成功调用（库会防御性校验）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖：三条验收场景（语句合并的交叉组合反例、删除私有资源 Deny、
`svc:read*` 拆分等价与分支移除）、反例与独立逐语句授权计算的一致性、
通配符语义、超长反例、空策略/全拒策略、JSON 读写，以及 300 组随机策略
与暴力枚举的交叉验证和最大规模输入的终止性。
