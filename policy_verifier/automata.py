"""模式等价类自动机。

把每个维度（动作 / 资源）上的全部模式编译为 NFA，做乘积子集构造，
按“匹配了哪些模式”的布尔向量把整个名称域划分为有限个等价类。
同一等价类中的任意两个名称，对所有语句的匹配结果完全一致，
因此权限包含关系可以在这有限网格上精确判定（而非抽样）。
名称必须非空，故每个等价类记录一个非空代表串作为反例候选。
"""
from __future__ import annotations

from collections import deque

from .matching import NAME_CHARS

ALPHABET = tuple(sorted(NAME_CHARS))


class _PatternNfa:
    """单个通配符模式的 NFA。状态 0..n，接受态为 n。"""

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self.n = len(pattern)
        # 预计算每个状态在闭包后的 epsilon 可达集（仅 '*' 产生 epsilon 边）。
        self._closure: list[frozenset[int]] = []
        for i in range(self.n + 1):
            reach = {i}
            j = i
            while j < self.n and pattern[j] == "*":
                j += 1
                reach.add(j)
            self._closure.append(frozenset(reach))

    def start(self) -> frozenset[int]:
        return self._closure[0]

    def step(self, states: frozenset[int], ch: str) -> frozenset[int]:
        nxt: set[int] = set()
        for i in states:
            if i >= self.n:
                continue
            p = self.pattern[i]
            if p == "*":
                nxt.add(i)
            elif p == "?" or p == ch:
                nxt.add(i + 1)
        if not nxt:
            return frozenset()
        out: set[int] = set()
        for i in nxt:
            out |= self._closure[i]
        return frozenset(out)

    def accepts(self, states: frozenset[int]) -> bool:
        return self.n in states


def compute_classes(patterns: list[str]) -> dict[tuple[bool, ...], str]:
    """返回 {匹配向量: 一个非空代表串}，覆盖整个非空名称域。

    匹配向量是长度为 len(patterns) 的布尔元组，第 k 位表示该等价类中的
    名称是否匹配第 k 个模式。两个名称向量相同，则它们对任何由这些模式
    组成的语句/策略的匹配行为完全一致。
    """
    patterns = list(dict.fromkeys(patterns))
    if not patterns:
        # 无任何模式：整个非空名称域只有一个等价类。
        return {(): "a"}

    nfas = [_PatternNfa(p) for p in patterns]
    start = tuple(nfa.start() for nfa in nfas)

    rep_any: dict[tuple[frozenset[int], ...], str] = {start: ""}
    rep_nonempty: dict[tuple[frozenset[int], ...], str | None] = {start: None}
    queue: deque[tuple[frozenset[int], ...]] = deque([start])

    while queue:
        state = queue.popleft()
        base = rep_any[state]
        for ch in ALPHABET:
            nxt = tuple(nfa.step(state[k], ch) for k, nfa in enumerate(nfas))
            word = base + ch
            if nxt not in rep_any:
                rep_any[nxt] = word
                rep_nonempty[nxt] = word
                queue.append(nxt)
            elif rep_nonempty[nxt] is None:
                rep_nonempty[nxt] = word

    classes: dict[tuple[bool, ...], str] = {}
    for state, vec in (
        (s, tuple(nfa.accepts(s[k]) for k, nfa in enumerate(nfas)))
        for s in rep_any
    ):
        rep = rep_nonempty[state]
        if rep is None:
            continue  # 仅空串可达的类：名称域不含空串，跳过
        if vec not in classes or len(rep) < len(classes[vec]):
            classes[vec] = rep
    return classes
