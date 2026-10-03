"""通配符模式匹配与字符域校验。

名称字符域：英文字母、数字、冒号、斜杠、下划线、句点、连字符。
模式额外允许 '*'（任意长度序列，含零个字符）与 '?'（恰好一个字符）。
通配符可匹配冒号与斜杠，无目录边界与转义语法。匹配区分大小写。
"""
from __future__ import annotations

import string
from functools import lru_cache

NAME_CHARS = frozenset(string.ascii_letters + string.digits + ":/_.-")
PATTERN_EXTRA_CHARS = frozenset("*?")
PATTERN_CHARS = NAME_CHARS | PATTERN_EXTRA_CHARS


def is_valid_name(name: str) -> bool:
    return isinstance(name, str) and len(name) > 0 and set(name) <= NAME_CHARS


def is_valid_pattern(pattern: str) -> bool:
    return (
        isinstance(pattern, str)
        and len(pattern) > 0
        and set(pattern) <= PATTERN_CHARS
    )


def match_pattern(pattern: str, name: str) -> bool:
    """判断具体名称是否匹配模式。名称须为非空合法名称。"""

    @lru_cache(maxsize=None)
    def dp(i: int, j: int) -> bool:
        if i == len(pattern):
            return j == len(name)
        p = pattern[i]
        if p == "*":
            return dp(i + 1, j) or (j < len(name) and dp(i, j + 1))
        if j >= len(name):
            return False
        if p == "?":
            return dp(i + 1, j + 1)
        return p == name[j] and dp(i + 1, j + 1)

    return dp(0, 0)
