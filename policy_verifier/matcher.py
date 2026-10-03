"""Wildcard pattern matching for action/resource names.

Pattern syntax: '*' matches any (possibly empty) character sequence,
'?' matches exactly one character. All other characters match literally.
Matching is case-sensitive; wildcards also match ':' and '/'.
There is no escape syntax and no directory boundary semantics.
"""

from __future__ import annotations


def wildcard_match(pattern: str, text: str) -> bool:
    """Return True if `text` matches the wildcard `pattern`.

    Dynamic programming over pattern x text, O(len(pattern) * len(text)).
    """
    # reachable[j] == True iff the pattern prefix consumed so far can match
    # text[:j].
    reachable = [False] * (len(text) + 1)
    reachable[0] = True
    for symbol in pattern:
        nxt = [False] * (len(text) + 1)
        if symbol == "*":
            # '*' consumes zero or more characters: nxt[j] = OR of
            # reachable[0..j].
            seen = False
            for j in range(len(text) + 1):
                seen = seen or reachable[j]
                nxt[j] = seen
        elif symbol == "?":
            # '?' consumes exactly one character.
            for j in range(1, len(text) + 1):
                nxt[j] = reachable[j - 1]
        else:
            for j in range(1, len(text) + 1):
                if text[j - 1] == symbol:
                    nxt[j] = reachable[j - 1]
        reachable = nxt
        if not any(reachable):
            return False
    return reachable[len(text)]
