"""Exact policy-inclusion check over the whole (infinite) name domain.

A call (action, resource) is classified by its *signature*: the set of
action patterns matching the action together with the set of resource
patterns matching the resource. Two calls with equal signatures are
authorized identically by every policy built from these patterns, so the
semantics of both policies is fully determined by a finite table.

We enumerate every signature realizable by a non-empty name via BFS over
the product of the per-pattern NFAs (a wildcard pattern compiles to a
chain NFA of len(pattern)+1 positions), keeping a concrete witness string
per signature. Checking all signature pairs is exact: any counterexample
in the infinite domain has its signature pair enumerated, and every
enumerated pair comes with real witness names. The BFS state space is
finite, so the procedure always terminates with a definite answer.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from .models import NAME_CHARS, Policy


class _PatternNFA:
    """Chain NFA for one wildcard pattern, states are bitmasks of positions."""

    __slots__ = ("accept", "star_mask", "move", "_base")

    def __init__(self, pattern: str) -> None:
        self.accept = 1 << len(pattern)
        star = 0
        literal_positions: List[Tuple[int, str]] = []
        question = 0
        for i, symbol in enumerate(pattern):
            if symbol == "*":
                star |= 1 << i
            elif symbol == "?":
                question |= 1 << i
            else:
                literal_positions.append((i, symbol))
        self.star_mask = star
        # move[c]: positions that consume c and advance ('*', '?', literal==c).
        self.move: Dict[str, int] = {}
        base = star | question
        for i, symbol in literal_positions:
            self.move[symbol] = self.move.get(symbol, base) | (1 << i)
        self._base = base

    def closure(self, mask: int) -> int:
        # A '*' position also reaches the next position without consuming.
        while True:
            grown = mask | ((mask & self.star_mask) << 1)
            if grown == mask:
                return mask
            mask = grown

    def step(self, mask: int, char: str) -> int:
        advance = self.move.get(char, self._base)
        raw = (mask & self.star_mask) | ((mask & advance) << 1)
        return self.closure(raw)


def _alphabet(nfas: Sequence[_PatternNFA]) -> List[str]:
    """One representative per char class: every literal used by some pattern,
    plus one fresh name char standing for all chars used by no pattern."""
    literals: set = set()
    for nfa in nfas:
        literals.update(nfa.move.keys())
    chars = sorted(literals)
    fresh = next((c for c in sorted(NAME_CHARS) if c not in literals), None)
    if fresh is not None:
        chars.append(fresh)
    return chars


def _enumerate_signatures(
    patterns: Sequence[str],
) -> Dict[FrozenSet[int], str]:
    """Map each signature realizable by a non-empty name to a witness name."""
    nfas = [_PatternNFA(p) for p in patterns]
    if not nfas:
        # No patterns: every name has the empty signature.
        return {frozenset(): "a"}
    alphabet = _alphabet(nfas)
    start = tuple(nfa.closure(1) for nfa in nfas)
    visited = {start}
    queue = deque([(start, "")])
    signatures: Dict[FrozenSet[int], str] = {}
    while queue:
        state, word = queue.popleft()
        for char in alphabet:
            nxt = tuple(nfa.step(mask, char) for nfa, mask in zip(nfas, state))
            witness = word + char
            signature = frozenset(
                i for i, mask in enumerate(nxt) if mask & nfas[i].accept
            )
            if signature not in signatures:
                signatures[signature] = witness
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, witness))
    return signatures


def _compile_policy(
    policy: Policy,
    action_index: Dict[str, int],
    resource_index: Dict[str, int],
) -> Tuple[Tuple[str, FrozenSet[int], FrozenSet[int]], ...]:
    return tuple(
        (
            stmt.effect,
            frozenset(action_index[p] for p in stmt.actions),
            frozenset(resource_index[p] for p in stmt.resources),
        )
        for stmt in policy.statements
    )


def _allows(
    statements: Tuple[Tuple[str, FrozenSet[int], FrozenSet[int]], ...],
    action_sig: FrozenSet[int],
    resource_sig: FrozenSet[int],
) -> bool:
    allowed = False
    for effect, actions, resources in statements:
        if actions & action_sig and resources & resource_sig:
            if effect == "Deny":
                return False
            allowed = True
    return allowed


def find_new_permission(
    original: Policy, candidate: Policy
) -> Optional[Tuple[str, str]]:
    """Return (action, resource) allowed by `candidate` but not `original`,
    or None if candidate grants nothing beyond original.

    The check covers the entire name domain, not just logged names or
    pattern literals; the returned witnesses are concrete non-empty names.
    """
    action_patterns = sorted(
        {p for pol in (original, candidate) for s in pol.statements for p in s.actions}
    )
    resource_patterns = sorted(
        {p for pol in (original, candidate) for s in pol.statements for p in s.resources}
    )
    action_index = {p: i for i, p in enumerate(action_patterns)}
    resource_index = {p: i for i, p in enumerate(resource_patterns)}
    original_stmts = _compile_policy(original, action_index, resource_index)
    candidate_stmts = _compile_policy(candidate, action_index, resource_index)

    action_sigs = _enumerate_signatures(action_patterns)
    resource_sigs = _enumerate_signatures(resource_patterns)

    for action_sig, action_witness in action_sigs.items():
        if not _signature_useful(candidate_stmts, action_sig, side="action"):
            continue
        for resource_sig, resource_witness in resource_sigs.items():
            if _allows(candidate_stmts, action_sig, resource_sig) and not _allows(
                original_stmts, action_sig, resource_sig
            ):
                return (action_witness, resource_witness)
    return None


def _signature_useful(statements, signature, side: str) -> bool:
    """Cheap prune: skip action signatures no candidate Allow can match."""
    for effect, actions, _ in statements:
        if effect == "Allow" and actions & signature:
            return True
    return False
