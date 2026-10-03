"""Single-call authorization: the per-statement ground-truth evaluator."""

from __future__ import annotations

from .matcher import wildcard_match
from .models import Policy


def _statement_matches(statement, action: str, resource: str) -> bool:
    # A statement matches iff the action matches ANY action pattern and the
    # resource matches ANY resource pattern (all combinations, not pairwise).
    return any(wildcard_match(p, action) for p in statement.actions) and any(
        wildcard_match(p, resource) for p in statement.resources
    )


def is_authorized(policy: Policy, action: str, resource: str) -> bool:
    """True iff at least one Allow matches and no Deny matches.

    Deny overrides Allow; with no matching Allow the default is deny.
    """
    allowed = False
    for statement in policy.statements:
        if _statement_matches(statement, action, resource):
            if statement.effect == "Deny":
                return False
            allowed = True
    return allowed
