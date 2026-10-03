"""Top-level verification entry point used by the caller (upper layer)."""

from __future__ import annotations

from typing import List

from .authorize import is_authorized
from .inclusion import find_new_permission
from .models import (
    Call,
    Policy,
    VerificationReport,
    validate_calls,
    validate_policy,
)


def verify_candidate(
    original: Policy, candidate: Policy, successful_calls: List[Call]
) -> VerificationReport:
    """Verify that `candidate` can replace `original` for the same principal.

    Two independent checks, both always evaluated and reported:

    1. Every observed successful call stays authorized under the candidate
       (any violation is listed in ``lost_calls``).
    2. The candidate grants no permission beyond the original, over the
       whole name domain (a concrete violating (action, resource) pair is
       returned as ``new_permission_example`` when found).

    The caller guarantees the original policy authorizes every call in
    ``successful_calls``; this is validated defensively.
    """
    validate_policy(original)
    validate_policy(candidate)
    validate_calls(successful_calls)

    report = VerificationReport()

    for call in successful_calls:
        if not is_authorized(original, call.action, call.resource):
            raise ValueError(
                "successful call is denied by the original policy: "
                f"({call.action!r}, {call.resource!r})"
            )
        if not is_authorized(candidate, call.action, call.resource):
            report.lost_calls.append(call)
    report.preserves_calls = not report.lost_calls

    report.new_permission_example = find_new_permission(original, candidate)
    report.no_new_permissions = report.new_permission_example is None

    return report
