"""Least-privilege policy suggestion verifier.

Public API:
    load_policy / load_calls      -- read policy and call list JSON files
    is_authorized                 -- evaluate one call against a policy
    verify_candidate              -- full verification, returns a report
    find_new_permission           -- inclusion check only
    VerificationReport            -- result object
"""

from .authorize import is_authorized
from .inclusion import find_new_permission
from .models import (
    Call,
    Policy,
    Statement,
    VerificationReport,
    load_calls,
    load_policy,
    validate_calls,
    validate_policy,
)
from .verifier import verify_candidate

__all__ = [
    "Call",
    "Policy",
    "Statement",
    "VerificationReport",
    "find_new_permission",
    "is_authorized",
    "load_calls",
    "load_policy",
    "validate_calls",
    "validate_policy",
    "verify_candidate",
]
