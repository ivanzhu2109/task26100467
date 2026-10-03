"""Automated acceptance and cross-check tests for policy_verifier.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""

import itertools
import json
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_verifier import (  # noqa: E402
    Call,
    Policy,
    Statement,
    find_new_permission,
    is_authorized,
    load_calls,
    load_policy,
    verify_candidate,
)
from policy_verifier.matcher import wildcard_match  # noqa: E402


def brute_force_new_permission(original, candidate, alphabet, max_len):
    """Independent check: scan every concrete (action, resource) pair with
    names up to `max_len` chars and return the first pair allowed by the
    candidate but denied by the original, or None."""
    names = [
        "".join(chars)
        for length in range(1, max_len + 1)
        for chars in itertools.product(alphabet, repeat=length)
    ]
    for action in names:
        for resource in names:
            if is_authorized(candidate, action, resource) and not is_authorized(
                original, action, resource
            ):
                return (action, resource)
    return None


class WildcardMatchTests(unittest.TestCase):
    def test_star_matches_empty_and_separators(self):
        self.assertTrue(wildcard_match("svc:*", "svc:"))
        self.assertTrue(wildcard_match("*", ""))
        self.assertTrue(wildcard_match("a*c", "a/b:c"))

    def test_question_matches_exactly_one_char(self):
        self.assertTrue(wildcard_match("a?c", "abc"))
        self.assertFalse(wildcard_match("a?c", "ac"))
        self.assertFalse(wildcard_match("a?c", "abbc"))

    def test_case_sensitive_and_literal(self):
        self.assertFalse(wildcard_match("Svc:*", "svc:read"))
        self.assertFalse(wildcard_match("svc:read", "svc:readx"))


class AuthorizeTests(unittest.TestCase):
    def test_deny_overrides_allow_and_default_deny(self):
        policy = Policy(statements=(
            Statement("Allow", ("svc:*",), ("arn:*",)),
            Statement("Deny", ("svc:write",), ("arn:*",)),
        ))
        self.assertTrue(is_authorized(policy, "svc:read", "arn:x"))
        self.assertFalse(is_authorized(policy, "svc:write", "arn:x"))
        self.assertFalse(is_authorized(Policy(), "svc:read", "arn:x"))

    def test_lists_are_cross_product_not_positional(self):
        policy = Policy(statements=(
            Statement("Allow", ("a:one", "a:two"), ("r:x", "r:y")),
        ))
        self.assertTrue(is_authorized(policy, "a:one", "r:y"))
        self.assertTrue(is_authorized(policy, "a:two", "r:x"))


class AcceptanceScenarioTests(unittest.TestCase):
    """The three scenarios from the acceptance criteria."""

    def test_merged_statement_grants_cross_combinations(self):
        original = Policy(statements=(
            Statement("Allow", ("svc:read",), ("arn:a",)),
            Statement("Allow", ("svc:write",), ("arn:b",)),
        ))
        candidate = Policy(statements=(
            Statement("Allow", ("svc:read", "svc:write"), ("arn:a", "arn:b")),
        ))
        report = verify_candidate(
            original, candidate, [Call("svc:read", "arn:a"), Call("svc:write", "arn:b")]
        )
        self.assertFalse(report.no_new_permissions)
        action, resource = report.new_permission_example
        # The evidence must be a real cross combination, confirmed by the
        # independent per-statement evaluator.
        self.assertTrue(is_authorized(candidate, action, resource))
        self.assertFalse(is_authorized(original, action, resource))
        self.assertIn(action, ("svc:read", "svc:write"))
        self.assertIn(resource, ("arn:a", "arn:b"))
        self.assertTrue(report.preserves_calls)
        self.assertFalse(report.adoptable)

    def test_dropped_deny_on_private_resources(self):
        original = Policy(statements=(
            Statement("Allow", ("svc:*",), ("arn:*",)),
            Statement("Deny", ("svc:*",), ("arn:private/*",)),
        ))
        candidate = Policy(statements=(
            Statement("Allow", ("svc:*",), ("arn:*",)),
        ))
        # All observed calls hit public resources only.
        calls = [Call("svc:read", "arn:public/1"), Call("svc:write", "arn:public/2")]
        report = verify_candidate(original, candidate, calls)
        self.assertFalse(report.no_new_permissions)
        action, resource = report.new_permission_example
        self.assertTrue(is_authorized(candidate, action, resource))
        self.assertFalse(is_authorized(original, action, resource))
        self.assertTrue(resource.startswith("arn:private/"))
        self.assertTrue(report.preserves_calls)

    def test_split_then_remove_branch(self):
        original = Policy(statements=(
            Statement("Allow", ("svc:read*",), ("arn:*",)),
            Statement("Deny", ("svc:readSecret",), ("arn:*",)),
        ))
        split = Policy(statements=(
            Statement("Allow", ("svc:read", "svc:read?*"), ("arn:*",)),
            Statement("Deny", ("svc:readSecret",), ("arn:*",)),
        ))
        calls = [Call("svc:read", "arn:1"), Call("svc:readList", "arn:2")]
        report = verify_candidate(original, split, calls)
        self.assertTrue(report.adoptable, report)
        self.assertIsNone(report.new_permission_example)

        # Removing the branch that covers an observed call loses it without
        # widening anything.
        shrunk = Policy(statements=(
            Statement("Allow", ("svc:read",), ("arn:*",)),
            Statement("Deny", ("svc:readSecret",), ("arn:*",)),
        ))
        report2 = verify_candidate(original, shrunk, calls)
        self.assertTrue(report2.no_new_permissions)
        self.assertFalse(report2.preserves_calls)
        self.assertEqual(report2.lost_calls, [Call("svc:readList", "arn:2")])
        self.assertFalse(report2.adoptable)


class InclusionCrossCheckTests(unittest.TestCase):
    """Every counterexample must agree with the independent per-statement
    authorization computation; seeded random policies are cross-checked
    against brute-force enumeration of concrete names."""

    def check_pair(self, original, candidate, alphabet, max_len):
        found = find_new_permission(original, candidate)
        if found is not None:
            action, resource = found
            self.assertTrue(action and resource)
            self.assertTrue(is_authorized(candidate, action, resource))
            self.assertFalse(is_authorized(original, action, resource))
        expected = brute_force_new_permission(original, candidate, alphabet, max_len)
        self.assertEqual(
            expected is not None,
            found is not None,
            f"disagreement: engine={found} brute={expected}",
        )
        return found

    def test_seeded_random_policies(self):
        rng = random.Random(20261004)
        alphabet = "ab"
        pattern_chars = "ab*?"

        def rand_pattern():
            return "".join(rng.choice(pattern_chars) for _ in range(rng.randint(1, 4)))

        def rand_policy():
            statements = []
            for _ in range(rng.randint(0, 3)):
                statements.append(Statement(
                    rng.choice(["Allow", "Deny"]),
                    tuple(rand_pattern() for _ in range(rng.randint(1, 2))),
                    tuple(rand_pattern() for _ in range(rng.randint(1, 2))),
                ))
            return Policy(statements=tuple(statements))

        for _ in range(300):
            original = rand_policy()
            candidate = rand_policy()
            self.check_pair(original, candidate, alphabet, max_len=6)

    def test_witness_may_exceed_all_pattern_lengths(self):
        # Original allows exactly 4-char actions; candidate allows >= 4.
        # The shortest counterexample is a 5-char action, longer than every
        # pattern in both policies.
        original = Policy(statements=(
            Statement("Allow", ("????",), ("res",)),
        ))
        candidate = Policy(statements=(
            Statement("Allow", ("????*",), ("res",)),
        ))
        found = find_new_permission(original, candidate)
        self.assertIsNotNone(found)
        action, resource = found
        self.assertGreater(len(action), 4)
        self.assertTrue(is_authorized(candidate, action, resource))
        self.assertFalse(is_authorized(original, action, resource))

    def test_wildcards_span_colons_and_slashes(self):
        original = Policy(statements=(
            Statement("Allow", ("svc:read",), ("arn:a",)),
        ))
        candidate = Policy(statements=(
            Statement("Allow", ("svc:*",), ("arn:*",)),
        ))
        found = find_new_permission(original, candidate)
        self.assertIsNotNone(found)
        action, resource = found
        self.assertTrue(is_authorized(candidate, action, resource))
        self.assertFalse(is_authorized(original, action, resource))

    def test_empty_and_equivalent_policies(self):
        empty = Policy()
        self.assertIsNone(find_new_permission(empty, empty))
        policy = Policy(statements=(
            Statement("Allow", ("svc:*",), ("arn:*",)),
            Statement("Deny", ("svc:write",), ("arn:private",)),
        ))
        self.assertIsNone(find_new_permission(policy, policy))
        self.assertIsNone(find_new_permission(policy, empty))
        self.assertIsNotNone(find_new_permission(empty, policy))

    def test_deny_all_original(self):
        original = Policy(statements=(
            Statement("Deny", ("*",), ("*",)),
        ))
        candidate = Policy(statements=(
            Statement("Allow", ("svc:read",), ("arn:a",)),
        ))
        found = find_new_permission(original, candidate)
        self.assertEqual(found, ("svc:read", "arn:a"))
        self.assertIsNone(find_new_permission(original, original))


class VerifyCandidateTests(unittest.TestCase):
    def test_both_findings_returned_together(self):
        original = Policy(statements=(
            Statement("Allow", ("svc:read",), ("arn:a",)),
            Statement("Allow", ("svc:write",), ("arn:b",)),
            Statement("Allow", ("svc:list",), ("arn:c",)),
        ))
        candidate = Policy(statements=(
            Statement("Allow", ("svc:read", "svc:write"), ("arn:a", "arn:b")),
        ))
        calls = [Call("svc:list", "arn:c"), Call("svc:read", "arn:a")]
        report = verify_candidate(original, candidate, calls)
        self.assertFalse(report.preserves_calls)
        self.assertFalse(report.no_new_permissions)
        self.assertEqual(report.lost_calls, [Call("svc:list", "arn:c")])
        action, resource = report.new_permission_example
        self.assertTrue(is_authorized(candidate, action, resource))
        self.assertFalse(is_authorized(original, action, resource))

    def test_adoptable_candidate(self):
        original = Policy(statements=(
            Statement("Allow", ("svc:*",), ("arn:*",)),
        ))
        candidate = Policy(statements=(
            Statement("Allow", ("svc:read",), ("arn:public/*",)),
        ))
        calls = [Call("svc:read", "arn:public/1")]
        report = verify_candidate(original, candidate, calls)
        self.assertTrue(report.adoptable)
        self.assertEqual(report.lost_calls, [])
        self.assertIsNone(report.new_permission_example)

    def test_original_must_authorize_successful_calls(self):
        original = Policy(statements=(
            Statement("Allow", ("svc:read",), ("arn:a",)),
        ))
        with self.assertRaises(ValueError):
            verify_candidate(original, original, [Call("svc:write", "arn:a")])


class JsonIoTests(unittest.TestCase):
    def test_policy_and_calls_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = os.path.join(tmp, "policy.json")
            with open(policy_path, "w", encoding="utf-8") as handle:
                json.dump({
                    "statements": [
                        {"effect": "Allow", "actions": ["svc:read*"],
                         "resources": ["arn:public/*"]},
                        {"effect": "Deny", "actions": ["svc:readSecret"],
                         "resources": ["arn:public/*"]},
                    ]
                }, handle)
            policy = load_policy(policy_path)
            self.assertTrue(is_authorized(policy, "svc:read", "arn:public/x"))
            self.assertFalse(is_authorized(policy, "svc:readSecret", "arn:public/x"))

            calls_path = os.path.join(tmp, "calls.json")
            with open(calls_path, "w", encoding="utf-8") as handle:
                json.dump([{"action": "svc:read", "resource": "arn:public/x"}], handle)
            self.assertEqual(load_calls(calls_path), [Call("svc:read", "arn:public/x")])

    def test_invalid_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.json")
            with open(bad, "w", encoding="utf-8") as handle:
                json.dump({"statements": [
                    {"effect": "Allow", "actions": ["svc read"], "resources": ["a"]}
                ]}, handle)
            with self.assertRaises(ValueError):
                load_policy(bad)
            with open(bad, "w", encoding="utf-8") as handle:
                json.dump({"statements": [
                    {"effect": "Maybe", "actions": ["a"], "resources": ["b"]}
                ]}, handle)
            with self.assertRaises(ValueError):
                load_policy(bad)


class ScaleTests(unittest.TestCase):
    def test_max_size_inputs_terminate(self):
        # 24 statements / 64 patterns across both policies, 10000 calls.
        original = Policy(statements=tuple(
            Statement("Allow", (f"svc:action{i:02d}",), (f"arn:res{i:02d}",))
            for i in range(12)
        ))
        candidate = Policy(statements=tuple(
            Statement("Allow", (f"svc:action{i:02d}",), (f"arn:res{i:02d}",))
            for i in range(12)
        ))
        calls = [
            Call(f"svc:action{i % 12:02d}", f"arn:res{i % 12:02d}")
            for i in range(10000)
        ]
        report = verify_candidate(original, candidate, calls)
        self.assertTrue(report.adoptable)

        # Widened candidate must be caught at this scale too.
        widened = Policy(statements=candidate.statements + (
            Statement("Allow", ("svc:action00",), ("arn:res01",)),
        ))
        report2 = verify_candidate(original, widened, calls)
        self.assertFalse(report2.no_new_permissions)
        action, resource = report2.new_permission_example
        self.assertTrue(is_authorized(widened, action, resource))
        self.assertFalse(is_authorized(original, action, resource))


if __name__ == "__main__":
    unittest.main()
