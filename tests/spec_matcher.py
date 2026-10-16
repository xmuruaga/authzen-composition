"""Step matching written from the profile text ("Step patterns"), not from code.

Used as ground truth by the differential oracle and the interleaving suite, so
a defect in ``authzen_composition.model`` cannot hide itself by also being in
the checker. Nothing here imports the matching code under test.
"""

from __future__ import annotations

from collections.abc import Iterable


def pattern_matches(pattern: str, value: str) -> bool:
    """'A pattern that does not end in * matches exactly that string. A pattern
    that ends in * matches every string that begins with the text before the *.'"""
    if pattern[-1:] == "*":
        prefix = pattern[:-1]
        return value[: len(prefix)] == prefix
    return value == pattern


def step_matches(action_pattern: str, resource_patterns: Iterable[str],
                 class_patterns: Iterable[str], action: str, resource: str,
                 classes: Iterable[object], top: object) -> bool:
    """'An empty set matches every value. An Act matches the step when its
    action matches the action pattern, its resource matches at least one
    resource pattern, and one of its result classes matches at least one class
    pattern.' ``top`` stands for the conservative top, which matches every
    class pattern."""
    resource_patterns = list(resource_patterns)
    class_patterns = list(class_patterns)
    if not pattern_matches(action_pattern, action):
        return False
    if resource_patterns and not any(pattern_matches(p, resource) for p in resource_patterns):
        return False
    if class_patterns:
        return any(
            c is top or (isinstance(c, str) and pattern_matches(p, c))
            for c in classes for p in class_patterns
        )
    return True
