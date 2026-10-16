"""Exhaustive small-scope check of the composition predicate.

The random suites (differential oracle, interleaving, soundness) sample a
large space. This one covers a small space completely: every Restricted
Sequence of 2 or 3 steps over the step actions ``a``, ``b`` and ``*``, with
every combination of persistent marks on steps after the first, against every
history of up to 3 Acts over ``a``, ``b``, ``c`` in every outcome, and every
candidate action. In that space ``model._completes`` must agree with a
brute-force reading of the profile text that enumerates every assignment of
Acts to steps and checks its timing, with no dynamic programming.

Bugs in the predicate's position bookkeeping only show with a particular
mix of persistent steps, repeated actions and failed or open Acts; most
small counterexamples live inside this space (the small-scope hypothesis).
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator

from authzen_composition.model import (
    Act,
    ActOutcome,
    RestrictedSequence,
    SequenceStep,
    _completes,
)
from tests.spec_matcher import step_matches

STEP_ACTIONS = ("a", "b", "*")
ACT_ACTIONS = ("a", "b", "c")
MAX_HISTORY = 3
_TOP = object()


def _matches(step: SequenceStep, act: Act) -> bool:
    # Matching from the profile text (tests/spec_matcher.py), not from
    # SequenceStep.matches, the code under test. An open Act, and a completed
    # one that reported no class, is the conservative top.
    top = act.outcome is ActOutcome.OPEN or not act.result_classes
    classes: list[object] = [_TOP] if top else list(act.result_classes)
    return step_matches(step.action, step.resources, step.result_classes,
                        act.action, act.resource, classes, _TOP)


def brute_force(history: list[Act], cand: Act, seq: RestrictedSequence) -> bool:
    """The profile text: a non-persistent step takes effect at its Act's
    position; a persistent step at that position and every later point; a
    failed Act had no effect; the candidate must be part of the completion."""
    timeline = [a for a in history if a.outcome is not ActOutcome.FAILED] + [cand]
    options = [[a for a in timeline if _matches(s, a)] for s in seq.steps]
    for assignment in itertools.product(*options):
        if not any(a is cand for a in assignment):
            continue
        now = 0.0
        for step, act in zip(seq.steps, assignment, strict=True):
            if step.persistent:
                now = max(float(act.seq), now + 1e-6)
            elif act.seq > now:
                now = float(act.seq)
            else:
                break
        else:
            return True
    return False


def sequences() -> Iterator[RestrictedSequence]:
    for k in (2, 3):
        for actions in itertools.product(STEP_ACTIONS, repeat=k):
            for marks in itertools.product((False, True), repeat=k - 1):
                steps = (SequenceStep(actions[0]),) + tuple(
                    SequenceStep(a, persistent=p)
                    for a, p in zip(actions[1:], marks, strict=True)
                )
                yield RestrictedSequence("s", steps)


def histories() -> Iterator[list[Act]]:
    kinds = list(itertools.product(ACT_ACTIONS, ActOutcome))
    for n in range(MAX_HISTORY + 1):
        for combo in itertools.product(kinds, repeat=n):
            yield [Act(i, a, "r", o) for i, (a, o) in enumerate(combo, start=1)]


def test_predicate_agrees_with_brute_force_on_every_small_case() -> None:
    all_histories = list(histories())
    cases = 0
    mismatches: list[tuple[RestrictedSequence, list[Act], Act, bool]] = []
    for seq in sequences():
        for history in all_histories:
            for action in ACT_ACTIONS:
                cand = Act(len(history) + 1, action, "r", ActOutcome.OPEN)
                got = _completes(history, cand, seq)
                cases += 1
                if got != brute_force(history, cand, seq):
                    mismatches.append((seq, history, cand, got))
    assert cases == 126 * 820 * 3  # the whole space, nothing skipped
    assert mismatches == [], mismatches[:3]
