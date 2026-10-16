"""Exhaustive small-scope check of rule 5 (effect order) and of variants.

Every protocol schedule of up to three Acts (evaluate and admit, effect,
report outcome, in any interleaving) against every Restricted Sequence of two
or three steps over actions {a, b}, class patterns {none, p.*, f.*}, with a
persistent last step or not: 504 sequences, 34 sets of Acts. Each Act has an
action and a true class (p.x or f.x). Ground truth is the order the effects
happened, with the true classes, checked by brute force from the profile text
(a persistent step takes effect at its effect time and at every later point).
A variant is unsound if some schedule realizes the sequence in effect order.
Scope: no resource patterns, so an open Act's and a candidate's step sets are
either equal or disjoint here.

    PYTHONPATH=. python tools/rule5_exhaustive.py [variant ...]   # about 10 min each

Variants: profile (rule 5 as written), relaxed (also let a candidate through
when every step it could fill comes after every step the open Act could fill;
profile open question 11), equal_sets (an unsound control: equal step sets of
any size commute), none (rule 5 off, a control that must leak).
"""

from __future__ import annotations

import itertools
import sys
from collections.abc import Callable, Iterator

from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
    _step_set,
)

Exempt = Callable[[frozenset[int], frozenset[int]], bool]
VARIANTS: dict[str, Exempt | None] = {
    "profile": lambda t, m: t == m and len(m) == 1,
    "relaxed": lambda t, m: (t == m and len(m) == 1) or max(t) < min(m),
    "equal_sets": lambda t, m: t == m,
    "none": None,
}


def held(policy: CompositionPolicy, history: list[Act], cand: Act, exempt: Exempt | None) -> bool:
    if exempt is None:
        return False
    c = policy._normalize(cand)
    for seq in policy.sequences:
        mine = _step_set(seq, c)
        if not mine:
            continue
        for act in history:
            if act.outcome is ActOutcome.OPEN:
                theirs = _step_set(seq, policy._normalize(act))
                if theirs and not exempt(theirs, mine):
                    return True
    return False


def realized(effects: list[tuple[str, str]], seq: RestrictedSequence) -> bool:
    timeline = [Act(i, a, "r", ActOutcome.COMPLETED, frozenset({c}))
                for i, (a, c) in enumerate(effects, start=1)]
    options = [[a for a in timeline if s.matches(a)] for s in seq.steps]
    for assignment in itertools.product(*options):
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
    step_opts = [(a, c) for a in ("a", "b") for c in (None, "p.*", "f.*")]
    for k in (2, 3):
        for steps in itertools.product(step_opts, repeat=k):
            for last_persistent in (False, True):
                yield RestrictedSequence("s", tuple(
                    SequenceStep(a, result_classes=frozenset({c}) if c else frozenset(),
                                 persistent=last_persistent and i == k - 1)
                    for i, (a, c) in enumerate(steps)))


TASK_KINDS = [(a, c) for a in ("a", "b") for c in ("p.x", "f.x")]


def check(seq: RestrictedSequence, tasks: tuple[tuple[str, str], ...],
          exempt: Exempt | None) -> list[str] | None:
    policy = CompositionPolicy((seq,))
    n = len(tasks)

    def dfs(phase: tuple[int, ...], hist: tuple[tuple[str, str, int], ...],
            effects: tuple[tuple[str, str], ...], trace: tuple[str, ...]) -> list[str] | None:
        # phase: 0 new, 1 admitted (open), 2 effected (open), 3 reported
        # hist entries: (action, true class, task index)
        if realized(list(effects), seq):
            return list(trace)
        for i in range(n):
            a, c = tasks[i]
            if phase[i] == 0:
                history = [Act(j + 1, h[0], "r",
                               ActOutcome.COMPLETED if phase[h[2]] == 3 else ActOutcome.OPEN,
                               frozenset({h[1]}) if phase[h[2]] == 3 else frozenset())
                           for j, h in enumerate(hist)]
                cand = Act(len(hist) + 1, a, "r", ActOutcome.OPEN)
                if not policy.completes(history, cand).satisfied:
                    continue
                if held(policy, history, cand, exempt):
                    continue
                if not policy.can_extend_prefix(cand):
                    # Not serialized: its effect is immediate and irrelevant.
                    nxt = (*phase[:i], 3, *phase[i + 1:])
                    got = dfs(nxt, hist, (*effects, (a, c)), (*trace, f"{a}/{c} unserialized"))
                else:
                    nxt = (*phase[:i], 1, *phase[i + 1:])
                    got = dfs(nxt, (*hist, (a, c, i)), effects, (*trace, f"admit {a}/{c}"))
            elif phase[i] == 1:
                nxt = (*phase[:i], 2, *phase[i + 1:])
                got = dfs(nxt, hist, (*effects, (a, c)), (*trace, f"effect {a}/{c}"))
            elif phase[i] == 2:
                nxt = (*phase[:i], 3, *phase[i + 1:])
                got = dfs(nxt, hist, effects, (*trace, f"report {a}/{c}"))
            else:
                continue
            if got is not None:
                return got
        return None

    return dfs((0,) * n, (), (), ())


def main() -> None:
    names = sys.argv[1:] or list(VARIANTS)
    seqs = list(sequences())
    multisets = [t for n in (1, 2, 3)
                 for t in itertools.combinations_with_replacement(TASK_KINDS, n)]
    for name in names:
        exempt = VARIANTS[name]
        cases, leak = 0, None
        for seq in seqs:
            for tasks in multisets:
                cases += 1
                trace = check(seq, tasks, exempt)
                if trace is not None:
                    leak = (seq, tasks, trace)
                    break
            if leak:
                break
        if leak:
            seq, tasks, trace = leak
            steps = [(s.action, sorted(s.result_classes), s.persistent) for s in seq.steps]
            print(f"{name}: LEAK after {cases} cases: steps {steps}, tasks {tasks}: {trace}")
        else:
            print(f"{name}: no schedule realizes the sequence in effect order "
                  f"({cases} cases: {len(seqs)} sequences x {len(multisets)} task sets, "
                  f"every schedule)")


if __name__ == "__main__":
    main()
