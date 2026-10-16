"""Property test for the composition-soundness theorem.

Bounded Agents proves: an enforcement mechanism that denies any act completing
a prohibited ordered tuple, as an ordered subsequence of the session history,
admits no sequence that realizes a prohibited tuple, given a complete restriction
set and serialized admission.

The tests below generate random Missions and Restricted Sequences, drive
every act through the PDP and the MHS (which enforce the predicate and
serialize admission), and check that no admitted history contains a
prohibited sequence as an ordered subsequence.
"""

from __future__ import annotations

import itertools

from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
    _completes,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.types import Action, EvaluationRequest, Mission, Resource, Subject
from tests.spec_matcher import step_matches

ACTIONS = ["read", "write", "send", "copy", "delete"]
_TOP = object()  # a classless act counts as the conservative top
S = Subject("agent", "a")


def _is_subsequence(history: list[Act], seq: RestrictedSequence) -> bool:
    """True if the full sequence appears as an ordered subsequence of history."""
    idx = 0
    for act in sorted(history, key=lambda a: a.seq):
        if idx >= len(seq.steps):
            break
        s = seq.steps[idx]
        # Ground truth from the profile text, not from the code under test.
        if act.outcome is not ActOutcome.FAILED and step_matches(
            s.action, s.resources, s.result_classes, act.action, act.resource,
            act.result_classes or {_TOP}, top=_TOP,
        ):
            idx += 1
    return idx >= len(seq.steps)


def _seq_from_actions(actions: list[str]) -> RestrictedSequence:
    return RestrictedSequence(name="r", steps=tuple(SequenceStep(a) for a in actions))


restricted_sequences = st.lists(
    st.sampled_from(ACTIONS), min_size=2, max_size=3
).map(_seq_from_actions)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    seqs=st.lists(restricted_sequences, min_size=1, max_size=3),
    attempts=st.lists(st.sampled_from(ACTIONS), min_size=1, max_size=12),
)
def test_no_prohibited_subsequence_is_ever_admitted(seqs, attempts) -> None:
    policy = CompositionPolicy(tuple(seqs))
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy, mhs)

    for action in attempts:
        history = mhs.history("m")
        candidate = Act(len(history) + 1, action, "r", ActOutcome.OPEN)
        verdict = policy.completes(history, candidate)
        req = EvaluationRequest(
            subject=S, action=Action(action), resource=Resource("r", "r"),
            mission=Mission("m", "iss"),
            supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",),
        )
        decision = pdp.evaluate(req)
        # The PDP's decision must agree with the predicate.
        assert decision.decision == verdict.satisfied
        if decision.decision:
            # Admit it (serialized at the next position), mark completed.
            mhs.admit("m", candidate.seq, action, "r", writer="w")
            mhs.set_outcome("m", candidate.seq, ActOutcome.COMPLETED, writer="w")

    # Invariant: no prohibited sequence is an ordered subsequence of the
    # admitted history.
    final = mhs.history("m")
    for seq in seqs:
        assert not _is_subsequence(final, seq), (
            f"admitted history realizes prohibited sequence {seq.name}"
        )


@settings(max_examples=100, deadline=None)
@given(attempts=st.lists(st.sampled_from(ACTIONS), min_size=2, max_size=8))
def test_completes_matches_full_subsequence_check(attempts) -> None:
    # Cross-check the incremental _completes against a full subsequence scan.
    seq = RestrictedSequence("r", (SequenceStep("read"), SequenceStep("send")))
    history = [Act(i + 1, a, "r", ActOutcome.COMPLETED) for i, a in enumerate(attempts[:-1])]
    candidate = Act(len(history) + 1, attempts[-1], "r", ActOutcome.COMPLETED)
    incremental = _completes(history, candidate, seq)
    full = _is_subsequence(history + [candidate], seq) and seq.steps[-1].matches(candidate)
    assert incremental == full


# --- Refined alphabet: result classes, open and failed outcomes --------------
#
# Ground truth is what actually executed, with the classes it actually
# returned. What the PDP sees may lag or be less precise: an outcome may be
# unreported (OPEN), or the act may have affirmatively not run (FAILED). The
# invariant: no prohibited sequence is ever realized by the executed acts with
# their true classes, taken in admission order.

CLASSES = ["pd.salary", "pd.health", "public"]


def _class_step(action: str, cls: str | None) -> SequenceStep:
    if cls is None:
        return SequenceStep(action)
    return SequenceStep(action, result_classes=frozenset({cls.split(".")[0] + ".*"}))


class_steps = st.tuples(st.sampled_from(ACTIONS), st.one_of(st.none(), st.sampled_from(CLASSES)))
class_sequences = st.lists(class_steps, min_size=2, max_size=3).map(
    lambda steps: RestrictedSequence("r", tuple(_class_step(a, c) for a, c in steps))
)
# (action, true class returned, how the outcome is reported)
attempt = st.tuples(
    st.sampled_from(ACTIONS),
    st.sampled_from(CLASSES),
    st.sampled_from(["completed", "open", "failed"]),
)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(seqs=st.lists(class_sequences, min_size=1, max_size=3),
       attempts=st.lists(attempt, min_size=1, max_size=12))
def test_soundness_with_result_classes_and_partial_outcomes(seqs, attempts) -> None:
    policy = CompositionPolicy(tuple(seqs))
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy, mhs)
    executed: list[Act] = []  # ground truth

    for action, true_cls, report in attempts:
        req = EvaluationRequest(
            subject=S, action=Action(action), resource=Resource("r", "r"),
            mission=Mission("m", "iss"),
            supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",),
        )
        decision = pdp.evaluate(req)
        if not decision.decision:
            continue
        seq_no = len(mhs.history("m")) + 1
        mhs.admit("m", seq_no, action, "r", writer="w")
        if report == "failed":
            mhs.set_outcome("m", seq_no, ActOutcome.FAILED, writer="w")
            continue  # did not execute
        executed.append(Act(seq_no, action, "r", ActOutcome.COMPLETED, frozenset({true_cls})))
        if report == "completed":
            mhs.set_outcome("m", seq_no, ActOutcome.COMPLETED, writer="w",
                            result_classes=frozenset({true_cls}))
        # "open": effect happened, outcome never reported

    for seq in seqs:
        assert not _is_subsequence(executed, seq), (
            f"executed acts realize prohibited sequence {seq}"
        )


# --- Effect order: admitted acts finish at arbitrary later times -------------
#
# Each admitted act produces its effect only when a later "finish" op picks it,
# so effects can land in any order relative to admission. Ground truth is the
# EFFECT order with true classes. Invariant: no prohibited sequence is ever
# realized in effect order.

op = st.one_of(
    st.tuples(st.just("start"), st.sampled_from(ACTIONS), st.sampled_from(CLASSES)),
    st.tuples(st.just("finish"), st.integers(min_value=0, max_value=7), st.just("")),
)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(seqs=st.lists(class_sequences, min_size=1, max_size=3),
       ops=st.lists(op, min_size=1, max_size=16))
# The stalled send: a send is admitted and still in flight when a read is
# admitted, and the read lands first. Without rule 5 this realizes (read,
# send) in effect order every time; the random examples find it only sometimes.
@example(seqs=[RestrictedSequence("r", (SequenceStep("read"), SequenceStep("send")))],
         ops=[("start", "send", "public"), ("start", "read", "public"), ("finish", 1, "")])
def test_soundness_in_effect_order_with_delayed_effects(seqs, ops) -> None:
    policy = CompositionPolicy(tuple(seqs))
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy, mhs)
    in_flight: list[tuple[int, str, str]] = []  # (seq, action, true class)
    effects: list[Act] = []

    def finish(i: int) -> None:
        seq_no, action, cls = in_flight.pop(i)
        effects.append(Act(len(effects) + 1, action, "r", ActOutcome.COMPLETED,
                           frozenset({cls})))
        mhs.set_outcome("m", seq_no, ActOutcome.COMPLETED, writer="w",
                        result_classes=frozenset({cls}))

    for kind, a, b in ops:
        if kind == "finish":
            if in_flight:
                finish(int(a) % len(in_flight))
            continue
        req = EvaluationRequest(
            subject=S, action=Action(str(a)), resource=Resource("r", "r"),
            mission=Mission("m", "iss"),
            supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",),
        )
        if not pdp.evaluate(req).decision:
            continue
        seq_no = len(mhs.history("m")) + 1
        mhs.admit("m", seq_no, str(a), "r", writer="w")
        in_flight.append((seq_no, str(a), b))
    while in_flight:
        finish(0)

    for seq in seqs:
        assert not _is_subsequence(effects, seq), (
            f"effects realize prohibited sequence {seq}"
        )


# --- Effect order with resource patterns -------------------------------------
#
# The effect-order test above never restricts steps by resource. Same
# invariant, with steps that may carry a resource pattern
# (exact id or a prefix glob) and acts on several resources.

RESOURCES = ["hr/salaries", "hr/reviews", "out/mail", "doc/q4"]
RESOURCE_PATTERNS = ["hr/*", "out/*", "doc/q4", "hr/salaries"]


def _res_step(action: str, pattern: str | None, cls: str | None) -> SequenceStep:
    return SequenceStep(
        action,
        resources=frozenset() if pattern is None else frozenset({pattern}),
        result_classes=frozenset() if cls is None else frozenset({cls.split(".")[0] + ".*"}),
    )


res_steps = st.tuples(
    st.sampled_from(ACTIONS),
    st.one_of(st.none(), st.sampled_from(RESOURCE_PATTERNS)),
    st.one_of(st.none(), st.sampled_from(CLASSES)),
)
res_sequences = st.lists(res_steps, min_size=2, max_size=3).map(
    lambda steps: RestrictedSequence("r", tuple(_res_step(*s) for s in steps))
)
res_op = st.one_of(
    st.tuples(st.just("start"), st.sampled_from(ACTIONS), st.sampled_from(RESOURCES),
              st.sampled_from(CLASSES)),
    st.tuples(st.just("finish"), st.integers(min_value=0, max_value=7), st.just(""),
              st.just("")),
)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(seqs=st.lists(res_sequences, min_size=1, max_size=3),
       ops=st.lists(res_op, min_size=1, max_size=24))
def test_soundness_in_effect_order_with_resource_patterns(seqs, ops) -> None:
    policy = CompositionPolicy(tuple(seqs))
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy, mhs)
    in_flight: list[tuple[int, str, str, str]] = []  # (seq, action, resource, class)
    effects: list[Act] = []

    def finish(i: int) -> None:
        seq_no, action, res, cls = in_flight.pop(i)
        effects.append(Act(len(effects) + 1, action, res, ActOutcome.COMPLETED,
                           frozenset({cls})))
        mhs.set_outcome("m", seq_no, ActOutcome.COMPLETED, writer="w",
                        result_classes=frozenset({cls}))

    for kind, a, res, cls in ops:
        if kind == "finish":
            if in_flight:
                finish(int(a) % len(in_flight))
            continue
        req = EvaluationRequest(
            subject=S, action=Action(str(a)), resource=Resource("doc", str(res)),
            mission=Mission("m", "iss"),
            supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",),
        )
        if not pdp.evaluate(req).decision:
            continue
        seq_no = len(mhs.history("m")) + 1
        mhs.admit("m", seq_no, str(a), str(res), writer="w")
        in_flight.append((seq_no, str(a), str(res), str(cls)))
    while in_flight:
        finish(0)

    for seq in seqs:
        assert not _is_subsequence(effects, seq), (
            f"effects realize prohibited sequence {seq}"
        )


# --- Effect order with persistent steps -------------------------------------
#
# A persistent step (a share link, a forwarding rule, a webhook) stays in
# effect from the moment its effect lands. Ground truth: a sequence is
# realized if its steps can be given strictly increasing effect times, where a
# persistent step may use any time at or after its act's effect.

def _realized_with_persistence(effects: list[Act], seq: RestrictedSequence) -> bool:

    def ok(step: SequenceStep, act: Act) -> bool:
        return step_matches(step.action, step.resources, step.result_classes,
                            act.action, act.resource, act.result_classes or {_TOP},
                            top=_TOP)

    options = [[a for a in effects if ok(s, a)] for s in seq.steps]
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


persist_steps = st.tuples(
    st.sampled_from(ACTIONS),
    st.one_of(st.none(), st.sampled_from(RESOURCE_PATTERNS)),
    st.one_of(st.none(), st.sampled_from(CLASSES)),
    st.sampled_from([False, False, True]),
)
persist_sequences = st.lists(persist_steps, min_size=2, max_size=3).map(
    lambda steps: RestrictedSequence("r", tuple(
        SequenceStep(a, frozenset() if p is None else frozenset({p}),
                     frozenset() if c is None else frozenset({c.split(".")[0] + ".*"}),
                     persistent=pers and i > 0)
        for i, (a, p, c, pers) in enumerate(steps)))
)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(seqs=st.lists(persist_sequences, min_size=1, max_size=3),
       ops=st.lists(res_op, min_size=1, max_size=24))
def test_soundness_in_effect_order_with_persistent_steps(seqs, ops) -> None:
    policy = CompositionPolicy(tuple(seqs))
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy, mhs)
    in_flight: list[tuple[int, str, str, str]] = []
    effects: list[Act] = []  # seq = effect time

    def finish(i: int) -> None:
        seq_no, action, res, cls = in_flight.pop(i)
        effects.append(Act(len(effects) + 1, action, res, ActOutcome.COMPLETED,
                           frozenset({cls})))
        mhs.set_outcome("m", seq_no, ActOutcome.COMPLETED, writer="w",
                        result_classes=frozenset({cls}))

    for kind, a, res, cls in ops:
        if kind == "finish":
            if in_flight:
                finish(int(a) % len(in_flight))
            continue
        req = EvaluationRequest(
            subject=S, action=Action(str(a)), resource=Resource("doc", str(res)),
            mission=Mission("m", "iss"),
            supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",),
        )
        if not pdp.evaluate(req).decision:
            continue
        seq_no = len(mhs.history("m")) + 1
        mhs.admit("m", seq_no, str(a), str(res), writer="w")
        in_flight.append((seq_no, str(a), str(res), str(cls)))
    while in_flight:
        finish(0)

    for seq in seqs:
        assert not _realized_with_persistence(effects, seq), (
            f"effects realize prohibited sequence {seq}"
        )
