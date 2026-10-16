"""Whole-system interleaving: many PEP tasks, every step scheduled adversarially.

Each task goes through the PEP protocol one step at a time:
evaluate -> admit at ``expected_seq`` -> effect -> report outcome.
Hypothesis picks which task advances next, so permits go stale, admissions
race, effects land long after admission, outcomes are lost or never sent, and
acts affirmatively fail. Ground truth is the order in which effects actually
happened, with the classes they actually returned.

Invariant: no prohibited sequence is ever realized in effect order, for any
schedule. A second property checks the protocol never wedges a task forever
when every outcome is eventually reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from authzen_composition.mhs import HistoryConflict, MissionHistoryService
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.types import (
    OBLIGATION_MISSION_RECORD,
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)
from tests.spec_matcher import step_matches

ACTIONS = ["read", "write", "send"]
CLASSES = ["pd.salary", "public", "medical.x"]
WRITERS = ["pep.a", "pep.b", "pep.c"]


def _realizes(effects: list[Act], seq: RestrictedSequence) -> bool:
    # Ground truth from the profile text (tests/spec_matcher.py), not from the
    # matching code under test.
    i = 0
    for act in effects:
        s = seq.steps[i] if i < len(seq.steps) else None
        if s is not None and step_matches(s.action, s.resources, s.result_classes, act.action,
                                          act.resource, act.result_classes, top=None):
            i += 1
    return i == len(seq.steps)


@dataclass
class Task:
    writer: str
    action: str
    true_class: str
    fate: str  # "complete" | "fail" | "silent" (effect happens, outcome never sent)
    phase: str = "new"  # new -> permitted -> admitted -> effected -> done
    expected_seq: int | None = None
    seq: int | None = None
    events: list[str] = field(default_factory=list)


step = st.tuples(st.sampled_from([*ACTIONS, "*"]),
                 st.one_of(st.none(), st.sampled_from(["pd.*", "public", "medical.x"])))
sequences = st.lists(step, min_size=2, max_size=3).map(
    lambda steps: RestrictedSequence("s", tuple(
        SequenceStep(a, result_classes=frozenset({c}) if c else frozenset()) for a, c in steps
    ))
)
tasks = st.lists(st.builds(
    Task,
    writer=st.sampled_from(WRITERS),
    action=st.sampled_from(ACTIONS),
    true_class=st.sampled_from(CLASSES),
    fate=st.sampled_from(["complete", "complete", "fail", "silent"]),
), min_size=1, max_size=6)


def _run(seqs, task_list, schedule, lose_acks):
    named = tuple(RestrictedSequence(f"s{i}", s.steps) for i, s in enumerate(seqs))
    policy = CompositionPolicy(named)
    mhs = MissionHistoryService(trusted_writers=frozenset(WRITERS))
    pdp = CompositionPDP(policy, mhs)
    effects: list[Act] = []

    def advance(t: Task, lose: bool) -> None:
        if t.phase == "new":
            d = pdp.evaluate(EvaluationRequest(
                subject=Subject("agent", "a"), action=Action(t.action),
                resource=Resource("r", "r"), mission=Mission("m", "iss"),
                supported_mandatory_extensions=("obligations",),
                supported_obligations=(OBLIGATION_MISSION_RECORD,),
            ))
            if not d.decision:
                return  # denied: stays "new", may be retried later
            ob = next((o for o in d.obligations if o.type == OBLIGATION_MISSION_RECORD), None)
            if ob is None:
                # Matches no step: no admission needed, effect is irrelevant
                # to every sequence, but record it as ground truth anyway.
                effects.append(Act(len(effects) + 1, t.action, "r", ActOutcome.COMPLETED,
                                   frozenset({t.true_class})))
                t.phase = "done"
                return
            t.expected_seq = ob.properties["expected_seq"]
            t.phase = "permitted"
        elif t.phase == "permitted":
            assert t.expected_seq is not None
            try:
                act = mhs.admit("m", t.expected_seq, t.action, "r", writer=t.writer,
                                admission_id=f"{id(t)}")
            except HistoryConflict:
                t.phase = "new"  # stale permit: evaluate again
                return
            if lose:
                # The admission committed but the PEP never saw the ack: it
                # MUST NOT act. It retries with the same admission id next time.
                return
            t.seq = act.seq
            t.phase = "admitted"
        elif t.phase == "admitted":
            if t.fate != "fail":
                effects.append(Act(len(effects) + 1, t.action, "r", ActOutcome.COMPLETED,
                                   frozenset({t.true_class})))
            t.phase = "effected"
        elif t.phase == "effected":
            assert t.seq is not None
            if t.fate == "complete":
                mhs.set_outcome("m", t.seq, ActOutcome.COMPLETED, writer=t.writer,
                                result_classes=frozenset({t.true_class}),
                                admission_id=f"{id(t)}")
            elif t.fate == "fail":
                mhs.set_outcome("m", t.seq, ActOutcome.FAILED, writer=t.writer,
                                admission_id=f"{id(t)}")
            t.phase = "done"  # "silent" never reports: the act stays open

    for pick, lose in zip(schedule, lose_acks, strict=False):
        live = [t for t in task_list if t.phase != "done"]
        if not live:
            break
        advance(live[pick % len(live)], lose)
    # Drain: every task that can still make progress does.
    for _ in range(len(task_list) * 8):
        for t in task_list:
            if t.phase != "done":
                advance(t, False)
    return named, effects, task_list, mhs


@settings(max_examples=1500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(seqs=st.lists(sequences, min_size=1, max_size=3), task_list=tasks,
       schedule=st.lists(st.integers(0, 5), min_size=12, max_size=40),
       lose_acks=st.lists(st.booleans(), min_size=12, max_size=40))
def test_no_schedule_realizes_a_prohibited_sequence_in_effect_order(
        seqs, task_list, schedule, lose_acks) -> None:
    named, effects, _, mhs = _run(seqs, task_list, schedule, lose_acks)
    for seq in named:
        assert not _realizes(effects, seq), (seq, effects, mhs.history("m"))
    # The history never has a gap and every act was written by a trusted PEP.
    hist = mhs.history("m")
    assert [a.seq for a in hist] == list(range(1, len(hist) + 1))
    assert {mhs.recorded_by("m", a.seq) for a in hist} <= set(WRITERS)


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(seqs=st.lists(sequences, min_size=1, max_size=3),
       task_list=tasks.map(lambda ts: [Task(t.writer, t.action, t.true_class,
                                            "fail" if t.fate == "fail" else "complete")
                                       for t in ts]),
       schedule=st.lists(st.integers(0, 5), min_size=12, max_size=40))
def test_no_task_is_held_back_forever_when_outcomes_arrive(seqs, task_list, schedule) -> None:
    # Liveness of rule 5: with every outcome eventually reported, a task is
    # only ever stuck because the predicate itself prohibits it.
    named, _, final, mhs = _run(seqs, task_list, schedule, [])
    policy = CompositionPolicy(named)
    hist = mhs.history("m")
    assert all(a.outcome is not ActOutcome.OPEN for a in hist)
    for t in final:
        if t.phase != "done":
            assert t.phase == "new"
            cand = Act(len(hist) + 1, t.action, "r", ActOutcome.OPEN)
            assert not policy.completes(hist, cand).satisfied
