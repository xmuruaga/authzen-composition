"""Differential test: the PDP against an independent brute-force oracle.

The oracle is written from the profile text alone, without reusing any code
from ``authzen_composition.model``: it enumerates every ordered subsequence of
the history with ``itertools.combinations`` (no greedy scan), applies the
conservative top class by class, and derives the full decision (reason,
obligation, opt-in) from the profile's rules. Any disagreement with the PDP on
any generated case is a defect in one of them.
"""

from __future__ import annotations

import itertools
from dataclasses import replace

from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.types import Action, EvaluationRequest, Mission, Resource, Subject
from tests.spec_matcher import pattern_matches, step_matches

ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint

TOP = object()  # the oracle's own conservative top
ACTIONS = ["read", "write", "send", "re*"]  # "re*" is a literal action name
RESOURCES = ["int:a", "ext:b", "ext:c", "ext", "*"]
# No bare `*`: a set that names it is refused, since every class would then be
# recognized and none would be the conservative top (profile, Result classes).
CLASS_PATTERNS = ["pd.salary", "pd.*", "pd*", "public"]
CLASSES = ["pd.salary", "pd.health", "pd", "pdx", "public", "medical.x"]


def class_ok(pattern: str, cls: object) -> bool:
    return cls is TOP or (isinstance(cls, str) and pattern_matches(pattern, cls))


def effective(act: Act, vocab: list[str]) -> set[object] | None:
    """None for a failed act (never part of a subsequence)."""
    if act.outcome is ActOutcome.FAILED:
        return None
    if act.outcome is ActOutcome.OPEN or not act.result_classes:
        return {TOP}
    return {c if any(class_ok(p, c) for p in vocab) else TOP for c in act.result_classes}


def step_ok(step: SequenceStep, act: Act, vocab: list[str]) -> bool:
    eff = effective(act, vocab)
    if eff is None:
        return False
    return step_matches(step.action, step.resources, step.result_classes,
                        act.action, act.resource, eff, TOP)


def steps_matched(seq: RestrictedSequence, act: Act, vocab: list[str]) -> set[int]:
    return {i for i, s in enumerate(seq.steps) if step_ok(s, act, vocab)}


def oracle_decision(policy: CompositionPolicy, history: list[Act], cand: Act,
                    opted_in: bool, approved: bool = False
                    ) -> tuple[bool, str | None, bool, bool]:
    """(permit, reason, has_mission_record_obligation, requestable) from the
    profile. ``approved``: the request carries a valid approval of this act at
    this position."""
    vocab = [p for s in policy.sequences for st_ in s.steps for p in st_.result_classes]
    # Predicate, from the text: some sequence completed in Admission Order
    # with the candidate in it. A non-persistent step takes effect at its
    # Act's position; a persistent step at that position "and at every later
    # point of the Mission". Enumerate every assignment of Acts to steps
    # (no dynamic programming), then check the timing is feasible.
    timeline = [*history, cand]
    completed = []
    for seq in policy.sequences:
        options = [[a for a in timeline if step_ok(s, a, vocab)] for s in seq.steps]
        for assignment in itertools.product(*options):
            if not any(a is cand for a in assignment):
                continue
            now = 0.0
            feasible = True
            for step, act in zip(seq.steps, assignment, strict=True):
                if step.persistent:
                    # Effective from its own position on: the earliest moment
                    # after `now` at which it is in effect.
                    now = max(float(act.seq), now + 1e-6)
                elif act.seq > now:
                    now = float(act.seq)
                else:
                    feasible = False
                    break
            if feasible:
                completed.append(seq)
                break
    # "requestable when policy allows a person to approve every Restricted
    # Sequence the Act would complete", and only to a PEP that adopted
    # mission_record
    requestable = bool(completed) and all(s.requestable for s in completed) and opted_in
    if completed and not (approved and requestable):
        return (False, "prohibited_composition", False, requestable)
    # Effect order (rule 5): an open act of the same sequence holds it back,
    # unless both match exactly one and the same step.
    for seq in policy.sequences:
        mine = steps_matched(seq, cand, vocab)
        if not mine:
            continue
        for act in history:
            if act.outcome is not ActOutcome.OPEN:
                continue
            theirs = steps_matched(seq, act, vocab)
            if theirs and not (theirs == mine and len(mine) == 1):
                return (False, "history_pending", False, False)
    serialized = any(steps_matched(s, cand, vocab) for s in policy.sequences)
    if serialized and not opted_in:
        return (False, None, False, False)
    return (True, None, serialized, False)


step_strategy = st.builds(
    SequenceStep,
    action=st.sampled_from([*ACTIONS, "*", "re*", "s*"]),
    resources=st.frozensets(st.sampled_from(["ext:*", "int:a", "ext:b", "ext*", "*"]), max_size=2),
    result_classes=st.frozensets(st.sampled_from(CLASS_PATTERNS), max_size=2),
    persistent=st.sampled_from([False, False, True]),
)
sequence_strategy = st.builds(
    lambda steps, req: RestrictedSequence(
        "s", (replace(steps[0], persistent=False), *steps[1:]), requestable=req),
    st.lists(step_strategy, min_size=2, max_size=3), st.booleans(),
)
act_strategy = st.tuples(
    st.sampled_from(ACTIONS),
    st.sampled_from(RESOURCES),
    st.sampled_from(list(ActOutcome)),
    st.frozensets(st.sampled_from(CLASSES), max_size=3),
)


@settings(max_examples=1500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    seqs=st.lists(sequence_strategy, min_size=1, max_size=3),
    acts=st.lists(act_strategy, max_size=6),
    cand=st.tuples(st.sampled_from(ACTIONS), st.sampled_from(RESOURCES)),
    opted_in=st.booleans(),
)
# A recognized class does not make an unknown class of the same act harmless.
@example(
    seqs=[
        RestrictedSequence("s", (SequenceStep("read", result_classes=frozenset({"pd.*"})),
                                 SequenceStep("send"))),
        RestrictedSequence("s", (SequenceStep("read", result_classes=frozenset({"public"})),
                                 SequenceStep("write"))),
    ],
    acts=[("read", "int:a", ActOutcome.COMPLETED, frozenset({"public", "medical.x"}))],
    cand=("send", "ext:b"),
    opted_in=True,
)
def test_pdp_agrees_with_brute_force_oracle(seqs, acts, cand, opted_in) -> None:
    named = tuple(
        RestrictedSequence(f"s{i}", s.steps, s.requestable) for i, s in enumerate(seqs)
    )
    policy = CompositionPolicy(named)
    mhs = MissionHistoryService()
    history: list[Act] = []
    for i, (action, resource, outcome, classes) in enumerate(acts, start=1):
        mhs.admit("m", i, action, resource, writer="w")
        recorded = classes if outcome is ActOutcome.COMPLETED else frozenset()
        if outcome is not ActOutcome.OPEN:
            mhs.set_outcome("m", i, outcome, writer="w", result_classes=recorded)
        history.append(Act(i, action, resource, outcome, recorded))

    pdp = CompositionPDP(policy, mhs, access_request_endpoint=ARS)

    def request(approval: dict | None = None) -> EvaluationRequest:
        return EvaluationRequest(
            subject=Subject("agent", "a"), action=Action(cand[0]),
            resource=Resource("r", cand[1]), mission=Mission("m", "iss"),
            supported_mandatory_extensions=("obligations",) if opted_in else (),
            supported_obligations=("mission_record",),
            context={"approval": approval} if approval else {},
        )

    candidate = Act(len(history) + 1, cand[0], cand[1], ActOutcome.OPEN)
    decision = pdp.evaluate(request())
    permit, reason, obliged, requestable = oracle_decision(policy, history, candidate, opted_in)

    assert decision.decision is permit
    assert decision.reason == reason
    assert bool(decision.obligations) is obliged
    if obliged:
        (ob,) = decision.obligations
        assert ob.properties == {"mission": "m", "expected_seq": candidate.seq}
    # ARAP: requestable exactly when every completed sequence is approvable
    # and the PEP adopted mission_record.
    assert (decision.access_request is not None) is requestable
    assert (decision.evaluation_id is not None) is requestable
    if requestable:
        assert decision.evaluation_id is not None
        approval = pdp.approve(decision.evaluation_id)
        again = pdp.evaluate(request(approval))
        a_permit, a_reason, a_obliged, _ = oracle_decision(
            policy, history, candidate, opted_in, approved=True)
        assert (again.decision, again.reason, bool(again.obligations)) == (
            a_permit, a_reason, a_obliged)
