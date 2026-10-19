"""Metamorphic tests: relations that must hold between two evaluations.

Each test builds a case, transforms it in a way the profile says cannot make
the PDP more permissive (or cannot change the decision at all), and checks the
relation. They find defects that a single expected output cannot, because they
need no oracle for the expected decision.
"""

from __future__ import annotations

from dataclasses import replace

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import (
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.types import Action, EvaluationRequest, Mission, Resource, Subject
from tests.test_differential_oracle import (
    ACTIONS,
    RESOURCES,
    act_strategy,
    sequence_strategy,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
NOISE = "zz_noise"  # matches no generated action pattern ("*" excluded below)
SETTINGS = settings(max_examples=400, deadline=None,
                    suppress_health_check=[HealthCheck.too_slow])


DOMAIN = frozenset({"pd.*", "public"})  # the deployment's declared label domain


def _decide(seqs, acts, cand, domain=DOMAIN):  # noqa: ANN001, ANN202
    policy = CompositionPolicy(tuple(
        RestrictedSequence(f"s{i}", s.steps, s.requestable) for i, s in enumerate(seqs)),
        label_domain=domain)
    mhs = MissionHistoryService()
    for i, (action, resource, outcome, classes) in enumerate(acts, start=1):
        mhs.admit("m", i, action, resource, writer="w")
        if outcome is not ActOutcome.OPEN:
            mhs.set_outcome("m", i, outcome, writer="w",
                            result_classes=classes if outcome is ActOutcome.COMPLETED
                            else frozenset())
    d = CompositionPDP(policy, mhs).evaluate(EvaluationRequest(
        subject=Subject("agent", "a"), action=Action(cand[0]), resource=Resource("r", cand[1]),
        mission=Mission("m", ISSUER), supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",)))
    return d.decision, d.reason


def _no_star_action(seqs) -> bool:  # noqa: ANN001
    return all(not step.action.startswith(("*", "z")) for s in seqs for step in s.steps)


cands = st.tuples(st.sampled_from(ACTIONS), st.sampled_from(RESOURCES))
seq_lists = st.lists(sequence_strategy, min_size=1, max_size=3)
act_lists = st.lists(act_strategy, max_size=5)


@SETTINGS
@given(seqs=seq_lists, acts=act_lists, cand=cands, where=st.integers(0, 5),
       outcome=st.sampled_from(list(ActOutcome)))
def test_an_act_matching_no_step_never_changes_the_decision(seqs, acts, cand, where,
                                                           outcome) -> None:
    if not _no_star_action(seqs):
        return
    noisy = list(acts)
    noisy.insert(min(where, len(noisy)), (NOISE, "r", outcome, frozenset({"public"})))
    assert _decide(seqs, noisy, cand) == _decide(seqs, acts, cand)


@settings(max_examples=3000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(seqs=seq_lists, extra=seq_lists, acts=act_lists, cand=cands)
def test_adding_sequences_never_permits_more(seqs, extra, acts, cand) -> None:
    # 3000 examples, since violations are rare;
    # test_derived_label_domain_is_not_monotone below pins a counterexample.
    permit_more, _ = _decide([*seqs, *extra], acts, cand)
    permit_less, _ = _decide(seqs, acts, cand)
    assert not (permit_more and not permit_less)


@SETTINGS
@given(seqs=seq_lists, acts=act_lists, cand=cands, which=st.integers(0, 4))
def test_an_unreported_outcome_is_never_more_permissive(seqs, acts, cand, which) -> None:
    if not acts:
        return
    i = which % len(acts)
    if acts[i][2] is not ActOutcome.COMPLETED:
        return
    reported, _ = _decide(seqs, acts, cand)
    unreported_acts = list(acts)
    unreported_acts[i] = (acts[i][0], acts[i][1], ActOutcome.OPEN, frozenset())
    unreported, _ = _decide(seqs, unreported_acts, cand)
    assert not (unreported and not reported)


@SETTINGS
@given(seqs=seq_lists, acts=act_lists, cand=cands, which=st.integers(0, 8))
def test_marking_a_step_persistent_never_permits_more(seqs, acts, cand, which) -> None:
    flat = [(si, ti) for si, s in enumerate(seqs) for ti in range(1, len(s.steps))]
    si, ti = flat[which % len(flat)]
    target = seqs[si]
    steps = list(target.steps)
    steps[ti] = replace(steps[ti], persistent=True)
    marked = list(seqs)
    marked[si] = RestrictedSequence(target.name, tuple(steps), target.requestable)
    permit_marked, _ = _decide(marked, acts, cand)
    permit_plain, _ = _decide(seqs, acts, cand)
    assert not (permit_marked and not permit_plain)


@SETTINGS
@given(seqs=seq_lists, acts=act_lists, cand=cands)
def test_failed_acts_are_as_if_never_admitted(seqs, acts, cand) -> None:
    # Positions shift, so compare decision and reason only.
    kept = [a for a in acts if a[2] is not ActOutcome.FAILED]
    assert _decide(seqs, acts, cand) == _decide(seqs, kept, cand)


# With the label domain derived from the steps, an unrelated sequence that
# names a class narrows the top for every other one.
_A = RestrictedSequence("a", (SequenceStep("write", result_classes=frozenset({"public"})),
                              SequenceStep("write")))
_B = RestrictedSequence("b", (SequenceStep("read"),
                              SequenceStep("read", result_classes=frozenset({"pd.salary"}))))
_ACTS = [("write", "int:a", ActOutcome.COMPLETED, frozenset({"pd.salary"}))]


def test_derived_label_domain_is_not_monotone() -> None:
    # Documents why the profile makes the label domain explicit.
    assert _decide([_A], _ACTS, ("write", "int:a"), domain=None)[0] is False
    assert _decide([_A, _B], _ACTS, ("write", "int:a"), domain=None)[0] is True


def test_declared_label_domain_is_monotone_on_the_counterexample() -> None:
    # pd.salary is in the domain and is not `public`: both policies permit.
    assert _decide([_A], _ACTS, ("write", "int:a")) == _decide([_A, _B], _ACTS, ("write", "int:a"))
    assert _decide([_A], _ACTS, ("write", "int:a"))[0] is True
    # With a domain that does not know pd.salary, it is the top: both deny.
    narrow = frozenset({"public"})
    assert _decide([_A], _ACTS, ("write", "int:a"), domain=narrow)[0] is False
    assert _decide([_A, _B], _ACTS, ("write", "int:a"), domain=narrow)[0] is False
