"""Exact behavior that a looser test would let drift.

* The policy digest's canonical form. The History Authority pins a digest per
  Mission, so if a new release of the reference computed a different digest
  for the same set, every live Mission would be refused with
  ``policy_mismatch`` after an upgrade. The expected digests below are hashed
  from the canonical bytes written out literally, not from the code.
* The position after a persistent step: an Act that fills a persistent step
  "after t" sits strictly after t, never before it.
* The message that explains why a first step cannot be persistent.
* The ``policy_mismatch`` wire value, which another implementation's PEP
  matches on.
* Operator close of a stranded Act changes exactly the Act it names.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from authzen_composition import types as T
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

PROFILE = (Path(__file__).resolve().parents[1] / "docs"
           / "authzen-composition-profile-1_0.md").read_text(encoding="utf-8")

EXFIL = RestrictedSequence(
    "exfil",
    (
        SequenceStep("read", frozenset({"hr:*", "fin:*"}), frozenset({"pd.*", "fin.*"})),
        SequenceStep("send", frozenset({"external:*"}), persistent=True),
    ),
    requestable=True,
)
STEPS = (
    '[{"action":"read","persistent":false,"resources":["fin:*","hr:*"],'
    '"result_classes":["fin.*","pd.*"]},'
    '{"action":"send","persistent":true,"resources":["external:*"],"result_classes":[]}]'
)
SEQUENCES = '[{"name":"exfil","requestable":true,"steps":' + STEPS + "}]"


def _sha(canonical: str) -> str:
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_policy_digest_is_the_hash_of_the_documented_canonical_form() -> None:
    assert CompositionPolicy((EXFIL,)).digest == _sha('{"restricted_sequences":' + SEQUENCES + "}")


def test_policy_digest_with_label_domain_is_the_hash_of_the_documented_canonical_form() -> None:
    policy = CompositionPolicy((EXFIL,), label_domain=frozenset({"public", "pd.*"}))
    expected = _sha('{"label_domain":["pd.*","public"],"restricted_sequences":' + SEQUENCES + "}")
    assert policy.digest == expected


def test_a_persistent_step_filled_after_t_does_not_go_back_before_t() -> None:
    # Steps: a, then b (persistent), then a. History: b at 1. Candidate: a at 2.
    # The candidate fills step 1 at 2 and b's lasting effect fills step 2 just
    # after 2, but no Act fills step 3 after that: the sequence is not complete.
    # Placing step 2 *before* 2 would let the candidate fill step 3 as well.
    seq = RestrictedSequence(
        "s", (SequenceStep("a"), SequenceStep("b", persistent=True), SequenceStep("a"))
    )
    history = [Act(1, "b", "r", ActOutcome.COMPLETED)]
    assert _completes(history, Act(2, "a", "r", ActOutcome.OPEN), seq) is False
    # Control: with a second "a" admitted before the candidate, it completes.
    history.append(Act(2, "a", "r", ActOutcome.COMPLETED))
    assert _completes(history, Act(3, "a", "r", ActOutcome.OPEN), seq) is True


def test_first_step_persistent_message_says_where_the_mark_belongs() -> None:
    with pytest.raises(ValueError, match=r"^the first step cannot be persistent: put the "
                       r"lasting effect at the step where it exposes the data"):
        RestrictedSequence("s", (SequenceStep("a", persistent=True), SequenceStep("b")))


def test_policy_mismatch_reason_is_the_wire_value_the_profile_names() -> None:
    # A PEP of another implementation matches on this string.
    assert T.REASON_POLICY_MISMATCH == "policy_mismatch"
    assert "`policy_mismatch`" in PROFILE
    mhs = MissionHistoryService()
    read = SequenceStep("read")
    pinned = CompositionPolicy((RestrictedSequence("s", (read, SequenceStep("send"))),))
    other = CompositionPolicy(())
    request = EvaluationRequest(
        subject=Subject("agent", "a"), action=Action("read"), resource=Resource("r", "x"),
        mission=Mission("m", "iss"), supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",),
    )
    CompositionPDP(pinned, mhs).evaluate(request)
    decision = CompositionPDP(other, mhs).evaluate(request)
    assert (decision.decision, decision.reason) == (False, "policy_mismatch")


def test_operator_close_changes_exactly_the_named_act() -> None:
    # Three open Acts; closing the middle one must leave the first and the
    # last open, and keep the closed Act's own action and resource.
    mhs = MissionHistoryService(operators=frozenset({"ops"}))
    for seq, action in enumerate(("read", "write", "send"), start=1):
        mhs.admit("m", seq, action, f"res-{seq}", writer="w")
    closed = mhs.close_stranded("m", 2, operator="ops")
    assert (closed.seq, closed.action, closed.resource) == (2, "write", "res-2")
    history = mhs.history("m")
    assert [(a.seq, a.action, a.outcome) for a in history] == [
        (1, "read", ActOutcome.OPEN),
        (2, "write", ActOutcome.COMPLETED),
        (3, "send", ActOutcome.OPEN),
    ]
    # And the first one can be closed on its own.
    mhs.close_stranded("m", 1, operator="ops")
    assert [a.outcome for a in mhs.history("m")] == [
        ActOutcome.COMPLETED, ActOutcome.COMPLETED, ActOutcome.OPEN]
