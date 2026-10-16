"""Effect order versus admission order: an admitted act that has not finished.

The counterexample: SEND is admitted at position 1
and stalls before its effect. READ is admitted at 2 and runs. SEND resumes.
Admission order is SEND, READ (allowed); effect order is READ, SEND
(prohibited). If the send carries a reference (send document Q4) rather than a
value, data the read produced can reach it.

Rule under test: while an act relevant to a Restricted Sequence is admitted but
not finished (OPEN), the PDP does not admit another act of the same sequence
that could reorder with it in a way that matters. It denies with
``history_pending``; the PEP retries once the open act finishes.
"""

from __future__ import annotations

import random
import threading
import time

import pytest

from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pep import CompositionDenied, ReferencePEP
from authzen_composition.types import (
    EXTENSION_OBLIGATIONS,
    OBLIGATION_MISSION_RECORD,
    REASON_HISTORY_PENDING,
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)

S = Subject("agent", "agent-7")
SALARY = frozenset({"personal_data.salary"})
READ_SEND = RestrictedSequence(
    name="read_send",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send_message", resources=frozenset({"external:*"})),
    ),
)
READ_WRITE_SEND = RestrictedSequence(
    name="read_write_send",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("write_document"),
        SequenceStep("send_message", resources=frozenset({"external:*"})),
    ),
)


def _pep(pdp, mhs, writer, classes=frozenset()) -> ReferencePEP:
    return ReferencePEP(pdp, mhs, writer, classifier=lambda a, r, raw: classes)


def _run(pep, action, resource, perform=lambda: "ok"):
    return pep.enforce(
        mission_id="m1", mission_issuer="iss", subject=S,
        action=Action(action), resource=Resource("r", resource), perform=perform,
        max_retries=1,
    )


def test_stalled_send_blocks_read_until_it_finishes() -> None:
    """The exact counterexample, with two real PEPs and a stalled effect."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs)
    send_admitted = threading.Event()
    release_send = threading.Event()
    effects: list[str] = []

    def stalled_send() -> str:
        send_admitted.set()
        assert release_send.wait(5)
        effects.append("send")
        return "sent"

    sender = threading.Thread(
        target=lambda: _run(_pep(pdp, mhs, "pep.mail"), "send_message", "external:x",
                            perform=stalled_send)
    )
    sender.start()
    assert send_admitted.wait(5)
    assert mhs.history("m1")[0].outcome is ActOutcome.OPEN

    # READ while SEND is admitted but has not produced its effect.
    with pytest.raises(CompositionDenied) as exc:
        _run(_pep(pdp, mhs, "pep.hr", SALARY), "read_record", "hr:1",
             perform=lambda: effects.append("read"))
    assert exc.value.reason == REASON_HISTORY_PENDING
    assert effects == []

    release_send.set()
    sender.join(5)
    assert effects == ["send"]
    # Once SEND has finished, READ is admitted: effect order = admission order.
    _run(_pep(pdp, mhs, "pep.hr", SALARY), "read_record", "hr:1",
         perform=lambda: effects.append("read"))
    assert effects == ["send", "read"]


def test_by_reference_send_cannot_pick_up_later_writes() -> None:
    """k=3, by reference: SEND names
    document Q4 by reference and stalls; READ and WRITE into Q4 must not run
    before it finishes."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((READ_WRITE_SEND,)), mhs)
    mhs.admit("m1", 1, "send_message", "external:q4", writer="pep.mail")  # stalled
    assert not pdp.evaluate(_req("read_record", "hr:1")).decision
    assert not pdp.evaluate(_req("write_document", "doc:q4")).decision


def test_unrelated_acts_are_not_held_back() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs)
    mhs.admit("m1", 1, "send_message", "external:x", writer="pep.mail")  # open
    assert pdp.evaluate(_req("list_calendar", "cal:1")).decision


def test_acts_matching_the_same_steps_commute() -> None:
    """Two reads matching only step 1 can run concurrently: swapping them
    changes no embedding."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs)
    mhs.admit("m1", 1, "read_record", "hr:1", writer="pep.hr")  # open
    assert pdp.evaluate(_req("read_record", "hr:2")).decision


def test_failed_or_completed_acts_do_not_hold_back() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs)
    mhs.admit("m1", 1, "send_message", "external:x", writer="pep.mail")
    mhs.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="pep.mail")
    assert pdp.evaluate(_req("read_record", "hr:1")).decision


def test_pending_rule_in_the_model() -> None:
    policy = CompositionPolicy((READ_SEND,))
    open_send = Act(1, "send_message", "external:x", ActOutcome.OPEN)
    read = Act(2, "read_record", "hr:1")
    assert policy.pending_conflict([open_send], read) == ("read_send",)
    assert policy.pending_conflict([], read) == ()


def _req(action, resource):
    return EvaluationRequest(
        subject=S, action=Action(action), resource=Resource("r", resource),
        mission=Mission(id="m1", issuer="iss"),
        supported_mandatory_extensions=(EXTENSION_OBLIGATIONS,),
        supported_obligations=(OBLIGATION_MISSION_RECORD,),
    )


def test_acts_matching_several_steps_do_not_commute() -> None:
    """Two open-class reads that could each match step 1 or step 2: their true
    classes are unknown, so their effect order may matter."""
    two_reads = RestrictedSequence(
        name="health_then_salary_then_send",
        steps=(
            SequenceStep("read_record", result_classes=frozenset({"pd.health"})),
            SequenceStep("read_record", result_classes=frozenset({"pd.salary"})),
            SequenceStep("send_message"),
        ),
    )
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((two_reads,)), mhs)
    mhs.admit("m1", 1, "read_record", "hr:1", writer="pep.hr")  # open
    d = pdp.evaluate(_req("read_record", "hr:2"))
    assert not d.decision and d.reason == REASON_HISTORY_PENDING


def test_threaded_k3_never_realizes_read_write_send_in_effect_order() -> None:
    """Three real PEP
    threads (read, write, send) released together, each stalling a random
    moment between admission and effect, many rounds. Invariant: the true
    effect order never contains read, write, send as a subsequence."""

    violations: list[str] = []
    for rnd in range(120):
        mhs = MissionHistoryService()
        pdp = CompositionPDP(CompositionPolicy((READ_WRITE_SEND,)), mhs)
        barrier = threading.Barrier(3)
        order: list[str] = []
        lock = threading.Lock()
        rng = random.Random(rnd)
        delays = {n: rng.random() * 0.003 for n in ("read", "write", "send")}

        def worker(name, action, resource, classes, _pdp=pdp, _mhs=mhs,
                   _b=barrier, _order=order, _lock=lock, _delays=delays):
            def perform() -> str:
                time.sleep(_delays[name])
                with _lock:
                    _order.append(name)
                return "ok"

            pep = _pep(_pdp, _mhs, f"pep.{name}", classes)
            _b.wait()
            for _ in range(20):  # PEPs retry on history_pending / conflict
                try:
                    pep.enforce(mission_id="m1", mission_issuer="iss", subject=S,
                                action=Action(action), resource=Resource("r", resource),
                                perform=perform, max_retries=3)
                    return
                except CompositionDenied as exc:
                    if exc.reason == "prohibited_composition":
                        return
                    time.sleep(0.0005)

        threads = [
            threading.Thread(target=worker, args=("read", "read_record", "hr:1", SALARY)),
            threading.Thread(target=worker, args=("write", "write_document", "doc:q4",
                                                  frozenset())),
            threading.Thread(target=worker, args=("send", "send_message", "external:q4",
                                                  frozenset())),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        if order == ["read", "write", "send"]:
            violations.append(f"round {rnd}: {order}")
    assert violations == []


def test_failed_act_has_no_effective_classes() -> None:
    """A failed act did nothing, so it carries no classes, not the
    conservative top."""
    assert Act(1, "read_record", "hr:1", ActOutcome.FAILED).effective_classes() == frozenset()
