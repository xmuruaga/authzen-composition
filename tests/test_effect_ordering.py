"""Adversarial tests: admission order versus execution order.

The predicate reads admission order. These tests check that admission order is
a safe stand-in for effect order, under the profile's rules:

* the effect starts only after the admission is acknowledged;
* an act whose outcome is unknown stays OPEN and is matched at the top;
* ``failed`` is recorded only on affirmative non-execution, and only by the
  writer that admitted the act;
* admissions and outcomes are idempotent under retry.

The last section contrasts the predicate with two simplified baselines, a
negated "class completed" check and a one-latch exclusivity group, to show the
behavior that differs. The baselines model predicate semantics only; they are
not anyone's implementation.
"""

from __future__ import annotations

import contextlib
import threading
import time

import pytest

from authzen_composition.mhs import (
    HistoryConflict,
    MissionHistoryService,
    OutcomeAlreadySet,
    UnauthenticatedWriter,
)
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pep import CompositionDenied, NotPerformed, ReferencePEP
from authzen_composition.types import (
    EXTENSION_OBLIGATIONS,
    OBLIGATION_MISSION_RECORD,
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)

S = Subject("agent", "agent-7")
READ_THEN_SEND = RestrictedSequence(
    name="read_personal_then_send_external",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send_message", resources=frozenset({"external:*"})),
    ),
)
POLICY = CompositionPolicy((READ_THEN_SEND,))
SALARY = frozenset({"personal_data.salary"})


def _request(action: str, resource: str) -> EvaluationRequest:
    return EvaluationRequest(
        subject=S,
        action=Action(action),
        resource=Resource("r", resource),
        mission=Mission(id="m1", issuer="iss"),
        supported_mandatory_extensions=(EXTENSION_OBLIGATIONS,),
        supported_obligations=(OBLIGATION_MISSION_RECORD,),
    )


def _expected_seq(pdp: CompositionPDP, action: str, resource: str) -> int | None:
    d = pdp.evaluate(_request(action, resource))
    if not d.decision:
        return None
    ob = next(o for o in d.obligations if o.type == OBLIGATION_MISSION_RECORD)
    return int(ob.properties["expected_seq"])


def _pep(pdp, mhs, writer, classes=frozenset()) -> ReferencePEP:
    return ReferencePEP(pdp, mhs, writer, classifier=lambda a, r, raw: classes)


def _run(pep: ReferencePEP, action: str, resource: str, perform=lambda: "ok"):
    return pep.enforce(
        mission_id="m1", mission_issuer="iss", subject=S,
        action=Action(action), resource=Resource("r", resource), perform=perform,
    )


# --- 1. Both permitted before either is recorded ---------------------------


def test_both_permitted_at_same_version_read_wins_admission() -> None:
    """Read and send are both permitted against the empty history. The read is
    admitted first, so the send's admission conflicts. Re-evaluated, the send
    sees the read OPEN (unknown effect, matched at the top) and is denied
    before any effect."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICY, mhs)
    read_seq = _expected_seq(pdp, "read_record", "hr:1")
    send_seq = _expected_seq(pdp, "send_message", "external:x")
    assert read_seq == send_seq == 1  # both permitted, same version

    mhs.admit("m1", read_seq, "read_record", "hr:1", writer="pep.hr")

    with pytest.raises(HistoryConflict):
        mhs.admit("m1", send_seq, "send_message", "external:x", writer="pep.mail")
    # The send's PEP must re-evaluate; the read is still OPEN.
    assert _expected_seq(pdp, "send_message", "external:x") is None


def test_both_permitted_at_same_version_send_wins_admission() -> None:
    """Send admitted first, still open: the read waits (history_pending) until
    the send finishes, so the send's effect cannot land after the read's.
    Once the send has completed, the read is admitted at 2."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICY, mhs)
    send_seq = _expected_seq(pdp, "send_message", "external:x")
    assert send_seq == 1
    mhs.admit("m1", send_seq, "send_message", "external:x", writer="pep.mail")
    assert _expected_seq(pdp, "read_record", "hr:1") is None  # held back
    mhs.set_outcome("m1", send_seq, ActOutcome.COMPLETED, writer="pep.mail")
    read_seq = _expected_seq(pdp, "read_record", "hr:1")
    assert read_seq == 2
    mhs.admit("m1", read_seq, "read_record", "hr:1", writer="pep.hr")
    assert [a.action for a in mhs.history("m1")] == ["send_message", "read_record"]


def test_threaded_race_never_executes_read_then_send() -> None:
    """Real threads, released together, many rounds. Invariant: the read's
    effect never lands before the send's (the prohibited effect order), and
    every effect ran only after its own act was in the history."""
    violations: list[str] = []
    for _round in range(150):
        mhs = MissionHistoryService()
        pdp = CompositionPDP(POLICY, mhs)
        barrier = threading.Barrier(2)
        effects: dict[str, int] = {}
        lock = threading.Lock()

        def make_perform(name: str, action: str, _mhs=mhs, _effects=effects, _lock=lock):
            def perform() -> str:
                seqs = [a.seq for a in _mhs.history("m1") if a.action == action]
                if not seqs:
                    violations.append(f"{name}: effect before admission")
                time.sleep(0.001)  # widen the window between admission and effect
                with _lock:
                    _effects[name] = len(_effects)  # effect order, not admission
                return "ok"
            return perform

        def worker(name, action, resource, classes, _pdp=pdp, _mhs=mhs, _b=barrier):
            _pep_inst = _pep(_pdp, _mhs, f"pep.{name}", classes)
            _b.wait()
            with contextlib.suppress(CompositionDenied):
                _run(_pep_inst, action, resource, perform=make_perform(name, action))

        t1 = threading.Thread(target=worker, args=("read", "read_record", "hr:1", SALARY))
        t2 = threading.Thread(
            target=worker, args=("send", "send_message", "external:x", frozenset())
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        if "read" in effects and "send" in effects and effects["read"] < effects["send"]:
            violations.append(f"round {_round}: read@{effects['read']} < send@{effects['send']}")
    assert violations == []


# --- 2. No effect before a durable, acknowledged admission ------------------


class _UnreachableMHS(MissionHistoryService):
    def admit(self, *a, **k):  # type: ignore[override]
        raise ConnectionError("authority unreachable")


def test_no_effect_when_admission_is_never_acknowledged() -> None:
    mhs = _UnreachableMHS()
    pdp = CompositionPDP(POLICY, mhs)
    ran: list[bool] = []
    with pytest.raises(CompositionDenied) as exc:
        _run(_pep(pdp, mhs, "pep.mail"), "send_message", "external:x",
             perform=lambda: ran.append(True))
    assert exc.value.reason == "mission_record_unavailable"
    assert ran == []


class _LostAckMHS(MissionHistoryService):
    """Commits the first admission, then loses the acknowledgement."""

    def __init__(self) -> None:
        super().__init__()
        self.dropped = False

    def admit(self, *a, **k):  # type: ignore[override]
        act = super().admit(*a, **k)
        if not self.dropped:
            self.dropped = True
            raise ConnectionError("ack lost after commit")
        return act


def test_lost_ack_retry_is_idempotent_no_duplicate_act() -> None:
    mhs = _LostAckMHS()
    pdp = CompositionPDP(POLICY, mhs)
    ran: list[bool] = []
    _run(_pep(pdp, mhs, "pep.hr", SALARY), "read_record", "hr:1",
         perform=lambda: ran.append(True))
    history = mhs.history("m1")
    assert len(history) == 1  # no phantom second act
    assert history[0].outcome is ActOutcome.COMPLETED
    assert ran == [True]  # performed exactly once


def test_admission_id_is_bound_to_its_writer() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m1", 1, "read_record", "hr:1", writer="pep.hr", admission_id="a1")
    # Another writer reusing the id does not get the first writer's act.

    with pytest.raises(HistoryConflict):
        mhs.admit("m1", 1, "send_message", "external:x", writer="pep.mail", admission_id="a1")


# --- 3. Effect happened, outcome record fails, is late, or is duplicated ----


class _FlakyOutcomeMHS(MissionHistoryService):
    def __init__(self) -> None:
        super().__init__()
        self.fail_outcomes = True

    def set_outcome(self, *a, **k):  # type: ignore[override]
        if self.fail_outcomes:
            raise ConnectionError("outcome write failed")
        return super().set_outcome(*a, **k)


def test_outcome_write_fails_act_stays_open_and_blocks_send() -> None:
    mhs = _FlakyOutcomeMHS()
    pdp = CompositionPDP(POLICY, mhs)
    reader = _pep(pdp, mhs, "pep.hr", SALARY)
    assert _run(reader, "read_record", "hr:1") == "ok"  # effect happened
    assert mhs.history("m1")[0].outcome is ActOutcome.OPEN
    assert len(reader.unreported) == 1
    with pytest.raises(CompositionDenied):
        _run(_pep(pdp, mhs, "pep.mail"), "send_message", "external:x")


def test_late_outcome_is_redelivered_and_still_blocks_send() -> None:
    mhs = _FlakyOutcomeMHS()
    pdp = CompositionPDP(POLICY, mhs)
    reader = _pep(pdp, mhs, "pep.hr", SALARY)
    _run(reader, "read_record", "hr:1")
    mhs.fail_outcomes = False
    reader.redeliver()
    assert reader.unreported == []
    act = mhs.history("m1")[0]
    assert act.outcome is ActOutcome.COMPLETED and act.result_classes == SALARY
    with pytest.raises(CompositionDenied):
        _run(_pep(pdp, mhs, "pep.mail"), "send_message", "external:x")


def test_duplicate_outcome_is_idempotent_conflicting_outcome_rejected() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m1", 1, "read_record", "hr:1", writer="pep.hr")
    first = mhs.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="pep.hr", result_classes=SALARY)
    again = mhs.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="pep.hr", result_classes=SALARY)
    assert first == again
    with pytest.raises(OutcomeAlreadySet):
        mhs.set_outcome("m1", 1, ActOutcome.FAILED, writer="pep.hr")
    with pytest.raises(OutcomeAlreadySet):
        mhs.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="pep.hr",
                        result_classes=frozenset({"public"}))


def test_timeout_after_effect_is_not_recorded_as_failed() -> None:
    """A timeout does not prove non-execution. If it were recorded as
    `failed`, the read would drop out of the predicate and the send would pass."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICY, mhs)

    def read_then_timeout():
        raise TimeoutError("response lost; the read may have happened")

    with pytest.raises(TimeoutError):
        _run(_pep(pdp, mhs, "pep.hr", SALARY), "read_record", "hr:1",
             perform=read_then_timeout)
    assert mhs.history("m1")[0].outcome is ActOutcome.OPEN
    with pytest.raises(CompositionDenied):
        _run(_pep(pdp, mhs, "pep.mail"), "send_message", "external:x")


def test_affirmative_non_execution_releases_the_position() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICY, mhs)

    def refused():
        raise NotPerformed("rejected before reading")

    with pytest.raises(NotPerformed):
        _run(_pep(pdp, mhs, "pep.hr", SALARY), "read_record", "hr:1", perform=refused)
    assert mhs.history("m1")[0].outcome is ActOutcome.FAILED
    assert _run(_pep(pdp, mhs, "pep.mail"), "send_message", "external:x") == "ok"


def test_other_writer_cannot_hide_an_act_by_marking_it_failed() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICY, mhs)
    mhs.admit("m1", 1, "read_record", "hr:1", writer="pep.hr")
    with pytest.raises(UnauthenticatedWriter):
        mhs.set_outcome("m1", 1, ActOutcome.FAILED, writer="pep.mail")
    with pytest.raises(CompositionDenied):
        _run(_pep(pdp, mhs, "pep.mail"), "send_message", "external:x")


# --- 4. What differs from simpler predicates --------------------------------


def _negated_completed(history: list[Act], candidate_action: str) -> bool:
    """Baseline A: permit the send unless a COMPLETED read with a personal
    class is in the history. A negated positive "class completed" check."""
    if candidate_action != "send_message":
        return True
    return not any(
        a.action == "read_record" and a.outcome is ActOutcome.COMPLETED
        and any(c.startswith("personal_data.") for c in a.result_classes)
        for a in history
    )


def _exclusive_latch(history: list[Act], candidate_action: str) -> bool:
    """Baseline B: {read_record, send_message} as one exclusive group. Once one
    member is latched, any other member is denied, in either order."""
    group = {"read_record", "send_message"}
    latched = {
        a.action for a in history
        if a.action in group and a.outcome is not ActOutcome.FAILED
    }
    return not (latched - {candidate_action})


def test_contrast_open_read_negated_check_permits_predicate_denies() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICY, mhs)
    mhs.admit("m1", 1, "read_record", "hr:1", writer="pep.hr")  # in flight
    assert _negated_completed(mhs.history("m1"), "send_message") is True  # unsafe
    assert _expected_seq(pdp, "send_message", "external:x") is None  # denied


def test_contrast_order_exclusivity_blocks_safe_order_predicate_permits() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICY, mhs)
    seq = _expected_seq(pdp, "send_message", "external:x")
    assert seq == 1
    mhs.admit("m1", seq, "send_message", "external:x", writer="pep.mail")
    mhs.set_outcome("m1", seq, ActOutcome.COMPLETED, writer="pep.mail")
    assert _exclusive_latch(mhs.history("m1"), "read_record") is False  # blocks safe order
    assert _expected_seq(pdp, "read_record", "hr:1") == 2  # predicate permits it


def test_contrast_three_step_order_needs_ordered_subsequence() -> None:
    """Three steps: read, write, then send is prohibited; write, read, then send is
    not. Both histories hold the same set of acts; only order separates them."""
    three = RestrictedSequence(
        name="read_write_send",
        steps=(
            SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
            SequenceStep("write_document"),
            SequenceStep("send_message", resources=frozenset({"external:*"})),
        ),
    )
    policy = CompositionPolicy((three,))

    def acts(*names: str) -> list[Act]:
        return [
            Act(i + 1, n, "r", ActOutcome.COMPLETED,
                SALARY if n == "read_record" else frozenset({"personal_data.x"}))
            for i, n in enumerate(names)
        ]

    send = Act(99, "send_message", "external:x", ActOutcome.OPEN)
    assert not policy.completes(acts("read_record", "write_document"), send).satisfied
    assert policy.completes(acts("write_document", "read_record"), send).satisfied
