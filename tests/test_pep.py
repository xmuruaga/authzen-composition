"""PEP tests: obligation flow, fail-closed, retry on conflict, failed outcome."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from authzen_composition.mhs import HistoryConflict, MissionHistoryService
from authzen_composition.model import ActOutcome
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pep import CompositionDenied, NotPerformed, ReferencePEP
from authzen_composition.scenarios import EXFIL_POLICY
from authzen_composition.types import (
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
S = Subject("agent", "a")


def build():
    mhs = MissionHistoryService()
    return CompositionPDP(EXFIL_POLICY, mhs), mhs


def _enforce(pep: ReferencePEP, action: str, resource: str, perform=lambda: "ok"):
    return pep.enforce(
        mission_id="m1", mission_issuer="iss", subject=S,
        action=Action(action), resource=Resource("r", resource), perform=perform,
    )


def test_pep_records_and_sets_completed_with_classes() -> None:
    pdp, mhs = build()
    pep = ReferencePEP(pdp, mhs, "pep.hr",
                  classifier=lambda a, r, raw: frozenset({"personal_data.salary"}))
    _enforce(pep, "read_record", "hr:1")
    act = mhs.history("m1")[0]
    assert act.outcome is ActOutcome.COMPLETED
    assert act.result_classes == frozenset({"personal_data.salary"})
    assert mhs.recorded_by("m1", 1) == "pep.hr"


def test_pep_fail_closed_when_cannot_record() -> None:
    pdp, mhs = build()
    pep = ReferencePEP(pdp, mhs, "pep.hr", can_record=False)
    with pytest.raises(CompositionDenied) as exc:
        _enforce(pep, "read_record", "hr:1")
    assert exc.value.reason == "mission_record_unavailable"


def test_pep_records_failed_only_on_affirmative_non_execution() -> None:
    pdp, mhs = build()
    pep = ReferencePEP(pdp, mhs, "pep.hr")

    def refused():
        raise NotPerformed("resource refused before any effect")

    with pytest.raises(NotPerformed):
        _enforce(pep, "read_record", "hr:1", perform=refused)
    assert mhs.history("m1")[0].outcome is ActOutcome.FAILED


def test_pep_leaves_open_on_unknown_failure() -> None:
    pdp, mhs = build()
    pep = ReferencePEP(pdp, mhs, "pep.hr")

    def boom():
        raise RuntimeError("tool failed, effect unknown")

    with pytest.raises(RuntimeError):
        _enforce(pep, "read_record", "hr:1", perform=boom)
    assert mhs.history("m1")[0].outcome is ActOutcome.OPEN


def test_pep_retries_on_conflict_then_succeeds() -> None:
    pdp, mhs = build()
    pep = ReferencePEP(pdp, mhs, "pep.hr")
    # Pre-occupy position 1 so the PEP's first admit conflicts and it retries.
    mhs.admit("m1", 1, "other", "x", writer="pep.other")
    _enforce(pep, "read_record", "hr:1")
    assert [a.action for a in mhs.history("m1")] == ["other", "read_record"]


def test_pep_gives_up_after_max_retries() -> None:
    pdp, mhs = build()

    class StubbornMHS(MissionHistoryService):
        def admit(self, *a, **k):  # always conflict
            raise HistoryConflict("always")

    stub = StubbornMHS()
    pep = ReferencePEP(CompositionPDP(EXFIL_POLICY, stub), stub, "pep.hr")
    with pytest.raises(CompositionDenied) as exc:
        pep.enforce(mission_id="m1", mission_issuer="iss", subject=S,
                    action=Action("read_record"), resource=Resource("r", "hr:1"),
                    perform=lambda: "ok", max_retries=2)
    assert exc.value.reason == "too_many_conflicts"


def test_pep_denied_propagates_reason() -> None:
    pdp, mhs = build()
    # complete the prohibited composition first
    for pep_id, action, res, cls in (
        ("pep.hr", "read_record", "hr:1", frozenset({"personal_data.salary"})),
        ("pep.doc", "write_document", "doc:1", frozenset()),
    ):
        ReferencePEP(pdp, mhs, pep_id, classifier=lambda a, r, raw, c=cls: c).enforce(
            mission_id="m1", mission_issuer="iss", subject=S,
            action=Action(action), resource=Resource("r", res), perform=lambda: "ok")
    pep = ReferencePEP(pdp, mhs, "pep.mail")
    with pytest.raises(CompositionDenied) as exc:
        _enforce(pep, "send_message", "external:all")
    assert exc.value.reason == "prohibited_composition"


@pytest.mark.parametrize("recorded", [ActOutcome.FAILED, ActOutcome.COMPLETED])
def test_the_pep_does_not_act_on_an_admission_that_already_has_an_outcome(
        recorded: ActOutcome) -> None:
    # Profile, rule 3: an answer that returns the Act with an outcome already
    # recorded (a retry of an admission its PEP gave up on and resolved
    # failed, or a stale duplicate) is not an acknowledgement, so the action
    # must not start. It is an answer, not a lost acknowledgement: the PEP
    # neither retries nor owes the Act an outcome, which would contradict the
    # one recorded.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs)
    performed: list[str] = []
    calls: list[str] = []

    class Resolved:
        def admit(self, **kw: object) -> object:
            calls.append("admit")
            act = mhs.admit(**kw)  # type: ignore[arg-type]
            mhs.set_outcome(kw["mission_id"], act.seq, recorded,  # type: ignore[arg-type]
                            writer=kw["writer"], admission_id=kw["admission_id"])  # type: ignore[arg-type]
            return mhs.history(kw["mission_id"])[act.seq - 1]  # type: ignore[arg-type]

        def set_outcome(self, *a: object, **kw: object) -> object:
            return mhs.set_outcome(*a, **kw)  # type: ignore[arg-type]

        def history(self, *a: object, **kw: object) -> object:
            return mhs.history(*a, **kw)  # type: ignore[arg-type]

    pep = ReferencePEP(pdp=pdp, mhs=Resolved(), writer_id="pep.hr")  # type: ignore[arg-type]
    with pytest.raises(CompositionDenied) as denied:
        pep.enforce(mission_id="m1", mission_issuer=ISSUER, subject=Subject("agent", "a"),
                    action=Action("read_record"), resource=Resource("hr", "hr:1"),
                    perform=lambda: performed.append("read"))
    assert denied.value.reason == "mission_record_unavailable"
    assert performed == []
    assert calls == ["admit"] and pep.unreported == []


T0 = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
ARS = "https://pdp.example/access/v1/requests"
SALARY = frozenset({"personal_data.salary"})


def _approved_send(pep_clock: Callable[[], datetime]
                   ) -> tuple[ReferencePEP, MissionHistoryService, dict[str, str]]:
    """A send denied after a salary read and a write, approved at T0 (its
    approved_until is T0 + 5 minutes), and a mail PEP with the given clock."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS, clock=lambda: T0)
    _enforce(ReferencePEP(pdp, mhs, "pep.hr", classifier=lambda a, r, raw: SALARY),
             "read_record", "hr:1")
    _enforce(ReferencePEP(pdp, mhs, "pep.docs"), "write_document", "doc:1")
    mail = ReferencePEP(pdp, mhs, "pep.mail", clock=pep_clock)
    with pytest.raises(CompositionDenied) as exc:
        _enforce(mail, "send_message", "external:press")
    assert exc.value.evaluation_id is not None
    return mail, mhs, pdp.approve(exc.value.evaluation_id)


def _send_with(pep: ReferencePEP, approval: dict[str, str], performed: list[int]) -> object:
    return pep.enforce(mission_id="m1", mission_issuer="iss", subject=S,
                       action=Action("send_message"), resource=Resource("r", "external:press"),
                       perform=lambda: performed.append(1), context={"approval": approval})


def test_the_pep_admits_nothing_once_the_approval_has_expired() -> None:
    # Rule 3: no admission from the approval's approved_until on, even on a
    # permit (here the PDP's clock is behind); the PEP gives up instead.
    mail, mhs, approval = _approved_send(lambda: T0 + timedelta(minutes=6))
    performed: list[int] = []
    with pytest.raises(CompositionDenied) as exc:
        _send_with(mail, approval, performed)
    assert exc.value.reason == "approval_expired"
    assert performed == [] and [a.seq for a in mhs.history("m1")] == [1, 2]


def test_the_pep_does_not_start_an_admitted_act_once_the_approval_has_expired() -> None:
    # Expired between admission and the effect: the Act never ran, so the PEP
    # records it failed and releases the position.
    times = [T0 + timedelta(minutes=4), T0 + timedelta(minutes=6)]
    mail, mhs, approval = _approved_send(lambda: times.pop(0) if len(times) > 1 else times[0])
    performed: list[int] = []
    with pytest.raises(CompositionDenied) as exc:
        _send_with(mail, approval, performed)
    assert exc.value.reason == "approval_expired"
    assert performed == [] and mhs.history("m1")[2].outcome is ActOutcome.FAILED


def test_an_admission_refused_for_good_owes_no_failed() -> None:
    # Rule 3: an answer that refuses the admission for good (here the writer
    # is not trusted) shows nothing was admitted; no failed is kept, and no
    # incident follows.
    mhs = MissionHistoryService(trusted_writers=frozenset({"pep.hr"}))
    pep = ReferencePEP(CompositionPDP(EXFIL_POLICY, mhs), mhs, "pep.rogue")
    with pytest.raises(CompositionDenied) as exc:
        _enforce(pep, "read_record", "hr:1")
    assert exc.value.reason == "mission_record_unavailable"
    pep.redeliver()
    assert pep.unreported == [] and pep.refused == [] and mhs.history("m1") == []


def test_an_approval_held_back_by_an_open_act_is_not_used_up() -> None:
    # Approvals: a denial for another reason does not use the approval up.
    # The approved send waits under rule 5 while the write is open, then is
    # permitted with the same approval once the write has its outcome.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    mhs.admit("m1", 1, "read_record", "hr:1", writer="pep.hr")
    mhs.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="pep.hr", result_classes=SALARY)
    mhs.admit("m1", 2, "write_document", "doc:1", writer="pep.docs")

    def send(context: dict[str, object]) -> EvaluationRequest:
        return EvaluationRequest(S, Action("send_message"), Resource("r", "external:press"),
                                 mission=Mission("m1", "iss"),
                                 supported_mandatory_extensions=("obligations",),
                                 supported_obligations=("mission_record",), context=context)

    denied = pdp.evaluate(send({}))
    assert denied.evaluation_id is not None
    approval = pdp.approve(denied.evaluation_id)
    held = pdp.evaluate(send({"approval": approval}))
    assert (held.decision, held.reason) == (False, "history_pending")
    mhs.set_outcome("m1", 2, ActOutcome.COMPLETED, writer="pep.docs")
    assert pdp.evaluate(send({"approval": approval})).decision


class _Racing:
    """The History Authority, where another PEP takes the first position just
    before this PEP's first admission."""

    def __init__(self, mhs: MissionHistoryService) -> None:
        self.mhs, self.raced = mhs, False

    def history(self, mission_id: str, policy: str | None = None) -> list:
        return self.mhs.history(mission_id, policy=policy)

    def set_outcome(self, *args: object, **kwargs: object) -> object:
        return self.mhs.set_outcome(*args, **kwargs)

    def admit(self, mission_id: str, seq: int, action: str, resource: str, writer: str,
              admission_id: str | None = None) -> object:
        if not self.raced:
            self.raced = True
            self.mhs.admit(mission_id, seq, "read_record", "hr:2", writer="pep.other")
            self.mhs.set_outcome(mission_id, seq, ActOutcome.COMPLETED, writer="pep.other")
        return self.mhs.admit(mission_id, seq, action, resource, writer, admission_id)


def test_a_pep_that_loses_its_position_evaluates_again_and_is_admitted() -> None:
    # Rule 2: the loser of a race for a position evaluates again, against the
    # history that now holds the winner, and is admitted at the next position.
    mhs = MissionHistoryService()
    pep = ReferencePEP(CompositionPDP(EXFIL_POLICY, mhs), _Racing(mhs), "pep.hr")
    assert _enforce(pep, "read_record", "hr:1") == "ok"
    assert [(a.seq, a.resource, mhs.recorded_by("m1", a.seq)) for a in mhs.history("m1")] == [
        (1, "hr:2", "pep.other"), (2, "hr:1", "pep.hr")]


@pytest.mark.parametrize("approved_until", ["not a time", "2026-10-14T09:05:00"])
def test_an_approved_until_the_pep_cannot_read_is_taken_as_passed(approved_until: str) -> None:
    # Rule 3: a PEP that cannot tell when the approval ends does not act on it.
    mail, mhs, approval = _approved_send(lambda: T0)
    performed: list[int] = []
    with pytest.raises(CompositionDenied) as exc:
        _send_with(mail, {**approval, "approved_until": approved_until}, performed)
    assert exc.value.reason == "approval_expired" and performed == []
