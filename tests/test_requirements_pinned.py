"""Requirements pinned one by one.

Each test here pins one requirement of the profile directly, so that a
one-line change that breaks it fails a test cited for it in
docs/TRACEABILITY.md.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import HistoryConflict, MissionHistoryService
from authzen_composition.model import (
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.remote import RemoteUnavailable, _act
from authzen_composition.types import (
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint
SALARY = frozenset({"personal_data.salary"})
READ_SEND = RestrictedSequence("read_send", (
    SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
    SequenceStep("send_message", resources=frozenset({"external:*"})),
), requestable=True)


def _req(action: str, rid: str, mission: str = "m1", *,
         extensions: tuple[str, ...] = ("obligations",),
         obligations: tuple[str, ...] = ("mission_record",),
         resource_properties: dict[str, Any] | None = None,
         **context: Any) -> EvaluationRequest:
    return EvaluationRequest(
        Subject("agent", "a"), Action(action),
        Resource("r", rid, dict(resource_properties or {})),
        mission=Mission(mission, ISSUER), supported_mandatory_extensions=extensions,
        supported_obligations=obligations, context=dict(context))


def _completed(mhs: MissionHistoryService, mission: str, seq: int, action: str, rid: str,
               classes: frozenset[str] = frozenset()) -> None:
    mhs.admit(mission, seq, action, rid, writer="w")
    mhs.set_outcome(mission, seq, ActOutcome.COMPLETED, writer="w", result_classes=classes)


def _staged(mission: str = "m1") -> tuple[CompositionPDP, MissionHistoryService]:
    mhs = MissionHistoryService()
    _completed(mhs, mission, 1, "read_record", "hr:1", SALARY)
    return CompositionPDP(CompositionPolicy((READ_SEND,)), mhs, access_request_endpoint=ARS), mhs


# --- Result classes and the request -----------------------------------------------

def test_classes_the_request_carries_are_never_evidence() -> None:
    # Profile, Result classes: a PDP MUST NOT accept result classes that
    # originate with the agent. A read whose request claims `public` is still
    # the candidate, at the top: it gets mission_record and is admitted.
    policy = CompositionPolicy((READ_SEND,), label_domain=frozenset({"personal_data.*", "public"}))
    decision = CompositionPDP(policy, MissionHistoryService()).evaluate(
        _req("read_record", "hr:1", result_classes=["public"]))
    assert decision.decision and [o.type for o in decision.obligations] == ["mission_record"]


def test_a_history_the_request_carries_never_replaces_the_authority_s() -> None:
    # Profile, Predicate: a caller-supplied value is never evidence. A request
    # that claims an empty history is still decided on the read the History
    # Authority holds.
    pdp, _ = _staged()
    decision = pdp.evaluate(_req("send_message", "external:x", history=[], claimed_history=[]))
    assert (decision.decision, decision.reason) == (False, "prohibited_composition")


def test_neither_resource_type_nor_properties_takes_part_in_matching() -> None:
    # Profile, Step patterns: patterns match `resource.id` alone.
    pdp, _ = _staged()
    for rtype, props in (("mailbox", {}), ("other", {"internal": True})):
        request = EvaluationRequest(
            Subject("agent", "a"), Action("send_message"), Resource(rtype, "external:x", props),
            mission=Mission("m1", ISSUER), supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",))
        assert pdp.evaluate(request).reason == "prohibited_composition"


# --- Approvals --------------------------------------------------------------------

def test_an_approval_is_not_honoured_in_another_mission() -> None:
    # Profile, Approvals: an approval applies only in the same Mission, even
    # where the other Mission's history is the same.
    pdp, mhs = _staged()
    _completed(mhs, "m2", 1, "read_record", "hr:1", SALARY)
    denied = pdp.evaluate(_req("send_message", "external:x"))
    assert denied.evaluation_id is not None
    approval = pdp.approve(denied.evaluation_id)
    other = pdp.evaluate(_req("send_message", "external:x", "m2", approval=approval))
    assert (other.decision, other.reason) == (False, "prohibited_composition")
    assert pdp.evaluate(_req("send_message", "external:x", approval=approval)).decision


def test_an_approval_does_not_cover_other_resource_properties() -> None:
    # Profile, Approvals: the request a person approves includes the
    # resource's properties.
    pdp, _ = _staged()
    approved = {"cc": "internal:alice"}
    denied = pdp.evaluate(_req("send_message", "external:x", resource_properties=approved))
    assert denied.evaluation_id is not None
    approval = pdp.approve(denied.evaluation_id)
    other = pdp.evaluate(_req("send_message", "external:x", resource_properties={
        "cc": "external:rival"}, approval=approval))
    assert not other.decision
    assert pdp.evaluate(_req("send_message", "external:x", resource_properties=approved,
                             approval=approval)).decision


@pytest.mark.parametrize("extensions, obligations", [
    (("obligations",), ()), ((), ("mission_record",)), ((), ())])
def test_a_pep_that_opted_in_to_only_part_gets_no_requestable_denial(
        extensions: tuple[str, ...], obligations: tuple[str, ...]) -> None:
    # Profile, Predicate: a denial to a PEP that has not opted in to
    # mission_record, which needs both lists, MUST NOT be requestable.
    pdp, _ = _staged()
    denied = pdp.evaluate(_req("send_message", "external:x", extensions=extensions,
                               obligations=obligations))
    assert (denied.decision, denied.reason) == (False, "prohibited_composition")
    assert denied.access_request is None and denied.evaluation_id is None


def test_a_batch_conflict_after_an_approval_is_told_to_retry() -> None:
    # Profile, PDP rules: after an approval, every "evaluate again later"
    # denial carries next_action retry, history_conflict included.
    pdp, _ = _staged()
    denied = pdp.evaluate(_req("send_message", "external:x"))
    assert denied.evaluation_id is not None
    approval = pdp.approve(denied.evaluation_id)
    batch = pdp.evaluate_batch((_req("read_record", "hr:2"),
                                _req("send_message", "external:x", approval=approval)))
    second = batch.evaluations[1]
    assert (second.decision, second.reason) == (False, "history_conflict")
    assert second.context.get("next_action") == "retry"


def test_a_batch_conflicts_on_any_shared_sequence() -> None:
    # Profile, PDP rules: two Acts of a batch that could each fill a step of
    # the same sequence are not both permitted, even when one of them could
    # also fill a step of another sequence.
    other = RestrictedSequence("create_send", (SequenceStep("create_user"),
                                               SequenceStep("send_message")))
    pdp = CompositionPDP(CompositionPolicy((READ_SEND, other)), MissionHistoryService())
    batch = pdp.evaluate_batch((_req("read_record", "hr:1"), _req("send_message", "external:x")))
    assert [d.reason for d in batch.evaluations] == [None, "history_conflict"]


# --- History Authority ------------------------------------------------------------

def test_an_admission_id_is_scoped_to_its_writer() -> None:
    # Profile, History Authority item 2: a retry returns the Act already
    # admitted only for the same writer.
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "read_record", "hr:1", writer="pep.hr", admission_id="a1")
    with pytest.raises(HistoryConflict):
        mhs.admit("m", 1, "read_record", "hr:1", writer="pep.mail", admission_id="a1")
    assert [a.seq for a in mhs.history("m")] == [1]


def _patch(app: MHSHttpApp, token: str, body: dict[str, Any]) -> str:
    data = json.dumps(body).encode()
    env: dict[str, Any] = {"REQUEST_METHOD": "PATCH", "PATH_INFO": "/missions/m/acts/1",
                           "QUERY_STRING": "", "wsgi.input": io.BytesIO(data),
                           "CONTENT_LENGTH": str(len(data)),
                           "HTTP_AUTHORIZATION": f"Bearer {token}"}
    got: dict[str, Any] = {}
    b"".join(app(env, lambda s, h: got.update(s=s)))
    return str(got["s"])


def test_an_outcome_report_cannot_name_another_writer() -> None:
    # Profile, History Authority items 1 and 4: the writer is the
    # authenticated caller, never a name the report presents.
    mhs = MissionHistoryService(trusted_writers=frozenset({"pep.hr", "pep.mail"}))
    app = MHSHttpApp(mhs, StaticTokenAuthenticator({"t-hr": "pep.hr", "t-mail": "pep.mail"}))
    mhs.admit("m", 1, "read_record", "hr:1", writer="pep.hr", admission_id="a1")
    status = _patch(app, "t-mail", {"outcome": "failed", "admission_id": "a1",
                                    "recorded_by": "pep.hr"})
    assert status in ("400 Bad Request", "403 Forbidden")
    assert mhs.history("m")[0].outcome is ActOutcome.OPEN


_RECORD = {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"},
           "outcome": "completed", "result_classes": [], "recorded_by": "pep.hr"}


@pytest.mark.parametrize("member", sorted(_RECORD))
def test_a_record_missing_any_member_is_not_an_act_record(member: str) -> None:
    # Profile, History Authority: a record that lacks a member makes the
    # history unusable (rule 4).
    assert _act(dict(_RECORD)).seq == 1
    record = {k: v for k, v in _RECORD.items() if k != member}
    with pytest.raises(RemoteUnavailable):
        _act(record)


# --- Policy -----------------------------------------------------------------------

@pytest.mark.parametrize("steps", [(), (SequenceStep("read_record"),)])
def test_a_sequence_of_fewer_than_two_steps_is_refused(steps: tuple[SequenceStep, ...]) -> None:
    # Profile, Terminology: a PDP refuses to load a set with a sequence of
    # fewer than two steps.
    with pytest.raises(ValueError):
        RestrictedSequence("short", steps)
