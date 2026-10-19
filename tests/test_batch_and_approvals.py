"""Batch conflicts, completeness, stale reads, single-use approvals and
matching with overlapping steps."""

from __future__ import annotations

from datetime import timedelta

import pytest

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
    EXTENSION_OBLIGATIONS,
    OBLIGATION_MISSION_RECORD,
    REASON_HISTORY_CONFLICT,
    REASON_HISTORY_UNAVAILABLE,
    REASON_PROHIBITED_COMPOSITION,
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)

ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint

S = Subject("agent", "agent-7")
SALARY = frozenset({"personal_data.salary"})
READ_SEND = RestrictedSequence(
    name="read_send",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send_message", resources=frozenset({"external:*"})),
    ),
    requestable=True,
)
CREATE_DELETE = RestrictedSequence(
    name="create_delete",
    steps=(SequenceStep("create_user"), SequenceStep("delete_audit_log")),
)


def req(action: str, resource: str, **context: object) -> EvaluationRequest:
    return EvaluationRequest(
        subject=S, action=Action(action), resource=Resource("r", resource),
        mission=Mission(id="m1", issuer="iss"),
        supported_mandatory_extensions=(EXTENSION_OBLIGATIONS,),
        supported_obligations=(OBLIGATION_MISSION_RECORD,),
        context=dict(context),
    )


def read_done(mhs: MissionHistoryService) -> None:
    mhs.admit("m1", 1, "read_record", "hr:1", writer="pep.hr")
    mhs.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="pep.hr", result_classes=SALARY)


# --- Batch conflict is per Restricted Sequence ------------------------------


def test_batch_acts_extending_different_sequences_do_not_conflict() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((READ_SEND, CREATE_DELETE)), mhs,
                         access_request_endpoint=ARS)
    out = pdp.evaluate_batch((req("read_record", "hr:1"), req("create_user", "u:1")))
    assert [d.decision for d in out.evaluations] == [True, True]


def test_batch_acts_extending_same_sequence_conflict() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((READ_SEND, CREATE_DELETE)), mhs,
                         access_request_endpoint=ARS)
    out = pdp.evaluate_batch((req("read_record", "hr:1"), req("send_message", "external:x")))
    assert out.evaluations[1].reason == REASON_HISTORY_CONFLICT


def test_final_step_act_is_serialized_even_on_empty_history() -> None:
    """A lone send gets the obligation: a concurrent read could supply the
    prefix, so it must take a position (draft: matches any step)."""
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), MissionHistoryService(),
                         access_request_endpoint=ARS)
    d = pdp.evaluate(req("send_message", "external:x"))
    assert d.decision and d.obligations[0].type == OBLIGATION_MISSION_RECORD


# --- Completeness: gaps and stale reads -------------------------------------


class _GappyMHS(MissionHistoryService):
    def history(self, mission_id: str, policy: str | None = None) -> list[Act]:
        return [Act(1, "write_document", "d"), Act(3, "write_document", "d")]


def test_history_with_a_gap_fails_closed() -> None:
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), _GappyMHS(), access_request_endpoint=ARS)
    d = pdp.evaluate(req("send_message", "external:x"))
    assert not d.decision and d.reason == REASON_HISTORY_UNAVAILABLE


@pytest.mark.parametrize("seqs", [(2, 1), (1, 1), (1, 2, 2)])
def test_a_history_out_of_order_or_with_a_repeat_fails_closed(seqs: tuple[int, ...]) -> None:
    # Rule 4: the positions read are exactly 1 to n, in that order.
    class Disordered(MissionHistoryService):
        def history(self, mission_id: str, policy: str | None = None) -> list[Act]:
            return [Act(s, "write_document", "d") for s in seqs]

    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), Disordered(), access_request_endpoint=ARS)
    d = pdp.evaluate(req("send_message", "external:x"))
    assert not d.decision and d.reason == REASON_HISTORY_UNAVAILABLE


def test_a_designation_of_no_set_pins_no_new_mission() -> None:
    # History Authority, item 6: a designation of no set lets no new Mission be
    # pinned, so every first read is refused and the PDP decides nothing.
    mhs = MissionHistoryService()
    mhs.designate(frozenset())
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs, access_request_endpoint=ARS)
    d = pdp.evaluate(req("read_record", "hr:1"))
    assert not d.decision and d.reason == "policy_mismatch"
    assert mhs.policy_of("m1") is None


class _StaleView(MissionHistoryService):
    """A PDP-side replica that lags behind the authority by the last act."""

    def __init__(self, authority: MissionHistoryService) -> None:
        super().__init__()
        self._authority = authority

    def history(self, mission_id: str, policy: str | None = None) -> list[Act]:
        return self._authority.history(mission_id)[:-1]


def test_stale_read_is_caught_at_admission() -> None:
    """A stale replica: the PDP permits on stale history, but the
    obligation names a position the authority has already used, so the
    admission fails and the send never starts."""
    authority = MissionHistoryService()
    read_done(authority)
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), _StaleView(authority),
                         access_request_endpoint=ARS)
    d = pdp.evaluate(req("send_message", "external:x"))
    assert d.decision  # stale view: permitted ...
    seq = d.obligations[0].properties["expected_seq"]
    with pytest.raises(HistoryConflict):  # ... but cannot be admitted
        authority.admit("m1", seq, "send_message", "external:x", writer="pep.mail")


def test_a_view_that_is_not_a_prefix_of_the_history_passes_rule_2() -> None:
    """Why a read holds only durable records (History Authority, item 5). A
    replica that served an admission the authority then lost has a view of
    the right length but other Acts: the send is permitted on it, and its
    admission takes the authority's next position, after a salary read."""
    cleanup = RestrictedSequence("cleanup", (SequenceStep("write_document"),
                                             SequenceStep("delete_document")))
    policy = CompositionPolicy((READ_SEND, cleanup))
    replica = MissionHistoryService()
    replica.admit("m1", 1, "write_document", "doc:q4", writer="pep.docs")  # lost upstream
    authority = MissionHistoryService()
    read_done(authority)
    send = CompositionPDP(policy, replica, access_request_endpoint=ARS).evaluate(
        req("send_message", "external:x"))
    assert send.decision
    # The authority's own history denies it.
    denied = CompositionPDP(policy, authority, access_request_endpoint=ARS).evaluate(
        req("send_message", "external:x"))
    assert not denied.decision
    seq = send.obligations[0].properties["expected_seq"]
    authority.admit("m1", seq, "send_message", "external:x", writer="pep.mail")
    assert [a.action for a in authority.history("m1")] == ["read_record", "send_message"]


# --- ARAP: requestable denial, approval, re-evaluation ----------------------


def _denied(pdp: CompositionPDP) -> str:
    d = pdp.evaluate(req("send_message", "external:x"))
    assert not d.decision and d.reason == REASON_PROHIBITED_COMPOSITION
    assert d.access_request is not None and d.evaluation_id is not None
    return d.evaluation_id


def test_approved_reevaluation_permits_once() -> None:
    mhs = MissionHistoryService()
    read_done(mhs)
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs, access_request_endpoint=ARS)
    rid = _denied(pdp)
    approval = pdp.approve(rid)
    assert pdp.evaluate(req("send_message", "external:x", approval=approval)).decision
    # single use
    assert not pdp.evaluate(req("send_message", "external:x", approval=approval)).decision


def test_unapproved_or_forged_approval_does_not_permit() -> None:
    mhs = MissionHistoryService()
    read_done(mhs)
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs, access_request_endpoint=ARS)
    rid = _denied(pdp)
    for approval in ({"id": rid}, {"id": "apr_made-up"}, {"access_request_id": rid}, "yes", {}):
        assert not pdp.evaluate(req("send_message", "external:x", approval=approval)).decision
    with pytest.raises(KeyError):
        pdp.approve("made-up")


def test_approval_is_bound_to_act_and_history_position() -> None:
    mhs = MissionHistoryService()
    read_done(mhs)
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs, access_request_endpoint=ARS)
    rid = _denied(pdp)
    approval = pdp.approve(rid)
    # different recipient
    assert not pdp.evaluate(req("send_message", "external:other", approval=approval)).decision
    # history moved on: the approval is out of its scope (ARAP ``out_of_scope``),
    # so the PEP gets a fresh requestable denial and next_action "request"
    mhs.admit("m1", 2, "write_document", "d", writer="pep.doc")
    moved = pdp.evaluate(req("send_message", "external:x", approval=approval))
    assert (moved.decision, moved.reason) == (False, REASON_PROHIBITED_COMPOSITION)
    assert moved.context["next_action"] == "request" and moved.access_request is not None


class _NonRecordingPDP(CompositionPDP):
    """A PDP that does not record an approval as used at its first permit, as
    PDP replicas behave that verify an approval without sharing whether it was
    used (profile, Approvals, Replicas)."""

    def _consume(self, approval_id: str) -> bool:
        return True


@pytest.mark.parametrize("pdp_class", [CompositionPDP, _NonRecordingPDP])
def test_an_approval_admits_one_act_whether_or_not_the_pdp_records_its_use(
        pdp_class: type[CompositionPDP]) -> None:
    # Profile, Approvals, Lost responses and Replicas: a PDP that does not
    # record the use permits again at the approval's position, for a PEP whose
    # permit response was lost, and rule 2 still admits one Act there. Once
    # that position is taken the approval admits nothing more.
    mhs = MissionHistoryService()
    read_done(mhs)
    pdp = pdp_class(CompositionPolicy((READ_SEND,)), mhs, access_request_endpoint=ARS)
    approval = pdp.approve(_denied(pdp))
    first = pdp.evaluate(req("send_message", "external:x", approval=approval))
    assert first.decision
    seq = first.obligations[0].properties["expected_seq"]
    again = pdp.evaluate(req("send_message", "external:x", approval=approval))
    if pdp_class is _NonRecordingPDP:
        assert again.decision and again.obligations[0].properties["expected_seq"] == seq
    else:
        assert (again.decision, again.context["next_action"]) == (False, "request")
    mhs.admit("m1", seq, "send_message", "external:x", writer="pep.mail")
    with pytest.raises(HistoryConflict):
        mhs.admit("m1", seq, "send_message", "external:x", writer="pep.mail.2")
    after = pdp.evaluate(req("send_message", "external:x", approval=approval))
    assert (after.decision, after.reason) == (False, REASON_PROHIBITED_COMPOSITION)
    assert after.context["next_action"] == "request" and after.access_request is not None


@pytest.mark.parametrize("pdp_class", [CompositionPDP, _NonRecordingPDP])
def test_an_approved_act_that_loses_the_admission_race_needs_a_new_approval(
        pdp_class: type[CompositionPDP]) -> None:
    # Another Act takes the approval's position first, so the approved send's
    # admission fails (rule 2). Evaluated again with the same approval it is
    # denied with a fresh requestable denial, and nothing is permitted at the
    # next position. For a PDP that does not record the use, the position the
    # approval was given for is the only thing that stops a second Act.
    mhs = MissionHistoryService()
    read_done(mhs)
    pdp = pdp_class(CompositionPolicy((READ_SEND,)), mhs, access_request_endpoint=ARS)
    approval = pdp.approve(_denied(pdp))
    permit = pdp.evaluate(req("send_message", "external:x", approval=approval))
    seq = permit.obligations[0].properties["expected_seq"]
    mhs.admit("m1", seq, "write_document", "d", writer="pep.doc")
    with pytest.raises(HistoryConflict):
        mhs.admit("m1", seq, "send_message", "external:x", writer="pep.mail")
    again = pdp.evaluate(req("send_message", "external:x", approval=approval))
    assert (again.decision, again.reason) == (False, REASON_PROHIBITED_COMPOSITION)
    assert again.context["next_action"] == "request" and again.access_request is not None


def test_expired_approval_does_not_permit() -> None:
    mhs = MissionHistoryService()
    read_done(mhs)
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs, approval_ttl=timedelta(0),
                         access_request_endpoint=ARS)
    rid = _denied(pdp)
    approval = pdp.approve(rid)
    assert not pdp.evaluate(req("send_message", "external:x", approval=approval)).decision


def test_a_request_whose_window_closed_cannot_be_approved() -> None:
    # Profile, Approvals: the access request's expires_at bounds how long it can
    # be submitted and decided; after it, no approval is issued.
    mhs = MissionHistoryService()
    read_done(mhs)
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs, request_ttl=timedelta(0),
                         access_request_endpoint=ARS)
    rid = _denied(pdp)
    with pytest.raises(KeyError):
        pdp.approve(rid)


def test_approval_for_other_mission_does_not_permit() -> None:
    mhs = MissionHistoryService()
    read_done(mhs)
    mhs.admit("m2", 1, "read_record", "hr:1", writer="pep.hr")
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), mhs, access_request_endpoint=ARS)
    rid = _denied(pdp)
    approval = pdp.approve(rid)
    other = EvaluationRequest(
        subject=S, action=Action("send_message"), resource=Resource("r", "external:x"),
        mission=Mission(id="m2", issuer="iss"),
        supported_mandatory_extensions=(EXTENSION_OBLIGATIONS,),
        supported_obligations=(OBLIGATION_MISSION_RECORD,),
        context={"approval": approval},
    )
    assert not pdp.evaluate(other).decision


# --- Metadata, greedy matching -----------------------------------------------


def test_metadata_advertises_the_obligations_core_and_mission_record() -> None:
    # Profile, PDP rules: a PEP discovers this profile from mission_record in
    # supported_obligations; capability URNs are for extensions (Extensibility
    # Model), so the profile defines none of its own.
    pdp = CompositionPDP(CompositionPolicy((READ_SEND,)), MissionHistoryService())
    assert pdp.metadata() == {
        "capabilities": ["urn:openid:authzen:capability:obligations"],
        "supported_obligations": ["mission_record"],
    }


def test_greedy_match_is_complete_with_overlapping_steps() -> None:
    """Greedy left-to-right matching must not miss an embedding when steps
    overlap: earliest-match is exact for subsequence tests, checked here on a
    repeated, overlapping pattern."""
    seq = RestrictedSequence(
        name="aab",
        steps=(SequenceStep("a*"), SequenceStep("ab"), SequenceStep("send")),
    )
    policy = CompositionPolicy((seq,))
    hist = [Act(1, "ab", "r", ActOutcome.COMPLETED), Act(2, "ax", "r", ActOutcome.COMPLETED),
            Act(3, "ab", "r", ActOutcome.COMPLETED)]
    assert not policy.completes(hist, Act(4, "send", "r")).satisfied
