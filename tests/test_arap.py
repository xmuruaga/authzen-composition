"""ARAP's shared-state flow: the Access Request Service the PDP plays, its
HTTP routes, and the PEP-side client (ARAP Draft 1, openid/authzen ``6d5380c``).

Each section names the ARAP rule it pins.
"""

from __future__ import annotations

import io
import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from authzen_composition.arap import (
    RETENTION,
    AccessRequestError,
    AccessRequestService,
    NotAuthorized,
    entity,
    same,
)
from authzen_composition.http_binding import StaticTokenAuthenticator
from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import ActOutcome, CompositionPolicy, RestrictedSequence
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pdp_http import REQUESTS_PATH, PDPHttpApp, request_from_json
from authzen_composition.pep import ReferencePEP
from authzen_composition.remote import (
    AccessRequestClient,
    AccessRequestRefused,
    RemoteUnavailable,
    request_to_json,
)
from authzen_composition.scenarios import EXFIL_POLICY
from authzen_composition.types import (
    Action,
    Decision,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)
from tests.test_remote import serve

ISSUER = "https://missions.example"  # the issuer of every Mission here
ENDPOINT = "https://pdp.example/access/v1/requests"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _send(subject: str = "agent-7", to: str = "external:press", approval: dict | None = None,
          act: str | None = None) -> EvaluationRequest:
    props = {"act": {"sub": act}} if act else {}
    return EvaluationRequest(
        Subject("agent", subject, properties=props), Action("send_message"),
        Resource("recipient", to), mission=Mission("m", ISSUER),
        supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",),
        context={} if approval is None else {"approval": approval})


def _setup(policy: CompositionPolicy = EXFIL_POLICY, endpoint: str = ENDPOINT,
           loopback: bool = False) -> tuple[CompositionPDP, AccessRequestService, Clock]:
    clock = Clock()
    mhs = MissionHistoryService()
    for seq, (action, rid, classes) in enumerate(
            (("read_record", "hr:1", {"personal_data.salary"}),
             ("write_document", "doc:1", set())), start=1):
        mhs.admit("m", seq, action, rid, writer="pep")
        mhs.set_outcome("m", seq, ActOutcome.COMPLETED, writer="pep",
                        result_classes=frozenset(classes))
    pdp = CompositionPDP(policy, mhs, access_request_endpoint=endpoint, clock=clock,
                         allow_loopback_http=loopback)
    ars = AccessRequestService(pdp, submitters=frozenset({"pep.mail"}),
                               approvers=frozenset({"alice", "agent-7"}), clock=clock)
    return pdp, ars, clock


def _submission(request: EvaluationRequest, decision: Decision) -> dict[str, Any]:
    assert decision.access_request is not None
    body = request_to_json(request)
    body["denial"] = {"evaluation_id": decision.evaluation_id, "reason": decision.reason,
                      **decision.access_request}
    return body


def _denied(pdp: CompositionPDP, request: EvaluationRequest | None = None
            ) -> tuple[EvaluationRequest, Decision]:
    request = request or _send()
    decision = pdp.evaluate(request)
    assert not decision.decision and decision.access_request is not None
    return request, decision


# --- The whole flow --------------------------------------------------------

def test_deny_submit_approve_reevaluate_and_no_reuse() -> None:
    pdp, ars, _ = _setup()
    request, decision = _denied(pdp)
    status, answer = ars.submit("pep.mail", _submission(request, decision))
    task = answer["task"]
    assert status == 202 and task["status"] == "pending" and "result" not in answer
    assert task["status_endpoint"] == f"{ENDPOINT}/{task['id']}"
    assert task["id"].startswith("arq_") and len(task["id"]) == 36
    # "pending" gives the PEP nothing to act on.
    assert AccessRequestClient.approval(ars.status("pep.mail", task["id"])) is None

    done = ars.decide("alice", task["id"], approve=True)
    assert done["task"]["status"] == "approved"
    result = done["result"]
    assert result["mode"] == "reevaluate"
    assert set(result["approval"]) == {"id", "approved_until", "approved_at"}
    approval = AccessRequestClient.approval(ars.status("pep.mail", task["id"]))
    assert approval == result["approval"]

    # ARAP "Re-evaluate": the approval at context.approval, the rest unchanged.
    permit = pdp.evaluate(_send(approval=approval))
    assert permit.decision
    # Single use: presented again it is not applicable, and the PEP is told
    # to request again, with the fresh requestable denial it needs.
    again = pdp.evaluate(_send(approval=approval))
    assert not again.decision
    assert again.context["next_action"] == "request" and again.access_request is not None


def test_a_denied_task_carries_no_approval() -> None:
    pdp, ars, _ = _setup()
    _, answer = ars.submit("pep.mail", _submission(*_denied(pdp)))
    done = ars.decide("alice", answer["task"]["id"], approve=False)
    assert done["task"]["status"] == "denied" and "result" not in done
    assert AccessRequestClient.approval(done) is None


def test_an_approval_for_a_non_requestable_denial_is_told_to_stop() -> None:
    # ARAP "Handle a Re-evaluation Denial": no fresh access_request, so the
    # PDP says none rather than request.
    plain = CompositionPolicy(tuple(
        RestrictedSequence(s.name, s.steps, requestable=False) for s in EXFIL_POLICY.sequences))
    pdp, _, _ = _setup(plain)
    denied = pdp.evaluate(_send(approval={"id": "apr_x"}))
    assert not denied.decision and denied.access_request is None
    assert denied.context["next_action"] == "none"


# --- Process a Submission ----------------------------------------------------

@pytest.mark.parametrize("change, kind", [
    (lambda b: b.pop("denial"), "invalid_denial_binding"),
    (lambda b: b["denial"].pop("evaluation_id"), "invalid_denial_binding"),
    (lambda b: b["denial"].update(evaluation_id=None, binding_token="x.y.z"),
     "invalid_denial_binding"),
    (lambda b: b["denial"].pop("expires_at"), "invalid_denial_binding"),
    (lambda b: b["denial"].update(evaluation_id="eval_never_issued"), "not_requestable"),
    (lambda b: b["resource"].update(id="external:other"), "invalid_denial_binding"),
    (lambda b: b["subject"].update(id="agent-8"), "invalid_denial_binding"),
    (lambda b: b["action"].update(name="send_other"), "invalid_denial_binding"),
    (lambda b: b["action"].update(properties={"x": 1}), "invalid_denial_binding"),
    (lambda b: b["context"]["mission"].update(id="m2"), "invalid_denial_binding"),
    (lambda b: b["context"].pop("mission"), "invalid_denial_binding"),
    # The adoption declarations are authorization-relevant Context too.
    (lambda b: b["context"].update(supported_obligations=[]), "invalid_denial_binding"),
    (lambda b: b["context"].pop("supported_mandatory_extensions"), "invalid_denial_binding"),
    (lambda b: b["context"].update(supported_mandatory_extensions=["obligations", "x"]),
     "invalid_denial_binding"),
    (lambda b: b.update(context=[]), "invalid_denial_binding"),
    (lambda b: b.update(subject="agent-7"), "invalid_denial_binding"),
])
def test_a_submission_not_bound_to_the_denial_is_refused(change: Any, kind: str) -> None:
    pdp, ars, _ = _setup()
    body = _submission(*_denied(pdp))
    change(body)
    with pytest.raises(AccessRequestError) as exc:
        ars.submit("pep.mail", body)
    assert exc.value.kind == kind
    assert exc.value.problem()["type"] == "urn:openid:authzen:access-request:error:" + kind


def test_freshness_is_checked_against_the_recorded_expiry_not_the_echoed_one() -> None:
    pdp, ars, clock = _setup()
    body = _submission(*_denied(pdp))
    body["denial"]["expires_at"] = "2099-01-01T00:00:00Z"   # the PEP's echo is not trusted
    clock.now += pdp.request_ttl
    with pytest.raises(AccessRequestError) as exc:
        ars.submit("pep.mail", body)
    assert (exc.value.kind, exc.value.status) == ("expired_denial", 410)


def test_submission_time_context_and_the_actor_do_not_break_the_binding() -> None:
    pdp, ars, _ = _setup()
    request, decision = _denied(pdp, _send(act="https://orchestrator.example"))
    body = _submission(request, decision)
    body["context"]["justification"] = "Quarterly figures for the press office"
    del body["subject"]["properties"]["act"]       # ARAP: the actor may move to client.actor
    body["client"] = {"actor": {"sub": "https://orchestrator.example"}}
    assert ars.submit("pep.mail", body)[0] == 202


def test_an_approval_does_not_carry_to_another_actor() -> None:
    # ARAP's exact-match comparison leaves out subject.properties.act; this
    # profile's approval scope keeps it (ARAP lets a PDP record a narrower
    # scope), so a sub-agent with the same principal cannot use it.
    pdp, ars, _ = _setup()
    request, decision = _denied(pdp, _send(act="https://orchestrator.example"))
    _, answer = ars.submit("pep.mail", _submission(request, decision))
    approval = ars.decide("alice", answer["task"]["id"], approve=True)["result"]["approval"]
    for other in (_send(approval=approval, act="https://sub-agent.example"),
                  _send(approval=approval)):
        denied = pdp.evaluate(other)
        assert not denied.decision and denied.context["next_action"] == "request"
    assert pdp.evaluate(_send(approval=approval, act="https://orchestrator.example")).decision


def test_the_reference_pep_carries_the_actor_when_it_evaluates_again() -> None:
    # PEP processing rules: the actor stays in subject.properties.act at
    # re-evaluation, so the narrowed approval scope can compare it.
    pdp, ars, clock = _setup()
    request, decision = _denied(pdp, _send(act="https://orchestrator.example"))
    _, answer = ars.submit("pep.mail", _submission(request, decision))
    approval = ars.decide("alice", answer["task"]["id"], approve=True)["result"]["approval"]
    seen: list[EvaluationRequest] = []

    class Recording:
        def evaluate(self, r: EvaluationRequest) -> Decision:
            seen.append(r)
            return pdp.evaluate(r)

    pep = ReferencePEP(Recording(), pdp.mhs, "pep.mail", clock=clock)
    sent = pep.enforce(mission_id="m", mission_issuer=ISSUER,
                       subject=request.subject, action=request.action,
                       resource=request.resource, perform=lambda: "sent",
                       context={"approval": approval})
    assert sent == "sent"
    assert seen[0].subject.properties["act"] == {"sub": "https://orchestrator.example"}


def test_an_approval_does_not_carry_to_another_actor_in_context_actor() -> None:
    # The mission-bound drafts carry the acting lineage in context.actor,
    # never in subject; the approval scope compares that member too.
    pdp, ars, _ = _setup()
    parent = {"client_id": "orchestrator", "act": {"sub": "https://orchestrator.example"}}
    child = {"client_id": "sub-agent", "act": {"sub": "https://sub-agent.example"}}

    def send(actor: dict | None, approval: dict | None = None) -> EvaluationRequest:
        r = _send(approval=approval)
        if actor is not None:
            r.context["actor"] = actor
        return r

    request, decision = _denied(pdp, send(parent))
    _, answer = ars.submit("pep.mail", _submission(request, decision))
    approval = ars.decide("alice", answer["task"]["id"], approve=True)["result"]["approval"]
    for other in (send(child, approval), send(None, approval)):
        denied = pdp.evaluate(other)
        assert not denied.decision and denied.context["next_action"] == "request"
    assert pdp.evaluate(send(parent, approval)).decision
    # context.actor is authorization-relevant Context of the denial (ARAP
    # binds what approval scope compares), so a submission that changes or
    # drops it does not bind to the denial.
    request, decision = _denied(pdp, send(parent))
    for actor in (child, None):
        body = _submission(request, decision)
        if actor is None:
            del body["context"]["actor"]
        else:
            body["context"]["actor"] = actor
        with pytest.raises(AccessRequestError) as exc:
            ars.submit("pep.mail", body)
        assert exc.value.kind == "invalid_denial_binding"


def test_structural_comparison() -> None:
    assert same({"a": [1, "x"]}, {"a": [1.0, "x"]})
    assert not same(True, 1) and not same(1, True) and not same(0, False)
    assert not same([1, 2], [2, 1]) and not same([1], [1, 1])
    assert not same({"a": None}, {}) and not same("1", 1)
    assert same(None, None) and not same({"a": 1}, {"b": 1})
    assert entity({"type": "t", "id": "i", "properties": {}}, "subject") == {"type": "t", "id": "i"}
    with pytest.raises(ValueError):
        entity("agent", "subject")


def test_idempotent_submission() -> None:
    pdp, ars, _ = _setup()
    body = _submission(*_denied(pdp))
    first = ars.submit("pep.mail", body, idempotency_key="k1")[1]
    assert ars.submit("pep.mail", json.loads(json.dumps(body)), idempotency_key="k1")[1] == first
    changed = {**body, "context": {**body["context"], "justification": "other"}}
    with pytest.raises(AccessRequestError) as exc:
        ars.submit("pep.mail", changed, idempotency_key="k1")
    assert (exc.value.kind, exc.value.status) == ("duplicate_request", 409)
    # A key is scoped to its caller; without one every submission is new.
    assert ars.submit("pep.mail", body)[1]["task"]["id"] != first["task"]["id"]


# --- Task Handle, authorization, approver eligibility -------------------------

def test_only_configured_submitters_submit_and_only_the_requester_reads_the_task() -> None:
    pdp, ars, _ = _setup()
    body = _submission(*_denied(pdp))
    with pytest.raises(NotAuthorized):
        ars.submit("agent-7", body)
    task = ars.submit("pep.mail", body)[1]["task"]["id"]
    for caller, task_id in (("pep.hr", task), ("pep.mail", "arq_unknown")):
        with pytest.raises(AccessRequestError) as exc:
            ars.status(caller, task_id)
        assert exc.value.kind == "unknown_task"


@pytest.mark.parametrize("approver", ["mallory", "agent-7", "pep.mail"])
def test_an_ineligible_approver_cannot_approve(approver: str) -> None:
    # Not an approver; the request's own Subject (self-approval); the
    # requester. "agent-7" is configured as an approver and still refused.
    pdp, ars, _ = _setup()
    ars.approvers = frozenset({"alice", "agent-7", "pep.mail"})
    task = ars.submit("pep.mail", _submission(*_denied(pdp)))[1]["task"]["id"]
    with pytest.raises(NotAuthorized):
        ars.decide(approver, task, approve=True)
    assert ars.status("pep.mail", task)["task"]["status"] == "pending"


def test_a_terminal_task_does_not_transition_again() -> None:
    pdp, ars, _ = _setup()
    task = ars.submit("pep.mail", _submission(*_denied(pdp)))[1]["task"]["id"]
    ars.decide("alice", task, approve=False)
    with pytest.raises(AccessRequestError) as exc:
        ars.decide("alice", task, approve=True)
    assert (exc.value.kind, exc.value.status) == ("invalid_task_state", 409)
    with pytest.raises(AccessRequestError):
        ars.decide("alice", "arq_unknown", approve=True)


def test_a_pending_task_expires_and_then_is_gone() -> None:
    pdp, ars, clock = _setup()
    task = ars.submit("pep.mail", _submission(*_denied(pdp)))[1]["task"]["id"]
    clock.now += pdp.request_ttl
    assert ars.status("pep.mail", task)["task"]["status"] == "expired"
    with pytest.raises(AccessRequestError) as exc:
        ars.status("pep.mail", task)
    assert (exc.value.kind, exc.value.status) == ("task_expired", 410)
    with pytest.raises(AccessRequestError) as exc:
        ars.decide("alice", task, approve=True)
    assert exc.value.kind == "invalid_task_state"


def test_an_approval_whose_denial_was_spent_fails_the_task() -> None:
    pdp, ars, _ = _setup()
    request, decision = _denied(pdp)
    task = ars.submit("pep.mail", _submission(request, decision))[1]["task"]["id"]
    assert decision.evaluation_id is not None
    assert pdp.evaluate(_send(approval=pdp.approve(decision.evaluation_id))).decision
    assert ars.decide("alice", task, approve=True)["task"]["status"] == "failed"


def test_the_service_needs_an_endpoint_and_the_endpoint_https() -> None:
    with pytest.raises(ValueError):
        AccessRequestService(CompositionPDP(EXFIL_POLICY, MissionHistoryService()),
                             submitters=frozenset(), approvers=frozenset())
    for endpoint, loopback in (("http://127.0.0.1:8080/r", False),
                               ("http://example.com/r", True),
                               ("http://127.0.0.10/r", True)):
        with pytest.raises(ValueError):
            CompositionPDP(EXFIL_POLICY, MissionHistoryService(),
                           access_request_endpoint=endpoint, allow_loopback_http=loopback)
    CompositionPDP(EXFIL_POLICY, MissionHistoryService(),
                   access_request_endpoint="http://127.0.0.1:8080/r", allow_loopback_http=True)
    CompositionPDP(EXFIL_POLICY, MissionHistoryService(),
                   access_request_endpoint="http://127.0.0.1/r", allow_loopback_http=True)


# --- Concurrency and time ------------------------------------------------------

class _Gate(Clock):
    """Each evaluating thread waits for the other at its first clock reading,
    so both have checked their approval before either uses it."""

    def __init__(self) -> None:
        super().__init__()
        self.barrier = threading.Barrier(2)
        self.waited: set[str] = set()

    def __call__(self) -> datetime:
        name = threading.current_thread().name
        if name.startswith("eval-") and name not in self.waited:
            self.waited.add(name)
            self.barrier.wait(timeout=10)
        return super().__call__()


def test_two_approvals_of_one_denial_presented_at_once_give_one_permit() -> None:
    # The same denial submitted twice and both tasks approved: two approvals
    # of one request. Presented at the same time, one permit, and the other
    # evaluation is a denial, never an error.
    pdp, ars, _ = _setup()
    gate = _Gate()
    pdp.clock = gate
    request, decision = _denied(pdp)
    body = _submission(request, decision)
    approvals = [ars.decide(approver, ars.submit("pep.mail", body)[1]["task"]["id"],
                            approve=True)["result"]["approval"]
                 for approver in ("alice", "alice")]
    out: dict[str, Any] = {}

    def evaluate(name: str, approval: dict[str, Any]) -> None:
        try:
            out[name] = pdp.evaluate(_send(approval=approval))
        except Exception as exc:  # noqa: BLE001
            out[name] = exc

    threads = [threading.Thread(target=evaluate, args=(f"eval-{i}", a), name=f"eval-{i}")
               for i, a in enumerate(approvals)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert all(isinstance(d, Decision) for d in out.values()), out
    assert sorted(d.decision for d in out.values()) == [False, True]
    # The other evaluation's approval was spent with the request it approved:
    # it is told to ask again, with a fresh request, as when an approval
    # presented later no longer applies.
    lost = next(d for d in out.values() if not d.decision)
    assert lost.reason == "prohibited_composition" and lost.access_request is not None
    assert lost.context.get("next_action") == "request"


def test_a_second_approval_does_not_move_the_first_s_approved_until() -> None:
    pdp, ars, clock = _setup()
    request, decision = _denied(pdp)
    assert decision.evaluation_id is not None
    first = pdp.approve(decision.evaluation_id)
    clock.now += timedelta(minutes=4)
    second = pdp.approve(decision.evaluation_id)
    clock.now += timedelta(minutes=2)
    # The first approval's own approved_until has passed; the second's has not.
    # An expired approval does not apply, so the denial asks for a fresh request.
    expired = pdp.evaluate(_send(approval=first))
    assert not expired.decision and expired.context.get("next_action") == "request"
    assert pdp.evaluate(_send(approval=second)).decision


def test_an_approval_that_expires_before_it_is_used_gives_no_permit() -> None:
    # Checked, then used: an approval whose approved_until passes between the
    # check and its use (a thread preempted in between) is not used.
    pdp, ars, clock = _setup()
    request, decision = _denied(pdp)
    assert decision.evaluation_id is not None
    approval = pdp.approve(decision.evaluation_id)
    clock.now += pdp.approval_ttl
    assert pdp._consume(approval["id"]) is False


def test_a_denial_is_kept_while_any_of_its_approvals_can_be_used() -> None:
    # Two approvals of one request, the second given by a clock that stepped
    # back: the denial is not dropped while the first can still be used.
    pdp, ars, clock = _setup()
    request, decision = _denied(pdp)
    assert decision.evaluation_id is not None
    clock.now += pdp.request_ttl - timedelta(minutes=1)
    first = pdp.approve(decision.evaluation_id)
    clock.now -= timedelta(minutes=1)
    pdp.approve(decision.evaluation_id)
    clock.now += pdp.approval_ttl + timedelta(seconds=30)
    _denied(pdp, _send(to="external:other"))  # a new requestable denial prunes
    assert pdp.evaluate(_send(approval=first)).decision


def test_published_times_are_the_enforced_ones() -> None:
    # A clock between two seconds: the denial's expires_at and the approval's
    # approved_until are published to the second, and the PDP and the Access
    # Request Service enforce exactly what they published.
    pdp, ars, clock = _setup()
    clock.now += timedelta(milliseconds=500)
    request, decision = _denied(pdp)
    assert decision.access_request is not None and decision.evaluation_id is not None
    published = datetime.fromisoformat(decision.access_request["expires_at"])
    approval = pdp.approve(decision.evaluation_id)
    until = datetime.fromisoformat(approval["approved_until"])
    clock.now = until + timedelta(milliseconds=200)
    assert not pdp.evaluate(_send(approval=approval)).decision
    clock.now = published + timedelta(milliseconds=200)
    with pytest.raises(AccessRequestError) as exc:
        ars.submit("pep.mail", _submission(request, decision))
    assert exc.value.kind == "expired_denial"


def test_an_approval_given_late_in_the_window_can_still_be_collected() -> None:
    # The task keeps its result until approved_until, so the PEP can collect
    # an approval given just before the request's window closed.
    pdp, ars, clock = _setup()
    task = ars.submit("pep.mail", _submission(*_denied(pdp)))[1]["task"]["id"]
    clock.now += pdp.request_ttl - timedelta(seconds=2)
    approval = ars.decide("alice", task, approve=True)["result"]["approval"]
    clock.now += timedelta(seconds=3)
    answer = ars.status("pep.mail", task)
    assert answer["task"]["status"] == "approved"
    assert answer["task"]["expires_at"] == approval["approved_until"]
    assert pdp.evaluate(_send(approval=approval)).decision


def test_tasks_and_their_keys_are_forgotten_a_day_after_they_expire() -> None:
    # ARAP keeps an Idempotency-Key at least until task.expires_at and for 24
    # hours after the task's terminal status; a task reaches one by its
    # expires_at. After that the service forgets both, so retried prohibited
    # requests do not grow it without bound.
    pdp, ars, clock = _setup()
    body = _submission(*_denied(pdp))
    first = ars.submit("pep.mail", body, idempotency_key="k1")[1]
    for key in ("k2", None, "k3"):
        ars.submit("pep.mail", _submission(*_denied(pdp)), idempotency_key=key)
    clock.now += pdp.request_ttl + timedelta(hours=23)
    again = ars.submit("pep.mail", body, idempotency_key="k1")[1]
    assert again["task"]["id"] == first["task"]["id"]
    clock.now += timedelta(hours=1)
    ars.submit("pep.mail", _submission(*_denied(pdp)), idempotency_key="k4")
    assert len(ars._tasks) == len(ars._keys) == 1
    with pytest.raises(AccessRequestError) as exc:
        ars.status("pep.mail", first["task"]["id"])
    assert exc.value.kind == "unknown_task"


# --- What an Access Request is compared on ----------------------------------------

def _mission_members(c: dict[str, Any]) -> None:
    c["mission"].update(policy_version="v7", subject="user-1")


def _extension_entry(c: dict[str, Any]) -> None:
    c["supported_mandatory_extensions"].append(7)


def _obligation_entry(c: dict[str, Any]) -> None:
    c["supported_obligations"].insert(0, "")


@pytest.mark.parametrize("change", [_mission_members, _extension_entry, _obligation_entry])
def test_an_access_request_that_repeats_the_denied_request_as_sent_is_accepted(
        change: Callable[[dict[str, Any]], None]) -> None:
    # Profile, Approvals (ARAP binding): the Access Request repeats the
    # authorization-relevant Context as sent, and is compared structurally on
    # it. Members of context.mission the profile does not define, and adoption
    # entries the PDP ignores, are part of what was sent.
    pdp, ars, _ = _setup()
    body = request_to_json(_send())
    change(body["context"])
    decision = pdp.evaluate(request_from_json(body))
    assert decision.access_request is not None
    submission = {**body, "denial": {"evaluation_id": decision.evaluation_id,
                                     "reason": decision.reason, **decision.access_request}}
    status, answer = ars.submit("pep.mail", submission)
    assert status == 202 and answer["task"]["status"] == "pending"


def test_a_task_is_forgotten_after_its_retention_without_a_further_submission() -> None:
    pdp, ars, clock = _setup()
    task = ars.submit("pep.mail", _submission(*_denied(pdp)), idempotency_key="k1")[1]
    clock.now += pdp.request_ttl + RETENTION
    for call in (lambda: ars.status("pep.mail", task["task"]["id"]),
                 lambda: ars.decide("alice", task["task"]["id"], approve=True)):
        with pytest.raises(AccessRequestError) as exc:
            call()
        assert exc.value.kind == "unknown_task"
    assert ars._tasks == {} and ars._keys == {}


def test_an_approval_covers_a_number_written_another_way() -> None:
    # The approval scope compares numbers by value, as the Access Request
    # Service does: 1 and 1.0 are one number.
    pdp, ars, _ = _setup()
    request = _send()
    request.action.properties["copies"] = 1
    request, decision = _denied(pdp, request)
    assert decision.evaluation_id is not None
    approval = pdp.approve(decision.evaluation_id)
    again = _send(approval=approval)
    again.action.properties["copies"] = 1.0
    assert pdp.evaluate(again).decision


def test_a_mission_has_a_bounded_number_of_requestable_denials_outstanding() -> None:
    # Past the bound, a denial is still prohibited_composition, but not
    # requestable (ARAP leaves requestability to the PDP), until one expires.
    pdp, ars, clock = _setup()
    pdp.max_pending_per_mission = 2
    for to in ("external:a", "external:b"):
        assert _denied(pdp, _send(to=to))[1].access_request is not None
    third = pdp.evaluate(_send(to="external:c"))
    assert (third.decision, third.reason) == (False, "prohibited_composition")
    assert third.access_request is None and third.evaluation_id is None
    clock.now += pdp.request_ttl
    assert pdp.evaluate(_send(to="external:c")).access_request is not None


def test_an_approval_is_honored_only_for_the_pep_that_requested_it() -> None:
    # ARAP, Approval Verification: an approval applies to the authenticated
    # caller that requested it. Another PEP that presents it over HTTP gets the
    # denial of a request whose approval does not apply.
    pdp, ars, _ = _setup()
    app = PDPHttpApp(pdp, StaticTokenAuthenticator({"pep": "pep.mail", "hr": "pep.hr"}),
                     StaticTokenAuthenticator({"alice": "alice"}), access_requests=ars)
    request, decision = _denied(pdp)
    task = ars.submit("pep.mail", _submission(request, decision))[1]["task"]["id"]
    approval = ars.decide("alice", task, approve=True)["result"]["approval"]

    def evaluate(token: str) -> dict[str, Any]:
        data = json.dumps(request_to_json(_send(approval=approval))).encode()
        out = b"".join(app({"REQUEST_METHOD": "POST", "PATH_INFO": "/access/v1/evaluation",
                            "CONTENT_LENGTH": str(len(data)), "wsgi.input": io.BytesIO(data),
                            "HTTP_AUTHORIZATION": f"Bearer {token}"}, lambda s, h: None))
        return json.loads(out)

    stolen = evaluate("hr")
    assert stolen["decision"] is False
    assert stolen["context"]["reason"] == "prohibited_composition"
    assert evaluate("pep")["decision"] is True


def test_no_actor_in_the_delegation_chain_approves() -> None:
    # Profile, Approvals (who approves): neither the Subject nor any actor in
    # its delegation chain is an eligible approver.
    pdp, ars, _ = _setup()
    for request in (_send(act="alice"), _send()):
        if "act" not in request.subject.properties:
            request.context["actor"] = {"client_id": "orchestrator", "act": {"sub": "alice"}}
        task = ars.submit("pep.mail", _submission(*_denied(pdp, request)))[1]["task"]["id"]
        with pytest.raises(NotAuthorized):
            ars.decide("alice", task, approve=True)


def test_published_times_are_the_enforced_ones_whatever_the_clock_s_zone() -> None:
    # The second is taken in UTC, the zone the times are published in.
    pdp, ars, clock = _setup()
    zone = timezone(timedelta(microseconds=500_000))
    clock.now = datetime(2026, 10, 14, 9, 0, 0, 700_000, tzinfo=zone)
    request, decision = _denied(pdp)
    assert decision.evaluation_id is not None
    approval = pdp.approve(decision.evaluation_id)
    clock.now = datetime.fromisoformat(approval["approved_until"]) + timedelta(milliseconds=200)
    assert not pdp.evaluate(_send(approval=approval)).decision


def test_a_late_submission_is_expired_whatever_else_was_denied() -> None:
    # A submission after the denial's window is expired_denial, whether or
    # not the PDP has since dropped the denial.
    pdp, ars, clock = _setup()
    late = _submission(*_denied(pdp))
    clock.now += pdp.request_ttl + timedelta(seconds=1)
    _denied(pdp, _send(to="external:other"))  # drops the closed denial
    with pytest.raises(AccessRequestError) as exc:
        ars.submit("pep.mail", late)
    assert exc.value.kind == "expired_denial"


# --- HTTP routes ---------------------------------------------------------------

def _app(ars: AccessRequestService) -> PDPHttpApp:
    return PDPHttpApp(ars.pdp, StaticTokenAuthenticator({"pep": "pep.mail", "hr": "pep.hr"}),
                      StaticTokenAuthenticator({"person": "alice", "self": "agent-7"}),
                      base_url="https://pdp.example", access_requests=ars)


def _http(app: PDPHttpApp, method: str, path: str, token: str | None,
          body: object = None, key: str | None = None) -> tuple[str, str, dict]:
    raw = b"" if body is None else json.dumps(body).encode()
    env: dict[str, Any] = {"REQUEST_METHOD": method, "PATH_INFO": path,
                           "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw)}
    if token:
        env["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    if key:
        env["HTTP_IDEMPOTENCY_KEY"] = key
    got: dict[str, Any] = {}
    out = b"".join(app(env, lambda s, h: got.update(s=s, h=dict(h))))
    return got["s"], got["h"]["Content-Type"], json.loads(out)


def test_the_routes_over_http() -> None:
    pdp, ars, _ = _setup()
    app = _app(ars)
    body = _submission(*_denied(pdp))
    status, ctype, answer = _http(app, "POST", REQUESTS_PATH, "pep", body, key="k")
    assert (status, ctype) == ("202 Accepted", "application/json")
    task = answer["task"]["id"]
    assert _http(app, "POST", REQUESTS_PATH, "pep", body, key="k")[2] == answer
    status, ctype, problem = _http(app, "POST", REQUESTS_PATH, "pep",
                                   {**body, "action": {"name": "x"}}, key="k")
    assert (status, ctype) == ("409 Conflict", "application/problem+json")
    assert problem == {"type": "urn:openid:authzen:access-request:error:duplicate_request",
                       "title": "Idempotency-Key reused for another request", "status": 409,
                       "detail": "this Idempotency-Key was used for another request"}
    assert _http(app, "POST", REQUESTS_PATH, None, body)[0].startswith("401")
    assert _http(app, "POST", REQUESTS_PATH, "hr", body)[0] == "403 Forbidden"
    assert _http(app, "GET", f"{REQUESTS_PATH}/{task}", "pep")[2]["task"]["status"] == "pending"
    status, ctype, problem = _http(app, "GET", f"{REQUESTS_PATH}/{task}", "hr")
    assert (status, ctype, problem["status"]) == ("404 Not Found", "application/problem+json", 404)
    assert _http(app, "GET", f"{REQUESTS_PATH}/{task}", None)[0].startswith("401")

    decide = f"/approvals/v1/tasks/{task}"
    assert _http(app, "POST", decide, "pep", {"decision": "approve"})[0].startswith("401")
    assert _http(app, "POST", decide, "self", {"decision": "approve"})[0] == "403 Forbidden"
    assert _http(app, "POST", decide, "person", {"decision": "maybe"})[0] == "400 Bad Request"
    status, _, done = _http(app, "POST", decide, "person", {"decision": "approve"})
    assert status == "200 OK" and done["task"]["status"] == "approved"
    assert _http(app, "POST", decide, "person", {"decision": "deny"})[0] == "409 Conflict"
    assert _http(app, "PUT", REQUESTS_PATH, "pep", body)[0] == "404 Not Found"
    assert _http(app, "GET", REQUESTS_PATH + "/", "pep")[0] == "404 Not Found"
    assert _http(app, "POST", "/approvals/v1/tasks/", "person", {})[0] == "404 Not Found"


def test_an_expired_denial_is_410_gone_over_http() -> None:
    pdp, ars, clock = _setup()
    body = _submission(*_denied(pdp))
    clock.now += timedelta(hours=1)
    status, ctype, problem = _http(_app(ars), "POST", REQUESTS_PATH, "pep", body)
    assert (status, ctype, problem["status"]) == ("410 Gone", "application/problem+json", 410)
    assert _http(_app(ars), "POST", REQUESTS_PATH, "pep",
                 {**body, "denial": {"expires_at": "x", "evaluation_id": "nope"}}
                 )[:2] == ("400 Bad Request", "application/problem+json")


# --- The PEP-side client ----------------------------------------------------------

@contextmanager
def _served() -> Iterator[tuple[str, CompositionPDP, AccessRequestService]]:
    holder: dict[str, Any] = {}
    with serve(lambda environ, start_response: holder["app"](environ, start_response)) as url:
        pdp, ars, _ = _setup(endpoint=url + REQUESTS_PATH, loopback=True)
        holder["app"] = PDPHttpApp(pdp, StaticTokenAuthenticator({"pep": "pep.mail"}),
                                   StaticTokenAuthenticator({"person": "alice"}),
                                   base_url=url, access_requests=ars)
        yield url, pdp, ars


def test_the_client_submits_follows_the_task_and_returns_the_approval() -> None:
    with _served() as (url, pdp, ars):
        client = AccessRequestClient.discover(url, "pep")
        assert client is not None and client.endpoint == url + REQUESTS_PATH
        request, decision = _denied(pdp)
        answer = client.submit(request, decision, "key-1")
        assert client.submit(request, decision, "key-1") == answer   # a retry, same task
        task = answer["task"]
        assert AccessRequestClient.approval(client.status(task)) is None
        ars.decide("alice", task["id"], approve=True)
        approval = AccessRequestClient.approval(client.status(task))
        assert approval is not None and pdp.evaluate(_send(approval=approval)).decision
        with pytest.raises(AccessRequestRefused) as exc:
            client.submit(request, Decision(False, reason="prohibited_composition",
                                            access_request={"expires_at": "x"},
                                            evaluation_id="eval_unknown"), "key-2")
        assert (exc.value.status, exc.value.problem) == (400, "not_requestable")


def test_the_client_never_follows_a_url_on_another_origin() -> None:
    with _served() as (url, _, _):
        client = AccessRequestClient(url + REQUESTS_PATH, "pep")
        with pytest.raises(AccessRequestRefused):
            client.status({"id": "arq_x", "status": "pending",
                           "status_endpoint": "https://attacker.example/arq_x"})
        with pytest.raises(AccessRequestRefused):
            client._check(202, {"task": {"id": "a", "status": "pending",
                                         "status_endpoint": "https://attacker.example/a"}})
    with pytest.raises(ValueError):
        client.submit(_send(), Decision(True), "k")


def test_the_client_reads_only_an_approved_reevaluate_result() -> None:
    approved = {"task": {"status": "approved"},
                "result": {"mode": "reevaluate", "approval": {"id": "apr_1"}}}
    assert AccessRequestClient.approval(approved) == {"id": "apr_1"}
    for other in ({**approved, "task": {"status": "denied"}},
                  {**approved, "result": {"mode": "token", "approval": {"id": "apr_1"}}},
                  {**approved, "result": {"mode": "reevaluate", "approval": "apr_1"}},
                  {"task": "approved"}):
        assert AccessRequestClient.approval(other) is None


def test_the_client_without_a_published_endpoint() -> None:
    holder: dict[str, Any] = {}
    with serve(lambda e, s: holder["app"](e, s)) as url:
        holder["app"] = PDPHttpApp(CompositionPDP(EXFIL_POLICY, MissionHistoryService()),
                                   StaticTokenAuthenticator({}), StaticTokenAuthenticator({}),
                                   base_url=url)
        assert AccessRequestClient.discover(url, "pep") is None


def test_the_client_rejects_an_answer_without_a_task_handle() -> None:

    client = AccessRequestClient(ENDPOINT, "pep")
    for answer in ({}, {"task": {"id": "a"}}, {"task": "a"}):
        with pytest.raises(RemoteUnavailable):
            client._check(200, answer)
    refused = AccessRequestRefused
    with pytest.raises(refused) as exc:
        client._check(403, {"error": "no"})
    assert (exc.value.status, exc.value.problem, str(exc.value)) == (403, None, "no")
    with pytest.raises(refused) as exc:
        client._check(400, {"type": "about:blank", "detail": "d"})
    assert exc.value.problem is None


def test_the_client_echoes_every_denial_member_the_pdp_supplied() -> None:
    # ARAP "Construct the Submission": expires_at, evaluation_id,
    # binding_token, reason and template, each only when the PDP gave it.
    seen: list[dict[str, Any]] = []

    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        seen.append(json.loads(environ["wsgi.input"].read(length)))
        start_response("400 Bad Request", [("Content-Type", "application/problem+json")])
        return [json.dumps({"type": "urn:openid:authzen:access-request:error:"
                                    "invalid_denial_binding", "detail": "no"}).encode()]

    with serve(app) as url:
        client = AccessRequestClient(url + REQUESTS_PATH, "pep")
        tokened = Decision(False, access_request={"expires_at": "t", "binding_token": "b.c.d",
                                                  "template": "manager", "display": {}})
        with pytest.raises(AccessRequestRefused) as exc:
            client.submit(_send(), tokened, "k")
        assert exc.value.problem == "invalid_denial_binding"
        plain = Decision(False, reason="prohibited_composition", evaluation_id="eval_1",
                         access_request={"expires_at": "t"})
        with pytest.raises(AccessRequestRefused):
            client.submit(_send(), plain, "k2")
    assert [s["denial"] for s in seen] == [
        {"expires_at": "t", "binding_token": "b.c.d", "template": "manager"},
        {"expires_at": "t", "evaluation_id": "eval_1", "reason": "prohibited_composition"}]
    assert seen[1]["context"]["mission"] == {"id": "m", "issuer": ISSUER}


def test_a_submission_whose_properties_are_not_an_object_is_not_bound() -> None:
    pdp, ars, _ = _setup()
    body = _submission(*_denied(pdp))
    body["subject"]["properties"] = "admin"
    with pytest.raises(AccessRequestError) as exc:
        ars.submit("pep.mail", body)
    assert exc.value.kind == "invalid_denial_binding"


def test_adoption_lists_left_out_read_as_empty_as_the_pdp_read_them() -> None:
    # The declarations are compared by what the PDP reads from them, and an
    # omitted list reads as empty. A requestable denial goes only to a PEP that
    # adopted mission_record, so a submission that leaves its lists out reads
    # as one that did not adopt it, and does not match the denial.
    pdp, ars, _ = _setup()
    request, decision = _denied(pdp)
    body = _submission(request, decision)
    for member in ("supported_mandatory_extensions", "supported_obligations"):
        assert body["context"].pop(member)
    with pytest.raises(AccessRequestError) as exc:
        ars.submit("pep.mail", body)
    assert exc.value.kind == "invalid_denial_binding"


def test_an_approval_carries_to_another_instance_of_the_same_client() -> None:
    # ARAP lets a Task Handle be resumed from another process; the mission-bound
    # drafts' client_instance_id is a correlator of that instance, not part of
    # the actor's identity, so the approval scope leaves it out. The client
    # and its delegation chain stay bound.
    pdp, ars, _ = _setup()
    actor = {"client_id": "orchestrator", "client_instance_id": "i-1",
             "act": {"sub": "https://orchestrator.example"}}

    def send(a: dict, approval: dict | None = None) -> EvaluationRequest:
        r = _send(approval=approval)
        r.context["actor"] = a
        return r

    request, decision = _denied(pdp, send(actor))
    _, answer = ars.submit("pep.mail", _submission(request, decision))
    approval = ars.decide("alice", answer["task"]["id"], approve=True)["result"]["approval"]
    other_client = {**actor, "client_id": "sub-agent"}
    denied = pdp.evaluate(send(other_client, approval))
    assert not denied.decision and denied.context["next_action"] == "request"
    assert pdp.evaluate(send({**actor, "client_instance_id": "i-2"}, approval)).decision


def test_no_actor_of_a_delegation_chain_given_as_an_array_approves() -> None:
    # The mission-bound context.actor lists prior actors in an `act` array.
    pdp, ars, _ = _setup()
    request = _send()
    request.context["actor"] = {"client_id": "orchestrator",
                                "act": [{"sub": "carol"}, {"sub": "alice"}]}
    task = ars.submit("pep.mail", _submission(*_denied(pdp, request)))[1]["task"]["id"]
    with pytest.raises(NotAuthorized):
        ars.decide("alice", task, approve=True)
