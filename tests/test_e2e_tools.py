"""The end-to-end tool hosts, in one process: what their PEPs evaluate."""

from __future__ import annotations

import json
import secrets
from typing import Any

import pytest

from authzen_composition.arap import AccessRequestService
from authzen_composition.mhs import MissionHistoryService
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pep import ReferencePEP
from authzen_composition.remote import RemoteUnavailable, request_to_json
from authzen_composition.types import Decision, EvaluationRequest
from e2e import missions
from e2e.policies import POLICIES
from e2e.serve import _QuietHandler, build_tool
from e2e.tools import CANARY, DocStore, HRStore, Ledger, ToolHost, classifier_for
from tests.test_remote import serve


class _InProcessAccessRequests:
    """The PEP side of ARAP, in process (same interface as AccessRequestClient)."""

    def __init__(self, ars: AccessRequestService, caller: str) -> None:
        self.ars, self.caller = ars, caller

    def submit(self, request: EvaluationRequest, decision: Decision,
               idempotency_key: str) -> dict[str, Any]:
        assert decision.access_request is not None
        body = request_to_json(request)
        body["denial"] = {"evaluation_id": decision.evaluation_id, "reason": decision.reason,
                          **decision.access_request}
        return self.ars.submit(self.caller, body, idempotency_key)[1]

    def status(self, task: dict[str, Any]) -> dict[str, Any]:
        return self.ars.status(self.caller, task["id"])


def test_an_approval_to_send_one_attachment_does_not_send_another() -> None:
    # Profile, Approvals: the same send with a different attachment is a
    # different request. The mail PEP puts the attachment in the request it
    # evaluates, so an approval for one document cannot carry another.
    key = secrets.token_bytes(32)
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICIES["recommended"], mhs,
                         access_request_endpoint="https://pdp.example/access/v1/requests")
    ars = AccessRequestService(pdp, submitters=frozenset({"mail"}), approvers=frozenset({"alice"}))
    hr_store, docs_store, ledger = HRStore(), DocStore(), Ledger(None)

    def host(name: str, kind: str, **extra: Any) -> ToolHost:
        pep = ReferencePEP(pdp=pdp, mhs=mhs, writer_id=name,
                           classifier=classifier_for(kind, hr_store, docs_store))
        return ToolHost(name=name, kind=kind, pep=pep, issuer_key=key, ledger=ledger, **extra)

    hr = host("hr", "hr", hr=hr_store)
    docs = host("docs", "docs", docs=docs_store)
    mail = host("mail", "mail", doc_reader=docs_store.read,
                access_requests=_InProcessAccessRequests(ars, "mail"))
    token = missions.mint(key, "msn-swap", "agent-7")
    salary = hr.call(token, "read_record", {"employee": "emp-1"})["result"]
    docs.call(token, "write_document", {"doc": "payroll", "text": f"Notes: {salary}"})
    docs.call(token, "write_document", {"doc": "faq", "text": "Office hours."})
    asked = mail.call(token, "send_message", {"to": "press", "doc": "faq"})
    assert asked["reason"] == "prohibited_composition"
    task = asked["access_request_task"]
    ars.decide("alice", task, True)
    swapped = mail.call(token, "send_message",
                        {"to": "press", "doc": "payroll", "access_request_task": task})
    assert not swapped["ok"]
    assert not any(e.get("kind") == "expose" and e.get("audience") == "external"
                   and CANARY.search(e.get("content", "")) for e in ledger.entries)
    approved = mail.call(token, "send_message",
                         {"to": "press", "doc": "faq", "access_request_task": task})
    assert approved["ok"]


def test_an_approval_to_write_one_text_does_not_write_another() -> None:
    # Profile, Approvals: a person approves the request, and what a write
    # puts in a document is part of it. The documents PEP carries a digest of
    # the text in the request it evaluates, so an approval for one text
    # cannot carry another.
    key = secrets.token_bytes(32)
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICIES["recommended"], mhs,
                         access_request_endpoint="https://pdp.example/access/v1/requests")
    ars = AccessRequestService(pdp, submitters=frozenset({"docs"}), approvers=frozenset({"alice"}))
    hr_store, docs_store, ledger = HRStore(), DocStore(), Ledger(None)

    def host(name: str, kind: str, **extra: Any) -> ToolHost:
        pep = ReferencePEP(pdp=pdp, mhs=mhs, writer_id=name,
                           classifier=classifier_for(kind, hr_store, docs_store))
        return ToolHost(name=name, kind=kind, pep=pep, issuer_key=key, ledger=ledger, **extra)

    hr = host("hr", "hr", hr=hr_store)
    docs = host("docs", "docs", docs=docs_store,
                access_requests=_InProcessAccessRequests(ars, "docs"))
    token = missions.mint(key, "msn-write", "agent-7")
    assert docs.call(token, "share_document", {"doc": "faq"})["ok"]
    salary = hr.call(token, "read_record", {"employee": "emp-1"})["result"]
    asked = docs.call(token, "write_document", {"doc": "faq", "text": "Office hours."})
    assert asked["reason"] == "prohibited_composition"
    task = asked["access_request_task"]
    ars.decide("alice", task, True)
    swapped = docs.call(token, "write_document",
                        {"doc": "faq", "text": f"Notes: {salary}", "access_request_task": task})
    assert not swapped["ok"]
    assert not any(e.get("kind") == "expose" and CANARY.search(e.get("content", ""))
                   for e in ledger.entries)
    approved = docs.call(token, "write_document",
                         {"doc": "faq", "text": "Office hours.", "access_request_task": task})
    assert approved["ok"]


def test_a_delegated_token_never_outlives_its_parent() -> None:
    # Delegation carries the delegator's Mission; a sub-agent's credential
    # must not keep the Mission usable after the delegator's has expired.
    key = secrets.token_bytes(32)
    parent = missions.mint(key, "msn-d", "agent-7", ttl=5.0)
    child = missions.delegate(key, parent, "sub-agent")
    parent_claims, child_claims = missions.verify(key, parent), missions.verify(key, child)
    assert parent_claims is not None and child_claims is not None
    assert child_claims["exp"] <= parent_claims["exp"]
    assert child_claims["mission"] == "msn-d" and child_claims["delegated_by"] == "agent-7"


def test_a_delegated_token_never_outlives_its_parent_on_a_fine_clock(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # A clock that moves between any two readings, as a fine-grained one does:
    # the child's expiry is taken from the parent's, not computed again.
    key = secrets.token_bytes(32)
    ticks = iter(range(1_000, 2_000))
    monkeypatch.setattr(missions.time, "time", lambda: float(next(ticks)))
    parent = missions.mint(key, "msn-d", "agent-7", ttl=5.0)
    child = missions.delegate(key, parent, "sub-agent")
    parent_claims, child_claims = missions.verify(key, parent), missions.verify(key, child)
    assert parent_claims is not None and child_claims is not None
    assert child_claims["exp"] <= parent_claims["exp"]


def test_a_tool_host_refuses_a_pdp_that_does_not_issue_mission_record() -> None:
    # Profile, PEP processing rules: a PEP sends a request that carries a
    # Mission only to a PDP whose metadata lists mission_record.
    def legacy(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        start_response("200 OK", [("Content-Type", "application/json")])
        return [json.dumps({"capabilities": [], "supported_obligations": []}).encode()]

    with serve(legacy) as url, pytest.raises(SystemExit):
        build_tool({"kind": "mail", "name": "pep.mail", "pdp_url": url, "pdp_token": "t"})


def test_a_prohibited_call_repeated_asks_a_bounded_number_of_times() -> None:
    # Each repeat is a new denial (ARAP forbids reusing an evaluation_id
    # within its window), but the PDP stores a bounded number per Mission:
    # past it the denial is not requestable, so the Access Request Service
    # gets no more tasks either.
    key = secrets.token_bytes(32)
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICIES["recommended"], mhs,
                         access_request_endpoint="https://pdp.example/access/v1/requests")
    ars = AccessRequestService(pdp, submitters=frozenset({"mail"}), approvers=frozenset({"alice"}))
    hr_store, docs_store, ledger = HRStore(), DocStore(), Ledger(None)

    def host(name: str, kind: str, **extra: Any) -> ToolHost:
        pep = ReferencePEP(pdp=pdp, mhs=mhs, writer_id=name,
                           classifier=classifier_for(kind, hr_store, docs_store))
        return ToolHost(name=name, kind=kind, pep=pep, issuer_key=key, ledger=ledger, **extra)

    hr = host("hr", "hr", hr=hr_store)
    docs = host("docs", "docs", docs=docs_store)
    mail = host("mail", "mail", doc_reader=docs_store.read,
                access_requests=_InProcessAccessRequests(ars, "mail"))
    token = missions.mint(key, "msn-repeat", "agent-7")
    salary = hr.call(token, "read_record", {"employee": "emp-1"})["result"]
    docs.call(token, "write_document", {"doc": "payroll", "text": f"Notes: {salary}"})
    pdp.max_pending_per_mission = 3
    answers = [mail.call(token, "send_message", {"to": "press", "doc": "payroll"})
               for _ in range(5)]
    assert all(a["reason"] == "prohibited_composition" for a in answers)
    assert ["access_request_task" in a for a in answers] == [True] * 3 + [False] * 2
    assert len(ars._tasks) == len(pdp._pending) == 3


def test_the_e2e_servers_bound_how_long_a_connection_may_stall() -> None:
    # A caller that sends its request slowly holds a worker thread; the
    # end-to-end servers time such a connection out.
    assert _QuietHandler.timeout is not None and _QuietHandler.timeout > 0


class _AccessRequestsDown:
    """An Access Request Service that cannot be reached."""

    def submit(self, *args: Any) -> dict[str, Any]:
        raise RemoteUnavailable("unreachable")

    def status(self, *args: Any) -> dict[str, Any]:
        raise RemoteUnavailable("unreachable")


def test_an_access_request_service_outage_is_an_answer_not_a_crash() -> None:
    # The tool host reports an unreachable Access Request Service to the
    # agent; it does not fail the call with a server error.
    key = secrets.token_bytes(32)
    mhs = MissionHistoryService()
    pdp = CompositionPDP(POLICIES["recommended"], mhs,
                         access_request_endpoint="https://pdp.example/access/v1/requests")
    hr_store, docs_store, ledger = HRStore(), DocStore(), Ledger(None)

    def host(name: str, kind: str, **extra: Any) -> ToolHost:
        pep = ReferencePEP(pdp=pdp, mhs=mhs, writer_id=name,
                           classifier=classifier_for(kind, hr_store, docs_store))
        return ToolHost(name=name, kind=kind, pep=pep, issuer_key=key, ledger=ledger, **extra)

    hr, docs = host("hr", "hr", hr=hr_store), host("docs", "docs", docs=docs_store)
    mail = host("mail", "mail", doc_reader=docs_store.read, access_requests=_AccessRequestsDown())
    token = missions.mint(key, "msn-down", "agent-7")
    salary = hr.call(token, "read_record", {"employee": "emp-1"})["result"]
    docs.call(token, "write_document", {"doc": "payroll", "text": f"Notes: {salary}"})
    asked = mail.call(token, "send_message", {"to": "press", "doc": "payroll"})
    answers = asked.get("targets", [asked])
    assert any(a.get("reason") == "prohibited_composition" and "access_request_error" in a
               for a in answers)
    mail.tasks["arq_1"] = {"id": "arq_1"}
    polled = mail.call(token, "send_message",
                       {"to": "press", "doc": "payroll", "access_request_task": "arq_1"})
    assert polled["reason"] == "access_request_unavailable"
