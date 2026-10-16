"""The HTTP clients and the PDP's Access Evaluation endpoint, over real sockets.

Each test runs a WSGI app on 127.0.0.1 in a thread and talks to it with the
remote clients, so every byte crosses a real HTTP connection.
"""

from __future__ import annotations

import io
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from socketserver import ThreadingMixIn
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest

from authzen_composition import remote
from authzen_composition.arap import AccessRequestService
from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import (
    HistoryConflict,
    HistoryUnavailable,
    MissionHistoryService,
    OutcomeAlreadySet,
    PolicyMismatch,
    UnauthenticatedWriter,
)
from authzen_composition.model import ActOutcome, CompositionPolicy
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pdp_http import PDPHttpApp, request_from_json
from authzen_composition.pep import CompositionDenied, ReferencePEP
from authzen_composition.remote import (
    RemoteHistoryAuthority,
    RemotePDP,
    RemoteUnavailable,
    _act,
    decision_from_json,
    request_to_json,
)
from authzen_composition.scenarios import EXFIL_POLICY
from authzen_composition.types import (
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint

App = Callable[[dict[str, Any], Callable[..., Any]], Iterable[bytes]]


class _Server(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _Quiet(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


@contextmanager
def serve(app: App) -> Iterator[str]:
    server = make_server("127.0.0.1", 0, app, server_class=_Server, handler_class=_Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def _drain(environ: dict[str, Any]) -> None:
    """Read the request body before answering. A server that answers with the
    body unread closes the socket with a reset on Windows (WinError 10053),
    and the client then sees a lost connection instead of the answer, which in
    a fail-closed test passes for the wrong reason."""
    length = int(environ.get("CONTENT_LENGTH") or 0)
    if length:
        environ["wsgi.input"].read(length)


def canned(status: str, body: bytes) -> App:
    """An app that always answers ``status`` with ``body``."""
    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        _drain(environ)
        start_response(status, [("Content-Type", "application/json")])
        return [body]
    return app


TOKENS = {"t-hr": "pep.hr", "t-mail": "pep.mail", "t-pdp": "pdp"}


@contextmanager
def mhs_server() -> Iterator[tuple[str, MissionHistoryService]]:
    mhs = MissionHistoryService(trusted_writers=frozenset({"pep.hr", "pep.mail"}))
    with serve(MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))) as url:
        yield url, mhs


# --- RemoteHistoryAuthority ------------------------------------------------------

def test_remote_admit_outcome_and_history_round_trip() -> None:
    with mhs_server() as (url, mhs):
        hr = RemoteHistoryAuthority(url, "t-hr")
        act = hr.admit("m1", 1, "read_record", "hr:1", writer="ignored", admission_id="a1")
        assert (act.seq, act.action, act.resource, act.outcome) == (
            1, "read_record", "hr:1", ActOutcome.OPEN)
        # The identity comes from the credential, not from the writer argument.
        assert mhs.recorded_by("m1", 1) == "pep.hr"
        # Retry with the same admission id: the act already admitted.
        assert hr.admit("m1", 1, "read_record", "hr:1", writer="", admission_id="a1") == act
        done = hr.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="",
                              result_classes=frozenset({"personal_data.salary"}),
                              admission_id="a1")
        assert done.result_classes == frozenset({"personal_data.salary"})
        pdp = RemoteHistoryAuthority(url + "/", "t-pdp")
        assert pdp.history("m1", policy="sha256:x") == [done]
        assert pdp.history("m1") == [done]
        assert mhs.policy_of("m1") == "sha256:x"


def test_remote_admit_without_admission_id_and_mission_id_is_quoted() -> None:
    with mhs_server() as (url, mhs):
        act = RemoteHistoryAuthority(url, "t-hr").admit("m 1", 1, "a", "r", writer="")
        assert act.seq == 1
        assert mhs.next_seq("m 1") == 2


def test_remote_errors_map_to_the_in_memory_exceptions() -> None:
    with mhs_server() as (url, _):
        hr = RemoteHistoryAuthority(url, "t-hr")
        mail = RemoteHistoryAuthority(url, "t-mail")
        hr.admit("m1", 1, "read_record", "hr:1", writer="")
        with pytest.raises(HistoryConflict):
            hr.admit("m1", 3, "read_record", "hr:1", writer="")
        with pytest.raises(UnauthenticatedWriter):
            RemoteHistoryAuthority(url, "wrong").admit("m1", 2, "a", "r", writer="")
        with pytest.raises(UnauthenticatedWriter):
            mail.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="")
        hr.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="")
        with pytest.raises(OutcomeAlreadySet):
            hr.set_outcome("m1", 1, ActOutcome.FAILED, writer="")
        with pytest.raises(ValueError):
            hr.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="",
                           result_classes=frozenset({"a*"}))
        pdp = RemoteHistoryAuthority(url, "t-pdp")
        pdp.history("m1", policy="p1")
        with pytest.raises(PolicyMismatch):
            pdp.history("m1", policy="p2")
        with pytest.raises(HistoryUnavailable):
            RemoteHistoryAuthority(url, "wrong").history("m1")


@pytest.mark.parametrize(("status", "body"), [
    ("500 Internal Server Error", b'{"error": "boom"}'),
    ("200 OK", b"not json"),
    ("200 OK", b"[1, 2]"),
    ("200 OK", b'{"acts": "nope"}'),
    ("200 OK", b'{"acts": [{"seq": 1}]}'),
    ("404 Not Found", b'{"error": "unknown route"}'),
    ("409 Conflict", b'{"error": "x", "reason": "something_else"}'),
])
def test_unusable_history_answers_fail_closed(status: str, body: bytes) -> None:
    with serve(canned(status, body)) as url, pytest.raises(HistoryUnavailable):
        RemoteHistoryAuthority(url, "t").history("m1")


def test_unreachable_authority() -> None:
    with serve(canned("200 OK", b"{}")) as url:
        pass  # closed: nothing listens on the port any more
    dead = RemoteHistoryAuthority(url, "t", timeout=2)
    with pytest.raises(HistoryUnavailable):
        dead.history("m1")
    with pytest.raises(RemoteUnavailable):
        dead.admit("m1", 1, "a", "r", writer="")


def test_a_redirect_is_never_followed_with_the_credential() -> None:
    seen: list[str] = []

    def elsewhere(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        seen.append(environ.get("HTTP_AUTHORIZATION", ""))
        _drain(environ)
        start_response("200 OK", [("Content-Type", "application/json")])
        return [b'{"acts": [], "decision": true}']

    with serve(elsewhere) as other:
        def redirect(environ: dict[str, Any], start_response: Any) -> list[bytes]:
            _drain(environ)
            start_response("307 Temporary Redirect",
                           [("Location", other + environ.get("PATH_INFO", "")),
                            ("Content-Type", "application/json")])
            return [b"{}"]

        with serve(redirect) as url:
            with pytest.raises(HistoryUnavailable):
                RemoteHistoryAuthority(url, "secret").history("m1")
            with pytest.raises(RemoteUnavailable):
                RemoteHistoryAuthority(url, "secret").admit("m1", 1, "a", "r", writer="")
            with pytest.raises(RemoteUnavailable):
                RemotePDP(url, "secret").evaluate(EvaluationRequest(
                    Subject("agent", "a"), Action("read"), Resource("doc", "d")))
    assert seen == []


def test_admission_with_a_lost_acknowledgement_is_unavailable() -> None:
    with serve(canned("500 Internal Server Error", b"{}")) as url, \
            pytest.raises(RemoteUnavailable):
        RemoteHistoryAuthority(url, "t").admit("m1", 1, "a", "r", writer="")


@pytest.mark.parametrize("record", [
    {},
    {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}, "outcome": "open",
     "result_classes": "x", "recorded_by": "pep.hr"},
    {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}, "outcome": "open",
     "result_classes": [1], "recorded_by": "pep.hr"},
    {"seq": True, "action": {"name": "a"}, "resource": {"id": "r"}, "outcome": "open",
     "result_classes": [], "recorded_by": "pep.hr"},
    {"seq": "1", "action": {"name": "a"}, "resource": {"id": "r"}, "outcome": "open",
     "result_classes": [], "recorded_by": "pep.hr"},
    {"seq": 1, "action": {"name": 7}, "resource": {"id": "r"}, "outcome": "open",
     "result_classes": [], "recorded_by": "pep.hr"},
    {"seq": 1, "action": {"name": "a"}, "resource": {"id": None}, "outcome": "open",
     "result_classes": [], "recorded_by": "pep.hr"},
    {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}, "outcome": "maybe",
     "result_classes": [], "recorded_by": "pep.hr"},
    {"seq": 1, "action": "a", "resource": {"id": "r"}, "outcome": "open",
     "result_classes": [], "recorded_by": "pep.hr"},
])
def test_malformed_act_records_are_rejected(record: dict[str, Any]) -> None:
    with pytest.raises(RemoteUnavailable):
        _act(record)


VALID_RECORD: dict[str, Any] = {
    "seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:emp-1"},
    "outcome": "completed", "result_classes": ["public"], "recorded_by": "pep.hr"}


def test_a_valid_act_record_is_read() -> None:
    act = _act(VALID_RECORD)
    assert (act.seq, act.action, act.resource, act.outcome, act.result_classes) == (
        1, "read_record", "hr:emp-1", ActOutcome.COMPLETED, frozenset({"public"}))


# Profile, History Authority: an Act Record has seq, action, resource,
# outcome, result_classes and recorded_by; a record that lacks one, or holds
# a value of another type or outside its values, makes the history unusable.
@pytest.mark.parametrize("record", [
    {k: v for k, v in VALID_RECORD.items() if k != "recorded_by"},
    {**VALID_RECORD, "recorded_by": 7},
    {**VALID_RECORD, "recorded_by": ""},
    {**VALID_RECORD, "seq": 0},
    {**VALID_RECORD, "action": {"name": ""}},
    {**VALID_RECORD, "resource": {"id": ""}},
    {**VALID_RECORD, "result_classes": [""]},
    {**VALID_RECORD, "result_classes": ["personal_data.*"]},
    {**VALID_RECORD, "outcome": "failed"},
])
def test_a_record_outside_the_act_record_values_is_rejected(record: dict[str, Any]) -> None:
    with pytest.raises(RemoteUnavailable):
        _act(record)


def test_a_history_with_an_invalid_act_record_is_history_unavailable() -> None:
    record = {k: v for k, v in VALID_RECORD.items() if k != "recorded_by"}
    body = json.dumps({"acts": [record], "next_seq": 2}).encode()
    with serve(canned("200 OK", body)) as url:
        pdp = CompositionPDP(EXFIL_POLICY, RemoteHistoryAuthority(url, "t"))
        decision = pdp.evaluate(EvaluationRequest(
            Subject("agent", "a"), Action("write_document"), Resource("doc", "doc:x"),
            mission=Mission("m1", ISSUER), supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",)))
    assert (decision.decision, decision.reason) == (False, "history_unavailable")


# --- Access Evaluation over HTTP --------------------------------------------------

REQ = EvaluationRequest(
    subject=Subject("agent", "agent-7", {"team": "hr"}),
    action=Action("send_message", {"attachment": "doc:q4"}),
    resource=Resource("recipient", "external:press@partner.example"),
    mission=Mission("m1", ISSUER),
    supported_mandatory_extensions=("obligations",),
    supported_obligations=("mission_record",),
    context={"approval": {"id": "apr_1"}},
)


def test_request_json_round_trip() -> None:
    assert request_from_json(request_to_json(REQ)) == REQ
    bare = EvaluationRequest(Subject("agent", "a"), Action("x"), Resource("r", "1"))
    back = request_from_json(request_to_json(bare))
    assert back == bare and back.mission is None
    with_mission = EvaluationRequest(Subject("agent", "a"), Action("x"), Resource("r", "1"),
                                     mission=Mission("m1", ISSUER))
    assert request_to_json(with_mission)["context"]["mission"] == {"id": "m1", "issuer": ISSUER}
    assert request_from_json(request_to_json(with_mission)) == with_mission


def _valid() -> dict[str, Any]:
    return request_to_json(REQ)


@pytest.mark.parametrize("mutate", [
    lambda b: b.pop("subject"),
    lambda b: b["subject"].pop("type"),
    lambda b: b["subject"].update(properties=[]),
    lambda b: b["action"].pop("name"),
    lambda b: b["resource"].update(id=""),
    lambda b: b.update(context=[]),
    lambda b: b["context"].update(mission="m1"),
    lambda b: b["context"]["mission"].update(id=3),
    lambda b: b["context"]["mission"].update(issuer=""),
])
def test_invalid_evaluation_requests_are_rejected(mutate: Callable[[dict[str, Any]], Any]) -> None:
    body = _valid()
    mutate(body)
    with pytest.raises(ValueError):
        request_from_json(body)


@pytest.mark.parametrize("member, value", [
    ("supported_mandatory_extensions", "composition"),
    ("supported_obligations", [1]),
])
def test_a_malformed_adoption_list_is_read_as_no_adoption(member: str, value: Any) -> None:
    # The Obligations Core: a PDP "MUST NOT reject the request because of such
    # a value"; the Extensibility Model: ignore rather than reject. The request
    # is decided, as one from a PEP that did not adopt mission_record: a send
    # that must be serialized gets a plain deny, where the adopting PEP's same
    # request is permitted with mission_record.
    app = PDPHttpApp(CompositionPDP(EXFIL_POLICY, MissionHistoryService()),
                     StaticTokenAuthenticator({"t": "pep.mail"}), StaticTokenAuthenticator({}))

    def evaluate(body: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        data = json.dumps(body).encode()
        got: dict[str, str] = {}
        out = b"".join(app({"REQUEST_METHOD": "POST", "PATH_INFO": "/access/v1/evaluation",
                            "CONTENT_LENGTH": str(len(data)), "wsgi.input": io.BytesIO(data),
                            "HTTP_AUTHORIZATION": "Bearer t"},
                           lambda status, headers: got.update(status=status)))
        return got["status"], json.loads(out)

    body = _valid()
    body["context"].pop("approval")
    status, adopted = evaluate(body)
    assert status == "200 OK" and adopted["decision"] is True
    assert [o["type"] for o in adopted["context"]["obligations"]] == ["mission_record"]
    body["context"][member] = value
    assert evaluate(body) == ("200 OK", {"decision": False})


@pytest.mark.parametrize("body", [
    {},
    {"decision": "yes"},
    {"decision": True, "context": []},
    {"decision": True, "context": {"obligations": [{"id": "o"}]}},
    {"decision": True, "context": {"obligations": [5]}},
    {"decision": False, "context": {"reason": 5}},
    {"decision": False, "context": {"evaluation_id": 5}},
    {"decision": False, "context": {"access_request": "x"}},
])
def test_malformed_decisions_are_rejected(body: dict[str, Any]) -> None:
    with pytest.raises(RemoteUnavailable):
        decision_from_json(body)


def test_decision_json_round_trip() -> None:
    d = decision_from_json({"decision": False, "context": {
        "reason": "prohibited_composition", "evaluation_id": "eval_1",
        "access_request": {"expires_at": "2026-01-01T00:00:00+00:00"}, "extra": 1}})
    assert (d.decision, d.reason, d.evaluation_id, d.context) == (
        False, "prohibited_composition", "eval_1", {"extra": 1})
    p = decision_from_json({"decision": True, "context": {"obligations": [
        {"id": "o1", "type": "mission_record", "properties": {"expected_seq": 2}}]}})
    assert p.obligations[0].properties == {"expected_seq": 2}
    assert decision_from_json({"decision": True}).obligations == ()


@contextmanager
def deployment(policy: CompositionPolicy = EXFIL_POLICY,
               access_request_endpoint: str | None = ARS) -> Iterator[dict[str, Any]]:
    """MHS and PDP each behind their own HTTP server; the PDP reads the MHS over HTTP."""
    with mhs_server() as (mhs_url, mhs):
        pdp = CompositionPDP(policy=policy, mhs=RemoteHistoryAuthority(mhs_url, "t-pdp"),
                             access_request_endpoint=access_request_endpoint)
        ars = (None if access_request_endpoint is None else
               AccessRequestService(pdp, submitters=frozenset({"pep.hr", "pep.mail"}),
                                    approvers=frozenset({"alice"})))
        app = PDPHttpApp(pdp, StaticTokenAuthenticator({"e-hr": "pep.hr", "e-mail": "pep.mail"}),
                         StaticTokenAuthenticator({"person-1": "alice"}),
                         base_url="https://pdp.example/", access_requests=ars)
        with serve(app) as pdp_url:
            yield {"mhs": mhs, "mhs_url": mhs_url, "pdp": pdp, "pdp_url": pdp_url, "ars": ars}


def _pep(env: dict[str, Any], name: str, classes: frozenset[str] = frozenset()) -> ReferencePEP:
    return ReferencePEP(pdp=RemotePDP(env["pdp_url"], f"e-{name}"),
                        mhs=RemoteHistoryAuthority(env["mhs_url"], f"t-{name}"),
                        writer_id=f"pep.{name}",
                        classifier=lambda a, r, raw: classes)


def _enforce(pep: ReferencePEP, action: str, resource: str, **kw: Any) -> object:
    return pep.enforce(mission_id="m1", mission_issuer=ISSUER, subject=Subject("agent", "a7"),
                       action=Action(action), resource=Resource("r", resource),
                       perform=lambda: "done", **kw)


def test_pep_pdp_and_mhs_over_http_deny_the_composition_and_honour_an_approval() -> None:
    with deployment() as env:
        hr = _pep(env, "hr", frozenset({"personal_data.salary"}))
        mail = _pep(env, "mail")
        assert _enforce(hr, "read_record", "hr:1") == "done"
        assert _enforce(mail, "write_document", "doc:q4") == "done"
        with pytest.raises(CompositionDenied) as denied:
            _enforce(mail, "send_message", "external:press")
        assert denied.value.reason == "prohibited_composition"
        assert denied.value.evaluation_id
        # The PEP submits an Access Request for the denial it received; a
        # person approves the task (ARAP; the HTTP routes have their own tests).
        assert denied.value.request is not None and denied.value.decision is not None
        body = request_to_json(denied.value.request)
        body["denial"] = {"evaluation_id": denied.value.evaluation_id,
                          **denied.value.decision.access_request}
        _, answer = env["ars"].submit("pep.mail", body)
        result = env["ars"].decide("alice", answer["task"]["id"], approve=True)["result"]
        approval = {"approval": result["approval"]}
        assert _enforce(mail, "send_message", "external:press", context=approval) == "done"
        with pytest.raises(CompositionDenied):
            _enforce(mail, "send_message", "external:press", context=approval)
        assert [a.action for a in env["mhs"].history("m1")] == [
            "read_record", "write_document", "send_message"]


def test_pdp_http_routes_and_authentication() -> None:

    with deployment(access_request_endpoint=None) as env:
        base = env["pdp_url"]

        def call(method: str, path: str, token: str | None, data: bytes | None
                 ) -> tuple[int, dict[str, Any]]:
            req = urllib.request.Request(base + path, data=data, method=method)
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        status, meta = call("GET", "/.well-known/authzen-configuration", None, None)
        assert status == 200
        assert meta == {
            "policy_decision_point": "https://pdp.example",
            "access_evaluation_endpoint": "https://pdp.example/access/v1/evaluation",
            "capabilities": ["urn:openid:authzen:capability:obligations"],
            "supported_obligations": ["mission_record"],
        }
        body = json.dumps(request_to_json(REQ)).encode()
        assert call("POST", "/access/v1/evaluation", None, body)[0] == 401
        assert call("POST", "/access/v1/evaluation", "wrong", body)[0] == 401
        status, decision = call("POST", "/access/v1/evaluation", "e-hr", body)
        assert status == 200 and decision["decision"] is True
        assert call("POST", "/access/v1/evaluation", "e-hr", b"[]")[0] == 400
        # No Access Request Service configured: its routes do not exist.
        assert call("POST", "/access/v1/requests", "e-hr", b"{}")[0] == 404
        assert call("POST", "/approvals/v1/tasks/t", "person-1", b"{}")[0] == 404
        assert call("GET", "/access/v1/evaluation", "e-hr", None)[0] == 404
        assert call("GET", "/nowhere", None, None)[0] == 404


def test_remote_pdp_failures_never_let_the_pep_act() -> None:
    performed: list[str] = []
    for app in (canned("500 Internal Server Error", b"{}"),
                canned("401 Unauthorized", b'{"error": "no"}'),
                canned("200 OK", b'{"decision": "maybe"}')):
        with serve(app) as url:
            pep = ReferencePEP(pdp=RemotePDP(url + "/", "t"),
                               mhs=MissionHistoryService(), writer_id="pep.x")
            with pytest.raises(RemoteUnavailable):
                pep.enforce(mission_id="m1", mission_issuer=ISSUER, subject=Subject("a", "1"),
                            action=Action("x"), resource=Resource("r", "1"),
                            perform=lambda: performed.append("x"))
    assert performed == []


def test_mhs_conflict_bodies_carry_a_machine_readable_reason() -> None:

    with mhs_server() as (url, _):
        def post(path: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
            req = urllib.request.Request(url + path, method=method,
                                         data=json.dumps(body).encode())
            req.add_header("Authorization", "Bearer t-hr")
            try:
                with urllib.request.urlopen(req) as resp:
                    return dict(json.loads(resp.read()))
            except urllib.error.HTTPError as exc:
                return dict(json.loads(exc.read()))

        act = {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}}
        post("/missions/m1/acts", "POST", act)
        assert post("/missions/m1/acts", "POST", act)["reason"] == "seq_conflict"
        assert post("/missions/m1/acts/9", "PATCH",
                    {"outcome": "completed"})["reason"] == "outcome_conflict"


def test_redeliver_from_many_threads_delivers_each_outcome_once() -> None:
    """In a server, several requests redeliver at once while queued effects
    land: each kept outcome must be taken by exactly one of them. Reading the
    kept list is slowed down here, so two unsynchronized calls would both take
    the same list."""

    delivered: list[int] = []
    lock = threading.Lock()

    class Recording:
        def admit(self, *a: Any, **k: Any) -> Any:
            raise AssertionError("not used")

        def history(self, *a: Any, **k: Any) -> Any:
            raise AssertionError("not used")

        def set_outcome(self, mission_id: str, seq: int, *a: Any, **k: Any) -> Any:
            with lock:
                delivered.append(seq)

    class SlowReadPEP(ReferencePEP):
        @property  # type: ignore[override]
        def unreported(self) -> list[Any]:
            kept: list[Any] = self.__dict__["_kept"]
            time.sleep(0.05)
            return kept

        @unreported.setter
        def unreported(self, value: list[Any]) -> None:
            self.__dict__["_kept"] = value

    pep = SlowReadPEP(pdp=CompositionPDP(EXFIL_POLICY, MissionHistoryService(),
                                         access_request_endpoint=ARS),
                      mhs=Recording(), writer_id="pep.x", unreported=[])
    pep.unreported = [("m1", i, ActOutcome.COMPLETED, frozenset(), None) for i in range(50)]
    start = threading.Barrier(8)

    def redeliver() -> None:
        start.wait()
        pep.redeliver()

    threads = [threading.Thread(target=redeliver) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(delivered) == list(range(50))
    assert pep.unreported == []


# --- Wire contract details -----------------------------------------------------

ACT_JSON = (b'{"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"},'
            b' "outcome": "open", "result_classes": [], "recorded_by": "pep.hr"}')


def recording(status: str, body: bytes, seen: list[dict[str, Any]]) -> App:
    """``canned``, but keeps the request headers of every call."""
    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        seen.append({"method": environ["REQUEST_METHOD"],
                     "content_type": environ.get("CONTENT_TYPE", "")})
        _drain(environ)
        start_response(status, [("Content-Type", "application/json")])
        return [body]
    return app


def test_clients_send_a_json_content_type_exactly_when_there_is_a_body() -> None:
    seen: list[dict[str, Any]] = []
    with serve(recording("201 Created", ACT_JSON, seen)) as url:
        RemoteHistoryAuthority(url, "t").admit("m1", 1, "a", "r", writer="")
    with serve(recording("200 OK", ACT_JSON, seen)) as url:
        RemoteHistoryAuthority(url, "t").set_outcome("m1", 1, ActOutcome.FAILED, writer="")
    with serve(recording("200 OK", b'{"acts": []}', seen)) as url:
        RemoteHistoryAuthority(url, "t").history("m1")
    with serve(recording("200 OK", b'{"decision": true}', seen)) as url:
        RemotePDP(url, "t").evaluate(REQ)
    assert [(s["method"], s["content_type"] == "application/json") for s in seen] == [
        ("POST", True), ("PATCH", True), ("GET", False), ("POST", True)]


@pytest.mark.parametrize("body", [b"not json", b"[]", b'"x"'])
def test_unreadable_or_non_object_answers_are_unavailable_on_every_call(body: bytes) -> None:
    with serve(canned("201 Created", body)) as url, pytest.raises(RemoteUnavailable):
        RemoteHistoryAuthority(url, "t").admit("m1", 1, "a", "r", writer="")
    with serve(canned("200 OK", body)) as url:
        with pytest.raises(RemoteUnavailable):
            RemoteHistoryAuthority(url, "t").set_outcome("m1", 1, ActOutcome.FAILED, writer="")
        with pytest.raises(RemoteUnavailable):
            RemotePDP(url, "t").evaluate(REQ)


@pytest.mark.parametrize("acts", [b"{}", b'""', b"null", b"1"])
def test_history_without_an_acts_array_fails_closed(acts: bytes) -> None:
    # An empty object or string iterates as nothing: read as a list it would
    # be an empty history, and the PDP would permit as if nothing had happened.
    with serve(canned("200 OK", b'{"acts": ' + acts + b"}")) as url, \
            pytest.raises(HistoryUnavailable):
        RemoteHistoryAuthority(url, "t").history("m1")


@pytest.mark.parametrize("status", ["201 Created", "202 Accepted", "403 Forbidden",
                                    "404 Not Found", "500 Internal Server Error"])
def test_only_a_200_answer_is_a_decision(status: str) -> None:
    with serve(canned(status, b'{"decision": true}')) as url, \
            pytest.raises(RemoteUnavailable):
        RemotePDP(url, "t").evaluate(REQ)


@pytest.mark.parametrize("status", ["200 OK", "202 Accepted", "403 Forbidden",
                                    "404 Not Found", "409 Conflict"])
def test_an_unexpected_status_is_never_read_as_success(status: str) -> None:
    # A body shaped like success under the wrong status (a misrouted proxy,
    # an unknown 409 reason) is not an admission, an outcome or a history.
    with serve(canned(status, ACT_JSON)) as url:
        if not status.startswith("200"):
            with pytest.raises(RemoteUnavailable):
                RemoteHistoryAuthority(url, "t").set_outcome("m1", 1, ActOutcome.FAILED,
                                                             writer="")
        with pytest.raises(RemoteUnavailable):
            RemoteHistoryAuthority(url, "t").admit("m1", 1, "a", "r", writer="")
    if not status.startswith("200"):
        with serve(canned(status, b'{"acts": []}')) as url, pytest.raises(HistoryUnavailable):
            RemoteHistoryAuthority(url, "t").history("m1")


def test_request_properties_of_every_entity_cross_the_wire() -> None:
    req = EvaluationRequest(Subject("agent", "a", {"s": 1}), Action("x", {"a": 2}),
                            Resource("r", "1", {"r": 3}), mission=Mission("m1", ISSUER))
    wire = request_to_json(req)
    assert (wire["subject"]["properties"], wire["action"]["properties"],
            wire["resource"]["properties"]) == ({"s": 1}, {"a": 2}, {"r": 3})
    assert request_from_json(wire) == req


def test_absent_capability_lists_read_as_empty() -> None:
    body = request_to_json(REQ)
    del body["context"]["supported_obligations"]
    del body["context"]["supported_mandatory_extensions"]
    back = request_from_json(body)
    assert back.supported_obligations == ()
    assert back.supported_mandatory_extensions == ()


def test_reading_a_decision_does_not_change_the_body() -> None:
    body = {"decision": False, "context": {"reason": "prohibited_composition",
                                           "evaluation_id": "e1", "extra": 1}}
    snapshot = json.loads(json.dumps(body))
    decision_from_json(body)
    assert body == snapshot


def test_pdp_http_answer_bodies_and_media_type() -> None:

    with deployment() as env:
        base = env["pdp_url"]

        def call(method: str, path: str, token: str | None, data: bytes | None
                 ) -> tuple[int, str, dict[str, Any]]:
            req = urllib.request.Request(base + path, data=data, method=method)
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, resp.headers["Content-Type"], json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, exc.headers["Content-Type"], json.loads(exc.read())

        body = json.dumps(request_to_json(REQ)).encode()
        cases = [
            (("POST", "/access/v1/evaluation", None, body),
             401, {"error": "authentication is required"}),
            (("POST", "/approvals/v1/tasks/arq_x", None, b"{}"),
             401, {"error": "an approver credential is required"}),
            (("POST", "/access/v1/requests", None, b"{}"),
             401, {"error": "authentication is required"}),
            (("POST", "/approvals/v1/tasks/arq_x", "e-mail", b"{}"),
             401, {"error": "an approver credential is required"}),
            # A POST to an unknown path is not an approval, whoever sends it.
            (("POST", "/nowhere", "person-1", b'{"evaluation_id": "nope"}'),
             404, {"error": "unknown route"}),
            (("GET", "/nowhere", None, None), 404, {"error": "unknown route"}),
        ]
        for args, status, answer in cases:
            assert call(*args) == (status, "application/json", answer), args
        status, media, err = call("POST", "/access/v1/evaluation", "e-hr", b"[]")
        assert (status, media, list(err)) == (400, "application/json", ["error"])
        assert isinstance(err["error"], str) and err["error"]


def test_base_urls_lose_only_their_trailing_slash(monkeypatch: pytest.MonkeyPatch) -> None:
    """A base URL may end in any character; only a trailing ``/`` is dropped.
    (``https://pdp.example/BOX/`` must not become ``.../BO``.)"""

    seen: list[str] = []

    def record(method: str, url: str, headers: dict[str, str], data: bytes | None,
               timeout: float) -> Any:
        seen.append(url)
        raise OSError("not sent")

    monkeypatch.setattr("authzen_composition.remote._exchange", record)
    with pytest.raises(HistoryUnavailable):
        RemoteHistoryAuthority("https://mhs.example/BOX/", "t").history("m")
    with pytest.raises(RemoteUnavailable):
        RemotePDP("https://pdp.example/BOX/", "t").evaluate(REQ)
    assert seen == ["https://mhs.example/BOX/missions/m/acts",
                    "https://pdp.example/BOX/access/v1/evaluation"]

    app = PDPHttpApp(CompositionPDP(EXFIL_POLICY, MissionHistoryService(),
                                    access_request_endpoint=ARS),
                     StaticTokenAuthenticator({}), StaticTokenAuthenticator({}),
                     base_url="https://pdp.example/BOX/")
    out = b"".join(app({"REQUEST_METHOD": "GET",
                        "PATH_INFO": "/.well-known/authzen-configuration"},
                       lambda status, headers: None))
    meta = json.loads(out)
    assert meta["policy_decision_point"] == "https://pdp.example/BOX"
    assert meta["access_evaluation_endpoint"] == "https://pdp.example/BOX/access/v1/evaluation"


# --- Bounded answers ----------------------------------------------------------------

@contextmanager
def _raw_server(answer: Callable[[socket.socket], None]) -> Iterator[str]:
    """A server that reads a request and answers with raw bytes, as a faulty or
    hostile History Authority could."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.2)
    stop = threading.Event()

    def run() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(5)
                try:
                    conn.recv(65536)
                    answer(conn)
                except OSError:
                    pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        stop.set()
        thread.join(10)
        listener.close()


def test_an_answer_trickled_byte_by_byte_is_unavailable_within_the_timeout() -> None:
    # The timeout bounds the whole answer, not each read: an authority that
    # sends one byte at a time would otherwise hold the PDP for as long as it
    # likes, and every Mission's decisions with it.
    body = json.dumps({"acts": [], "next_seq": 1}).encode()

    def trickle(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                     b"Content-Length: %d\r\n\r\n" % len(body))
        for byte in body:
            time.sleep(0.25)
            conn.sendall(bytes([byte]))

    with _raw_server(trickle) as url:
        start = time.monotonic()
        with pytest.raises(HistoryUnavailable):
            RemoteHistoryAuthority(url, "t-pdp", timeout=1.0).history("m")
        assert time.monotonic() - start < 3.5


@pytest.mark.parametrize("declared", [True, False])
def test_an_answer_larger_than_the_limit_is_unavailable(
        monkeypatch: pytest.MonkeyPatch, declared: bool) -> None:
    # A larger answer is refused, whether its Content-Length says so up front
    # or it simply keeps coming, so a faulty or hostile authority cannot make
    # the PDP read without bound.
    monkeypatch.setattr(remote, "MAX_RESPONSE_BYTES", 1024, raising=False)
    body = json.dumps({"acts": [], "next_seq": 1}).encode() + b" " * 4096
    head = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
    if declared:
        head += b"Content-Length: %d\r\n" % len(body)

    def big(conn: socket.socket) -> None:
        conn.sendall(head + b"\r\n" + body)

    with _raw_server(big) as url, pytest.raises(HistoryUnavailable):
        RemoteHistoryAuthority(url, "t-pdp").history("m")


_BODY = {"subject": {"type": "agent", "id": "a"}, "action": {"name": "read_record"},
         "resource": {"type": "r", "id": "hr:1"}}


@pytest.mark.parametrize("mission", ["m", 7, [], {}, {"id": ""}, {"id": 7},
                                     {"id": "m", "issuer": ""}, {"id": "m"},
                                     {"id": "m", "issuer": 7}])
def test_a_malformed_mission_makes_the_request_malformed(mission: Any) -> None:
    # Profile, Request: a `context.mission` that is not an Object, or whose
    # `id` is not a non-empty String, is rejected, never read as no Mission.
    with pytest.raises(ValueError):
        request_from_json({**_BODY, "context": {"mission": mission}})


@pytest.mark.parametrize("member", ["supported_mandatory_extensions", "supported_obligations"])
def test_a_null_mission_is_absent_and_adoption_lists_are_read_leniently(member: str) -> None:
    # Obligations Core: a PDP ignores a value it did not advertise and never
    # rejects a request for it; Extensibility Model: an unusable opt-in is no
    # adoption. A member that is not an Array reads as absent, and an entry
    # that is not a non-empty String is ignored.
    assert request_from_json({**_BODY, "context": {"mission": None}}).mission is None
    for absent in ("obligations", {"obligations": True}, None, 7):
        assert getattr(request_from_json({**_BODY, "context": {member: absent}}), member) == ()
    mixed = [1, "", "obligations", {"x": 1}, "mission_record"]
    assert getattr(request_from_json({**_BODY, "context": {member: mixed}}), member) == (
        "obligations", "mission_record")
    assert getattr(request_from_json({**_BODY, "context": {}}), member) == ()


def test_an_answer_declared_larger_than_the_limit_is_refused_before_its_body(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # A declared length over the limit is refused at once: the client does
    # not wait for a body it would refuse anyway.
    monkeypatch.setattr(remote, "MAX_RESPONSE_BYTES", 1024)

    def declared_only(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 1025\r\n\r\n")
        time.sleep(4)

    with _raw_server(declared_only) as url:
        start = time.monotonic()
        with pytest.raises(HistoryUnavailable):
            RemoteHistoryAuthority(url, "t-pdp", timeout=3.0).history("m")
        assert time.monotonic() - start < 2.0


@pytest.mark.parametrize("declared", [True, False])
def test_an_answer_of_exactly_the_limit_is_read(
        monkeypatch: pytest.MonkeyPatch, declared: bool) -> None:
    monkeypatch.setattr(remote, "MAX_RESPONSE_BYTES", 1024)
    head = json.dumps({"acts": [], "next_seq": 1}).encode()
    body = head + b" " * (1024 - len(head))
    lines = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
    if declared:
        lines += b"Content-Length: 1024\r\n"

    def exact(conn: socket.socket) -> None:
        conn.sendall(lines + b"\r\n" + body)

    with _raw_server(exact) as url:
        assert RemoteHistoryAuthority(url, "t-pdp").history("m") == []


@pytest.mark.parametrize("meta, issues", [
    ({"supported_obligations": ["mission_record"]}, True),
    ({"supported_obligations": ["other"]}, False),
    ({"supported_obligations": "mission_record"}, False),
    ({}, False),
])
def test_a_pep_learns_from_metadata_whether_the_pdp_issues_mission_record(
        meta: dict[str, Any], issues: bool) -> None:
    # Profile, PEP rules: a PEP sends a request that carries a Mission only to
    # a PDP that lists mission_record in supported_obligations; one that does
    # not implement the profile would permit without it.
    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        start_response("200 OK", [("Content-Type", "application/json")])
        return [json.dumps(meta).encode()]

    with serve(app) as url:
        assert RemotePDP(url, "t").issues_mission_record() is issues


def test_a_pdp_whose_metadata_cannot_be_read_is_not_taken_to_issue_it() -> None:
    with serve(canned("500 Internal Server Error", b"{}")) as url:
        assert RemotePDP(url, "t").issues_mission_record() is False


def test_an_answer_whose_headers_trickle_in_is_unavailable_within_the_timeout() -> None:
    # The timeout bounds the whole exchange, headers included: an authority
    # that sends its status line one byte at a time would otherwise hold the
    # PDP however long it likes.
    head = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"

    def trickle(conn: socket.socket) -> None:
        for byte in head:
            time.sleep(0.25)
            conn.sendall(bytes([byte]))

    with _raw_server(trickle) as url:
        start = time.monotonic()
        with pytest.raises(HistoryUnavailable):
            RemoteHistoryAuthority(url, "t-pdp", timeout=1.0).history("m")
        assert time.monotonic() - start < 3.5


@pytest.mark.parametrize("answer", [
    b"GARBAGE\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nX: " + b"a" * 70000 + b"\r\n\r\n{}",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
], ids=["status-line", "header-too-long", "bad-chunk"])
def test_an_answer_that_is_not_http_is_unavailable(answer: bytes) -> None:
    # A PDP that answers with something other than HTTP gave no decision: the
    # PEP gets RemoteUnavailable, never another exception, and the PDP is not
    # taken to issue mission_record.
    def send(conn: socket.socket) -> None:
        conn.sendall(answer)

    with _raw_server(send) as url:
        with pytest.raises(RemoteUnavailable):
            RemotePDP(url, "t", timeout=2.0).evaluate(REQ)
        assert RemotePDP(url, "t", timeout=2.0).issues_mission_record() is False


@pytest.mark.parametrize("scheme", ["file", "ftp", "gopher"])
def test_a_url_that_is_not_http_or_https_is_never_read(scheme: str) -> None:
    # Only an HTTP or HTTPS exchange is an answer, even where a server at that
    # address would answer one.
    body = b'{"supported_obligations": ["mission_record"]}'

    def metadata(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                     b"Content-Length: %d\r\n\r\n%s" % (len(body), body))

    with _raw_server(metadata) as url:
        assert RemotePDP(url, "t", timeout=2.0).issues_mission_record()
        other = url.replace("http", scheme, 1)
        assert not RemotePDP(other, "t", timeout=2.0).issues_mission_record()
        with pytest.raises(HistoryUnavailable):
            RemoteHistoryAuthority(other, "t", timeout=2.0).history("m")
    with pytest.raises(RemoteUnavailable):
        RemotePDP("http:///no-host", "t", timeout=1.0).evaluate(REQ)


def test_no_read_or_write_starts_once_the_exchange_time_is_spent() -> None:
    left, right = socket.socketpair()
    with left, right:
        spent = remote._Deadline(left, time.monotonic() - 0.001)
        right.sendall(b"x")
        with pytest.raises(TimeoutError):
            spent.readinto(bytearray(1))
        with pytest.raises(TimeoutError):
            spent.sendall(b"x")


def test_an_answer_nested_too_deeply_to_read_is_unavailable() -> None:
    with serve(canned("200 OK", b"[" * 100_000)) as url:
        with pytest.raises(RemoteUnavailable):
            RemotePDP(url, "t", timeout=5.0).evaluate(REQ)
        with pytest.raises(HistoryUnavailable):
            RemoteHistoryAuthority(url, "t", timeout=5.0).history("m")
