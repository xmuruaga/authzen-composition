"""Exact values on the wire and at the edges: wire strings, immutability,
glob precision, batch reservation, PEP return values and retry bound, and the
HTTP binding's exact responses.
"""

from __future__ import annotations

import dataclasses
import io
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from authzen_composition import types as T
from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionDecision,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
    _glob_match,
)
from authzen_composition.pdp import CompositionPDP, _PendingApproval
from authzen_composition.pep import CompositionDenied, ReferencePEP
from authzen_composition.scenarios import EXFIL_POLICY
from authzen_composition.types import (
    Action,
    EvaluationRequest,
    EvaluationsSemantic,
    Mission,
    Resource,
    Subject,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint

ROOT = Path(__file__).resolve().parents[1]
PROFILE = (ROOT / "docs" / "authzen-composition-profile-1_0.md").read_text(encoding="utf-8")
S = Subject("agent", "a")


def _req(action: str, resource: str, mission: str = "m1") -> EvaluationRequest:
    return EvaluationRequest(
        subject=S, action=Action(action), resource=Resource("r", resource),
        mission=Mission(mission, "iss"),
        supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",),
    )


def _completed(mhs: MissionHistoryService, seq: int, action: str, res: str,
               classes: frozenset[str] = frozenset()) -> None:
    mhs.admit("m1", seq, action, res, writer="w")
    mhs.set_outcome("m1", seq, ActOutcome.COMPLETED, writer="w", result_classes=classes)


# --- Wire strings are exactly the ones the profile defines -------------------

@pytest.mark.parametrize("value", [
    ActOutcome.OPEN, ActOutcome.COMPLETED, ActOutcome.FAILED,
    T.REASON_PROHIBITED_COMPOSITION, T.REASON_HISTORY_UNAVAILABLE,
    T.REASON_HISTORY_CONFLICT, T.REASON_HISTORY_PENDING,
    T.OBLIGATION_MISSION_RECORD,
])
def test_wire_value_is_the_one_the_profile_defines(value: str) -> None:
    assert f"`{value}`" in PROFILE


def test_outcome_and_semantic_values_are_literal() -> None:
    assert [o.value for o in ActOutcome] == ["open", "completed", "failed"]
    assert [s.value for s in EvaluationsSemantic] == [
        "execute_all", "deny_on_first_deny", "permit_on_first_permit",
    ]


def test_mission_record_obligation_has_the_profile_shape() -> None:
    pdp = CompositionPDP(EXFIL_POLICY, MissionHistoryService(), access_request_endpoint=ARS)
    (ob,) = pdp.evaluate(_req("read_record", "hr:1")).obligations
    assert ob.type == "mission_record"
    assert ob.id
    assert ob.properties == {"mission": "m1", "expected_seq": 1}


def test_prohibited_denial_does_not_name_the_sequence() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    _completed(mhs, 1, "read_record", "hr:1", frozenset({"personal_data.salary"}))
    _completed(mhs, 2, "write_document", "doc:1")
    d = pdp.evaluate(_req("send_message", "external:x"))
    assert d.reason == "prohibited_composition"
    assert d.context == {}


def test_composition_decision_defaults() -> None:
    d = CompositionDecision(satisfied=True)
    assert d.completed == () and d.requestable is False


# --- Records and decisions cannot be altered after creation ------------------

@pytest.mark.parametrize("obj", [
    Act(1, "a", "r"),
    SequenceStep("a"),
    RestrictedSequence("n", (SequenceStep("a"), SequenceStep("b"))),
    CompositionDecision(satisfied=True),
    CompositionPolicy(),
    Subject("t", "i"), Action("a"), Resource("t", "i"), Mission("m", ISSUER),
    EvaluationRequest(Subject("t", "i"), Action("a"), Resource("t", "i")),
    T.Obligation("o", "t"), T.Decision(True), T.EvaluationResponse(),
    _PendingApproval("m", "a", "r", 1, expires=None),  # type: ignore[arg-type]
], ids=lambda o: type(o).__name__)
def test_value_objects_are_immutable(obj: object) -> None:
    field = dataclasses.fields(obj)[0].name  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(obj, field, getattr(obj, field))


# --- Glob precision ----------------------------------------------------------

def test_dot_star_glob_requires_the_dot() -> None:
    assert _glob_match("personal_data.*", "personal_data.salary")
    assert not _glob_match("personal_data.*", "personal_dataX")
    assert not _glob_match("personal_data.*", "personal_data")


# --- Batch: only a permitted act reserves its sequence -----------------------

def test_batch_denied_act_does_not_reserve_its_sequence() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    _completed(mhs, 1, "read_record", "hr:1", frozenset({"personal_data.salary"}))
    _completed(mhs, 2, "write_document", "doc:1")
    first, second = pdp.evaluate_batch(
        (_req("send_message", "external:x"), _req("read_record", "hr:9"))
    ).evaluations
    assert first.reason == "prohibited_composition"
    # The denied send admits nothing, so the read is decided on its own.
    assert second.decision is True


# --- Expired approvals do not accumulate -------------------------------------

def test_expired_pending_approvals_are_pruned() -> None:
    t0 = datetime(2030, 1, 1, tzinfo=UTC)
    now = [t0]
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, clock=lambda: now[0],
                         request_ttl=timedelta(seconds=10), approval_ttl=timedelta(seconds=10),
                         access_request_endpoint=ARS)
    _completed(mhs, 1, "read_record", "hr:1", frozenset({"personal_data.salary"}))
    _completed(mhs, 2, "write_document", "doc:1")
    a = pdp.evaluate(_req("send_message", "external:x")).evaluation_id
    assert a is not None
    apr = pdp.approve(a)
    now[0] = t0 + timedelta(seconds=10)  # its window and its approval have both expired
    b = pdp.evaluate(_req("send_message", "external:y")).evaluation_id
    assert b is not None
    assert list(pdp._pending) == [b]
    assert apr["id"] not in pdp._approvals


# --- PEP ---------------------------------------------------------------------

def _pep(mhs: MissionHistoryService, policy: CompositionPolicy = EXFIL_POLICY) -> ReferencePEP:
    return ReferencePEP(CompositionPDP(policy, mhs, access_request_endpoint=ARS), mhs, "pep.x")


def _enforce(pep: ReferencePEP, action: str, resource: str, perform):
    return pep.enforce(mission_id="m1", mission_issuer="iss", subject=S,
                       action=Action(action), resource=Resource("r", resource),
                       perform=perform)


def test_pep_returns_the_result_when_no_admission_is_needed() -> None:
    assert _enforce(_pep(MissionHistoryService()), "unrelated", "x:1", lambda: 42) == 42


def test_pep_tries_admission_exactly_twice_then_refuses() -> None:
    calls: list[int] = []

    class LostAcks(MissionHistoryService):
        def admit(self, *args, **kwargs):  # type: ignore[override]
            calls.append(1)
            raise ConnectionError("no acknowledgement")

    ran: list[int] = []
    with pytest.raises(CompositionDenied) as exc:
        _enforce(_pep(LostAcks()), "read_record", "hr:1", lambda: ran.append(1))
    assert exc.value.reason == "mission_record_unavailable"
    assert len(calls) == 2
    assert ran == []


def test_composition_denied_without_reason() -> None:
    e = CompositionDenied(None)
    assert e.reason is None and str(e) == "denied"


# --- HTTP binding: exact responses -------------------------------------------

TOKENS = {"t-hr": "pep.hr", "t-mail": "pep.mail"}


def _call(app: MHSHttpApp, method: str, path: str, body=None, token: str = "t-hr"):
    raw = json.dumps(body).encode() if body is not None else b""
    environ = {
        "REQUEST_METHOD": method, "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw),
        "HTTP_AUTHORIZATION": f"Bearer {token}",
    }
    got: dict = {}
    payload = b"".join(app(environ, lambda s, h: got.update(status=s, headers=h)))
    got["json"] = json.loads(payload)
    return got


def _admit_body(seq: int, action: str = "read_record", res: str = "hr:1") -> dict:
    return {"seq": seq, "action": {"name": action}, "resource": {"id": res}}


def test_http_exact_status_lines_and_content_type() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator(TOKENS),
                     auditors=frozenset(TOKENS.values()))
    cases = [
        (("POST", "/missions/m1/acts", _admit_body(1)), "201 Created"),
        (("POST", "/missions/m1/acts", _admit_body(5)), "409 Conflict"),
        (("PATCH", "/missions/m1/acts/1", {"outcome": "completed"}), "200 OK"),
        (("PATCH", "/missions/m1/acts/1", {"outcome": "failed"}), "409 Conflict"),
        (("PATCH", "/missions/m1/acts/9", {"outcome": "completed"}), "409 Conflict"),
        (("GET", "/missions/m1/acts", None), "200 OK"),
        (("POST", "/missions/m1/acts", {"seq": 2}), "400 Bad Request"),
        (("GET", "/nope", None), "404 Not Found"),
        (("DELETE", "/missions/m1/acts", None), "405 Method Not Allowed"),
    ]
    for (method, path, body), status in cases:
        r = _call(app, method, path, body)
        assert r["status"] == status, (method, path, r)
        assert r["headers"] == [("Content-Type", "application/json")]
    assert _call(app, "GET", "/missions/m1/acts", token="bad")["status"] == "401 Unauthorized"


def test_http_act_record_has_exactly_the_profile_members() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator(TOKENS))
    r = _call(app, "POST", "/missions/m1/acts", _admit_body(1))
    assert r["json"] == {
        "seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"},
        "outcome": "open", "result_classes": [], "recorded_by": "pep.hr",
    }


def test_http_history_names_each_acts_own_writer() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator(TOKENS),
                     auditors=frozenset(TOKENS.values()))
    _call(app, "POST", "/missions/m1/acts", _admit_body(1), token="t-hr")
    _call(app, "POST", "/missions/m1/acts", _admit_body(2, "send_message", "x"), token="t-mail")
    g = _call(app, "GET", "/missions/m1/acts")["json"]
    assert [a["recorded_by"] for a in g["acts"]] == ["pep.hr", "pep.mail"]
    assert g["next_seq"] == 3
    p = _call(app, "PATCH", "/missions/m1/acts/2", {"outcome": "completed"}, token="t-mail")
    assert p["json"]["recorded_by"] == "pep.mail"


def test_http_missions_are_isolated() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator(TOKENS),
                     auditors=frozenset(TOKENS.values()))
    _call(app, "POST", "/missions/m1/acts", _admit_body(1))
    assert _call(app, "POST", "/missions/m2/acts", _admit_body(1))["status"] == "201 Created"
    assert _call(app, "GET", "/missions/m2/acts")["json"]["next_seq"] == 2
    assert _call(app, "GET", "/missions/m3/acts")["json"] == {"acts": [], "next_seq": 1}


def test_http_get_on_an_act_path_is_not_allowed() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator(TOKENS))
    _call(app, "POST", "/missions/m1/acts", _admit_body(1))
    r = _call(app, "GET", "/missions/m1/acts/1")
    assert r["status"] == "405 Method Not Allowed"
    assert re.search(r"GET not allowed", r["json"]["error"])
