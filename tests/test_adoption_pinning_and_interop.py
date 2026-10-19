"""Approvals approved twice, who may pin a Mission's policy, Mission ids that
are URIs, adoption through the Obligations Core, and what the interop vectors
must pin.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from socketserver import ThreadingMixIn
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest

import interop.verify_vectors as vv
from authzen_composition import model
from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import (
    HistoryUnavailable,
    MissionHistoryService,
    NoActAtPosition,
    NotPermitted,
    OutcomeAlreadySet,
    UnauthenticatedWriter,
)
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
    _step_set,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pdp_http import PDPHttpApp
from authzen_composition.pep import CompositionDenied, ReferencePEP
from authzen_composition.remote import RemoteHistoryAuthority, RemoteUnavailable, decision_from_json
from authzen_composition.scenarios import EXFIL, EXFIL_POLICY, READ_SEND, SHARE_LINK
from authzen_composition.types import (
    OBLIGATION_MISSION_RECORD,
    REASON_POLICY_MISMATCH,
    REASON_PROHIBITED_COMPOSITION,
    Action,
    Decision,
    EvaluationRequest,
    Mission,
    Obligation,
    Resource,
    Subject,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint

# --- 1. One access request approved twice -------------------------------------


def _staged(pdp_mhs: tuple[CompositionPDP, MissionHistoryService]) -> None:
    _, mhs = pdp_mhs
    for seq, (action, rid, classes) in enumerate(
            (("read_record", "hr:1", {"personal_data.salary"}),
             ("write_document", "doc:1", set())), start=1):
        mhs.admit("m", seq, action, rid, writer="pep")
        mhs.set_outcome("m", seq, ActOutcome.COMPLETED, writer="pep",
                        result_classes=frozenset(classes))


def _send(approval: str | None = None) -> EvaluationRequest:
    return EvaluationRequest(
        Subject("agent", "a"), Action("send_message"), Resource("r", "external:x"),
        mission=Mission("m", ISSUER), supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",),
        context={"approval": {"id": approval}} if approval else {})


def test_a_second_approval_of_a_spent_request_is_a_denial_not_an_error() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    _staged((pdp, mhs))
    denied = pdp.evaluate(_send())
    assert denied.evaluation_id is not None
    # Two people approve the same access request (or one clicks twice).
    first = pdp.approve(denied.evaluation_id)["id"]
    second = pdp.approve(denied.evaluation_id)["id"]
    assert pdp.evaluate(_send(first)).decision
    # The request was spent by the first approval's permit. The second one
    # is no longer valid: a denial, never an exception.
    again = pdp.evaluate(_send(second))
    assert (again.decision, again.reason) == (False, REASON_PROHIBITED_COMPOSITION)


def test_spending_one_approval_leaves_another_requests_approval_valid() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    _staged((pdp, mhs))

    def to(target: str, approval: str | None = None) -> EvaluationRequest:
        return EvaluationRequest(
            Subject("agent", "a"), Action("send_message"), Resource("r", target),
            mission=Mission("m", ISSUER), supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",),
            context={"approval": {"id": approval}} if approval else {})

    first, second = (pdp.evaluate(to(t)) for t in ("external:x", "external:y"))
    assert first.evaluation_id and second.evaluation_id
    a1 = pdp.approve(first.evaluation_id)["id"]
    a2 = pdp.approve(second.evaluation_id)["id"]
    assert pdp.evaluate(to("external:x", a1)).decision
    # Another access request, approved on its own: still valid.
    assert pdp.evaluate(to("external:y", a2)).decision


def test_a_second_approval_over_http_is_a_denial_not_a_server_error() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    _staged((pdp, mhs))
    app = PDPHttpApp(pdp, StaticTokenAuthenticator({"pep": "pep.mail"}),
                     StaticTokenAuthenticator({"person": "person"}))

    def post(path: str, token: str, body: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        raw = json.dumps(body).encode()
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": path, "CONTENT_LENGTH": str(len(raw)),
               "wsgi.input": io.BytesIO(raw), "HTTP_AUTHORIZATION": f"Bearer {token}"}
        got: dict[str, str] = {}
        out = b"".join(app(env, lambda s, h: got.update(s=s)))
        return got["s"], json.loads(out)

    send = {"subject": {"type": "agent", "id": "a"}, "action": {"name": "send_message"},
            "resource": {"type": "r", "id": "external:x"},
            "context": {"mission": {"id": "m", "issuer": ISSUER},
                        "supported_mandatory_extensions": ["obligations"],
                        "supported_obligations": ["mission_record"]}}
    status, denied = post("/access/v1/evaluation", "pep", send)
    eid = denied["context"]["evaluation_id"]
    approvals = [pdp.approve(eid)["id"] for _ in range(2)]
    with_first = {**send, "context": {**send["context"], "approval": {"id": approvals[0]}}}
    with_second = {**send, "context": {**send["context"], "approval": {"id": approvals[1]}}}
    status, body = post("/access/v1/evaluation", "pep", with_first)
    assert (status, body["decision"]) == ("200 OK", True)
    status, body = post("/access/v1/evaluation", "pep", with_second)
    # A denial (a fresh access request a person may approve), not a 500.
    assert status == "200 OK"
    assert (body["decision"], body["context"]["reason"]) == (False, REASON_PROHIBITED_COMPOSITION)
    assert body["context"]["evaluation_id"] != eid


# --- 2. Only a PDP's read pins the Mission's set of Restricted Sequences ---------

TOKENS = {"t-pep": "pep.mail", "t-pdp": "pdp", "t-audit": "auditor"}


def _get(app: MHSHttpApp, token: str, query: str = "") -> tuple[str, dict[str, Any]]:
    env = {"REQUEST_METHOD": "GET", "PATH_INFO": "/missions/m/acts", "QUERY_STRING": query,
           "wsgi.input": io.BytesIO(b""), "HTTP_AUTHORIZATION": f"Bearer {token}"}
    got: dict[str, str] = {}
    out = b"".join(app(env, lambda s, h: got.update(s=s)))
    return got["s"], json.loads(out)


def test_a_writer_cannot_pin_the_missions_policy() -> None:
    # History Authority item 6: the first *PDP* read that names a set pins it.
    # A PEP that could pin would make every PDP of the deployment's set refuse
    # the Mission, or, mid-rollout, bind it to an older and weaker set.
    mhs = MissionHistoryService(trusted_writers=frozenset({"pep.mail"}))
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}),
                     auditors=frozenset({"auditor"}))
    status, body = _get(app, "t-pep", "policy=sha256%3Aold")
    assert status == "403 Forbidden" and set(body) == {"error"}
    assert mhs.policy_of("m") is None
    # An auditor's read without a digest neither pins nor is refused.
    assert _get(app, "t-audit")[0] == "200 OK"
    assert _get(app, "t-audit", "policy=sha256%3Aold")[0] == "403 Forbidden"
    assert mhs.policy_of("m") is None
    # The PDP's read pins.
    assert _get(app, "t-pdp", "policy=sha256%3Anew")[0] == "200 OK"
    assert mhs.policy_of("m") == "sha256:new"


def test_by_default_no_caller_may_pin() -> None:
    # Like the authenticator, the set of PDP identities has no permissive
    # default: a binding deployed without it refuses every pin (and so every
    # PDP decision fails closed) instead of letting any credential pin.
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS))
    assert _get(app, "t-pdp", "policy=sha256%3Anew")[0] == "403 Forbidden"
    assert mhs.policy_of("m") is None


# --- 3. A Mission id that is a URI -------------------------------------------------


class _Server(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _RawPathHandler(WSGIRequestHandler):
    """wsgiref with the request target kept, as gunicorn (``RAW_URI``) and
    uWSGI (``REQUEST_URI``) keep it."""

    def get_environ(self) -> dict[str, Any]:
        env: dict[str, Any] = super().get_environ()
        env["RAW_URI"] = self.path
        return env

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


@contextmanager
def _serve(app: Any) -> Iterator[str]:
    server = make_server("127.0.0.1", 0, app, server_class=_Server,
                         handler_class=_RawPathHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


URI_MISSION = "https://missions.example/m/8f14e45f"


def test_a_uri_mission_id_round_trips_over_the_binding() -> None:
    # The profile asks issuers for globally unique ids, "for example a URI
    # under the issuer's own authority". Such an id contains '/'.
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    with _serve(app) as url:
        pep = RemoteHistoryAuthority(url, "t-pep")
        pep.admit(URI_MISSION, 1, "read_record", "hr:1", writer="")
        pep.set_outcome(URI_MISSION, 1, ActOutcome.COMPLETED, writer="",
                        result_classes=frozenset({"personal_data.salary"}))
        assert [a.seq for a in mhs.history(URI_MISSION)] == [1]
        pdp = CompositionPDP(EXFIL_POLICY, RemoteHistoryAuthority(url, "t-pdp"))
        d = pdp.evaluate(EvaluationRequest(
            Subject("agent", "a"), Action("write_document"), Resource("r", "doc:1"),
            mission=Mission(URI_MISSION, ISSUER),
            supported_mandatory_extensions=("obligations",),
            supported_obligations=("mission_record",)))
        assert d.decision and d.obligations[0].properties["expected_seq"] == 2
        assert mhs.policy_of(URI_MISSION) == EXFIL_POLICY.digest


def test_ids_that_differ_only_by_a_slash_are_different_missions() -> None:
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    with _serve(app) as url:
        pep = RemoteHistoryAuthority(url, "t-pep")
        pep.admit("m/", 1, "read_record", "hr:1", writer="")
        assert RemoteHistoryAuthority(url, "t-pdp").history("m") == []
        assert [a.seq for a in mhs.history("m/")] == [1]


@pytest.mark.parametrize("key", ["RAW_URI", "REQUEST_URI"])
def test_the_raw_target_is_read_from_either_server_key(key: str) -> None:
    # gunicorn keeps the request target as RAW_URI, uWSGI as REQUEST_URI.
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    raw = json.dumps({"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}}).encode()
    env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/missions/urn:x/a/acts",
           key: "/missions/urn:x%2Fa/acts", "CONTENT_LENGTH": str(len(raw)),
           "wsgi.input": io.BytesIO(raw), "HTTP_AUTHORIZATION": "Bearer t-pep"}
    got: dict[str, str] = {}
    b"".join(app(env, lambda s, h: got.update(s=s)))
    assert got["s"] == "201 Created"
    assert mhs.next_seq("urn:x/a") == 2


def test_the_raw_target_is_read_below_the_mount_point() -> None:
    # Mounted under a prefix: SCRIPT_NAME holds it, and the raw target
    # carries it too.
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    raw = json.dumps({"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}}).encode()
    env = {"REQUEST_METHOD": "POST", "SCRIPT_NAME": "/mhs/v1",
           "PATH_INFO": "/missions/urn:x/a/acts", "RAW_URI": "/mhs/v1/missions/urn:x%2Fa/acts",
           "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw),
           "HTTP_AUTHORIZATION": "Bearer t-pep"}
    got: dict[str, str] = {}
    b"".join(app(env, lambda s, h: got.update(s=s)))
    assert got["s"] == "201 Created"
    assert mhs.next_seq("urn:x/a") == 2


# --- 4. What the interop vectors must pin -------------------------------------------
#
# Each deviant below is a plausible second implementation that gets one rule
# of the profile wrong, most of them unsafely. The vectors are the
# conformance artefact another implementer runs, so each deviant must fail
# at least one of them.


ROOT_VECTORS = (__import__("pathlib").Path(__file__).resolve().parents[1]
                / "interop" / "test-vectors" / "composition-vectors.json")


def _classless_completed_is_not_the_top(self: Act) -> frozenset[str]:
    if self.outcome is ActOutcome.FAILED:
        return frozenset()
    if self.outcome is not ActOutcome.COMPLETED:
        return frozenset({model.CONSERVATIVE_TOP})
    return self.result_classes


class _SerializeOnlyWithHistory(CompositionPDP):
    def evaluate(self, request: EvaluationRequest) -> Decision:
        d = super().evaluate(request)
        if d.decision and request.mission and not self.mhs.history(request.mission.id):
            return Decision(decision=True)
        return d


def _pending(exempt: Any) -> Any:
    def pending_conflict(self: CompositionPolicy, history: list[Act],
                         candidate: Act) -> tuple[str, ...]:
        hits = []
        for seq in self.sequences:
            mine = _step_set(seq, self._normalize(candidate))
            for act in history:
                if act.outcome is ActOutcome.OPEN and mine:
                    theirs = _step_set(seq, self._normalize(act))
                    if theirs and not exempt(theirs, mine):
                        hits.append(seq.name)
                        break
        return tuple(hits)
    return pending_conflict


def _dot_star_matches_the_bare_prefix(pattern: str, value: str) -> bool:
    if pattern.endswith(".*"):
        return value.startswith(pattern[:-2])
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


class _RequiresComposition(CompositionPDP):
    def evaluate(self, request: EvaluationRequest) -> Decision:
        d = super().evaluate(request)
        if d.obligations and "composition" not in request.supported_mandatory_extensions:
            return Decision(decision=False)
        return d


class _RejectsUnknownExtensions(CompositionPDP):
    def evaluate(self, request: EvaluationRequest) -> Decision:
        if set(request.supported_mandatory_extensions) - {"obligations", "composition"}:
            return Decision(decision=False)
        return super().evaluate(request)


def _open_persistent_act_holds_nothing(self: CompositionPolicy, history: list[Act],
                                       candidate: Act) -> tuple[str, ...]:
    # Rule 5 as written, except that an open Act matching only persistent
    # steps holds nothing back.
    hits = []
    for seq in self.sequences:
        mine = _step_set(seq, self._normalize(candidate))
        for act in history:
            if act.outcome is ActOutcome.OPEN and mine:
                theirs = _step_set(seq, self._normalize(act))
                lasting = all(seq.steps[i].persistent for i in theirs)
                if theirs and not lasting and not (theirs == mine and len(mine) == 1):
                    hits.append(seq.name)
                    break
    return tuple(hits)


def _candidate_without_classes(self: CompositionPDP, history: list[Act],
                               request: EvaluationRequest) -> Act:
    # The candidate matched with no result classes instead of at the top.
    return Act(len(history) + 1, request.action.name, request.resource.id, ActOutcome.FAILED)


DEVIANTS = {
    "a completed Act that reported no class is not the top":
        (Act, "effective_classes", _classless_completed_is_not_the_top),
    "no mission_record for a step-matching Act on an empty history":
        (None, "CompositionPDP", _SerializeOnlyWithHistory),
    "rule 5 exempts an open Act that shares any step with the candidate":
        (CompositionPolicy, "pending_conflict", _pending(lambda a, b: bool(a & b))),
    "rule 5 exempts equal step sets of any size":
        (CompositionPolicy, "pending_conflict", _pending(lambda a, b: a == b)),
    # Sound in an exhaustive small scope, but more permissive than rule 5 as
    # written: V27 pins the difference.
    "rule 5 also exempts an open Act whose steps all come before the candidate's":
        (CompositionPolicy, "pending_conflict",
         _pending(lambda a, b: (a == b and len(b) == 1) or max(a) < min(b))),
    "still requires a separate `composition` opt-in":
        (None, "CompositionPDP", _RequiresComposition),
    "refuses a request listing an extension it does not implement":
        (None, "CompositionPDP", _RejectsUnknownExtensions),
    "an open Act that matches only persistent steps holds nothing back":
        (CompositionPolicy, "pending_conflict", _open_persistent_act_holds_nothing),
    "the candidate is matched with no result classes, not at the top":
        (CompositionPDP, "_candidate", _candidate_without_classes),
    "`a.*` also matches `a`":
        (model, "_name_match", _dot_star_matches_the_bare_prefix),
}


@pytest.mark.parametrize("name", sorted(DEVIANTS))
def test_vectors_catch_a_deviant_implementation(name: str,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    target, attr, value = DEVIANTS[name]
    monkeypatch.setattr(vv if target is None else target, attr, value)
    data = json.loads(ROOT_VECTORS.read_text(encoding="utf-8"))
    assert vv.run(data), f"every vector passes with the deviant: {name}"


# --- 5. Adoption of the Obligations Core (openid/authzen PR #697) -------------
#
# The profile takes its opt-in signals from the proposed Obligations Core.
# There, a PDP MUST NOT return an `obligations` member to a PEP that did not
# list `obligations` in `supported_mandatory_extensions`, and MUST NOT emit a
# type the PEP did not list in `supported_obligations` (an omitted list is
# empty); policy that needs the obligation then gets a plain core DENY.


def _write(extensions: tuple[str, ...], types: tuple[str, ...]) -> EvaluationRequest:
    return EvaluationRequest(
        Subject("agent", "a"), Action("write_document"), Resource("r", "doc:1"),
        mission=Mission("m", ISSUER), supported_mandatory_extensions=extensions,
        supported_obligations=types)


@pytest.mark.parametrize(("extensions", "types"), [
    (("composition",), ("mission_record",)),          # obligations not adopted
    (("obligations",), ()),             # mission_record not listed
    (("obligations",), ("step-up",)),   # another type only
])
def test_mission_record_only_to_a_pep_that_adopted_it(extensions: tuple[str, ...],
                                                      types: tuple[str, ...]) -> None:
    pdp = CompositionPDP(EXFIL_POLICY, MissionHistoryService())
    d = pdp.evaluate(_write(extensions, types))
    # A plain core deny: no obligation, no composition reason.
    assert (d.decision, d.reason, d.obligations) == (False, None, ())


def test_an_adopting_pep_gets_mission_record() -> None:
    pdp = CompositionPDP(EXFIL_POLICY, MissionHistoryService())
    # "obligations" alone, so a PDP that still required a composition opt-in
    # would fail this test.
    d = pdp.evaluate(_write(("obligations",), ("mission_record",)))
    assert d.decision and [o.type for o in d.obligations] == ["mission_record"]


def test_an_act_that_needs_no_obligation_needs_no_adoption() -> None:
    pdp = CompositionPDP(EXFIL_POLICY, MissionHistoryService())
    d = pdp.evaluate(EvaluationRequest(
        Subject("agent", "a"), Action("list_events"), Resource("r", "cal:1"),
        mission=Mission("m", ISSUER)))
    assert (d.decision, d.obligations) == (True, ())


def test_the_reference_pep_adopts_obligations_and_lists_mission_record() -> None:
    seen: list[EvaluationRequest] = []

    class Recorder:
        def evaluate(self, request: EvaluationRequest) -> Decision:
            seen.append(request)
            return Decision(decision=True)

    ReferencePEP(pdp=Recorder(), mhs=MissionHistoryService(), writer_id="pep").enforce(
        mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
        action=Action("list_events"), resource=Resource("r", "cal:1"), perform=lambda: None)
    assert set(seen[0].supported_mandatory_extensions) == {"obligations"}
    assert "mission_record" in seen[0].supported_obligations


# --- 6. A composite tool is admitted as the Acts it performs ----------------------


def test_a_composite_tool_admitted_part_by_part_stops_before_the_send() -> None:
    # PEP rules: a call that performs several operations ("write the report
    # and mail it") MUST be admitted as the separate Acts it performs, in
    # order, each before its part runs. Admitted as one Act under its own
    # name, it matches no step, and the leak goes through.

    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs)
    pep = ReferencePEP(pdp=pdp, mhs=mhs, writer_id="pep.tools",
                       classifier=lambda a, r, raw: frozenset({"personal_data.salary"})
                       if a == "read_record" else frozenset())
    ran: list[str] = []

    def act(action: str, resource: str) -> object:
        return pep.enforce(mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
                           action=Action(action), resource=Resource("r", resource),
                           perform=lambda: ran.append(action))

    act("read_record", "hr:emp-1")
    # Split, in order: the write runs, the send is denied before it starts.
    act("write_document", "doc:report")
    with pytest.raises(CompositionDenied) as denied:
        act("send_message", "external:press@partner.example")
    assert denied.value.reason == REASON_PROHIBITED_COMPOSITION
    assert ran == ["read_record", "write_document"]
    # The same call admitted whole: no step matches it, nothing serializes it.
    act("export_and_mail", "external:press@partner.example")
    assert ran[-1] == "export_and_mail"
    assert [a.action for a in mhs.history("m")] == ["read_record", "write_document"]


def test_an_id_that_is_not_utf8_is_a_bad_request_not_a_guess() -> None:
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    env = {"REQUEST_METHOD": "GET", "PATH_INFO": "/missions/\xff/acts",
           "RAW_URI": "/missions/%ff/acts?policy=x", "QUERY_STRING": "policy=x",
           "wsgi.input": io.BytesIO(b""), "HTTP_AUTHORIZATION": "Bearer t-pdp"}
    got: dict[str, str] = {}
    body = json.loads(b"".join(app(env, lambda s, h: got.update(s=s))))
    assert got["s"] == "400 Bad Request" and set(body) == {"error"}
    assert mhs.policy_of("\xff") is None and mhs.policy_of("\ufffd") is None


# --- 7. An adopting PEP never acts on a permit it cannot fully enforce -------------
#
# Obligations Core (PR #697): "An Adopting PEP that does not understand
# an Obligation, or cannot apply it, MUST treat a PERMIT as a DENY". The merged
# Obligations profile says the same of any PEP. The reference PEP lists
# `obligations`, so it is an Adopting PEP.


@pytest.mark.parametrize("obligations", [
    (Obligation("o1", "step-up"),),
    (Obligation("o1", "mission_record", {"mission": "m", "expected_seq": 1}),
     Obligation("o2", "notification")),
])
def test_a_permit_with_an_obligation_the_pep_does_not_know_is_a_deny(
        obligations: tuple[Obligation, ...]) -> None:
    class PDP:
        def evaluate(self, request: EvaluationRequest) -> Decision:
            return Decision(decision=True, obligations=obligations)

    mhs = MissionHistoryService()
    ran: list[str] = []
    with pytest.raises(CompositionDenied) as denied:
        ReferencePEP(pdp=PDP(), mhs=mhs, writer_id="pep").enforce(
            mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
            action=Action("read_record"), resource=Resource("r", "hr:1"),
            perform=lambda: ran.append("ran"))
    assert denied.value.reason == "obligation_not_understood"
    assert ran == [] and mhs.history("m") == []


# --- 8. An outcome the History Authority will never accept is not retried ---------


class _NeverPDP:
    def evaluate(self, request: EvaluationRequest) -> Decision:
        return Decision(decision=False)


def test_an_outcome_refused_for_good_is_not_redelivered_forever() -> None:
    # An operator closed a stranded Act whose PEP was in fact alive (History
    # Authority item 7). The PEP's kept outcome can never be recorded: it is
    # handed to the operator once, and the Act stays at the top.

    mhs = MissionHistoryService(operators=frozenset({"ops"}))
    mhs.admit("m", 1, "read_record", "hr:1", writer="pep.hr")
    pep = ReferencePEP(pdp=_NeverPDP(), mhs=mhs, writer_id="pep.hr")
    pep.unreported.append(("m", 1, ActOutcome.COMPLETED, frozenset({"public"}), None))
    mhs.close_stranded("m", 1, "ops")
    pep.redeliver()
    assert pep.unreported == []
    assert [r[:4] for r in pep.refused] == [("m", 1, ActOutcome.COMPLETED, frozenset({"public"}))]
    pep.redeliver()
    assert len(pep.refused) == 1
    act = mhs.history("m")[0]
    assert (act.outcome, act.result_classes) == (ActOutcome.COMPLETED, frozenset())


def test_an_outcome_refused_over_http_is_not_redelivered_forever() -> None:
    mhs = MissionHistoryService(operators=frozenset({"ops"}))
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    with _serve(app) as url:
        remote = RemoteHistoryAuthority(url, "t-pep")
        remote.admit("m", 1, "read_record", "hr:1", writer="")
        pep = ReferencePEP(pdp=_NeverPDP(), mhs=remote, writer_id="pep.mail")
        pep.unreported.append(("m", 1, ActOutcome.COMPLETED, frozenset({"public"}), None))
        mhs.close_stranded("m", 1, "ops")
        pep.redeliver()
        assert pep.unreported == [] and len(pep.refused) == 1


def test_a_transient_outcome_failure_is_still_kept() -> None:
    class Down(MissionHistoryService):
        def set_outcome(self, *a: Any, **k: Any) -> Act:
            raise ConnectionError("authority unreachable")

    pep = ReferencePEP(pdp=_NeverPDP(), mhs=Down(), writer_id="pep.hr")
    pep.unreported.append(("m", 1, ActOutcome.COMPLETED, frozenset(), None))
    pep.redeliver()
    assert len(pep.unreported) == 1 and pep.refused == []


def test_an_outcome_for_an_act_the_authority_does_not_hold_is_refused() -> None:
    # "No Act at that position" for an Act this PEP admitted means the
    # authority lost an acknowledged admission: final, and an incident.

    mhs = MissionHistoryService()
    pep = ReferencePEP(pdp=_NeverPDP(), mhs=mhs, writer_id="pep.hr")
    pep.unreported.append(("m", 5, ActOutcome.COMPLETED, frozenset(), None))
    pep.redeliver()
    assert pep.unreported == [] and [r[:2] for r in pep.refused] == [("m", 5)]


# --- 9. Obligations Core discovery ------------------------------------------


def test_metadata_advertises_the_obligations_extension_and_what_it_issues() -> None:
    # Obligations profile on main: a PDP that implements it MUST include
    # supported_obligations in its metadata. Obligations Core (PR #697):
    # also its capability URN, and a PDP ignores request values it did not
    # advertise, so mission_record must be advertised to be issued at all.

    meta = CompositionPDP(EXFIL_POLICY, MissionHistoryService()).metadata()
    assert "urn:openid:authzen:capability:obligations" in meta["capabilities"]
    assert OBLIGATION_MISSION_RECORD in meta["supported_obligations"]


# --- 10. No separate opt-in for this profile -------------------------------------
#
# Extensibility Model: "A profile that carries a mandatory element is adopted
# by opting into that element's extension, so it needs no separate signal."
# The profile's only mandatory element is the mission_record obligation.


def test_adopting_the_obligations_extension_is_enough() -> None:
    pdp = CompositionPDP(EXFIL_POLICY, MissionHistoryService())
    d = pdp.evaluate(_write(("obligations",), ("mission_record",)))
    assert d.decision and [o.type for o in d.obligations] == ["mission_record"]
    # An extension the PDP does not implement is a no-op, never a refusal.
    d = pdp.evaluate(_write(("obligations", "x-not-implemented"), ("mission_record",)))
    assert d.decision and [o.type for o in d.obligations] == ["mission_record"]


# --- 11. Who reads a Mission's history ---------------------------------------------


def test_only_pdps_and_auditors_read_a_missions_history() -> None:
    # A history holds every Act's action, resource and classes: personal data
    # such as an employee id or a recipient's address. A writer has no need to
    # read it.
    mhs = MissionHistoryService(trusted_writers=frozenset({"pep.mail"}))
    mhs.admit("m", 1, "send_message", "external:press@partner.example", writer="pep.mail")
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}),
                     auditors=frozenset({"auditor"}))
    status, body = _get(app, "t-pep")
    assert status == "403 Forbidden" and set(body) == {"error"}
    assert _get(app, "t-audit")[0] == "200 OK"
    assert _get(app, "t-pdp", "policy=sha256%3Ax")[0] == "200 OK"
    # By default nobody reads.
    bare = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS))
    assert {_get(bare, t)[0] for t in ("t-pep", "t-audit", "t-pdp")} == {"403 Forbidden"}


# --- 12. Which set a new Mission gets (designation at the History Authority) -------

_OLD_SET = CompositionPolicy((EXFIL,))
_NEW_SET = CompositionPolicy((EXFIL, SHARE_LINK))


def _decide(pdp: CompositionPDP, mission: str, action: str = "share_public",
            rid: str = "doc:q4") -> tuple[bool, str | None]:
    d = pdp.evaluate(EvaluationRequest(
        Subject("agent", "a"), Action(action), Resource("r", rid), mission=Mission(mission, ISSUER),
        supported_mandatory_extensions=("obligations",), supported_obligations=("mission_record",)))
    return d.decision, d.reason


def test_a_designated_set_binds_a_new_mission_whichever_pdp_reads_first() -> None:
    mhs = MissionHistoryService(new_mission_policies=frozenset({_NEW_SET.digest}))
    old, new = CompositionPDP(_OLD_SET, mhs), CompositionPDP(_NEW_SET, mhs)
    # The old replica happens to decide first: refused, and nothing is pinned.
    assert _decide(old, "m") == (False, REASON_POLICY_MISMATCH)
    assert mhs.policy_of("m") is None
    assert _decide(new, "m")[0]
    assert mhs.policy_of("m") == _NEW_SET.digest
    assert _decide(old, "m") == (False, REASON_POLICY_MISMATCH)


def test_a_designation_never_moves_a_pin() -> None:
    mhs = MissionHistoryService()
    old, new = CompositionPDP(_OLD_SET, mhs), CompositionPDP(_NEW_SET, mhs)
    assert _decide(old, "before")[0]               # no designation: first read pins
    mhs.designate(frozenset({_OLD_SET.digest, _NEW_SET.digest}))
    assert _decide(new, "canary")[0]               # both designated: either may start one
    mhs.designate(frozenset({_NEW_SET.digest}))
    assert _decide(old, "before")[0]               # still decides its own Mission
    assert _decide(new, "before") == (False, REASON_POLICY_MISMATCH)
    assert _decide(old, "after") == (False, REASON_POLICY_MISMATCH)
    assert (mhs.policy_of("before"), mhs.policy_of("canary")) == (_OLD_SET.digest, _NEW_SET.digest)


def test_an_empty_designation_starts_no_mission_and_still_serves_audit_reads() -> None:
    mhs = MissionHistoryService(new_mission_policies=frozenset())
    assert _decide(CompositionPDP(_NEW_SET, mhs), "m") == (False, REASON_POLICY_MISMATCH)
    assert mhs.policy_of("m") is None
    # An auditor still reads over the binding.
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}),
                     auditors=frozenset({"auditor"}))
    assert _get(app, "t-audit") == ("200 OK", {"acts": [], "next_seq": 1})


def test_a_first_pin_outside_the_designation_is_a_policy_mismatch_over_the_binding() -> None:
    mhs = MissionHistoryService(new_mission_policies=frozenset({"sha256:new"}))
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    status, body = _get(app, "t-pdp", "policy=sha256%3Aold")
    assert (status, body.get("reason")) == ("409 Conflict", "policy_mismatch")
    assert mhs.policy_of("m") is None
    assert _get(app, "t-pdp", "policy=sha256%3Anew")[0] == "200 OK"


def test_a_pdp_reads_and_pins_before_deciding_an_act_that_matches_no_step() -> None:
    # Profile: a PDP reads, naming its digest, before it decides any request
    # for a Mission, so an Act it permits without admission is still decided
    # under the Mission's set.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(_OLD_SET, mhs)
    assert _decide(pdp, "m", "list_events", "cal:me") == (True, None)
    assert mhs.policy_of("m") == _OLD_SET.digest


# --- 13. The digest names the set ------------------------------------------------


def test_the_digest_does_not_depend_on_the_order_or_repetition_of_the_sequences() -> None:
    # Profile: every PDP deciding for a Mission computes the same digest for
    # the same set. Two PDPs provisioned with the same sequences in another
    # order would otherwise refuse each other's Missions.

    one = CompositionPolicy((EXFIL, READ_SEND))
    assert one.digest == CompositionPolicy((READ_SEND, EXFIL)).digest
    assert one.digest == CompositionPolicy((EXFIL, READ_SEND, EXFIL)).digest
    assert one.digest != CompositionPolicy((EXFIL,)).digest


def test_the_digest_lists_several_sequences_by_their_canonical_text() -> None:
    # The order is part of the reference's canonical form, so it is pinned
    # from bytes written out literally, like the single-sequence form in
    # test_digest_and_operator_close.py. The two sequences share a name and differ in
    # their second step, where ordering by key-sorted text (false before
    # true) and by insertion order (resources first) disagree.

    first = RestrictedSequence("s", (SequenceStep("a"), SequenceStep("b", frozenset({"z"}))))
    second = RestrictedSequence(
        "s", (SequenceStep("a"), SequenceStep("b", frozenset({"a"}), persistent=True)))
    head = ('{"name":"s","requestable":false,"steps":[{"action":"a","persistent":false,'
            '"resources":[],"result_classes":[]},{"action":"b","persistent":')
    canonical = ('{"restricted_sequences":[' + head
                 + 'false,"resources":["z"],"result_classes":[]}]},'
                 + head + 'true,"resources":["a"],"result_classes":[]}]}]}')
    expected = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert CompositionPolicy((first, second)).digest == expected
    assert CompositionPolicy((second, first)).digest == expected


# --- 14. The verifier other implementers port reads the policy as defined ----------


@pytest.mark.parametrize(("path", "value"), [
    (("requestable",), "false"),
    (("steps", 1, "persistent"), "true"),
    (("steps", 0, "resources"), "external:*"),
])
def test_the_vector_verifier_rejects_a_mistyped_policy(path: tuple[object, ...],
                                                       value: object) -> None:
    data = json.loads(ROOT_VECTORS.read_text(encoding="utf-8"))
    sequence = copy.deepcopy(data["scenarios"][0]["policy"]["restricted_sequences"][0])
    target: Any = sequence
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        vv.policy_from_json({"restricted_sequences": [sequence]})


def test_the_vector_verifier_reads_a_step_without_persistent_as_not_persistent() -> None:
    # Vectors README: "A step without the member is not persistent." Every
    # step of the shipped vectors carries the member, so no vector pins the
    # default; a port that read a missing member as true would pass them all.

    step = {"action": "a", "resources": [], "result_classes": []}
    policy = vv.policy_from_json({"restricted_sequences": [
        {"name": "s", "requestable": False, "steps": [step, {**step, "action": "b"}]}]})
    assert [st.persistent for st in policy.sequences[0].steps] == [False, False]


# --- 15. mission_record as an Obligation Type ---------------------------------------


def test_an_approval_is_bound_to_the_adoption_declarations_as_the_pdp_reads_them() -> None:
    # PR #697, Binding: the approval covers the declarations. Support Opt-In
    # and Item Negotiation: an extension the PDP does not implement is a no-op
    # and a type it did not advertise is absent, so neither changes it.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    _staged((pdp, mhs))
    denied = pdp.evaluate(_send())
    assert denied.evaluation_id is not None
    approval = pdp.approve(denied.evaluation_id)["id"]

    def again(extensions: tuple[str, ...], types: tuple[str, ...]) -> EvaluationRequest:
        return EvaluationRequest(
            Subject("agent", "a"), Action("send_message"), Resource("r", "external:x"),
            mission=Mission("m", ISSUER), supported_mandatory_extensions=extensions,
            supported_obligations=types, context={"approval": {"id": approval}})

    d = pdp.evaluate(again(("composition",), ("mission_record",)))   # opt-in withdrawn
    assert (d.decision, d.reason) == (False, REASON_PROHIBITED_COMPOSITION)
    d = pdp.evaluate(again(("obligations", "x-other"), ("mission_record", "notification")))
    assert d.decision and [o.type for o in d.obligations] == ["mission_record"]


@pytest.mark.parametrize("obligations", [
    (Obligation("o1", "mission_record", {"mission": "m", "expected_seq": 1, "x": True}),),
    (Obligation("o1", "mission_record", {"mission": "other", "expected_seq": 1}),),
    (Obligation("o1", "mission_record", {"expected_seq": 1}),),
    (Obligation("o1", "mission_record", {"mission": "m", "expected_seq": "1"}),),
    (Obligation("o1", "mission_record", {"mission": "m", "expected_seq": True}),),
    (Obligation("o1", "mission_record", {"mission": "m", "expected_seq": 0}),),
    (Obligation("o1", "mission_record", {"mission": "m", "expected_seq": 1.0}),),
    # Beyond I-JSON's exact integers: another JSON parser would round it.
    (Obligation("o1", "mission_record", {"mission": "m", "expected_seq": 2**53}),),
    (Obligation("o1", "mission_record", {"mission": "m", "expected_seq": 1}),
     Obligation("o2", "mission_record", {"mission": "m", "expected_seq": 2})),
])
def test_a_mission_record_the_pep_cannot_comply_with_is_a_deny(
        obligations: tuple[Obligation, ...]) -> None:
    class PDP:
        def evaluate(self, request: EvaluationRequest) -> Decision:
            return Decision(decision=True, obligations=obligations)

    mhs = MissionHistoryService()
    ran: list[str] = []
    with pytest.raises(CompositionDenied) as denied:
        ReferencePEP(pdp=PDP(), mhs=mhs, writer_id="pep").enforce(
            mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
            action=Action("read_record"), resource=Resource("r", "hr:1"),
            perform=lambda: ran.append("ran"))
    assert denied.value.reason == "obligation_not_understood"
    assert ran == [] and mhs.history("m") == []


@pytest.mark.parametrize("obligations", [
    [],
    [{"id": "o1", "type": "mission_record"}],
    [{"id": "o1", "type": "mission_record", "properties": []}],
    {"id": "o1"},
])
def test_a_malformed_obligations_member_is_not_a_decision(obligations: Any) -> None:
    with pytest.raises(RemoteUnavailable):
        decision_from_json({"decision": True, "context": {"obligations": obligations}})


# --- 16. HTTP semantics, refusals, an absent Mission, ARAP signals -----------------


def _call(app: Any, method: str, path: str, token: str | None, body: dict[str, Any] | None = None,
          raw_uri: str | None = None) -> tuple[str, dict[str, str], dict[str, Any]]:
    data = json.dumps(body).encode() if body is not None else b""
    env: dict[str, Any] = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "",
                           "wsgi.input": io.BytesIO(data), "CONTENT_LENGTH": str(len(data))}
    if raw_uri is not None:
        env["RAW_URI"] = raw_uri
    if token is not None:
        env["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    got: dict[str, Any] = {}
    out = b"".join(app(env, lambda s, h: got.update(s=s, h=dict(h))))
    return got["s"], got["h"], json.loads(out)


def test_an_authenticated_caller_without_the_role_gets_403_and_no_credential_gets_401() -> None:
    # RFC 9110: 401 is for a missing or invalid credential and carries
    # WWW-Authenticate; an authenticated identity that may not do this gets
    # 403. A PEP can then tell "my credential failed" from "not mine to do".
    mhs = MissionHistoryService(trusted_writers=frozenset({"pep.mail", "pep.hr"}))
    tokens = {**TOKENS, "t-hr": "pep.hr", "t-stranger": "stranger"}
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(tokens), pdps=frozenset({"pdp"}),
                     auditors=frozenset({"auditor"}))
    act = {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"}}
    assert _call(app, "POST", "/missions/m/acts", "t-hr", act)[0] == "201 Created"
    status, headers, _ = _call(app, "GET", "/missions/m/acts", None)
    assert status == "401 Unauthorized" and headers.get("WWW-Authenticate") == "Bearer"
    assert _call(app, "GET", "/missions/m/acts", "t-pep")[0] == "403 Forbidden"
    assert _call(app, "POST", "/missions/m/acts", "t-stranger",
                 {**act, "seq": 2})[0] == "403 Forbidden"
    status, headers, _ = _call(app, "PATCH", "/missions/m/acts/1", "t-pep", {"outcome": "failed"})
    assert status == "403 Forbidden" and "WWW-Authenticate" not in headers


def test_the_http_client_reads_403_as_not_permitted() -> None:
    client = RemoteHistoryAuthority("http://ha.invalid", "t")
    with pytest.raises(NotPermitted):
        client._raise_for(403, {"error": "no"})
    with pytest.raises(UnauthenticatedWriter) as exc:
        client._raise_for(401, {"error": "no"})
    assert not isinstance(exc.value, NotPermitted)
    # A position that holds no Act is told apart from the other outcome
    # conflicts, so that a PEP can recognize the refusal of the failed of an
    # admission it gave up on.
    with pytest.raises(NoActAtPosition):
        client._raise_for(409, {"error": "no act", "reason": "outcome_conflict", "no_act": True})
    for body in ({"error": "set", "reason": "outcome_conflict"},
                 {"error": "set", "reason": "outcome_conflict", "no_act": "yes"}):
        with pytest.raises(OutcomeAlreadySet) as conflict:
            client._raise_for(409, body)
        assert not isinstance(conflict.value, NoActAtPosition)


@pytest.mark.parametrize(("exc", "final"), [
    ("value", True),             # 400: the authority refuses the outcome itself
    ("not_permitted", True),     # 403: another writer's Act, or not trusted
    ("unauthenticated", False),  # 401: the PEP's own credential failed; retry
])
def test_a_permanent_refusal_is_final_and_a_credential_failure_is_retried(exc: str,
                                                                          final: bool) -> None:
    errors = {"value": ValueError("a result class must not contain '*'"),
              "not_permitted": NotPermitted("only 'pep.mail' may set this outcome"),
              "unauthenticated": UnauthenticatedWriter("authentication is required")}

    class _Refusing(MissionHistoryService):
        def set_outcome(self, *args: Any, **kwargs: Any) -> Act:
            raise errors[exc]

    pep = ReferencePEP(pdp=_NeverPDP(), mhs=_Refusing(), writer_id="pep.hr")
    pep.unreported.append(("m", 1, ActOutcome.COMPLETED, frozenset(), None))
    pep.redeliver()
    assert (len(pep.refused), len(pep.unreported)) == ((1, 0) if final else (0, 1))


def test_a_request_without_a_mission_that_could_fill_a_step_is_denied() -> None:
    # Without a Mission the PDP cannot read the history the decision depends
    # on; a PEP that omits it (or a batch item whose own context drops it)
    # must not get a permit for an Act a sequence restricts.
    pdp = CompositionPDP(EXFIL_POLICY, MissionHistoryService())
    no_mission = EvaluationRequest(Subject("agent", "a"), Action("send_message"),
                                   Resource("r", "external:x"))
    denied = pdp.evaluate(no_mission)
    assert not denied.decision and denied.reason == "history_unavailable"
    unrelated = EvaluationRequest(Subject("agent", "a"), Action("list_calendars"),
                                  Resource("r", "cal:1"))
    assert pdp.evaluate(unrelated).decision
    batch = pdp.evaluate_batch((no_mission, unrelated)).evaluations
    assert [d.decision for d in batch] == [False, True]


@pytest.mark.parametrize("reason", ["history_pending", "history_unavailable"])
def test_an_approved_act_that_must_wait_is_told_to_retry(reason: str) -> None:
    # ARAP: on a re-evaluation that presents an approval, the PEP drives its
    # next step from next_action; an unregistered reason falls back to
    # "none", which would abandon a valid approval.

    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint="https://ars.example/requests")
    _staged((pdp, mhs))
    if reason == "history_pending":
        # An open write, admitted before the denial: rule 5 holds the send.
        mhs.admit("m", 3, "write_document", "doc:2", writer="pep")
    denied = pdp.evaluate(_send())
    assert denied.evaluation_id is not None
    approval = pdp.approve(denied.evaluation_id)["id"]
    if reason == "history_unavailable":
        def down(*args: Any, **kwargs: Any) -> list[Act]:
            raise HistoryUnavailable("down")
        mhs.history = down  # type: ignore[method-assign]
    waiting = pdp.evaluate(_send(approval))
    assert not waiting.decision and waiting.reason == reason
    assert waiting.context.get("next_action") == "retry"
    # Without an approval the same denial carries no ARAP signal.
    assert "next_action" not in pdp.evaluate(_send()).context


def test_requestable_denials_need_an_access_request_endpoint() -> None:
    # ARAP: a PDP "MUST NOT include context.access_request unless ... an
    # Access Request Endpoint is available", and one that supports ARAP
    # publishes it, as an HTTPS URI, with the capability URN.
    mhs = MissionHistoryService()
    plain = CompositionPDP(EXFIL_POLICY, mhs)
    _staged((plain, mhs))
    denied = plain.evaluate(_send())
    assert not denied.decision and denied.reason == REASON_PROHIBITED_COMPOSITION
    assert denied.access_request is None and denied.evaluation_id is None
    assert "access_request_endpoint" not in plain.metadata()
    url = "https://ars.example/requests"
    arap = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=url)
    assert arap.evaluate(_send()).access_request is not None
    meta = arap.metadata()
    assert meta["access_request_endpoint"] == url
    assert "urn:openid:authzen:capability:access-request" in meta["capabilities"]
    with pytest.raises(ValueError):
        CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint="http://ars.example/requests")


@pytest.mark.parametrize("target", ["/missions/a%zz/acts", "/missions/a%2/acts",
                                    "/missions/%/acts"])
def test_a_malformed_escape_in_the_mission_id_is_a_400(target: str) -> None:
    # Otherwise "a%zz" and "a%25zz" would address the same Mission.
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator(TOKENS),
                     pdps=frozenset({"pdp"}), auditors=frozenset({"auditor"}))
    assert _call(app, "GET", "/missions/x/acts", "t-audit",
                 raw_uri=target)[0] == "400 Bad Request"


def test_the_vector_verifier_rejects_a_string_where_a_list_of_names_is_expected() -> None:
    # tuple("obligations") would read as the extensions o, b, l, ...

    with pytest.raises(ValueError):
        vv._names("obligations", "supported_mandatory_extensions")
    assert vv._names(["obligations"], "supported_mandatory_extensions") == ("obligations",)


def test_a_pep_that_gives_up_on_an_unacknowledged_admission_resolves_it() -> None:
    # Rule 3: no acknowledgement, no effect. If the admission did commit and
    # only the acknowledgement was lost, the Act is admitted and will never
    # run; left open, it would hold back its sequences until an operator
    # closed it. The PEP that gives up records it failed, which it can
    # truthfully assert because it never acted.

    class _LosesAcks(MissionHistoryService):
        def admit(self, *args: Any, **kwargs: Any) -> Act:
            super().admit(*args, **kwargs)  # commits (idempotent on retry)
            raise ConnectionError("acknowledgement lost")

    mhs = _LosesAcks()
    pdp = CompositionPDP(EXFIL_POLICY, mhs)
    pep = ReferencePEP(pdp=pdp, mhs=mhs, writer_id="pep.hr")
    ran: list[str] = []
    with pytest.raises(CompositionDenied):
        pep.enforce(mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
                    action=Action("read_record"), resource=Resource("r", "hr:1"),
                    perform=lambda: ran.append("ran"))
    assert ran == []
    pep.redeliver()
    assert [(a.seq, a.outcome) for a in mhs.history("m")] == [(1, ActOutcome.FAILED)]


@pytest.mark.parametrize("raw_uri", ["/missions/msn-caf\u00c3\u00a9/acts",
                                     "/missions/msn-caf\u00e9/acts"])
def test_a_raw_target_with_a_non_ascii_character_is_refused(raw_uri: str) -> None:
    # RFC 3986: a request target is ASCII, every other octet percent-encoded.
    # Read raw, UTF-8 bytes would name another Mission than the same id
    # percent-encoded, and one Mission would have two histories.
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    act = {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"}}
    status, _, _ = _call(app, "POST", "/missions/x/acts", "t-pep", act, raw_uri=raw_uri)
    assert status == "400 Bad Request"
    status, _, _ = _call(app, "POST", "/missions/x/acts", "t-pep", act,
                         raw_uri="/missions/msn-caf%C3%A9/acts")
    assert status == "201 Created"
    assert mhs.next_seq("msn-caf\u00e9") == 2


def test_a_body_nested_too_deeply_is_a_400_not_a_server_error() -> None:
    # A request is answered with a decision or a 400, never a 500: deep
    # nesting accepted by the parser must not overflow later processing.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    app = PDPHttpApp(pdp, StaticTokenAuthenticator({"t": "pep"}),
                     StaticTokenAuthenticator({}))
    deep: Any = "x"
    for _ in range(200):
        deep = {"k": deep}
    body = {"subject": {"type": "agent", "id": "a", "properties": {"p": deep}},
            "action": {"name": "send_message"},
            "resource": {"type": "r", "id": "external:x"},
            "context": {"mission": {"id": "m", "issuer": ISSUER}}}
    status, _, answer = _call(app, "POST", "/access/v1/evaluation", "t", body)
    assert status == "400 Bad Request", (status, answer)
    shallow = {**body, "subject": {"type": "agent", "id": "a", "properties": {"p": {"k": "x"}}}}
    assert _call(app, "POST", "/access/v1/evaluation", "t", shallow)[0] == "200 OK"


@pytest.mark.parametrize("container", ["object", "array"])
def test_the_nesting_limit_counts_objects_and_arrays_and_allows_exactly_64(
        container: str) -> None:
    # Binding: a body is nested at most 64 levels deep, counting each object
    # and array on the deepest path, the body itself included.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    app = PDPHttpApp(pdp, StaticTokenAuthenticator({"t": "pep"}),
                     StaticTokenAuthenticator({}))

    def body(levels: int) -> dict[str, Any]:
        # The body, subject and properties are three levels.
        value: Any = "x"
        for _ in range(levels - 3):
            value = {"k": value} if container == "object" else [value]
        return {"subject": {"type": "agent", "id": "a", "properties": {"p": value}},
                "action": {"name": "send_message"},
                "resource": {"type": "r", "id": "external:x"},
                "context": {"mission": {"id": "m", "issuer": ISSUER}}}

    assert _call(app, "POST", "/access/v1/evaluation", "t", body(64))[0] == "200 OK"
    assert _call(app, "POST", "/access/v1/evaluation", "t", body(65))[0] == "400 Bad Request"


def test_the_largest_expected_seq_is_understood() -> None:
    # Obligation: `expected_seq` is an integer from 1 to 2^53 - 1. The largest
    # is understood, and the PEP tries to admit there; the authority refuses,
    # since the Mission is empty, and nothing runs.
    top = 2**53 - 1

    class PDP:
        def evaluate(self, request: EvaluationRequest) -> Decision:
            return Decision(decision=True, obligations=(
                Obligation("o1", "mission_record", {"mission": "m", "expected_seq": top}),))

    mhs = MissionHistoryService()
    tried: list[int] = []

    class Recording:
        def admit(self, **kw: Any) -> Any:
            tried.append(kw["seq"])
            return mhs.admit(**kw)

        def set_outcome(self, *a: Any, **kw: Any) -> Any:
            return mhs.set_outcome(*a, **kw)

        def history(self, *a: Any, **kw: Any) -> Any:
            return mhs.history(*a, **kw)

    ran: list[str] = []
    with pytest.raises(CompositionDenied) as denied:
        ReferencePEP(pdp=PDP(), mhs=Recording(), writer_id="pep").enforce(  # type: ignore[arg-type]
            mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
            action=Action("read_record"), resource=Resource("r", "hr:1"),
            perform=lambda: ran.append("ran"))
    assert denied.value.reason != "obligation_not_understood"
    assert tried and set(tried) == {top}
    assert ran == [] and mhs.history("m") == []


def test_a_body_framed_by_transfer_encoding_is_refused() -> None:
    # Binding: a body is framed by Content-Length alone. With Transfer-Encoding
    # as well, a proxy in front and the service could disagree on where the
    # request ends, and read different requests from the same bytes.
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator(TOKENS), pdps=frozenset({"pdp"}))
    data = json.dumps({"seq": 1, "action": {"name": "read_record"},
                       "resource": {"id": "hr:1"}}).encode()
    env: dict[str, Any] = {
        "REQUEST_METHOD": "POST", "PATH_INFO": "/missions/m/acts", "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(data), "CONTENT_LENGTH": str(len(data)),
        "HTTP_TRANSFER_ENCODING": "chunked", "HTTP_AUTHORIZATION": "Bearer t-pep"}
    got: dict[str, Any] = {}
    b"".join(app(env, lambda s, h: got.update(s=s)))
    assert got["s"] == "400 Bad Request"
    assert mhs.next_seq("m") == 1


def test_an_approved_act_refused_for_its_policy_digest_is_told_when_to_retry() -> None:
    # Profile, PDP rules: with `policy_mismatch` the PDP SHOULD include
    # `retry_after`, since the same PDP would answer the same way. ARAP: an
    # integer number of seconds, RECOMMENDED with `next_action` `retry`.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint="https://ars.example/requests")
    _staged((pdp, mhs))
    denied = pdp.evaluate(_send())
    assert denied.evaluation_id is not None
    approval = pdp.approve(denied.evaluation_id)["id"]
    other = CompositionPolicy((RestrictedSequence("other", (
        SequenceStep("read_record"), SequenceStep("upload_file"))),))
    refused = CompositionPDP(other, mhs).evaluate(_send(approval))
    assert (refused.decision, refused.reason) == (False, "policy_mismatch")
    assert refused.context.get("next_action") == "retry"
    after = refused.context.get("retry_after")
    assert isinstance(after, int) and not isinstance(after, bool) and after > 0


def test_a_pep_that_did_not_adopt_mission_record_gets_no_requestable_denial() -> None:
    # Profile, Predicate: no approval can lead to a permit for an Act that
    # needs mission_record when the PEP did not adopt it, so the denial is not
    # requestable. ARAP: a PDP MAY include context.access_request only "when
    # the denied access is eligible for approval".
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    _staged((pdp, mhs))
    plain = EvaluationRequest(
        Subject("agent", "a"), Action("send_message"), Resource("r", "external:x"),
        mission=Mission("m", ISSUER))
    denied = pdp.evaluate(plain)
    assert (denied.decision, denied.reason) == (False, "prohibited_composition")
    assert denied.access_request is None and denied.evaluation_id is None
    assert pdp.evaluate(_send()).access_request is not None


def test_an_approved_request_without_a_mission_is_told_to_stop() -> None:
    # Profile, PDP rules: waiting cannot give a request a Mission, so with an
    # approval present the denial carries next_action "none", not "retry".
    mhs = MissionHistoryService()
    pdp = CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS)
    _staged((pdp, mhs))
    denied = pdp.evaluate(_send())
    assert denied.evaluation_id is not None
    approval = pdp.approve(denied.evaluation_id)["id"]
    missionless = EvaluationRequest(
        Subject("agent", "a"), Action("send_message"), Resource("r", "external:x"),
        supported_mandatory_extensions=("obligations",), supported_obligations=("mission_record",),
        context={"approval": {"id": approval}})
    answer = pdp.evaluate(missionless)
    assert (answer.decision, answer.reason) == (False, "history_unavailable")
    assert answer.context.get("next_action") == "none"
