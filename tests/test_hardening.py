"""Attacks and edge cases, one test each, named after what it blocks."""

from __future__ import annotations

import io
import json
import threading
from datetime import UTC, datetime, timedelta

import pytest

from authzen_composition.http_binding import (
    MAX_BODY_BYTES,
    MHSHttpApp,
    StaticTokenAuthenticator,
)
from authzen_composition.mhs import (
    HistoryConflict,
    MissionHistoryService,
    OutcomeAlreadySet,
    UnauthenticatedWriter,
    UnknownAct,
)
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
    Action,
    Decision,
    EvaluationRequest,
    Mission,
    Obligation,
    Resource,
    Subject,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
EXFIL = RestrictedSequence(
    "exfil", (SequenceStep("read", result_classes=frozenset({"pd.*"})), SequenceStep("send"))
)
# A second sequence that makes "public" a class the policy recognizes.
OTHER = RestrictedSequence(
    "other", (SequenceStep("read", result_classes=frozenset({"public"})), SequenceStep("delete"))
)
POLICY = CompositionPolicy((EXFIL, OTHER))


def _read(classes: set[str]) -> Act:
    return Act(1, "read", "r", ActOutcome.COMPLETED, frozenset(classes))


def test_known_class_does_not_launder_an_unknown_one() -> None:
    # Attack: a classifier tags a salary record {"public", "medical.x"}. The
    # unknown class is the top; "public" being recognized must not hide it.
    d = POLICY.completes([_read({"public", "medical.x"})], Act(2, "send", "r"))
    assert d.satisfied is False and d.completed == ("exfil",)


def test_only_known_classes_are_matched_as_recorded() -> None:
    assert POLICY.completes([_read({"public"})], Act(2, "send", "r")).satisfied is True


def test_only_unknown_classes_are_the_top() -> None:
    assert POLICY.completes([_read({"medical.x"})], Act(2, "send", "r")).satisfied is False


def test_an_action_named_star_is_not_a_wildcard() -> None:
    # Attack: an act whose action or resource is literally "*" must not
    # match every step. The top applies to result classes only.
    seq = RestrictedSequence("s", (SequenceStep("read"), SequenceStep("send",
                                   resources=frozenset({"ext:*"}))))
    policy = CompositionPolicy((seq,))
    star = Act(1, "*", "*", ActOutcome.COMPLETED)
    assert policy.completes([star], Act(2, "send", "ext:x")).satisfied is True
    assert policy.completes([Act(1, "read", "r", ActOutcome.COMPLETED)],
                            Act(2, "send", "*")).satisfied is True
    assert policy.extendable_sequences(Act(1, "*", "*")) == frozenset()


# --- HTTP binding: every malformed input is a clean 400, never a crash -------


GOOD = {"seq": 1, "action": {"name": "read"}, "resource": {"id": "r"}}


def _http(method: str, path: str, raw: bytes, length: str | None = "auto",
          app: MHSHttpApp | None = None) -> tuple[str, dict]:
    app = app or MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}))
    env = {"REQUEST_METHOD": method, "PATH_INFO": path, "wsgi.input": io.BytesIO(raw),
           "HTTP_AUTHORIZATION": "Bearer t"}
    if length == "auto":
        env["CONTENT_LENGTH"] = str(len(raw))
    elif length is not None:
        env["CONTENT_LENGTH"] = length
    got: dict = {}
    out = b"".join(app(env, lambda s, h: got.update(s=s)))
    return got["s"], json.loads(out)


def _j(v: object) -> bytes:
    return json.dumps(v).encode()


@pytest.mark.parametrize(("raw", "length", "error"), [
    (_j({**GOOD, "seq": None}), "auto", "seq must be a positive integer"),
    (_j({**GOOD, "seq": True}), "auto", "seq must be a positive integer"),
    (_j({**GOOD, "seq": 1.0}), "auto", "seq must be a positive integer"),
    (_j({**GOOD, "seq": "1"}), "auto", "seq must be a positive integer"),
    (_j({**GOOD, "seq": 0}), "auto", "seq must be a positive integer"),
    (_j({**GOOD, "action": "read"}), "auto", "action must be an object"),
    (_j({**GOOD, "action": {"name": ""}}), "auto", "action.name must be a non-empty string"),
    (_j({**GOOD, "action": {"name": {"x": 1}}}), "auto",
     "action.name must be a non-empty string"),
    (_j({**GOOD, "resource": []}), "auto", "resource must be an object"),
    (_j({**GOOD, "admission_id": 7}), "auto", "admission_id must be a non-empty string"),
    (b'{"seq": 1, "seq": 2}', "auto", "duplicate member 'seq'"),
    (b'{"seq": NaN}', "auto", "NaN is not valid JSON"),
    (b'{"seq": Infinity}', "auto", "Infinity is not valid JSON"),
    (b"[" * 100_000, "auto", "body too large"),
    (b"[" * 60_000, "auto", "body nested too deeply"),
    # Nesting is checked before parsing, so the answer does not depend on how
    # deep the platform's JSON parser can recurse.
    (b"[" * 65, "auto", "body nested too deeply"),
    (b"[1]", "auto", "body must be a JSON object"),
    (b"", "auto", "body must be a JSON object"),
    (_j(GOOD), "-1", "invalid Content-Length"),
    (_j(GOOD), " 3", "invalid Content-Length"),
    (_j(GOOD), "\u0663", "invalid Content-Length"),
    (_j(GOOD), "999", "body shorter than Content-Length"),
    (_j(GOOD), None, "body must be a JSON object"),
], ids=lambda v: v[:40].decode("latin-1") if isinstance(v, bytes) else str(v)[:40])
def test_malformed_admission_is_a_clean_400(raw: bytes, length: str | None, error: str) -> None:
    status, body = _http("POST", "/missions/m/acts", raw, length)
    assert (status, body) == ("400 Bad Request", {"error": error})


def test_body_size_limit_is_64_kib() -> None:
    assert MAX_BODY_BYTES == 64 * 1024
    pad = _j({**GOOD, "pad": "x" * (MAX_BODY_BYTES - len(_j(GOOD)) - 11)})
    assert len(pad) == MAX_BODY_BYTES
    assert _http("POST", "/missions/m/acts", pad)[0] == "201 Created"


@pytest.mark.parametrize(("seg", "body", "error"), [
    ("01", {"outcome": "completed"}, "act position must be a positive decimal integer"),
    ("+1", {"outcome": "completed"}, "act position must be a positive decimal integer"),
    ("\u0661", {"outcome": "completed"}, "act position must be a positive decimal integer"),
    ("0", {"outcome": "completed"}, "act position must be a positive decimal integer"),
    ("9" * 19, {"outcome": "completed"}, "act position must be a positive decimal integer"),
    ("1", {"outcome": ["x"]}, "outcome must be a non-empty string"),
    ("1", {"outcome": "done"}, "outcome must be 'completed' or 'failed'"),
    ("1", {"outcome": "completed", "result_classes": 5},
     "result_classes must be an array of strings"),
    ("1", {"outcome": "completed", "result_classes": "abc"},
     "result_classes must be an array of strings"),
    ("1", {"outcome": "completed", "result_classes": [1]},
     "result_classes[] must be a non-empty string"),
])
def test_malformed_outcome_is_a_clean_400(seg: str, body: dict, error: str) -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}),
                     auditors=frozenset({"pep.a"}))
    assert _http("POST", "/missions/m/acts", _j(GOOD), app=app)[0] == "201 Created"
    status, out = _http("PATCH", f"/missions/m/acts/{seg}", _j(body), app=app)
    assert (status, out) == ("400 Bad Request", {"error": error})
    # Nothing changed: the act is still open.
    assert _http("GET", "/missions/m/acts", b"", app=app)[1]["acts"][0]["outcome"] == "open"


def test_admission_id_and_null_classes_are_accepted() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}))
    a = _http("POST", "/missions/m/acts", _j({**GOOD, "admission_id": "x1"}), app=app)
    b = _http("POST", "/missions/m/acts", _j({**GOOD, "admission_id": "x1"}), app=app)
    assert a == b and a[0] == "201 Created"
    s, out = _http("PATCH", "/missions/m/acts/1",
                   _j({"outcome": "completed", "result_classes": None,
                       "admission_id": "x1"}), app=app)
    assert (s, out["result_classes"]) == ("200 OK", [])


def test_missing_wsgi_input_is_a_clean_400() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}))
    env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/missions/m/acts", "CONTENT_LENGTH": "2",
           "HTTP_AUTHORIZATION": "Bearer t"}
    got: dict = {}
    out = json.loads(b"".join(app(env, lambda s, h: got.update(s=s))))
    assert got["s"] == "400 Bad Request" and set(out) == {"error"}


# --- Approval and admission-retry integrity ----------------------------------


REQ_SEQ = RestrictedSequence(
    "exfil", (SequenceStep("read", result_classes=frozenset({"pd.*"})), SequenceStep("send")),
    requestable=True,
)


def _send_req(approval: dict | None = None) -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject("agent", "a"), action=Action("send"), resource=Resource("r", "x"),
        mission=Mission("m", "iss"), supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",),
        context={"approval": approval} if approval else {},
    )


def _approved_send_pdp() -> tuple[CompositionPDP, MissionHistoryService, dict]:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((REQ_SEQ,)), mhs, access_request_endpoint=ARS)
    mhs.admit("m", 1, "read", "hr", writer="w")
    mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                    result_classes=frozenset({"pd.salary"}))
    denied = pdp.evaluate(_send_req())
    assert denied.reason == "prohibited_composition" and denied.evaluation_id
    return pdp, mhs, pdp.approve(denied.evaluation_id)


def test_a_denial_after_the_approval_check_does_not_burn_the_approval() -> None:
    # An approval spent as soon as it is checked would be thrown away by a
    # later plain deny (here: the PEP forgot to opt in).
    pdp, _, rid = _approved_send_pdp()
    no_opt_in = EvaluationRequest(
        subject=Subject("agent", "a"), action=Action("send"), resource=Resource("r", "x"),
        mission=Mission("m", "iss"), context={"approval": rid},
    )
    assert pdp.evaluate(no_opt_in).decision is False
    assert pdp.evaluate(_send_req(rid)).decision is True
    # Single use: the permit spent it.
    assert pdp.evaluate(_send_req(rid)).reason == "prohibited_composition"


def test_an_approval_cannot_be_spent_twice_concurrently() -> None:
    for _ in range(50):
        pdp, _, rid = _approved_send_pdp()
        barrier = threading.Barrier(8)
        results: list[bool] = []

        def go(pdp: CompositionPDP = pdp, rid: dict = rid,
               barrier: threading.Barrier = barrier, results: list[bool] = results) -> None:
            barrier.wait()
            results.append(pdp.evaluate(_send_req(rid)).decision)

        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count(True) == 1


def test_an_approval_is_consumed_only_once() -> None:
    pdp, _, rid = _approved_send_pdp()
    assert pdp._approved(_send_req(rid), _cand(), ("exfil",)) == rid["id"]
    assert pdp._consume(rid["id"]) is True
    assert pdp._consume(rid["id"]) is False


def test_permit_is_withdrawn_if_the_approval_was_spent_in_between() -> None:
    pdp, _, rid = _approved_send_pdp()
    real = pdp._consume

    def spent_first(request_id: str) -> bool:
        assert real(request_id) is True  # a concurrent evaluation got there first
        return real(request_id)

    pdp._consume = spent_first  # type: ignore[method-assign]
    d = pdp.evaluate(_send_req(rid))
    assert (d.decision, d.reason) == (False, "prohibited_composition")


def _cand() -> Act:
    return Act(2, "send", "x", ActOutcome.OPEN)


def test_admission_id_reuse_for_a_different_act_is_a_conflict() -> None:
    mhs = MissionHistoryService()
    first = mhs.admit("m", 1, "read", "hr:1", writer="w", admission_id="a1")
    assert mhs.admit("m", 1, "read", "hr:1", writer="w", admission_id="a1") == first
    for action, resource, seq in [("send", "hr:1", 1), ("read", "hr:2", 1), ("read", "hr:1", 2)]:
        try:
            mhs.admit("m", seq, action, resource, writer="w", admission_id="a1")
        except HistoryConflict:
            continue
        raise AssertionError(f"reused admission_id accepted for {(action, resource, seq)}")
    assert len(mhs.history("m")) == 1


# --- Error messages, result-class validation and immutability ---------------


def test_mhs_error_messages() -> None:
    mhs = MissionHistoryService(trusted_writers=frozenset({"w", "v"}))
    cases = [
        (lambda: mhs.admit("m", 1, "a", "r", writer=""), UnauthenticatedWriter,
         "writer identity is required"),
        (lambda: mhs.admit("m", 1, "a", "r", writer="x"), UnauthenticatedWriter,
         "writer 'x' is not trusted"),
        (lambda: mhs.admit("m", 2, "a", "r", writer="w"), HistoryConflict,
         "mission m: seq 2 is not the next position"),
    ]
    for call, exc, msg in cases:
        with pytest.raises(exc) as e:
            call()
        assert str(e.value) == msg
    mhs.admit("m", 1, "a", "r", writer="w", admission_id="k")
    more = [
        (lambda: mhs.admit("m", 2, "b", "r", writer="w", admission_id="k"), HistoryConflict,
         "mission m: admission_id already used for a different act"),
        (lambda: mhs.set_outcome("m", 1, ActOutcome.OPEN, writer="w"), OutcomeAlreadySet,
         "cannot set an outcome back to open"),
        (lambda: mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w",
                                 result_classes=frozenset({"x"})), ValueError,
         "a failed outcome carries no result classes"),
        (lambda: mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                                 result_classes=frozenset({"pd.*"})), ValueError,
         "a result class must not contain '*'"),
        (lambda: mhs.set_outcome("m", 9, ActOutcome.COMPLETED, writer="w"), UnknownAct,
         "mission m: no act at seq 9"),
        (lambda: mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="v", admission_id="k"),
         UnauthenticatedWriter,
         "mission m seq 1: only the writer that admitted this act may set its outcome"),
        # Another writer that names no admission of the Act learns only that.
        (lambda: mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="v"),
         UnknownAct, "mission m seq 1: no act of this admission"),
        (lambda: mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                                 admission_id="other"),
         UnknownAct, "mission m seq 1: no act of this admission"),
        (lambda: mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w"),
         UnknownAct, "mission m seq 1: no act of this admission"),
        (lambda: mhs.recorded_by("m", 9), UnknownAct, "mission m: no act at seq 9"),
    ]
    for call, exc, msg in more:
        with pytest.raises(exc) as e:
            call()
        assert str(e.value) == msg
    mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w", admission_id="k")
    with pytest.raises(OutcomeAlreadySet) as e:
        mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w", admission_id="k")
    assert str(e.value) == "mission m seq 1: outcome already set"
    with pytest.raises(ValueError, match="^a restricted sequence needs at least two steps$"):
        RestrictedSequence("s", (SequenceStep("a"),))


def test_unauthenticated_outcome_learns_nothing_about_the_act() -> None:
    # Authentication comes before any lookup, so an unauthenticated caller
    # cannot probe which positions exist.
    mhs = MissionHistoryService()
    for seq in (1, 99):
        with pytest.raises(UnauthenticatedWriter, match="writer identity is required"):
            mhs.set_outcome("m", seq, ActOutcome.COMPLETED, writer="")


def test_star_in_a_result_class_is_rejected_by_the_authority() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "read", "r", writer="w")
    for bad in ("*", "pd.*", "a*b"):
        with pytest.raises(ValueError):
            mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                            result_classes=frozenset({bad}))
    assert mhs.history("m")[0].outcome is ActOutcome.OPEN


def test_reference_defaults_and_repr() -> None:
    pdp, _, rid = _approved_send_pdp()
    assert pdp.request_ttl == timedelta(minutes=15)
    # Approval ids are lookup handles into server state: keep them out of
    # repr and logs. The clock and lock are not part of the value either.
    text = repr(pdp)
    eval_ids = list(pdp._pending)
    assert rid["id"] not in text and "lock" not in text.lower() and "lambda" not in text
    assert eval_ids and not any(e in text for e in eval_ids)
    assert rid["id"].startswith("apr_") and eval_ids[0].startswith("eval_")
    ob = pdp.evaluate(_send_req(rid)).obligations[0]
    assert ob.id == "obl-mission-record"
    assert pdp._pending == {} and pdp._approvals == {}


def test_approval_expiry_and_pruning_boundaries() -> None:
    t0 = datetime(2030, 1, 1, tzinfo=UTC)
    now = [t0]
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((REQ_SEQ,)), mhs, clock=lambda: now[0],
                         request_ttl=timedelta(seconds=10), approval_ttl=timedelta(seconds=10),
                         access_request_endpoint=ARS)
    mhs.admit("m", 1, "read", "hr", writer="w")
    mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                    result_classes=frozenset({"pd.salary"}))
    first = pdp.evaluate(_send_req())
    assert first.access_request == {"expires_at": "2030-01-01T00:00:10Z"}
    assert first.evaluation_id is not None
    now[0] = t0 + timedelta(seconds=4)
    apr = pdp.approve(first.evaluation_id)
    # The approval's own lifetime, counted from the decision.
    assert apr["approved_until"] == "2030-01-01T00:00:14Z"
    now[0] = t0 + timedelta(seconds=14)  # exactly at expiry: no longer valid
    assert pdp.evaluate(_send_req(apr)).decision is False
    # That denial created a fresh request and pruned the spent one and its
    # approval, at the exact boundary (expiry is inclusive).
    assert first.evaluation_id not in pdp._pending and apr["id"] not in pdp._approvals
    second = pdp.evaluate(_send_req())
    assert second.evaluation_id is not None
    # The request window is inclusive too: at its end it can no longer be approved.
    now[0] = t0 + timedelta(seconds=24)
    with pytest.raises(KeyError):
        pdp.approve(second.evaluation_id)
    now[0] = t0 + timedelta(seconds=23)
    apr2 = pdp.approve(second.evaluation_id)
    now[0] = t0 + timedelta(seconds=32)  # one second before its expiry
    assert pdp.evaluate(_send_req(apr2)).decision is True


def test_pep_gives_up_after_five_conflicts_by_default() -> None:
    attempts: list[int] = []

    class AlwaysConflict(MissionHistoryService):
        def admit(self, *args, **kwargs):  # type: ignore[override]
            attempts.append(1)
            raise HistoryConflict("lost the race")

    mhs = AlwaysConflict()
    pep = ReferencePEP(CompositionPDP(CompositionPolicy((REQ_SEQ,)), mhs,
                                      access_request_endpoint=ARS), mhs, "pep")
    ran: list[int] = []
    with pytest.raises(CompositionDenied) as e:
        pep.enforce(mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
                    action=Action("read"), resource=Resource("r", "hr"),
                    perform=lambda: ran.append(1))
    assert e.value.reason == "too_many_conflicts"
    assert len(attempts) == 5 and ran == []


def test_static_authenticator_returns_empty_string_when_unauthenticated() -> None:
    auth = StaticTokenAuthenticator({"t": "pep.a"})
    assert auth({}) == ""
    assert auth({"HTTP_AUTHORIZATION": "Bearer nope"}) == ""
    assert auth({"HTTP_AUTHORIZATION": "Basic t"}) == ""
    assert auth({"HTTP_AUTHORIZATION": "Bearer t"}) == "pep.a"


def test_missing_request_method_is_treated_as_get() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}),
                     auditors=frozenset({"pep.a"}))
    got: dict = {}
    out = b"".join(app({"PATH_INFO": "/missions/m/acts", "HTTP_AUTHORIZATION": "Bearer t"},
                       lambda s, h: got.update(s=s)))
    assert (got["s"], json.loads(out)) == ("200 OK", {"acts": [], "next_seq": 1})


def test_exact_error_bodies() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}))
    assert _http("GET", "/nope", b"", app=app) == ("404 Not Found", {"error": "unknown route"})
    env = {"REQUEST_METHOD": "GET", "PATH_INFO": "/missions/m/acts"}
    got: dict = {}
    out = json.loads(b"".join(app(env, lambda s, h: got.update(s=s))))
    assert (got["s"], out) == ("401 Unauthorized", {"error": "authentication is required"})
    assert _http("PATCH", "/missions/m/acts/3", _j({"outcome": "completed"}), app=app) == (
        "409 Conflict", {"error": "mission m: no act at seq 3", "reason": "outcome_conflict",
                         "no_act": True})
    _http("POST", "/missions/m/acts", _j(GOOD), app=app)
    _http("PATCH", "/missions/m/acts/1", _j({"outcome": "completed"}), app=app)
    assert _http("PATCH", "/missions/m/acts/1", _j({"outcome": "failed"}), app=app) == (
        "409 Conflict", {"error": "mission m seq 1: outcome already set",
                         "reason": "outcome_conflict"})
    assert _http("POST", "/missions/m/acts", _j(GOOD), app=app) == (
        "409 Conflict",
        {"error": "mission m: seq 1 is not the next position", "reason": "seq_conflict"})


# --- Wire form, ARAP shapes, routing, auth ordering --------------------------


ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint


def test_decision_wire_form_puts_every_member_in_context() -> None:
    d = Decision(decision=False, reason="prohibited_composition",
                 access_request={"expires_at": "2030-01-01T00:00:10+00:00"},
                 evaluation_id="eval_1")
    assert d.to_json() == {"decision": False, "context": {
        "reason": "prohibited_composition", "evaluation_id": "eval_1",
        "access_request": {"expires_at": "2030-01-01T00:00:10+00:00"}}}
    p = Decision(decision=True, obligations=(Obligation("obl-1", "mission_record",
                                                        {"mission": "m", "expected_seq": 3}),))
    assert p.to_json() == {"decision": True, "context": {"obligations": [
        {"id": "obl-1", "type": "mission_record",
         "properties": {"mission": "m", "expected_seq": 3}}]}}
    assert Decision(decision=True).to_json() == {"decision": True}
    assert Decision(decision=False, context={"x": 1}).to_json() == {
        "decision": False, "context": {"x": 1}}


def test_requestable_denial_has_the_arap_shape() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((REQ_SEQ,)), mhs, access_request_endpoint=ARS)
    mhs.admit("m", 1, "read", "hr", writer="w")
    mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                    result_classes=frozenset({"pd.salary"}))
    ctx = pdp.evaluate(_send_req()).to_json()["context"]
    assert set(ctx) == {"reason", "evaluation_id", "access_request"}
    assert set(ctx["access_request"]) == {"expires_at"}
    datetime.fromisoformat(ctx["access_request"]["expires_at"])
    apr = pdp.approve(ctx["evaluation_id"])
    assert set(apr) == {"id", "approved_until"}
    # RFC 3339 in UTC, the approval's own lifetime after the decision.
    until = datetime.fromisoformat(apr["approved_until"])
    assert apr["approved_until"].endswith("Z") and until > datetime.now(UTC)


def test_only_approval_id_is_trusted_from_the_request() -> None:
    # ARAP: values outside trusted state are not authoritative. A forged
    # approved_until, or an evaluation id presented as an approval, is ignored.
    pdp, _, apr = _approved_send_pdp()
    assert pdp.evaluate(_send_req({"id": apr["id"], "approved_until": "2999-01-01T00:00:00Z"})
                        ).decision is True
    pdp2, _, apr2 = _approved_send_pdp()
    eval_id = next(iter(pdp2._pending))
    for forged in ({"id": eval_id}, {"approved_until": apr2["approved_until"]},
                   {"id": apr2["id"].upper()}, {"id": 7}):
        assert pdp2.evaluate(_send_req(forged)).decision is False
    assert pdp2.evaluate(_send_req(apr2)).decision is True


def test_one_pdps_approval_is_unknown_to_another() -> None:
    pdp_a, mhs, apr = _approved_send_pdp()
    pdp_b = CompositionPDP(CompositionPolicy((REQ_SEQ,)), mhs, access_request_endpoint=ARS)
    assert pdp_b.evaluate(_send_req(apr)).decision is False


@pytest.mark.parametrize("path", [
    "/missions/m/acts/1/extra", "/missions/m/acts/1/a/b", "/x/m/acts", "/missions/m/x",
    "/missions/m", "/",
])
@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "DELETE"])
def test_unknown_paths_are_404_for_every_method(path: str, method: str) -> None:
    assert _http(method, path, _j(GOOD)) == ("404 Not Found", {"error": "unknown route"})


@pytest.mark.parametrize(("path", "method"), [
    ("/missions/m/acts", "DELETE"), ("/missions/m/acts", "PATCH"),
    ("/missions/m/acts/1", "GET"), ("/missions/m/acts/1", "POST"),
])
def test_wrong_method_on_a_known_path_is_405(path: str, method: str) -> None:
    status, body = _http(method, path, _j(GOOD))
    assert status == "405 Method Not Allowed"
    assert body == {"error": f"{method} not allowed on {path}"}


def test_unauthenticated_malformed_outcome_is_401_not_400() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "read", "r", writer="w")
    for outcome, classes in ((ActOutcome.FAILED, {"x"}), (ActOutcome.COMPLETED, {"a*"}),
                             (ActOutcome.OPEN, set())):
        with pytest.raises(UnauthenticatedWriter):
            mhs.set_outcome("m", 1, outcome, writer="", result_classes=frozenset(classes))


@pytest.mark.parametrize(("method", "path", "raw"), [
    ("POST", "/missions/m/acts", b"not json"),
    ("POST", "/missions/m/acts", _j({"seq": "x"})),
    ("POST", "/missions/m/acts", _j(GOOD)),
    ("PATCH", "/missions/m/acts/1", b"{"),
    ("PATCH", "/missions/m/acts/01", _j({"outcome": "completed"})),
    ("PATCH", "/missions/m/acts/1", _j({"outcome": "completed"})),
    ("GET", "/missions/m/acts", b""),
])
def test_unauthenticated_http_caller_gets_401_whatever_the_body(
        method: str, path: str, raw: bytes) -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}))
    env = {"REQUEST_METHOD": method, "PATH_INFO": path, "wsgi.input": io.BytesIO(raw),
           "CONTENT_LENGTH": str(len(raw)), "HTTP_AUTHORIZATION": "Bearer wrong"}
    got: dict = {}
    out = json.loads(b"".join(app(env, lambda s, h: got.update(s=s))))
    assert (got["s"], out) == ("401 Unauthorized", {"error": "authentication is required"})


# --- Approval cannot cover a sequence policy does not allow to be approved ----

HARD = RestrictedSequence(  # not requestable: a person may never approve it
    "hard", (SequenceStep("read", result_classes=frozenset({"pd.*"})),
             SequenceStep("send", resources=frozenset({"x"}))),
)


def _overlap_pdp(policy: CompositionPolicy) -> tuple[CompositionPDP, MissionHistoryService]:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy, mhs, access_request_endpoint=ARS)
    mhs.admit("m", 1, "read", "hr", writer="w")
    mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                    result_classes=frozenset({"pd.salary"}))
    return pdp, mhs


def test_denial_completing_a_non_requestable_sequence_is_not_requestable() -> None:
    # One send completes both REQ_SEQ (requestable) and HARD (not). With
    # "any" instead of "all", approving the requestable one would silently
    # authorize the hard-prohibited one.
    for order in ((REQ_SEQ, HARD), (HARD, REQ_SEQ)):
        pdp, _ = _overlap_pdp(CompositionPolicy(order))
        d = pdp.evaluate(_send_req())
        assert d.reason == "prohibited_composition"
        assert d.access_request is None and d.evaluation_id is None
        assert pdp._pending == {}


def test_approval_never_covers_a_sequence_it_was_not_issued_for() -> None:
    # Defence in depth: even if policy changes between denial and
    # re-evaluation so that the same act now also completes another sequence,
    # the approval does not stretch to cover it.
    pdp, _ = _overlap_pdp(CompositionPolicy((REQ_SEQ,)))
    d = pdp.evaluate(_send_req())
    assert d.evaluation_id is not None
    apr = pdp.approve(d.evaluation_id)
    also_req = RestrictedSequence("other", HARD.steps, requestable=True)
    pdp.policy = CompositionPolicy((REQ_SEQ, also_req))
    assert pdp.evaluate(_send_req(apr)).decision is False
    pdp.policy = CompositionPolicy((REQ_SEQ,))
    assert pdp.evaluate(_send_req(apr)).decision is True


def _unauth(method: str, path: str) -> tuple[str, dict]:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}))
    env = {"REQUEST_METHOD": method, "PATH_INFO": path, "wsgi.input": io.BytesIO(b"")}
    got: dict = {}
    out = b"".join(app(env, lambda s, h: got.update(s=s)))
    return got["s"], json.loads(out)


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/no/such/route"),            # unknown route: would be 404
    ("PATCH", "/missions/m1/acts"),       # wrong method: would be 405
    ("DELETE", "/missions/m1/acts/1"),    # wrong method: would be 405
    ("POST", "/missions/m1/acts"),
    ("GET", "/missions/m1/acts"),
    ("PATCH", "/missions/m1/acts/1"),
])
def test_unauthenticated_requests_are_401_before_routing(method: str, path: str) -> None:
    # Without a credential the caller must not learn whether a route or a
    # method exists, and must not get its method or path echoed.
    status, body = _unauth(method, path)
    assert status == "401 Unauthorized"
    assert body == {"error": "authentication is required"}


def test_an_approval_lasts_its_own_lifetime_counted_from_the_decision() -> None:
    # Profile, Approvals: the access request's expires_at bounds only how long
    # the PEP has to submit the request; the approval has its own lifetime,
    # counted from the decision, so one granted late in that window is usable.
    t0 = datetime(2030, 1, 1, tzinfo=UTC)
    now = [t0]
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((REQ_SEQ,)), mhs, clock=lambda: now[0],
                         request_ttl=timedelta(seconds=10), access_request_endpoint=ARS)
    mhs.admit("m", 1, "read", "hr", writer="w")
    mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                    result_classes=frozenset({"pd.salary"}))
    denied = pdp.evaluate(_send_req())
    assert denied.evaluation_id is not None
    now[0] = t0 + timedelta(seconds=9)
    apr = pdp.approve(denied.evaluation_id)
    assert apr["approved_until"] == "2030-01-01T00:05:09Z"
    now[0] = t0 + timedelta(seconds=60)  # the request window closed long ago
    assert pdp.evaluate(_send_req(apr)).decision is True


def test_pruning_keeps_a_denial_whose_approval_is_still_valid() -> None:
    # Pruning drops a stored denial only once its window and any approval of it
    # have both expired: an approval given late in the window stays usable
    # after another requestable denial triggers pruning.
    t0 = datetime(2030, 1, 1, tzinfo=UTC)
    now = [t0]
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((REQ_SEQ,)), mhs, clock=lambda: now[0],
                         request_ttl=timedelta(seconds=10), approval_ttl=timedelta(seconds=60),
                         access_request_endpoint=ARS)
    mhs.admit("m", 1, "read", "hr", writer="w")
    mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                    result_classes=frozenset({"pd.salary"}))
    first = pdp.evaluate(_send_req())
    unapproved = pdp.evaluate(_send_req())
    assert first.evaluation_id is not None and unapproved.evaluation_id is not None
    now[0] = t0 + timedelta(seconds=9)
    apr = pdp.approve(first.evaluation_id)
    now[0] = t0 + timedelta(seconds=30)  # both windows closed; the approval is valid
    assert pdp.evaluate(_send_req()).evaluation_id is not None  # prunes
    assert unapproved.evaluation_id not in pdp._pending
    assert first.evaluation_id in pdp._pending and apr["id"] in pdp._approvals
    assert pdp.evaluate(_send_req(apr)).decision is True

