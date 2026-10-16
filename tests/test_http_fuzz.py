"""Fuzzing the HTTP binding: arbitrary methods, paths, headers and bodies.

Invariants: the app never raises, always answers with a JSON object body and a
status the binding documents, never a 5xx, and an unauthenticated caller never
changes the history.
"""

from __future__ import annotations

import io
import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import MissionHistoryService
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pdp_http import PDPHttpApp
from authzen_composition.scenarios import EXFIL_POLICY

ISSUER = "https://missions.example"  # the issuer of every Mission here
STATUSES = {
    "200 OK", "201 Created", "400 Bad Request", "401 Unauthorized",
    "404 Not Found", "405 Method Not Allowed", "409 Conflict",
}
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False)
    | st.text(max_size=8),
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=6), inner,
                                                                max_size=3),
    max_leaves=8,
)
bodies = st.one_of(
    st.binary(max_size=40),
    json_values.map(lambda v: json.dumps(v).encode()),
    st.fixed_dictionaries({}, optional={
        "seq": json_values | st.integers(-2, 4),
        "action": json_values | st.fixed_dictionaries({"name": json_values}),
        "resource": json_values | st.fixed_dictionaries({"id": json_values}),
        "admission_id": json_values,
        "outcome": json_values | st.sampled_from(["open", "completed", "failed"]),
        "result_classes": json_values,
    }).map(lambda v: json.dumps(v).encode()),
)
paths = st.one_of(
    st.text(max_size=30),
    st.builds(lambda m, n: f"/missions/{m}/acts" + (f"/{n}" if n is not None else ""),
              st.sampled_from(["m1", "m2", "", " "]),
              st.one_of(st.none(), st.text(max_size=4), st.integers(-1, 3).map(str),
                        st.sampled_from(["01", "+1", "1_0", "\u0661", "9" * 30]))),
    st.sampled_from(["/missions/m1/acts", "/missions/m1/acts/1", "/missions/m1/acts/2"]),
)


def _good_admit(seq: int) -> bytes:
    return json.dumps({"seq": seq, "action": {"name": "read"},
                       "resource": {"id": "r"}}).encode()


bodies = st.one_of(bodies, st.integers(1, 3).map(_good_admit),
                   st.sampled_from([b'{"outcome": "completed"}', b'{"outcome": "failed"}',
                                    b'{"seq": 1, "seq": 2}', b'{"a": NaN}',
                                    b"[" * 5000 + b"]" * 5000]))


def _app() -> tuple[MHSHttpApp, MissionHistoryService]:
    mhs = MissionHistoryService()
    return MHSHttpApp(mhs, StaticTokenAuthenticator({"tok": "pep.a"}),
                      auditors=frozenset({"pep.a"})), mhs


def _send(app: MHSHttpApp, method: str, path: str, body: bytes, auth: str,
          length: str | None) -> tuple[str, object]:
    environ = {
        "REQUEST_METHOD": method, "PATH_INFO": path, "wsgi.input": io.BytesIO(body),
        "HTTP_AUTHORIZATION": auth,
    }
    if length == "auto":
        environ["CONTENT_LENGTH"] = str(len(body))
    elif length is not None:
        environ["CONTENT_LENGTH"] = length
    got: dict[str, str] = {}
    payload = b"".join(app(environ, lambda s, h: got.update(status=s)))
    return got["status"], json.loads(payload)


@settings(max_examples=1500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    reqs=st.lists(st.tuples(
        st.sampled_from(["POST", "POST", "PATCH", "PATCH", "GET", "PUT", "", "post"]),
        paths, bodies,
        st.sampled_from(["Bearer tok", "Bearer tok", "Bearer nope", "", "Bearer  tok"]),
        st.sampled_from(["auto", "auto", "auto", None, "-5", "abc", "", " 3", "3", "70000",
                         "\u0663"]),
    ), min_size=1, max_size=6),
)
def test_binding_never_crashes_and_answers_documented_json(reqs) -> None:
    app, mhs = _app()
    for method, path, body, auth, length in reqs:
        before = mhs.history("m1") + mhs.history("m2")
        status, payload = _send(app, method, path, body, auth, length)
        assert status in STATUSES
        assert isinstance(payload, dict)
        if status[0] in "45":
            assert set(payload) <= {"error", "reason"} and isinstance(payload["error"], str)
            assert payload.get("reason", "seq_conflict") in {
                "seq_conflict", "outcome_conflict", "policy_mismatch"}
            assert ("reason" in payload) == status.startswith("409")
        if auth != "Bearer tok":
            assert mhs.history("m1") + mhs.history("m2") == before


# --- the PDP's Access Evaluation endpoint ------------------------------------


PDP_STATUSES = {"200 OK", "201 Created", "400 Bad Request", "401 Unauthorized",
                "404 Not Found"}
eval_bodies = st.one_of(
    bodies,
    st.fixed_dictionaries({}, optional={
        "subject": json_values | st.fixed_dictionaries(
            {"type": json_values, "id": json_values}, optional={"properties": json_values}),
        "action": json_values | st.fixed_dictionaries(
            {"name": json_values}, optional={"properties": json_values}),
        "resource": json_values | st.fixed_dictionaries(
            {"type": json_values, "id": json_values}, optional={"properties": json_values}),
        "context": json_values | st.fixed_dictionaries({}, optional={
            "mission": json_values | st.fixed_dictionaries(
                {"id": json_values}, optional={"issuer": json_values}),
            "supported_mandatory_extensions": json_values,
            "supported_obligations": json_values,
            "approval": json_values,
        }),
        "evaluation_id": json_values,
    }).map(lambda v: json.dumps(v).encode()),
    # Well-formed requests, so the authentication invariant is exercised.
    st.builds(
        lambda mission, action, resource: json.dumps({
            "subject": {"type": "agent", "id": "a7"}, "action": {"name": action},
            "resource": {"type": "r", "id": resource},
            "context": ({"mission": {"id": mission, "issuer": ISSUER},
                         "supported_mandatory_extensions": ["obligations"],
                         "supported_obligations": ["mission_record"]} if mission else {}),
        }).encode(),
        st.sampled_from(["m1", "m2", None]),
        st.sampled_from(["read_record", "write_document", "send_message"]),
        st.sampled_from(["hr:1", "external:press", "doc:1"]),
    ),
)


@settings(max_examples=1500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    reqs=st.lists(st.tuples(
        st.sampled_from(["POST", "POST", "GET", "PUT", ""]),
        st.sampled_from(["/access/v1/evaluation", "/access/v1/evaluation",
                         "/access/v1/requests", "/approvals/v1/tasks/arq_x",
                         "/.well-known/authzen-configuration", "/x", ""]),
        eval_bodies,
        st.sampled_from(["Bearer pep", "Bearer pep", "Bearer person", "Bearer nope", ""]),
        st.sampled_from(["auto", "auto", None, "-1", "abc", "70000"]),
    ), min_size=1, max_size=6),
)
def test_pdp_endpoint_never_crashes_and_unauthenticated_calls_never_evaluate(reqs) -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy=EXFIL_POLICY, mhs=mhs)
    calls: list[object] = []
    real = pdp.evaluate
    pdp.evaluate = lambda request: calls.append(request) or real(request)  # type: ignore[method-assign]
    app = PDPHttpApp(pdp, StaticTokenAuthenticator({"pep": "pep.a"}),
                     StaticTokenAuthenticator({"person": "alice"}))
    for method, path, body, auth, length in reqs:
        before = len(calls)
        status, payload = _send(app, method, path, body, auth, length)  # type: ignore[arg-type]
        assert status in PDP_STATUSES
        assert isinstance(payload, dict)
        if status[0] in "45":
            assert set(payload) == {"error"} and isinstance(payload["error"], str)
        if status.startswith("200") and path == "/access/v1/evaluation":
            assert isinstance(payload.get("decision"), bool)
        if auth != "Bearer pep":
            # Only an authenticated PEP gets an evaluation.
            assert len(calls) == before
        else:
            assert len(calls) - before == (status.startswith("200")
                                           and path == "/access/v1/evaluation")
