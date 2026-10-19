"""HTTP binding tests via a WSGI test client (no network)."""

from __future__ import annotations

import io
import json

from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import MissionHistoryService

TOKENS_BY_WRITER = {"pep.hr": "s3cr3t-hr", "pep.mail": "s3cr3t-mail"}
WRITERS_BY_TOKEN = {v: k for k, v in TOKENS_BY_WRITER.items()}


def call(app, method, path, body=None, writer="pep.hr"):
    raw = json.dumps(body).encode() if body is not None else b""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": io.BytesIO(raw),
        "HTTP_AUTHORIZATION": f"Bearer {TOKENS_BY_WRITER[writer]}" if writer else "",
    }
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    chunks = app(environ, start_response)
    payload = b"".join(chunks)
    captured["json"] = json.loads(payload) if payload else {}
    return captured


def app():
    return MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator(WRITERS_BY_TOKEN),
                      auditors=frozenset(WRITERS_BY_TOKEN.values()))


def test_admit_then_get() -> None:
    a = app()
    r = call(a, "POST", "/missions/m1/acts",
             {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"}})
    assert r["status"].startswith("201")
    assert r["json"]["recorded_by"] == "pep.hr"
    g = call(a, "GET", "/missions/m1/acts")
    assert g["status"].startswith("200")
    assert g["json"]["next_seq"] == 2
    assert g["json"]["acts"][0]["action"]["name"] == "read_record"


def test_admit_retry_with_same_admission_id_is_idempotent() -> None:
    a = app()
    body = {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"},
            "admission_id": "adm-1"}
    first = call(a, "POST", "/missions/m1/acts", body)
    again = call(a, "POST", "/missions/m1/acts", body)
    assert first["status"].startswith("201") and again["status"].startswith("201")
    assert call(a, "GET", "/missions/m1/acts")["json"]["next_seq"] == 2


def test_conflict_on_wrong_seq() -> None:
    a = app()
    call(a, "POST", "/missions/m1/acts",
         {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}})
    r = call(a, "POST", "/missions/m1/acts",
             {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}})
    assert r["status"].startswith("409")


def test_patch_outcome() -> None:
    a = app()
    call(a, "POST", "/missions/m1/acts",
         {"seq": 1, "action": {"name": "read"}, "resource": {"id": "hr:1"}})
    r = call(a, "PATCH", "/missions/m1/acts/1",
             {"outcome": "completed", "result_classes": ["personal_data.salary"]})
    assert r["status"].startswith("200")
    assert r["json"]["result_classes"] == ["personal_data.salary"]


def test_patch_twice_conflicts() -> None:
    a = app()
    call(a, "POST", "/missions/m1/acts",
         {"seq": 1, "action": {"name": "read"}, "resource": {"id": "hr:1"}})
    call(a, "PATCH", "/missions/m1/acts/1", {"outcome": "completed"})
    r = call(a, "PATCH", "/missions/m1/acts/1", {"outcome": "failed"})
    assert r["status"].startswith("409")


def test_unauthenticated_writer() -> None:
    a = app()
    r = call(a, "POST", "/missions/m1/acts",
             {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}}, writer="")
    assert r["status"].startswith("401")


def test_unknown_route() -> None:
    a = app()
    r = call(a, "GET", "/health")
    assert r["status"].startswith("404")


def test_bad_body() -> None:
    a = app()
    r = call(a, "POST", "/missions/m1/acts", body=[1, 2, 3])
    assert r["status"].startswith("400")


def test_method_not_allowed() -> None:
    a = app()
    r = call(a, "DELETE", "/missions/m1/acts")
    assert r["status"].startswith("405")


def test_a_get_without_content_length_is_read() -> None:
    a = app()
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/missions/m1/acts",
        "wsgi.input": io.BytesIO(b""),
        "HTTP_AUTHORIZATION": f"Bearer {TOKENS_BY_WRITER['pep.hr']}",
    }
    captured = {}
    chunks = a(environ, lambda s, h: captured.update(status=s))
    assert captured["status"].startswith("200")
    assert json.loads(b"".join(chunks))["next_seq"] == 1


def test_patch_missing_outcome_is_bad_request() -> None:
    a = app()
    call(a, "POST", "/missions/m1/acts",
         {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}})
    r = call(a, "PATCH", "/missions/m1/acts/1", {})
    assert r["status"].startswith("400")


def test_malformed_content_length_is_a_bad_request() -> None:
    a = app()
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/missions/m1/acts",
        "CONTENT_LENGTH": "not-a-number",
        "wsgi.input": io.BytesIO(b""),
        "HTTP_AUTHORIZATION": f"Bearer {TOKENS_BY_WRITER['pep.hr']}",
    }
    captured = {}
    chunks = a(environ, lambda s, h: captured.update(status=s))
    assert captured["status"].startswith("400")
    assert json.loads(b"".join(chunks))["error"] == "invalid Content-Length"


def test_zero_content_length_post_is_empty_body() -> None:
    a = app()
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/missions/m1/acts",
        "CONTENT_LENGTH": "0",
        "wsgi.input": io.BytesIO(b""),
        "HTTP_AUTHORIZATION": f"Bearer {TOKENS_BY_WRITER['pep.hr']}",
    }
    captured = {}
    a(environ, lambda s, h: captured.update(status=s))
    assert captured["status"].startswith("400")  # an empty body is not a JSON object


def _raw(app, method, path, auth, body=None):
    raw = json.dumps(body).encode() if body is not None else b""
    environ = {
        "REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": io.BytesIO(raw), "HTTP_AUTHORIZATION": auth,
    }
    captured = {}
    chunks = app(environ, lambda s, h: captured.update(status=s))
    captured["json"] = json.loads(b"".join(chunks))
    return captured


def test_writer_name_as_bearer_is_not_an_identity() -> None:
    """Knowing a writer's name must not let a caller act as that writer: the
    bearer secret, not the name, is the credential."""
    a = app()
    _raw(a, "POST", "/missions/m1/acts", f"Bearer {TOKENS_BY_WRITER['pep.hr']}",
         {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"}})
    r = _raw(a, "PATCH", "/missions/m1/acts/1", "Bearer pep.hr", {"outcome": "failed"})
    assert r["status"].startswith("401")


def test_other_authenticated_writer_cannot_mark_failed() -> None:
    a = app()
    call(a, "POST", "/missions/m1/acts",
         {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"}})
    r = call(a, "PATCH", "/missions/m1/acts/1", {"outcome": "failed"}, writer="pep.mail")
    # Authenticated but not the writer that admitted the Act: 403 (RFC 9110);
    # 401 is for a missing or failed credential.
    assert r["status"].startswith("403")


def test_unauthenticated_read_is_refused() -> None:
    r = _raw(app(), "GET", "/missions/m1/acts", "")
    assert r["status"].startswith("401")


def test_failed_with_result_classes_is_rejected() -> None:
    a = app()
    call(a, "POST", "/missions/m1/acts",
         {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"}})
    r = call(a, "PATCH", "/missions/m1/acts/1",
             {"outcome": "failed", "result_classes": ["personal_data.salary"]})
    assert r["status"].startswith("400")


def test_outcome_open_or_unknown_is_a_bad_request() -> None:
    """Only completed and failed are reportable. 'open' is a valid state name,
    but not an outcome a PEP can report: 400 at validation, not 409."""
    a = app()
    call(a, "POST", "/missions/m1/acts",
         {"seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:1"}})
    for outcome in ("open", "done", "COMPLETED"):
        r = call(a, "PATCH", "/missions/m1/acts/1", {"outcome": outcome})
        assert r["status"] == "400 Bad Request", outcome
        assert r["json"] == {"error": "outcome must be 'completed' or 'failed'"}
    r = call(a, "PATCH", "/missions/m1/acts/1", {"outcome": "completed"})
    assert r["status"] == "200 OK"


def test_static_authenticator_requires_bearer_scheme() -> None:
    auth = StaticTokenAuthenticator({"t": "w"})
    assert auth({"HTTP_AUTHORIZATION": "Basic t"}) == ""
    assert auth({"HTTP_AUTHORIZATION": "Bearer t"}) == "w"


def test_a_caller_who_may_not_read_is_refused_before_its_query_is_read() -> None:
    # A writer that is neither a PDP nor an auditor gets 403 for any query,
    # malformed or not: the binding does not parse a query for a caller who
    # may not read.
    binding = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.hr"}),
                         pdps=frozenset({"pdp"}))
    statuses: list[str] = []
    for query in ("policy=a&policy=b", "&".join(f"f{i}=1" for i in range(100))):
        b"".join(binding({"REQUEST_METHOD": "GET", "PATH_INFO": "/missions/m/acts",
                          "QUERY_STRING": query, "wsgi.input": io.BytesIO(b""),
                          "HTTP_AUTHORIZATION": "Bearer t"},
                         lambda s, h: statuses.append(s)))
    assert statuses == ["403 Forbidden"] * 2
