"""Wire details of the ARAP flow that another implementation reads: problem
bodies, messages, the Task Handle's exact shape, structural comparison edge
cases, and the PEP client's handling of answers.
"""

from __future__ import annotations

import io
import json
from datetime import timedelta
from typing import Any

import pytest

from authzen_composition import remote
from authzen_composition.arap import (
    AccessRequestError,
    AccessRequestService,
    NotAuthorized,
    entity,
    same,
)
from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import MissionHistoryService
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pdp_http import REQUESTS_PATH
from authzen_composition.remote import (
    AccessRequestClient,
    AccessRequestRefused,
    RemoteUnavailable,
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
from tests.test_arap import ENDPOINT, _app, _denied, _http, _send, _setup, _submission
from tests.test_remote import canned, serve

PROBLEMS = {
    "not_requestable": (400, "Access is not requestable"),
    "expired_denial": (410, "The requestable denial has expired"),
    "invalid_denial_binding": (400, "The request cannot be bound to the denial"),
    "duplicate_request": (409, "Idempotency-Key reused for another request"),
    "unknown_task": (404, "Unknown task"),
    "task_expired": (410, "The task has expired"),
    "invalid_task_state": (409, "The task cannot do that in its current state"),
}


@pytest.mark.parametrize("kind", sorted(PROBLEMS))
def test_every_problem_body(kind: str) -> None:
    status, title = PROBLEMS[kind]
    error = AccessRequestError(kind, "why")
    assert error.status == status
    assert error.problem() == {"type": "urn:openid:authzen:access-request:error:" + kind,
                               "title": title, "status": status, "detail": "why"}


@pytest.mark.parametrize("change, detail", [
    (lambda b: b.pop("denial"), "denial is required"),
    (lambda b: b["denial"].pop("evaluation_id"), "denial.evaluation_id is required"),
    (lambda b: b["denial"].pop("expires_at"), "denial.expires_at is required"),
    (lambda b: b["denial"].update(evaluation_id="eval_x"),
     "no requestable denial with this evaluation_id"),
    (lambda b: b.update(context=[]), "context must be an object"),
    (lambda b: b.update(subject=[["type", "agent"]]), "subject must be an object"),
    (lambda b: b["resource"].update(id="r2"),
     "subject, resource, action or context differ from the denied evaluation"),
])
def test_submission_problem_details(change: Any, detail: str) -> None:
    pdp, ars, _ = _setup()
    body = _submission(*_denied(pdp))
    change(body)
    with pytest.raises(AccessRequestError) as exc:
        ars.submit("pep.mail", body)
    assert str(exc.value) == detail


def test_other_problem_and_refusal_details() -> None:
    pdp, ars, clock = _setup()
    body = _submission(*_denied(pdp))
    with pytest.raises(NotAuthorized) as refused:
        ars.submit("agent-7", body)
    assert str(refused.value) == "this caller may not submit access requests"
    task = ars.submit("pep.mail", body)[1]["task"]["id"]
    with pytest.raises(NotAuthorized) as refused:
        ars.decide("pep.mail", task, approve=True)
    assert str(refused.value) == "this approver is not eligible for this request"
    with pytest.raises(AccessRequestError) as exc:
        ars.status("pep.hr", task)
    assert str(exc.value) == "unknown task"
    with pytest.raises(AccessRequestError) as exc:
        ars.decide("alice", "arq_none", approve=True)
    assert str(exc.value) == "unknown task"
    ars.decide("alice", task, approve=False)
    with pytest.raises(AccessRequestError) as exc:
        ars.decide("alice", task, approve=False)
    assert str(exc.value) == "the task is denied"
    clock.now += pdp.request_ttl
    with pytest.raises(AccessRequestError) as exc:
        ars.status("pep.mail", task)
    assert str(exc.value) == "the task has expired"
    fresh_pdp, fresh_ars, fresh_clock = _setup()
    late = _submission(*_denied(fresh_pdp))
    fresh_clock.now += timedelta(hours=1)
    with pytest.raises(AccessRequestError) as exc:
        fresh_ars.submit("pep.mail", late)
    assert str(exc.value) == "the requestable denial has expired"
    with pytest.raises(ValueError, match="^the PDP publishes no access_request_endpoint$"):
        AccessRequestService(CompositionPDP(EXFIL_POLICY, MissionHistoryService()),
                             submitters=frozenset(), approvers=frozenset())


def test_the_task_handle_and_result_exact_shape() -> None:
    pdp, ars, _ = _setup()
    status, answer = ars.submit("pep.mail", _submission(*_denied(pdp)))
    task_id = answer["task"]["id"]
    # The denial expires 15 minutes after 09:00 UTC; RFC 3339 with "Z".
    assert answer == {"task": {"id": task_id, "status": "pending",
                               "status_endpoint": f"{ENDPOINT}/{task_id}",
                               "expires_at": "2026-10-14T09:15:00Z"}}
    done = ars.decide("alice", task_id, approve=True)
    assert done["result"]["approval"]["approved_at"] == "2026-10-14T09:00:00Z"


def test_structural_comparison_edges() -> None:
    assert same("x", "x") and not same("x", "y")
    assert same(1, 1.0) and not same(1, 2) and not same(1, "1") and not same("1", 1)
    assert not same([1], "x") and not same("x", [1])
    assert not same({}, "x") and not same("x", {})
    assert not same(None, False)


def test_entity_drops_only_the_subjects_actor_and_keeps_other_properties() -> None:
    with pytest.raises(ValueError, match="^subject must be an object$"):
        entity([["type", "agent"]], "subject")
    assert entity({"id": "a", "properties": {"act": 1, "x": 2}}, "subject") == {
        "id": "a", "properties": {"x": 2}}
    assert entity({"id": "r", "properties": {"act": 1}}, "resource") == {
        "id": "r", "properties": {"act": 1}}


def test_a_submission_that_keeps_the_actor_is_bound() -> None:
    # ARAP excludes subject.properties.act from the comparison, on both sides.
    pdp, ars, _ = _setup()
    body = _submission(*_denied(pdp, _send(act="https://orchestrator.example")))
    assert body["subject"]["properties"] == {"act": {"sub": "https://orchestrator.example"}}
    assert ars.submit("pep.mail", body)[0] == 202


def test_other_properties_are_bound() -> None:

    request = EvaluationRequest(
        Subject("agent", "agent-7", properties={"tier": "gold", "act": {"sub": "o"}}),
        Action("send_message"), Resource("recipient", "external:press", properties={"act": "x"}),
        mission=Mission("m", "https://missions.example"),
        supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",))
    pdp, ars, _ = _setup()
    body = _submission(*_denied(pdp, request))
    for path, value in ((("subject", "tier"), "silver"), (("resource", "act"), "y")):
        changed = json.loads(json.dumps(body))
        changed[path[0]]["properties"][path[1]] = value
        with pytest.raises(AccessRequestError):
            ars.submit("pep.mail", changed)
    assert ars.submit("pep.mail", body)[0] == 202


def test_an_idempotent_retry_with_members_in_another_order_is_the_same_request() -> None:
    pdp, ars, clock = _setup()
    body = _submission(*_denied(pdp))
    first = ars.submit("pep.mail", body, idempotency_key="k")[1]
    reordered = {k: body[k] for k in reversed(list(body))}
    assert ars.submit("pep.mail", reordered, idempotency_key="k")[1] == first
    # A retry after the task expired reports it expired, not still pending.
    clock.now += pdp.request_ttl
    assert ars.submit("pep.mail", body, idempotency_key="k")[1]["task"]["status"] == "expired"


def test_the_loopback_endpoint_needs_the_flag() -> None:
    with pytest.raises(ValueError,
                       match=r"^access_request_endpoint must be an HTTPS URI \(ARAP\)$"):
        CompositionPDP(EXFIL_POLICY, MissionHistoryService(),
                       access_request_endpoint="http://127.0.0.1:8080/r")


def test_http_error_bodies_of_the_access_request_routes() -> None:
    pdp, ars, _ = _setup()
    app = _app(ars)
    body = _submission(*_denied(pdp))
    assert _http(app, "POST", REQUESTS_PATH, "hr", body)[1:] == (
        "application/json", {"error": "this caller may not submit access requests"})
    assert _http(app, "GET", f"{REQUESTS_PATH}/arq_x", None)[2] == {
        "error": "authentication is required"}
    task = _http(app, "POST", REQUESTS_PATH, "pep", body)[2]["task"]["id"]
    decide = f"/approvals/v1/tasks/{task}"
    assert _http(app, "POST", decide, "person", {})[2] == {
        "error": "decision must be a non-empty string"}
    assert _http(app, "POST", decide, "person", {"decision": "x"})[2] == {
        "error": "decision must be 'approve' or 'deny'"}


def test_an_empty_idempotency_key_header_is_no_key() -> None:
    pdp, ars, _ = _setup()
    app = _app(ars)
    body = _submission(*_denied(pdp))

    def post() -> str:
        raw = json.dumps(body).encode()
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": REQUESTS_PATH,
               "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw),
               "HTTP_AUTHORIZATION": "Bearer pep", "HTTP_IDEMPOTENCY_KEY": ""}
        out = b"".join(app(env, lambda s, h: None))
        task_id: str = json.loads(out)["task"]["id"]
        return task_id

    assert post() != post()


def test_the_outcome_admission_id_must_be_a_string() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "w"}))
    raw = json.dumps({"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"},
                      "admission_id": "k"}).encode()

    def call(method: str, path: str, data: bytes) -> tuple[str, dict[str, Any]]:
        env = {"REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": str(len(data)),
               "wsgi.input": io.BytesIO(data), "HTTP_AUTHORIZATION": "Bearer t"}
        got: dict[str, str] = {}
        out = b"".join(app(env, lambda s, h: got.update(s=s)))
        return got["s"], json.loads(out)

    assert call("POST", "/missions/m/acts", raw)[0] == "201 Created"
    assert call("PATCH", "/missions/m/acts/1",
                json.dumps({"outcome": "failed", "admission_id": 7}).encode()) == (
        "400 Bad Request", {"error": "admission_id must be a non-empty string"})


# --- The PEP-side client -----------------------------------------------------------

def test_the_client_accepts_a_synchronously_completed_task() -> None:
    # ARAP "Access Request Response": 201 Created when the service completes
    # the request at once.
    client = AccessRequestClient(ENDPOINT, "pep")
    answer = {"task": {"id": "a", "status": "approved", "status_endpoint": ENDPOINT + "/a"}}
    assert client._check(201, answer) == answer


def test_the_client_refusals_carry_status_and_detail() -> None:
    client = AccessRequestClient(ENDPOINT, "pep")
    with pytest.raises(AccessRequestRefused) as exc:
        client._check(202, {"task": {"id": "a", "status": "pending",
                                     "status_endpoint": "https://other.example/a"}})
    assert (exc.value.status, str(exc.value)) == (202, "status endpoint on another origin")
    with pytest.raises(AccessRequestRefused) as exc:
        client.status({"status_endpoint": "https://other.example/a"})
    assert (exc.value.status, exc.value.problem, str(exc.value)) == (
        0, None, "status endpoint on another origin")
    with pytest.raises(AccessRequestRefused) as exc:
        client._check(409, {"type": "urn:openid:authzen:access-request:error:duplicate_request",
                            "detail": "the detail", "error": "not this"})
    assert (exc.value.problem, str(exc.value)) == ("duplicate_request", "the detail")
    with pytest.raises(RemoteUnavailable, match="^answer has no task handle$"):
        client._check(200, {})


def test_the_client_submits_only_a_requestable_denial() -> None:
    client = AccessRequestClient(ENDPOINT, "pep")
    for decision in (Decision(True), Decision(False, reason="prohibited_composition")):
        with pytest.raises(ValueError, match="^only a requestable denial can be submitted$"):
            client.submit(_send(), decision, "k")


def test_discovery_keeps_a_base_path_ending_in_x() -> None:
    seen: list[str] = []

    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        seen.append(environ["PATH_INFO"])
        start_response("200 OK", [("Content-Type", "application/json")])
        return [json.dumps({"access_request_endpoint": "https://pdp.example/r"}).encode()]

    with serve(app) as url:
        client = AccessRequestClient.discover(url + "/BOX/", "pep")
    assert client is not None and client.endpoint == "https://pdp.example/r"
    assert seen == ["/BOX/.well-known/authzen-configuration"]


def test_booleans_and_mixed_containers_compare_by_type() -> None:
    assert same(True, True) and same(False, False) and not same(True, False)
    # A list never equals an object, even one whose member names match.
    assert not same(["k"], {"k": 1}) and not same({"k": 1}, ["k"])


def test_a_decision_after_expiry_finds_the_task_expired() -> None:
    pdp, ars, clock = _setup()
    task = ars.submit("pep.mail", _submission(*_denied(pdp)))[1]["task"]["id"]
    clock.now += pdp.request_ttl
    with pytest.raises(AccessRequestError) as exc:
        ars.decide("alice", task, approve=True)
    assert str(exc.value) == "the task is expired"


@pytest.mark.parametrize("endpoint", [
    "http://10.0.0.5:9999/collect",
    "file:///C:/Windows/win.ini",
    "https://user@ars.example/r",
    "ftp://ars.example/r",
    "/access/v1/requests",
    "https:///access/v1/requests",
])
def test_discovery_refuses_an_endpoint_the_credential_must_not_go_to(endpoint: str) -> None:
    # ARAP: the endpoint is an HTTPS URI, and a PEP does not submit its
    # credential to a host it does not trust. Plain HTTP is accepted only to
    # this machine.
    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        start_response("200 OK", [("Content-Type", "application/json")])
        return [json.dumps({"access_request_endpoint": endpoint}).encode()]

    with serve(app) as url:
        assert AccessRequestClient.discover(url, "pep") is None


def test_discovery_keeps_to_the_trusted_origins_when_the_deployment_lists_them() -> None:
    # ARAP: a PEP trusts the endpoint's origin, or keeps an explicit allowlist
    # of trusted Access Request Service hosts.
    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        start_response("200 OK", [("Content-Type", "application/json")])
        return [json.dumps({"access_request_endpoint": "https://ars.example/r"}).encode()]

    with serve(app) as url:
        trusted = AccessRequestClient.discover(
            url, "pep", trusted_origins=frozenset({"https://ars.example"}))
        assert trusted is not None and trusted.endpoint == "https://ars.example/r"
        assert AccessRequestClient.discover(
            url, "pep", trusted_origins=frozenset({"https://other.example"})) is None


def test_a_server_error_from_the_access_request_service_is_an_outage() -> None:
    # A 5xx is no answer, whatever its body: never a refusal the PEP acts on,
    # and never "this PDP publishes no endpoint".
    pdp, _, _ = _setup()
    request, decision = _denied(pdp)
    body = b'{"type": "urn:openid:authzen:access-request:error:not_requestable", "error": "x"}'
    unavailable = pytest.raises(RemoteUnavailable)
    with serve(canned("503 Service Unavailable", body)) as url, unavailable:
        AccessRequestClient(url + REQUESTS_PATH, "t").submit(request, decision, "k")
    meta = b'{"access_request_endpoint": "x"}'
    with serve(canned("500 Internal Server Error", meta)) as url, pytest.raises(RemoteUnavailable):
        AccessRequestClient.discover(url, "t")


def test_the_answer_size_limit_is_the_one_the_binding_document_states() -> None:
    # docs/mission-history-service.md: an answer larger than 16 MiB is refused.
    assert remote.MAX_RESPONSE_BYTES == 16 * 1024 * 1024
