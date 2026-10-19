"""The composition PDP over the AuthZEN Access Evaluation API (WSGI).

* ``GET  /.well-known/authzen-configuration`` -> PDP metadata: the Obligations
  Core's capability and ``supported_obligations`` (``mission_record``)
* ``POST /access/v1/evaluation``               -> one Access Evaluation
* ``POST /access/v1/requests``                 -> ARAP Access Request submission,
  when an ``AccessRequestService`` is configured
* ``GET  /access/v1/requests/{task}``          -> ARAP Task Status
* ``POST /approvals/v1/tasks/{task}``          -> a person's decision,
  ``{"decision": "approve"}`` or ``"deny"`` (the deployment's approval
  interface, not part of ARAP or the Authorization API)

Evaluation callers are PEPs and must authenticate: the PDP trusts the
``context.mission`` a PEP sends, so an unauthenticated caller must not be able
to evaluate under someone else's Mission. Approvals take a separate
credential, held by the people who may approve, never by the agent or a PEP.
The ``properties`` of subject, action and resource are taken as the PEP sends
them: they are PEP-attested, and an approval is bound to them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from authzen_composition.arap import AccessRequestError, AccessRequestService, NotAuthorized
from authzen_composition.http_binding import (
    Authenticator,
    StartResponse,
    discard_unread_body,
    nonempty_string,
    read_json_body,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.types import (
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)

EVALUATION_PATH = "/access/v1/evaluation"
REQUESTS_PATH = "/access/v1/requests"
TASKS_PATH = "/approvals/v1/tasks"
METADATA_PATH = "/.well-known/authzen-configuration"
# Context members an Access Request repeats as the PEP sent them.
_SENT = ("mission", "supported_mandatory_extensions", "supported_obligations")


def _entity(body: dict[str, Any], key: str, *, typed: bool) -> tuple[str, str, dict[str, Any]]:
    """(type, id-or-name, properties) of ``subject``, ``action`` or ``resource``."""
    obj = body.get(key)
    if not isinstance(obj, dict):
        raise ValueError(f"{key} must be an object")
    props = obj.get("properties", {})
    if not isinstance(props, dict):
        raise ValueError(f"{key}.properties must be an object")
    if typed:
        return (nonempty_string(obj.get("type"), f"{key}.type"),
                nonempty_string(obj.get("id"), f"{key}.id"), props)
    return "", nonempty_string(obj.get("name"), f"{key}.name"), props


def _strings(value: Any) -> tuple[str, ...]:
    """An adoption list as the PDP reads it. A member that is not an Array is
    no adoption, and an entry that is not a non-empty String is a value the
    PDP did not advertise, which it ignores and never rejects the request for
    (Extensibility Model; Obligations Core, Item Negotiation)."""
    if not isinstance(value, list):
        return ()
    return tuple(v for v in value if isinstance(v, str) and v)


def request_from_json(body: dict[str, Any]) -> EvaluationRequest:
    """An ``EvaluationRequest`` from an Access Evaluation request body."""
    s_type, s_id, s_props = _entity(body, "subject", typed=True)
    _, a_name, a_props = _entity(body, "action", typed=False)
    r_type, r_id, r_props = _entity(body, "resource", typed=True)
    raw_ctx = body.get("context", {})
    if not isinstance(raw_ctx, dict):
        raise ValueError("context must be an object")
    ctx = dict(raw_ctx)
    mission = None
    raw_mission = ctx.pop("mission", None)
    if raw_mission is not None:
        if not isinstance(raw_mission, dict):
            raise ValueError("context.mission must be an object")
        mission = Mission(
            id=nonempty_string(raw_mission.get("id"), "context.mission.id"),
            issuer=nonempty_string(raw_mission.get("issuer"), "context.mission.issuer"),
        )
    extensions = _strings(ctx.pop("supported_mandatory_extensions", None))
    obligations = _strings(ctx.pop("supported_obligations", None))
    return EvaluationRequest(
        subject=Subject(type=s_type, id=s_id, properties=s_props),
        action=Action(name=a_name, properties=a_props),
        resource=Resource(type=r_type, id=r_id, properties=r_props),
        mission=mission,
        supported_mandatory_extensions=extensions,
        supported_obligations=obligations,
        context=ctx,
        sent={k: raw_ctx[k] for k in _SENT if raw_ctx.get(k) is not None},
    )


class PDPHttpApp:
    """A WSGI app exposing one ``CompositionPDP``."""

    def __init__(self, pdp: CompositionPDP, authenticate_pep: Authenticator,
                 authenticate_approver: Authenticator, base_url: str = "",
                 access_requests: AccessRequestService | None = None) -> None:
        self._pdp = pdp
        self._ars = access_requests
        self._authenticate_pep = authenticate_pep
        self._authenticate_approver = authenticate_approver
        self._base = base_url.rstrip("/")

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")
        content_type = "application/json"
        try:
            status, body = self._route(method, path, environ)
        except AccessRequestError as exc:
            # ARAP "Error Responses": RFC 9457 problem details.
            status = f"{exc.status} {_REASON_PHRASES[exc.status]}"
            body, content_type = exc.problem(), "application/problem+json"
        except NotAuthorized as exc:
            status, body = "403 Forbidden", {"error": str(exc)}
        except ValueError as exc:
            status, body = "400 Bad Request", {"error": str(exc)}
        discard_unread_body(environ)
        headers = [("Content-Type", content_type)]
        if status.startswith("401"):
            # RFC 9110: a 401 carries a challenge.
            headers.append(("WWW-Authenticate", "Bearer"))
        start_response(status, headers)
        return [json.dumps(body).encode("utf-8")]

    def _route(self, method: str, path: str,
               environ: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        if path == METADATA_PATH and method == "GET":
            meta = self._pdp.metadata()
            return "200 OK", {
                "policy_decision_point": self._base,
                "access_evaluation_endpoint": self._base + EVALUATION_PATH,
                **meta,
            }
        if path == EVALUATION_PATH and method == "POST":
            caller = self._authenticate_pep(environ)
            if not caller:
                return "401 Unauthorized", {"error": "authentication is required"}
            request = replace(request_from_json(read_json_body(environ)), caller=caller)
            return "200 OK", self._pdp.evaluate(request).to_json()
        if self._ars is not None:
            routed = self._access_requests(self._ars, method, path, environ)
            if routed is not None:
                return routed
        return "404 Not Found", {"error": "unknown route"}

    def _access_requests(self, ars: AccessRequestService, method: str, path: str,
                         environ: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
        if path == REQUESTS_PATH and method == "POST":
            caller = self._authenticate_pep(environ)
            if not caller:
                return "401 Unauthorized", {"error": "authentication is required"}
            key = environ.get("HTTP_IDEMPOTENCY_KEY")
            status, answer = ars.submit(caller, read_json_body(environ),
                                        key if isinstance(key, str) and key else None)
            return f"{status} {_REASON_PHRASES[status]}", answer
        prefix, _, task_id = path.rpartition("/")
        if prefix == REQUESTS_PATH and task_id and method == "GET":
            caller = self._authenticate_pep(environ)
            if not caller:
                return "401 Unauthorized", {"error": "authentication is required"}
            return "200 OK", ars.status(caller, task_id)
        if prefix == TASKS_PATH and task_id and method == "GET":
            approver = self._authenticate_approver(environ)
            if not approver:
                return "401 Unauthorized", {"error": "an approver credential is required"}
            return "200 OK", ars.review(approver, task_id)
        if prefix == TASKS_PATH and task_id and method == "POST":
            approver = self._authenticate_approver(environ)
            if not approver:
                return "401 Unauthorized", {"error": "an approver credential is required"}
            decision = nonempty_string(read_json_body(environ).get("decision"), "decision")
            if decision not in ("approve", "deny"):
                raise ValueError("decision must be 'approve' or 'deny'")
            return "200 OK", ars.decide(approver, task_id, decision == "approve")
        return None


_REASON_PHRASES = {202: "Accepted", 400: "Bad Request", 404: "Not Found",
                   409: "Conflict", 410: "Gone"}
