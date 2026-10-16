"""A minimal ARAP Access Request Service for the composition PDP.

ARAP (AuthZEN Access Request and Approval Profile, Draft 1, openid/authzen
``6d5380c``) lets a PEP that received a requestable denial submit an Access
Request, follow its task, and evaluate again with the approval once a person
has approved. This module implements the shared-state form of that flow: the
service is part of the PDP, so it resolves ``denial.evaluation_id`` and the
PDP resolves ``approval.id`` from state they share (ARAP "Denial Binding by
Reference", "Approval Reference by Lookup").

Implemented: submission (``denial`` echo, binding by ``evaluation_id``,
freshness against the recorded expiry, structural comparison of Subject,
Resource, Action and the authorization-relevant Context, ``Idempotency-Key``),
the Task Handle and its status, the approval workflow's decision by an eligible
approver, the ``reevaluate`` completion result, and the problem types of
ARAP "Error Responses".

Not implemented: binding artifacts (``binding_token``, ``approval.state``)
and so ARAP's Interoperability Baseline, which requires verifying them as JWS
(openid/authzen PR #738, a draft the Working Group has not decided, proposes
making them declared capabilities); cancellation (optional: no
``links.cancel`` is offered); bulk submissions; callbacks; machine-readable
forms.
"""

from __future__ import annotations

import json
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from authzen_composition.pdp import CompositionPDP, rfc3339

PROBLEM = "urn:openid:authzen:access-request:error:"

_TITLES = {
    "not_requestable": "Access is not requestable",
    "expired_denial": "The requestable denial has expired",
    "invalid_denial_binding": "The request cannot be bound to the denial",
    "duplicate_request": "Idempotency-Key reused for another request",
    "unknown_task": "Unknown task",
    "task_expired": "The task has expired",
    "invalid_task_state": "The task cannot do that in its current state",
}
_STATUS = {
    "not_requestable": 400, "expired_denial": 410, "invalid_denial_binding": 400,
    "duplicate_request": 409, "unknown_task": 404, "task_expired": 410,
    "invalid_task_state": 409,
}


_ADOPTION = frozenset({"supported_mandatory_extensions", "supported_obligations"})
_ABSENT = object()  # never structurally equal to a JSON value
# How long a task and its Idempotency-Key are kept after the task expires. A
# task reaches a terminal status by its expires_at, and ARAP keeps a key for at
# least 24 hours after that ("Idempotency and Retries").
RETENTION = timedelta(hours=24)


class AccessRequestError(Exception):
    """An ARAP problem (RFC 9457): ``kind`` names the problem type."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.status = _STATUS[kind]

    def problem(self) -> dict[str, Any]:
        return {"type": PROBLEM + self.kind, "title": _TITLES[self.kind],
                "status": self.status, "detail": str(self)}


class NotAuthorized(Exception):
    """The caller may not perform this operation (HTTP 403)."""


def _past(when: str, now: datetime) -> bool:
    """Whether an RFC 3339 time a submission echoes is before ``now``; one
    that cannot be read is not."""
    try:
        moment = datetime.fromisoformat(when)
    except ValueError:
        return False
    return moment.tzinfo is not None and moment <= now


def same(a: object, b: object) -> bool:
    """ARAP "Structural Comparison": same JSON type, numbers by value,
    strings code point for code point, arrays in order, objects with the same
    members. A Boolean is never equal to a number."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, int | float) and isinstance(b, int | float):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def entity(value: object, what: str) -> dict[str, Any]:
    """A Subject, Resource or Action as the binding compares it: the object
    without an empty ``properties`` (absent and empty mean the same here),
    and without ``subject.properties.act``, which ARAP excludes because a PEP
    may move the actor to ``client.actor``."""
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object")
    out = dict(value)
    props = out.get("properties")
    if isinstance(props, dict):
        props = {k: v for k, v in props.items() if not (what == "subject" and k == "act")}
        if props:
            out["properties"] = props
        else:
            del out["properties"]
    return out


@dataclass
class _Task:
    id: str
    requester: str
    evaluation_id: str
    subject_id: str
    expires: datetime
    status: str = "pending"
    result: dict[str, Any] | None = None
    submission: bytes = b""
    key: str | None = None
    # The actors of the request's delegation chain, who may not approve it.
    actors: frozenset[str] = frozenset()


@dataclass
class AccessRequestService:
    """The Access Request Service role, played by the PDP itself.

    ``endpoint`` is the Access Request Endpoint the PDP publishes; task status
    endpoints are below it. ``submitters`` are the identities allowed to
    submit (the deployment's PEPs, never the agent); ``approvers`` are the
    people who may decide. An approver is never eligible for a request they
    submitted or whose Subject they are (ARAP "Approver Eligibility").
    """

    pdp: CompositionPDP
    submitters: frozenset[str]
    approvers: frozenset[str]
    # Timezone-aware, like the PDP's clock it is compared with.
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC), repr=False)
    _tasks: dict[str, _Task] = field(default_factory=dict, repr=False)
    _keys: dict[tuple[str, str], str] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if self.pdp.access_request_endpoint is None:
            raise ValueError("the PDP publishes no access_request_endpoint")

    @property
    def endpoint(self) -> str:
        endpoint = self.pdp.access_request_endpoint
        assert endpoint is not None
        return endpoint

    def _handle(self, task: _Task) -> dict[str, Any]:
        return {"id": task.id, "status": task.status,
                "status_endpoint": f"{self.endpoint}/{task.id}",
                "expires_at": rfc3339(task.expires)}

    def _answer(self, task: _Task) -> dict[str, Any]:
        out: dict[str, Any] = {"task": self._handle(task)}
        if task.result is not None:
            out["result"] = task.result
        return out

    def _refresh(self, task: _Task) -> None:
        if task.status == "pending" and self.clock() >= task.expires:
            task.status = "expired"

    def _purge(self) -> None:
        """Forget the tasks, and their Idempotency-Keys, whose retention
        passed. Tasks are kept in submission order, and the scan stops at the
        first one still kept: a later one waits for it, at most the length of
        a request's window and an approval's."""
        horizon = self.clock() - RETENTION
        stale = []
        for task in self._tasks.values():
            if task.expires > horizon:
                break
            stale.append(task)
        for task in stale:
            del self._tasks[task.id]
            if task.key is not None:
                del self._keys[(task.requester, task.key)]

    def submit(self, caller: str, body: dict[str, Any],
               idempotency_key: str | None = None) -> tuple[int, dict[str, Any]]:
        """Accept an Access Request (ARAP "Process a Submission") and return
        the HTTP status and the response body."""
        if caller not in self.submitters:
            raise NotAuthorized("this caller may not submit access requests")
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with self._lock:
            self._purge()
            if idempotency_key is not None:
                known = self._keys.get((caller, idempotency_key))
                if known is not None:
                    task = self._tasks[known]
                    if task.submission != canonical:
                        raise AccessRequestError(
                            "duplicate_request",
                            "this Idempotency-Key was used for another request")
                    self._refresh(task)
                    return 202, self._answer(task)

            denial = body.get("denial")
            if not isinstance(denial, dict):
                raise AccessRequestError("invalid_denial_binding", "denial is required")
            evaluation_id = denial.get("evaluation_id")
            if not isinstance(evaluation_id, str):
                # A binding_token alone cannot be verified here (no binding
                # artifacts): the submission has no binding this service can use.
                raise AccessRequestError("invalid_denial_binding",
                                         "denial.evaluation_id is required")
            if not isinstance(denial.get("expires_at"), str):
                raise AccessRequestError("invalid_denial_binding",
                                         "denial.expires_at is required")
            record = self.pdp.denial_binding(evaluation_id)
            if record is None:
                if _past(denial["expires_at"], self.clock()):
                    # Its window closed, and the PDP has since dropped it.
                    raise AccessRequestError("expired_denial",
                                             "the requestable denial has expired")
                # This PDP issued no requestable denial with this id (or it
                # was spent or purged): the submission is not based on one.
                raise AccessRequestError(
                    "not_requestable", "no requestable denial with this evaluation_id")
            bound, expires = record
            # Freshness against the recorded expiry, not the echoed one.
            if self.clock() >= expires:
                raise AccessRequestError("expired_denial", "the requestable denial has expired")
            context = body.get("context", {})
            if not isinstance(context, dict):
                raise AccessRequestError("invalid_denial_binding", "context must be an object")
            try:
                submitted = {k: entity(body.get(k), k) for k in ("subject", "resource", "action")}
            except ValueError as exc:
                raise AccessRequestError("invalid_denial_binding", str(exc)) from exc
            # An adoption list the PEP left out reads as empty, as the PDP read it.
            relevant = {k: context.get(k, [] if k in _ADOPTION else _ABSENT)
                        for k in bound["context"]}
            if not (all(same(submitted[k], bound[k]) for k in submitted)
                    and same(relevant, bound["context"])):
                raise AccessRequestError(
                    "invalid_denial_binding",
                    "subject, resource, action or context differ from the denied evaluation")

            task = _Task(id="arq_" + secrets.token_hex(16), requester=caller,
                         evaluation_id=evaluation_id, subject_id=bound["subject"]["id"],
                         actors=frozenset(bound.get("actors", ())),
                         expires=expires, submission=canonical, key=idempotency_key)
            self._tasks[task.id] = task
            if idempotency_key is not None:
                self._keys[(caller, idempotency_key)] = task.id
            return 202, self._answer(task)

    def status(self, caller: str, task_id: str) -> dict[str, Any]:
        """The task's current state (ARAP "Task Status Endpoint"). A caller
        other than the requester learns nothing, not even that it exists."""
        with self._lock:
            self._purge()
            task = self._tasks.get(task_id)
            if task is None or caller != task.requester:
                raise AccessRequestError("unknown_task", "unknown task")
            if self.clock() >= task.expires and task.status != "pending":
                raise AccessRequestError("task_expired", "the task has expired")
            self._refresh(task)
            return self._answer(task)

    def decide(self, approver: str, task_id: str, approve: bool) -> dict[str, Any]:
        """A person's decision in the approval workflow. Not part of ARAP's
        wire protocol: it is the deployment's approval interface."""
        with self._lock:
            self._purge()
            task = self._tasks.get(task_id)
            if task is None:
                raise AccessRequestError("unknown_task", "unknown task")
            if (approver not in self.approvers or approver in (task.requester, task.subject_id)
                    or approver in task.actors):
                raise NotAuthorized("this approver is not eligible for this request")
            self._refresh(task)
            if task.status != "pending":
                raise AccessRequestError("invalid_task_state", f"the task is {task.status}")
            if not approve:
                task.status = "denied"
                return self._answer(task)
            try:
                approval = self.pdp.approve(task.evaluation_id, task.requester)
            except KeyError:
                # The denial was spent or purged in the meantime.
                task.status = "failed"
                return self._answer(task)
            task.status = "approved"
            task.result = {"mode": "reevaluate", "approval": {
                **approval, "approved_at": rfc3339(self.clock())}}
            # Kept until the approval can no longer be used, so that the PEP
            # can collect one given late in the request's window.
            task.expires = max(task.expires, datetime.fromisoformat(approval["approved_until"]))
            return self._answer(task)
