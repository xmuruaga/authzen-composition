"""Clients for the History Authority and the PDP over HTTP.

With these, a PEP, a PDP and a History Authority can run as separate
processes, on separate hosts, and talk only over the wire:

* ``RemoteHistoryAuthority`` speaks the non-normative MHS HTTP binding
  (``http_binding``, docs/mission-history-service.md);
* ``RemotePDP`` speaks the AuthZEN Access Evaluation API (``pdp_http``).

Both fail closed. A History Authority that cannot be read raises
``HistoryUnavailable``, which the PDP turns into a ``history_unavailable``
denial. An admission that gets no acknowledgement raises ``RemoteUnavailable``,
and the PEP retries it once with the same ``admission_id`` before refusing to
act. A PDP that cannot be reached raises ``RemoteUnavailable``, so the PEP
never performs the action.

The service takes the writer identity from the credential, so the ``writer``
argument of the ``HistoryAuthority`` methods is ignored here.
"""

from __future__ import annotations

import http.client
import io
import json
import socket
import time
from contextlib import closing
from typing import Any
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from authzen_composition.mhs import (
    HistoryConflict,
    HistoryUnavailable,
    NotPermitted,
    OutcomeAlreadySet,
    PolicyMismatch,
    UnauthenticatedWriter,
)
from authzen_composition.model import Act, ActOutcome
from authzen_composition.types import Decision, EvaluationRequest, Obligation


class RemoteUnavailable(Exception):
    """No usable answer from the remote party: unreachable, timed out, a
    server error, or a response this client cannot read."""


class RemoteNotPermitted(NotPermitted, RemoteUnavailable):
    """A 403 from the History Authority: authenticated, but not allowed this.
    Never a success (a ``RemoteUnavailable``), and final for a PEP's outcome
    (a ``NotPermitted``)."""


# A larger answer is refused before it is read in full: a History Authority or
# PDP that sends more is faulty or hostile, and reading it would let it exhaust
# the caller.
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_CHUNK = 64 * 1024


class _Deadline(io.RawIOBase):
    """A connected socket whose every read and write is bounded by what is
    left of one exchange's time. The socket timeout bounds each read, not the
    exchange: a peer that sends its answer, headers included, one byte at a
    time would otherwise hold the caller for as long as it likes."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        super().__init__()
        self._sock, self._deadline = sock, deadline

    def _arm(self) -> None:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("no answer in time")
        self._sock.settimeout(left)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        self._arm()
        return self._sock.recv_into(buffer)

    def sendall(self, data: bytes) -> None:
        self._arm()
        self._sock.sendall(data)

    def makefile(self, mode: str) -> io.BufferedReader:
        # http.client reads the answer through this, and may close the
        # connection before it has read the body: the reader gets its own
        # handle, and the exchange closes the socket.
        return io.BufferedReader(_Deadline(self._sock, self._deadline))


def _read(resp: http.client.HTTPResponse) -> bytes:
    """The answer's body, at most ``MAX_RESPONSE_BYTES`` long."""
    declared = resp.headers.get("Content-Length")
    if declared is not None and declared.strip().isdigit() \
            and int(declared) > MAX_RESPONSE_BYTES:
        raise ValueError("answer too large")
    chunks: list[bytes] = []
    size = 0
    while chunk := resp.read1(_CHUNK):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise ValueError("answer too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _exchange(method: str, url: str, headers: dict[str, str], data: bytes | None,
              timeout: float) -> tuple[int, bytes]:
    """Sends one request and reads its answer. Once the connection is open, the
    request and the whole answer, headers included, are bounded by one deadline,
    ``timeout`` from the start; connecting is bounded by the socket timeout for
    each address tried (name resolution has no bound of its own). Never
    follows a redirect, which would resend the bearer credential to whatever
    host the answer names: a 3xx is returned as is, and no caller reads it as
    success."""
    deadline = time.monotonic() + timeout
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("not an http or https URL")
    kind = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    conn = kind(parts.hostname, parts.port, timeout=timeout)
    with closing(conn):
        conn.connect()
        with conn.sock as sock:
            conn.sock = _Deadline(sock, deadline)
            conn.request(method, urlunsplit(("", "", parts.path or "/", parts.query, "")),
                         data, headers)
            resp = conn.getresponse()
            return resp.status, _read(resp)


def _call(method: str, url: str, token: str, body: dict[str, Any] | None,
          timeout: float, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    """One HTTP exchange. Returns (status, JSON body); raises
    ``RemoteUnavailable`` when there is no readable answer."""
    data = None if body is None else json.dumps(body).encode("utf-8")
    sent = {"Authorization": f"Bearer {token}", **(headers or {})}
    if data is not None:
        sent["Content-Type"] = "application/json"
    try:
        status, raw = _exchange(method, url, sent, data, timeout)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        # Refused or reset connections and timeouts are OSErrors; an answer
        # that is not HTTP is an HTTPException.
        raise RemoteUnavailable(f"{method} {url}: {exc}") from exc
    if status >= 500:
        raise RemoteUnavailable(f"{method} {url}: HTTP {status}")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RemoteUnavailable(f"{method} {url}: unreadable body") from exc
    if not isinstance(parsed, dict):
        raise RemoteUnavailable(f"{method} {url}: body is not a JSON object")
    return status, parsed


def _act(obj: Any) -> Act:
    """An Act from its wire form. Raises ``RemoteUnavailable`` if it is not a
    valid Act Record (profile, History Authority): a member missing, of
    another type, or outside its values. The PDP then fails closed (rule 4)."""
    try:
        classes = obj["result_classes"]
        if not isinstance(classes, list) or not all(
                isinstance(c, str) and c and "*" not in c for c in classes):
            raise TypeError("result_classes")
        seq = obj["seq"]
        action = obj["action"]["name"]
        resource = obj["resource"]["id"]
        recorded_by = obj["recorded_by"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise TypeError("seq")
        if not (isinstance(action, str) and action and isinstance(resource, str) and resource):
            raise TypeError("action or resource")
        if not (isinstance(recorded_by, str) and recorded_by):
            raise TypeError("recorded_by")
        outcome = ActOutcome(obj["outcome"])
        if outcome is ActOutcome.FAILED and classes:
            raise ValueError("a failed Act carries no result classes")
        return Act(seq=seq, action=action, resource=resource,
                   outcome=outcome, result_classes=frozenset(classes))
    except (KeyError, TypeError, ValueError) as exc:
        raise RemoteUnavailable(f"malformed act record: {exc}") from exc


class RemoteHistoryAuthority:
    """A ``HistoryAuthority`` reached over the MHS HTTP binding."""

    def __init__(self, base_url: str, token: str, timeout: float = 5.0) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def _acts_url(self, mission_id: str) -> str:
        return f"{self._base}/missions/{quote(mission_id, safe='')}/acts"

    def _raise_for(self, status: int, body: dict[str, Any]) -> None:
        """Map an error answer to the exception the in-memory service raises."""
        error = str(body.get("error", ""))
        if status == 401:
            raise UnauthenticatedWriter(error)
        if status == 403:
            raise RemoteNotPermitted(error)
        if status == 409:
            reason = body.get("reason")
            if reason == "seq_conflict":
                raise HistoryConflict(error)
            if reason == "outcome_conflict":
                raise OutcomeAlreadySet(error)
            if reason == "policy_mismatch":
                raise PolicyMismatch(error)
        if status == 400:
            raise ValueError(error)
        raise RemoteUnavailable(f"HTTP {status}: {error}")

    def admit(self, mission_id: str, seq: int, action: str, resource: str,
              writer: str, admission_id: str | None = None) -> Act:
        body: dict[str, Any] = {"seq": seq, "action": {"name": action},
                                "resource": {"id": resource}}
        if admission_id is not None:
            body["admission_id"] = admission_id
        status, answer = _call("POST", self._acts_url(mission_id), self._token, body,
                               self._timeout)
        if status != 201:
            self._raise_for(status, answer)
        return _act(answer)

    def set_outcome(self, mission_id: str, seq: int, outcome: ActOutcome, writer: str,
                    result_classes: frozenset[str] = frozenset(),
                    admission_id: str | None = None) -> Act:
        body: dict[str, Any] = {"outcome": outcome.value,
                                "result_classes": sorted(result_classes)}
        if admission_id is not None:
            body["admission_id"] = admission_id
        status, answer = _call("PATCH", f"{self._acts_url(mission_id)}/{seq}", self._token,
                               body, self._timeout)
        if status != 200:
            self._raise_for(status, answer)
        return _act(answer)

    def history(self, mission_id: str, policy: str | None = None) -> list[Act]:
        url = self._acts_url(mission_id)
        if policy is not None:
            url += "?" + urlencode({"policy": policy})
        try:
            status, answer = _call("GET", url, self._token, None, self._timeout)
            if status != 200:
                self._raise_for(status, answer)
            acts = answer.get("acts")
            if not isinstance(acts, list):
                raise RemoteUnavailable("history has no acts array")
            return [_act(a) for a in acts]
        except PolicyMismatch:
            raise
        except Exception as exc:
            # Unreachable, unauthenticated, malformed: the PDP cannot
            # establish the history, so it fails closed.
            raise HistoryUnavailable(str(exc)) from exc


def request_to_json(request: EvaluationRequest) -> dict[str, Any]:
    """The Access Evaluation request body for ``request``."""
    context: dict[str, Any] = dict(request.context)
    if request.mission is not None:
        context["mission"] = {"id": request.mission.id, "issuer": request.mission.issuer}
    context["supported_mandatory_extensions"] = list(request.supported_mandatory_extensions)
    context["supported_obligations"] = list(request.supported_obligations)
    return {
        "subject": {"type": request.subject.type, "id": request.subject.id,
                    "properties": dict(request.subject.properties)},
        "action": {"name": request.action.name, "properties": dict(request.action.properties)},
        "resource": {"type": request.resource.type, "id": request.resource.id,
                     "properties": dict(request.resource.properties)},
        "context": context,
    }


def decision_from_json(body: dict[str, Any]) -> Decision:
    """A ``Decision`` from an Access Evaluation response body. Raises
    ``RemoteUnavailable`` if it is not one."""
    decision = body.get("decision")
    if not isinstance(decision, bool):
        raise RemoteUnavailable("response has no boolean decision")
    ctx = body.get("context", {})
    if not isinstance(ctx, dict):
        raise RemoteUnavailable("response context is not an object")
    ctx = dict(ctx)
    reason = ctx.pop("reason", None)
    evaluation_id = ctx.pop("evaluation_id", None)
    access_request = ctx.pop("access_request", None)
    if "obligations" in ctx and not (
            isinstance(ctx["obligations"], list) and ctx["obligations"]
            and all(isinstance(o, dict) and isinstance(o.get("id"), str)
                    and isinstance(o.get("type"), str)
                    and isinstance(o.get("properties"), dict)
                    for o in ctx["obligations"])):
        # Obligations Core: the member is a non-empty array of
        # Obligation objects, each with id, type and properties; anything
        # else is malformed, and the PEP must not act on it.
        raise RemoteUnavailable("malformed obligations")
    raw_obligations = ctx.pop("obligations", [])
    obligations = tuple(
        Obligation(id=o["id"], type=o["type"], properties=dict(o["properties"]))
        for o in raw_obligations
    )
    if not (
        (reason is None or isinstance(reason, str))
        and (evaluation_id is None or isinstance(evaluation_id, str))
        and (access_request is None or isinstance(access_request, dict))
    ):
        raise RemoteUnavailable("malformed decision context")
    return Decision(decision=decision, reason=reason, obligations=obligations,
                    access_request=access_request, context=ctx,
                    evaluation_id=evaluation_id)


class RemotePDP:
    """A PDP reached over the AuthZEN Access Evaluation API."""

    def __init__(self, base_url: str, token: str, timeout: float = 5.0) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def evaluate(self, request: EvaluationRequest) -> Decision:
        status, body = _call("POST", f"{self._base}/access/v1/evaluation", self._token,
                             request_to_json(request), self._timeout)
        if status != 200:
            # Not a decision. The PEP must not act on it.
            raise RemoteUnavailable(f"HTTP {status}: {body.get('error', '')}")
        return decision_from_json(body)

    def issues_mission_record(self) -> bool:
        """Whether the PDP's metadata lists ``mission_record`` in
        ``supported_obligations``. A PEP sends a request that carries a
        Mission only to such a PDP (profile, PEP processing rules): one that
        does not implement the profile would permit without it. An unreadable
        answer is a no."""
        try:
            status, meta = _call("GET", f"{self._base}/.well-known/authzen-configuration",
                                 self._token, None, self._timeout)
        except RemoteUnavailable:
            return False
        supported = meta.get("supported_obligations") if status == 200 else None
        return isinstance(supported, list) and "mission_record" in supported


class AccessRequestRefused(Exception):
    """The Access Request Service answered with an ARAP problem (RFC 9457)
    or refused the caller. ``problem`` is the problem type's last segment
    (``not_requestable``, ``expired_denial`` ...) or ``None``."""

    def __init__(self, status: int, problem: str | None, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.problem = problem


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def _may_receive_credential(url: str, trusted_origins: frozenset[str] | None) -> bool:
    """ARAP "Check the URLs": the endpoint is an HTTPS URI (plain HTTP only to
    this machine), names no user information, and, when the deployment lists
    trusted origins, is on one of them."""
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None or not parts.hostname:
        return False
    if parts.scheme != "https" and not (parts.scheme == "http"
                                        and parts.hostname in _LOOPBACK):
        return False
    return trusted_origins is None or _origin(url) in trusted_origins


class AccessRequestClient:
    """The PEP side of ARAP (PEP Processing): submit an Access Request for a
    requestable denial, and read its task until a person has decided.

    The Access Request Endpoint is the one the PDP publishes in its
    metadata. Every URL the service returns must have the same origin, so an
    autonomous PEP never sends its credential elsewhere (ARAP "Check the
    URLs").
    """

    def __init__(self, endpoint: str, token: str, timeout: float = 5.0) -> None:
        self.endpoint = endpoint
        self._token = token
        self._timeout = timeout

    @classmethod
    def discover(cls, pdp_base_url: str, token: str, timeout: float = 5.0,
                 trusted_origins: frozenset[str] | None = None
                 ) -> AccessRequestClient | None:
        """From the PDP's metadata; None if it publishes no endpoint, or one
        this PEP may not send its credential to: not HTTPS (plain HTTP only to
        this machine), with user information, or, when the deployment lists
        ``trusted_origins``, on none of them."""
        status, meta = _call("GET", pdp_base_url.rstrip("/")
                             + "/.well-known/authzen-configuration", token, None, timeout)
        endpoint = meta.get("access_request_endpoint") if status == 200 else None
        if not (isinstance(endpoint, str)
                and _may_receive_credential(endpoint, trusted_origins)):
            return None
        return cls(endpoint, token, timeout)

    def _check(self, status: int, answer: dict[str, Any]) -> dict[str, Any]:
        if status in (200, 201, 202):
            task = answer.get("task")
            if not (isinstance(task, dict) and isinstance(task.get("id"), str)
                    and isinstance(task.get("status"), str)
                    and isinstance(task.get("status_endpoint"), str)):
                raise RemoteUnavailable("answer has no task handle")
            if _origin(task["status_endpoint"]) != _origin(self.endpoint):
                raise AccessRequestRefused(status, None, "status endpoint on another origin")
            return answer
        kind = answer.get("type")
        problem = (kind.rsplit(":", 1)[-1]
                   if isinstance(kind, str) and kind.startswith(
                       "urn:openid:authzen:access-request:error:") else None)
        raise AccessRequestRefused(status, problem,
                                   str(answer.get("detail") or answer.get("error") or ""))

    def submit(self, request: EvaluationRequest, decision: Decision,
               idempotency_key: str) -> dict[str, Any]:
        """Submit an Access Request for the requestable denial ``decision``
        of ``request`` (ARAP "Construct the Submission"): the denied
        Subject, Resource, Action and Context unchanged, and every ``denial``
        member the PDP supplied, echoed."""
        if decision.decision or decision.access_request is None:
            raise ValueError("only a requestable denial can be submitted")
        body = request_to_json(request)
        denial: dict[str, Any] = {"expires_at": decision.access_request.get("expires_at")}
        if decision.evaluation_id is not None:
            denial["evaluation_id"] = decision.evaluation_id
        if decision.reason is not None:
            denial["reason"] = decision.reason
        for member in ("binding_token", "template"):
            if member in decision.access_request:
                denial[member] = decision.access_request[member]
        body["denial"] = denial
        status, answer = _call("POST", self.endpoint, self._token, body, self._timeout,
                               headers={"Idempotency-Key": idempotency_key})
        return self._check(status, answer)

    def status(self, task: dict[str, Any]) -> dict[str, Any]:
        """The task's current state, from its ``status_endpoint``."""
        endpoint = task.get("status_endpoint")
        if not isinstance(endpoint, str) or _origin(endpoint) != _origin(self.endpoint):
            raise AccessRequestRefused(0, None, "status endpoint on another origin")
        status, answer = _call("GET", endpoint, self._token, None, self._timeout)
        return self._check(status, answer)

    @staticmethod
    def approval(answer: dict[str, Any]) -> dict[str, Any] | None:
        """The approval to present at re-evaluation, or None: only an
        ``approved`` task with a ``reevaluate`` result carries one (ARAP
        "Handle Completion"); any other status or mode is not an approval."""
        task, result = answer.get("task"), answer.get("result")
        if not (isinstance(task, dict) and task.get("status") == "approved"
                and isinstance(result, dict) and result.get("mode") == "reevaluate"):
            return None
        approval = result.get("approval")
        return approval if isinstance(approval, dict) else None
