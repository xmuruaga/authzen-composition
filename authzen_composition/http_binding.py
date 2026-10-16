"""Minimal HTTP binding for the MHS (see docs/mission-history-service.md).

A thin, framework-free WSGI application over ``MissionHistoryService`` so that
independent PEPs, PDPs and MHSs interoperate:

* ``POST   /missions/{id}/acts``            -> 201 if seq is next, 409 on conflict
* ``PATCH  /missions/{id}/acts/{n}``        -> set outcome once, from open
* ``GET    /missions/{id}/acts``            -> ordered history + next position

The writer identity comes from an ``Authenticator`` the deployment supplies,
for example one that verifies a workload credential (mTLS client certificate,
a signed workload token). The identity is recorded by the service and is never
read from the request body. The binding ships no default authenticator, so it
cannot be deployed with the identity taken on trust.
``StaticTokenAuthenticator`` maps opaque secrets to writer identities; it is a
test stand-in for a real credential check.
"""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any, TypeAlias
from urllib.parse import parse_qs, unquote

from authzen_composition.mhs import (
    HistoryConflict,
    MissionHistoryService,
    NotPermitted,
    OutcomeAlreadySet,
    PolicyMismatch,
    UnauthenticatedWriter,
    UnknownAct,
)
from authzen_composition.model import Act, ActOutcome

StartResponse: TypeAlias = Callable[[str, list[tuple[str, str]]], Any]
# Returns the authenticated writer identity, or "" if the caller is not
# authenticated.
Authenticator: TypeAlias = Callable[[dict[str, Any]], str]


class StaticTokenAuthenticator:
    """Maps bearer secrets to writer identities (test stand-in).

    The token is a secret, not the identity: knowing a writer's name does not
    let a caller act as that writer.
    """

    def __init__(self, tokens: Mapping[str, str]) -> None:
        self._tokens = dict(tokens)

    def __call__(self, environ: dict[str, Any]) -> str:
        header = environ.get("HTTP_AUTHORIZATION", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return ""
        presented = header[len(prefix):]
        for token, writer in self._tokens.items():
            if hmac.compare_digest(token, presented):
                return writer
        return ""


def _act_to_json(act: Act, recorded_by: str) -> dict[str, Any]:
    return {
        "seq": act.seq,
        "action": {"name": act.action},
        "resource": {"id": act.resource},
        "outcome": act.outcome.value,
        "result_classes": sorted(act.result_classes),
        "recorded_by": recorded_by,
    }


# Requests larger than this are rejected before they are read.
MAX_BODY_BYTES = 64 * 1024
# Requests nested deeper than this are rejected once read, before parsing.
MAX_BODY_DEPTH = 64
_SEQ_SEGMENT = re.compile(r"[1-9][0-9]{0,17}")
# Set in the WSGI environ once the request body has been consumed.
_BODY_READ = "authzen_composition.body_read"


def discard_unread_body(environ: dict[str, Any]) -> None:
    """Consume a request body the answer did not need (a 401 or 404 decided
    before the body was read). A server that answers with the body unread can
    close the socket with a reset, and the client then sees a lost connection
    instead of the answer (on Windows, ``ConnectionAbortedError`` instead of
    a 401). Bounded by ``MAX_BODY_BYTES``: a larger declared body is not
    read, and that client may see the reset. A client that declares a body
    and then stalls holds the worker until the server's socket timeout, as
    it already could while sending headers; a production front end bounds
    both."""
    if environ.get(_BODY_READ):
        return
    raw = environ.get("CONTENT_LENGTH") or "0"
    stream = environ.get("wsgi.input")
    if (stream is not None and isinstance(raw, str) and raw.isascii() and raw.isdigit()
            and 0 < int(raw) <= MAX_BODY_BYTES):
        stream.read(int(raw))
    environ[_BODY_READ] = True


_MALFORMED_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def path_segments(environ: dict[str, Any]) -> list[str]:
    """The non-empty segments of the request path below the app's mount
    point, each percent-decoded on its own.

    A Mission id is one segment with every reserved character encoded, so a
    URI id keeps its ``/`` as ``%2F``. WSGI decodes ``PATH_INFO`` before the
    app sees it, which turns that ``%2F`` into a separator, so the segments
    are taken from the raw request target when the server provides it
    (``RAW_URI``, or ``REQUEST_URI``), minus the segments of ``SCRIPT_NAME``.
    Without it, ``PATH_INFO`` is split as is, and an id containing ``/``
    cannot be addressed (its requests are ``404``).
    """
    raw = environ.get("RAW_URI") or environ.get("REQUEST_URI")
    if not (isinstance(raw, str) and raw.startswith("/")):
        return [p for p in environ.get("PATH_INFO", "").split("/") if p]
    mount = len([p for p in environ.get("SCRIPT_NAME", "").split("/") if p])
    target = raw.split("?", 1)[0]
    # A malformed escape or invalid UTF-8 is a 400, never a guessed id: unquote
    # keeps a malformed escape as it is, so "a%zz" and "a%25zz" would name the
    # same Mission.
    if _MALFORMED_ESCAPE.search(target):
        raise ValueError("malformed percent-escape in the request target")
    if not target.isascii():
        # RFC 3986: every other octet is percent-encoded. Read raw, UTF-8
        # bytes would name another Mission than the same id encoded.
        raise ValueError("the request target must be ASCII, percent-encoded")
    return [unquote(p, errors="strict") for p in target.split("/") if p][mount:]


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Two parsers that keep a different copy of a duplicated key would read
    # different requests from the same bytes.
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate member {key!r}")
        out[key] = value
    return out


def nonempty_string(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty string")
    return value


# A PEP reports only these; "open" is the state before any report.
_REPORTABLE_OUTCOMES = frozenset({ActOutcome.COMPLETED.value, ActOutcome.FAILED.value})


def read_json_body(environ: dict[str, Any]) -> dict[str, Any]:
    """The request body as a JSON object, read strictly: a valid
    Content-Length within ``MAX_BODY_BYTES``, UTF-8, no duplicate member, no
    NaN or Infinity. Anything else is a ``ValueError``, answered with 400."""
    if "HTTP_TRANSFER_ENCODING" in environ:
        # A body is framed by Content-Length alone: with Transfer-Encoding as
        # well, a proxy and this service could disagree on where it ends.
        raise ValueError("Transfer-Encoding is not supported")
    raw_length = environ.get("CONTENT_LENGTH") or "0"
    if not (isinstance(raw_length, str) and raw_length.isascii() and raw_length.isdigit()):
        raise ValueError("invalid Content-Length")
    length = int(raw_length)
    if length > MAX_BODY_BYTES:
        raise ValueError("body too large")
    raw = environ["wsgi.input"].read(length) if length else b""
    environ[_BODY_READ] = True
    if len(raw) != length:
        raise ValueError("body shorter than Content-Length")
    if not raw:
        raise ValueError("body must be a JSON object")
    text = raw.decode("utf-8")
    # Checked before parsing: how deep the JSON parser itself can recurse
    # depends on the platform's stack, and later processing (canonical
    # digests, comparisons) recurses into the body.
    if _depth(text) > MAX_BODY_DEPTH:
        raise ValueError("body nested too deeply")
    data = json.loads(text, object_pairs_hook=_unique_keys, parse_constant=_reject_constant)
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    return data


# A JSON string, or one bracket outside any string.
_STRING_OR_BRACKET = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]', re.DOTALL)


def _depth(text: str) -> int:
    """How many objects and arrays deep a JSON text nests, read without parsing
    it, so malformed and unterminated text counts too."""
    deepest = level = 0
    for match in _STRING_OR_BRACKET.finditer(text):
        token = match.group()
        if token in "[{":
            level += 1
            deepest = max(deepest, level)
        elif token in "]}":
            level -= 1
    return deepest


def _member(body: dict[str, Any], key: str, inner: str) -> str:
    obj = body.get(key)
    if not isinstance(obj, dict):
        raise ValueError(f"{key} must be an object")
    return nonempty_string(obj.get(inner), f"{key}.{inner}")


def _seq(value: Any) -> int:
    # bool is an int in Python; a JSON true is not a position.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("seq must be a positive integer")
    return int(value)


def _classes(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise ValueError("result_classes must be an array of strings")
    return frozenset(nonempty_string(c, "result_classes[]") for c in value)


class MHSHttpApp:
    """A WSGI app exposing one MissionHistoryService.

    ``pdps`` are the identities whose reads may name a policy digest, and so
    pin the Mission's set of Restricted Sequences (profile, History Authority
    items 5 and 6: the first *PDP* read pins). Any other caller that names
    one gets ``403``: a PEP that could pin would make the deployment's PDPs
    refuse the Mission, or, mid-rollout, bind it to an older set.

    Only those PDPs and the ``auditors`` read a Mission's history at all. A
    history holds every Act's action, resource and classes, which can be
    personal data (an employee id, a recipient's address); a writer has no
    need to read it. Neither read set has a permissive default. Writers do:
    a ``MissionHistoryService`` with no ``trusted_writers`` accepts any
    authenticated identity as a writer, PDPs and auditors included, so a
    deployment configures its writers.

    A missing or invalid credential is a ``401`` with a ``WWW-Authenticate``
    challenge; an authenticated identity that may not do what it asks is a
    ``403`` (RFC 9110).
    """

    def __init__(self, mhs: MissionHistoryService, authenticate: Authenticator,
                 pdps: frozenset[str] = frozenset(),
                 auditors: frozenset[str] = frozenset()) -> None:
        self._mhs = mhs
        self._authenticate = authenticate
        self._pdps = pdps
        self._auditors = auditors

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")
        writer = self._authenticate(environ)
        headers = [("Content-Type", "application/json")]
        try:
            status, body = self._route(method, path, writer, environ)
        except NotPermitted as exc:
            # Authenticated, but not allowed this (RFC 9110, 403).
            status, body = "403 Forbidden", {"error": str(exc)}
        except UnauthenticatedWriter as exc:
            # No valid credential: RFC 9110 requires a challenge with a 401.
            status, body = "401 Unauthorized", {"error": str(exc)}
            headers.append(("WWW-Authenticate", "Bearer"))
        except HistoryConflict as exc:
            # The ``reason`` lets a remote client tell the two 409s apart
            # without parsing the human-readable ``error``.
            status, body = "409 Conflict", {"error": str(exc), "reason": "seq_conflict"}
        except (UnknownAct, OutcomeAlreadySet) as exc:
            status, body = "409 Conflict", {"error": str(exc), "reason": "outcome_conflict"}
        except (KeyError, ValueError) as exc:
            status, body = "400 Bad Request", {"error": str(exc)}
        payload = json.dumps(body).encode("utf-8")
        discard_unread_body(environ)
        start_response(status, headers)
        return [payload]

    @staticmethod
    def _require_identity(identity: str) -> None:
        # Authenticate before reading the body, so an unauthenticated caller
        # learns nothing, not even whether its request was well formed.
        if not identity:
            raise UnauthenticatedWriter("authentication is required")

    def _route(
        self, method: str, path: str, writer: str, environ: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        # Authenticate before routing, so an unauthenticated caller cannot
        # tell a known route from an unknown one or a valid method from an
        # invalid one: every request without a credential is a 401.
        self._require_identity(writer)
        parts = path_segments(environ)
        # /missions/{id}/acts  or  /missions/{id}/acts/{n}
        if not (3 <= len(parts) <= 4) or parts[0] != "missions" or parts[2] != "acts":
            return "404 Not Found", {"error": "unknown route"}
        mission_id = parts[1]

        if len(parts) == 3 and method == "POST":
            body = read_json_body(environ)
            seq = _seq(body.get("seq"))
            action = _member(body, "action", "name")
            resource = _member(body, "resource", "id")
            admission_id = body.get("admission_id")
            act = self._mhs.admit(
                mission_id, seq, action, resource, writer=writer,
                admission_id=(
                    None if admission_id is None else nonempty_string(admission_id, "admission_id")
                ),
            )
            return "201 Created", _act_to_json(act, writer)

        if len(parts) == 3 and method == "GET":
            # Reads are authenticated too: the history reveals what the agent
            # did and which classes of data it touched (authenticated above).
            # A PDP names the set of Restricted Sequences it applies in the
            # ``policy`` query parameter; the first such read pins it.
            if writer not in self._pdps | self._auditors:
                raise NotPermitted("only a PDP or an auditor may read a Mission's history")
            query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True,
                             max_num_fields=8)
            policies = query.get("policy", [])
            if len(policies) > 1 or (policies and not policies[0]):
                raise ValueError("policy must be given at most once and be non-empty")
            if policies and writer not in self._pdps:
                raise NotPermitted("only a PDP may name the policy of a Mission")
            try:
                history = self._mhs.history(mission_id, policy=policies[0] if policies else None)
            except PolicyMismatch as exc:
                return "409 Conflict", {"error": str(exc), "reason": "policy_mismatch"}
            return "200 OK", {
                "acts": [
                    _act_to_json(a, self._mhs.recorded_by(mission_id, a.seq))
                    for a in history
                ],
                # From the same read: positions are gapless, so the next one
                # follows the last, even if another Act was admitted since.
                "next_seq": len(history) + 1,
            }

        if len(parts) == 4 and method == "PATCH":
            if not _SEQ_SEGMENT.fullmatch(parts[3]):
                raise ValueError("act position must be a positive decimal integer")
            seq = int(parts[3])
            body = read_json_body(environ)
            name = nonempty_string(body.get("outcome"), "outcome")
            if name not in _REPORTABLE_OUTCOMES:
                raise ValueError("outcome must be 'completed' or 'failed'")
            outcome = ActOutcome(name)
            classes = _classes(body.get("result_classes"))
            admission_id = body.get("admission_id")
            act = self._mhs.set_outcome(
                mission_id, seq, outcome, writer=writer, result_classes=classes,
                admission_id=(
                    None if admission_id is None else nonempty_string(admission_id, "admission_id")
                ),
            )
            return "200 OK", _act_to_json(act, self._mhs.recorded_by(mission_id, seq))

        return "405 Method Not Allowed", {"error": f"{method} not allowed on {path}"}
