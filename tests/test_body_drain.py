"""Both HTTP apps consume a request body they answer without needing.

An answer sent with the body unread can reach the client as a connection reset
instead of the answer (on Windows, ``ConnectionAbortedError`` instead of a 401).
These tests check the drain directly on the WSGI ``environ``, so they do not
depend on socket timing.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from authzen_composition.arap import AccessRequestService
from authzen_composition.http_binding import (
    MAX_BODY_BYTES,
    MHSHttpApp,
    StaticTokenAuthenticator,
    discard_unread_body,
)
from authzen_composition.mhs import MissionHistoryService
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pdp_http import PDPHttpApp
from authzen_composition.scenarios import EXFIL_POLICY


def _environ(method: str, path: str, body: bytes, token: str = "",
             length: str | None = None) -> dict[str, Any]:
    env: dict[str, Any] = {"REQUEST_METHOD": method, "PATH_INFO": path,
                           "CONTENT_LENGTH": str(len(body)) if length is None else length,
                           "wsgi.input": io.BytesIO(body)}
    if token:
        env["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return env


def _call(app: Any, env: dict[str, Any]) -> str:
    seen: list[str] = []
    app(env, lambda status, headers: seen.append(status))
    return seen[0]


def _apps() -> list[Any]:
    mhs = MissionHistoryService(trusted_writers=frozenset({"w"}))
    auth = StaticTokenAuthenticator({"t": "w"})
    pdp = CompositionPDP(policy=EXFIL_POLICY, mhs=mhs,
                         access_request_endpoint="https://pdp.example/access/v1/requests")
    ars = AccessRequestService(pdp, submitters=frozenset({"w"}), approvers=frozenset())
    return [MHSHttpApp(mhs, auth),
            PDPHttpApp(pdp, auth, StaticTokenAuthenticator({}), access_requests=ars)]


BODY = json.dumps({"pad": "x" * 10_000}).encode()


CASES = [
    # (app, credential, path, status answered before the body is needed)
    (0, "", "/missions/m/acts", "401"),
    (0, "t", "/nowhere/at/all/here/x", "404"),
    (1, "", "/access/v1/evaluation", "401"),
    (1, "", "/approvals/v1/tasks/arq_x", "401"),
    (1, "", "/access/v1/requests", "401"),
    (1, "t", "/nowhere", "404"),
]


@pytest.mark.parametrize("which, token, path, status", CASES)
def test_an_early_answer_still_consumes_the_body(which: int, token: str, path: str,
                                                 status: str) -> None:
    env = _environ("POST", path, BODY, token)
    assert _call(_apps()[which], env).startswith(status)
    assert env["wsgi.input"].tell() == len(BODY)


def test_discard_reads_a_body_once_and_never_more_than_the_cap() -> None:
    env = _environ("POST", "/", b"abc")
    discard_unread_body(env)
    assert env["wsgi.input"].tell() == 3
    one = _environ("POST", "/", b"a")              # the smallest body is drained too
    discard_unread_body(one)
    assert one["wsgi.input"].tell() == 1
    env["wsgi.input"] = io.BytesIO(b"zzz")
    discard_unread_body(env)                      # already consumed: no second read
    assert env["wsgi.input"].tell() == 0
    big = _environ("POST", "/", b"y" * 10, length=str(MAX_BODY_BYTES + 1))
    discard_unread_body(big)
    assert big["wsgi.input"].tell() == 0
    for bad in ("", "-1", "1e3", "\u00b2"):
        env = _environ("POST", "/", b"abc", length=bad)
        discard_unread_body(env)
        assert env["wsgi.input"].tell() == 0
    no_stream = {"CONTENT_LENGTH": "3"}
    discard_unread_body(no_stream)              # no input stream: nothing to read
    assert no_stream[next(k for k in no_stream if k != "CONTENT_LENGTH")] is True


def test_a_body_the_route_read_is_not_read_again() -> None:
    mhs_app, _ = _apps()
    body = json.dumps({"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"}}).encode()
    stream = io.BytesIO(body + b"TRAILING")
    env = _environ("POST", "/missions/m/acts", body, "t")
    env["wsgi.input"] = stream
    assert _call(mhs_app, env).startswith("201")
    assert stream.tell() == len(body)
