"""Run one component of the end-to-end deployment as its own process.

    python -m e2e.serve <config.json>

Roles: ``mhs`` (History Authority over the MHS HTTP binding), ``pdp`` (the
composition PDP over the Access Evaluation API, reading history from the MHS
over HTTP), ``tool`` (a resource with its PEP in front, talking to the PDP and
the MHS over HTTP) and ``flaky`` (a proxy that commits an admission and then
loses its acknowledgement). Every server binds 127.0.0.1 only and prints
``READY <port>`` once it listens.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from authzen_composition.arap import AccessRequestService
from authzen_composition.http_binding import MHSHttpApp, StartResponse, StaticTokenAuthenticator
from authzen_composition.mhs import (
    MissionHistoryService,
    NotPermitted,
    OutcomeAlreadySet,
    UnknownAct,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pdp_http import REQUESTS_PATH, PDPHttpApp
from authzen_composition.pep import ReferencePEP
from authzen_composition.remote import AccessRequestClient, RemoteHistoryAuthority, RemotePDP
from e2e.policies import POLICIES
from e2e.tools import DocStore, HRStore, Ledger, ToolHost, classifier_for, http_doc_reader

App = Any

# Client timeout for every hop inside the deployment (PEP -> PDP, PDP -> MHS,
# proxy -> MHS). The library default (5 s) suits a quiet network; the harness
# runs a dozen concurrent Missions, often next to other test runs, and a hop
# that timed out there would fail closed and fail a scenario for load, not for
# behavior. Outages in A13 answer 503 at once and never wait on it.
HOP_TIMEOUT = 20.0


class _ThreadingServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    # The default listen backlog (5) refuses connections when a dozen agents
    # call at once; a refused read is a fail-closed history_unavailable.
    request_queue_size = 128


class _QuietHandler(WSGIRequestHandler):
    # A caller that stalls its request holds a worker thread; time it out.
    timeout = 30

    def get_environ(self) -> dict[str, Any]:
        # Keep the raw request target, as gunicorn (RAW_URI) does, so the MHS
        # binding can address a Mission id that contains '/' (a URI).
        env: dict[str, Any] = super().get_environ()
        env["RAW_URI"] = self.path
        return env

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


def _json(start_response: StartResponse, status: str, body: dict[str, Any]) -> Iterable[bytes]:
    start_response(status, [("Content-Type", "application/json")])
    return [json.dumps(body).encode("utf-8")]


def _body(environ: dict[str, Any]) -> dict[str, Any]:
    length = int(environ.get("CONTENT_LENGTH") or 0)
    data = json.loads(environ["wsgi.input"].read(length) or b"{}")
    return data if isinstance(data, dict) else {}


def build_mhs(cfg: dict[str, Any]) -> App:
    """The MHS binding, plus a separate operator interface for closing a
    stranded Act (the binding has none, by design; see the MHS document)."""
    operators = StaticTokenAuthenticator(cfg.get("operator_tokens", {}))
    mhs = MissionHistoryService(trusted_writers=frozenset(cfg["writers"]),
                                operators=frozenset(cfg.get("operator_tokens", {}).values()))
    binding = MHSHttpApp(mhs, StaticTokenAuthenticator(cfg["tokens"]),
                         pdps=frozenset(cfg.get("pdps", ())),
                         auditors=frozenset(cfg.get("auditors", ())))

    def app(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        if not path.startswith("/operator/"):
            return binding(environ, start_response)
        operator = operators(environ)
        if not operator:
            return _json(start_response, "401 Unauthorized", {"error": "operator only"})
        # POST /operator/close {"mission": ..., "seq": n}
        req = _body(environ)
        try:
            mission, seq = str(req["mission"]), int(req["seq"])
        except (KeyError, TypeError, ValueError):
            return _json(start_response, "400 Bad Request",
                         {"error": "mission and seq are required"})
        try:
            act = mhs.close_stranded(mission, seq, operator)
        except NotPermitted as exc:
            return _json(start_response, "403 Forbidden", {"error": str(exc)})
        except (UnknownAct, OutcomeAlreadySet) as exc:
            return _json(start_response, "409 Conflict", {"error": str(exc)})
        return _json(start_response, "200 OK", {"seq": act.seq, "outcome": act.outcome.value})

    return app


def build_pdp(cfg: dict[str, Any]) -> App:
    policy = POLICIES[cfg["policy"]]
    if cfg.get("sabotage") == "no_rule5":
        # Red check only: a PDP that skips the effect-order rule (rule 5).
        # Frozen dataclass, so patch the instance through object.__setattr__.
        object.__setattr__(policy, "pending_conflict", lambda history, candidate: False)
    # The PDP plays ARAP's Access Request Service itself, at its own address
    # (plain HTTP on the loopback address, for this harness only).
    endpoint = cfg["self_url"] + REQUESTS_PATH
    pdp = CompositionPDP(policy=policy,
                         mhs=RemoteHistoryAuthority(cfg["mhs_url"], cfg["mhs_token"],
                                                    timeout=HOP_TIMEOUT),
                         access_request_endpoint=endpoint, allow_loopback_http=True)
    ars = AccessRequestService(pdp, submitters=frozenset(cfg["pep_tokens"].values()),
                               approvers=frozenset(cfg["approver_tokens"].values()))
    return PDPHttpApp(pdp, StaticTokenAuthenticator(cfg["pep_tokens"]),
                      StaticTokenAuthenticator(cfg["approver_tokens"]),
                      base_url=cfg["self_url"], access_requests=ars)


def build_tool(cfg: dict[str, Any]) -> App:
    kind = cfg["kind"]
    hr = HRStore() if kind == "hr" else None
    docs = DocStore() if kind == "docs" else None
    remote_pdp = RemotePDP(cfg["pdp_url"], cfg["pdp_token"], timeout=HOP_TIMEOUT)
    if not remote_pdp.issues_mission_record():
        # A PDP without the profile would ignore the Mission and permit
        # without mission_record (profile, PEP processing rules).
        raise SystemExit(f"{cfg['name']}: the PDP does not advertise mission_record")
    pep = ReferencePEP(pdp=remote_pdp,
                       mhs=RemoteHistoryAuthority(cfg["mhs_url"], cfg["mhs_token"],
                                                  timeout=HOP_TIMEOUT),
                       writer_id=cfg["name"], classifier=classifier_for(kind, hr))
    host = ToolHost(
        name=cfg["name"], kind=kind, pep=pep, issuer_key=bytes.fromhex(cfg["issuer_key"]),
        ledger=Ledger(Path(cfg["ledger"])), hr=hr, docs=docs,
        doc_reader=http_doc_reader(cfg["docs_url"]) if cfg.get("docs_url") else None,
        queue_delay=float(cfg.get("queue_delay", 0)),
        manual_queue=bool(cfg.get("manual_queue", False)),
        expand_lists=bool(cfg.get("expand_lists", True)),
        # The Access Request Endpoint the PDP publishes in its metadata.
        access_requests=AccessRequestClient.discover(cfg["pdp_url"], cfg["pdp_token"],
                                                     HOP_TIMEOUT),
        allow_crash=bool(cfg.get("allow_crash", False)),
    )

    def app(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        method, path = environ["REQUEST_METHOD"], environ.get("PATH_INFO", "")
        if method == "POST" and path == "/tools/call":
            auth = environ.get("HTTP_AUTHORIZATION", "")
            token = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else ""
            req = _body(environ)
            args = req.get("arguments", {})
            result = host.call(token, str(req.get("name", "")),
                               args if isinstance(args, dict) else {})
            return _json(start_response, "200 OK", result)
        if method == "GET" and path.startswith("/internal/doc/") and docs is not None:
            # Resource-to-resource, for delivery by reference. Not an agent tool.
            return _json(start_response, "200 OK",
                         {"content": docs.read(path.removeprefix("/internal/doc/"))})
        if method == "POST" and path == "/_release":
            # Run control, not an agent tool: deliver what is queued.
            host.release.set()
            return _json(start_response, "200 OK", {"released": True})
        return _json(start_response, "404 Not Found", {"error": "unknown route"})

    return app


def build_flaky(cfg: dict[str, Any]) -> App:
    """A proxy in front of the MHS that misbehaves in the ways a network and
    a replica do:

    * the first ``fail_first`` admissions are committed upstream, then
      answered 500: the acknowledgement is lost;
    * ``POST /_control {"down": true}`` makes every forwarded call fail until
      ``{"down": false}``: an outage between this PEP and the authority;
    * with ``stale`` set, history reads omit the latest Act: a lagging replica.
    """
    state: dict[str, Any] = {"left": int(cfg.get("fail_first", 0)), "down": False}
    stale = bool(cfg.get("stale", False))
    target = cfg["target"].rstrip("/")

    def app(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        method, path = environ["REQUEST_METHOD"], environ.get("PATH_INFO", "")
        if path == "/_control" and method == "POST":
            state["down"] = bool(_body(environ).get("down"))
            return _json(start_response, "200 OK", {"down": state["down"]})
        if state["down"]:
            return _json(start_response, "503 Service Unavailable", {"error": "outage"})
        query = environ.get("QUERY_STRING", "")
        length = int(environ.get("CONTENT_LENGTH") or 0)
        data = environ["wsgi.input"].read(length) if length else None
        req = urllib.request.Request(target + path + (f"?{query}" if query else ""),
                                     data=data, method=method)
        if environ.get("HTTP_AUTHORIZATION"):
            req.add_header("Authorization", environ["HTTP_AUTHORIZATION"])
        if environ.get("CONTENT_TYPE"):
            req.add_header("Content-Type", environ["CONTENT_TYPE"])
        try:
            with urllib.request.urlopen(req, timeout=HOP_TIMEOUT) as resp:
                status, raw = f"{resp.status} {resp.reason}", resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = f"{exc.code} {exc.reason}", exc.read()
        if method == "POST" and path.endswith("/acts") and state["left"] > 0:
            state["left"] -= 1
            return _json(start_response, "500 Internal Server Error",
                         {"error": "acknowledgement lost"})
        if stale and method == "GET" and status.startswith("200"):
            body = json.loads(raw)
            # A replica that has not yet seen the latest admission: the view
            # is well formed (positions 1 to n-1) but one Act behind.
            body["acts"] = body["acts"][:-1]
            body["next_seq"] = len(body["acts"]) + 1
            raw = json.dumps(body).encode("utf-8")
        start_response(status, [("Content-Type", "application/json")])
        return [raw]

    return app


BUILDERS = {"mhs": build_mhs, "pdp": build_pdp, "tool": build_tool, "flaky": build_flaky}


def main() -> None:
    cfg = json.loads(Path(sys.argv[1]).read_text("utf-8"))
    server = make_server("127.0.0.1", 0, lambda environ, start_response: [],
                         server_class=_ThreadingServer, handler_class=_QuietHandler)
    # Built once the port is known: the PDP publishes its own address.
    cfg["self_url"] = f"http://127.0.0.1:{server.server_port}"
    server.set_app(BUILDERS[cfg["role"]](cfg))
    print(f"READY {server.server_port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
