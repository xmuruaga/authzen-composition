"""Simulated resources behind three PEPs, with an independent ground truth.

Each tool host is a resource (HR records, documents, mail) with the PEP that
guards it in front, the way a gateway sits in front of an MCP-style tool
server. Agents call tools; the PEP evaluates and admits each call; the
resource performs it.

Ground truth comes from the data, not from the policy. Every salary record
carries a unique canary string. Every place where content becomes visible to
an outside party (a delivered mail, a public share link, a write into a
shared document) is logged as an exposure with its full content. The oracle
(``exposures``) then asks one question that does not depend on the profile at
all: did a canary reach an external audience without a person's approval?
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from authzen_composition.pep import (
    CompositionDenied,
    EffectPending,
    NotPerformed,
    ReferencePEP,
)
from authzen_composition.remote import (
    AccessRequestClient,
    AccessRequestRefused,
    RemoteUnavailable,
)
from authzen_composition.types import Action, Resource, Subject
from e2e import missions

CANARY = re.compile(r"CANARY-[A-Za-z0-9-]+")
INTERNAL_DOMAIN = "corp.example"
ISSUER = "https://missions.example"


class Ledger:
    """Append-only log of resource events, in true effect order per process.

    Timestamps are ``time.time_ns()`` on one machine, so entries from several
    processes can be merged into one effect order.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def log(self, **entry: Any) -> None:
        entry["t"] = time.time_ns()
        with self._lock:
            self.entries.append(entry)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")


def read_ledgers(paths: list[Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in paths:
        if p.exists():
            out += [json.loads(line) for line in p.read_text("utf-8").splitlines() if line]
    return sorted(out, key=lambda e: e["t"])


def exposures(entries: list[dict[str, Any]],
              granted: frozenset[tuple[str, str, str | None]] = frozenset()
              ) -> list[dict[str, Any]]:
    """External exposures of a canary that no person approved. Must be empty.

    An exposure the resource logged as approved counts as approved only if a
    person actually granted an approval for that Mission, target and attachment
    (``granted``): the flag the resource logs comes from the request, so the
    oracle does not take it on trust.
    """
    return [
        e for e in entries
        if e.get("kind") == "expose" and e.get("audience") == "external"
        and CANARY.search(e.get("content", ""))
        and not (e.get("approved")
                 and (e.get("mission"), e.get("target"), e.get("attachment")) in granted)
    ]


# --- directory: canonical identifiers (profile, "Canonical identifiers") ----

ALIASES = {"press": "press@partner.example", "boss": "alice@corp.example"}
LISTS = {
    "all-staff": ("alice@corp.example", "bob@corp.example", "press@partner.example"),
    "hr-team": ("alice@corp.example", "bob@corp.example"),
}


def canonical_targets(to: str, *, expand_lists: bool = True) -> list[str]:
    """The canonical recipients of ``to``: aliases resolved, lists expanded to
    members, trust domain first. An address the directory cannot place is
    recorded in the most exposed domain."""
    name = ALIASES.get(to.strip().lower(), to.strip().lower())
    if name in LISTS:
        if not expand_lists:
            return [f"group:{name}"]  # what a non-conforming PEP would record
        return [t for m in LISTS[name] for t in canonical_targets(m)]
    domain = name.rpartition("@")[2]
    return [f"internal:{name}" if domain == INTERNAL_DOMAIN else f"external:{name}"]


# --- resources -----------------------------------------------------------------

@dataclass
class HRStore:
    canaries: dict[str, str] = field(default_factory=dict)

    def record(self, employee: str) -> tuple[str, frozenset[str]]:
        """(content, result classes the HR system assigns)."""
        if employee == "handbook":
            return "Employee handbook: holidays are listed on the intranet.", frozenset({"public"})
        if employee == "notes":
            # Free text the HR system cannot classify: no classes, the top.
            return "Meeting notes: discuss office move.", frozenset()
        canary = self.canaries.setdefault(employee, f"CANARY-{employee}-{secrets.token_hex(4)}")
        return f"Salary of {employee}: 91,000 EUR ({canary})", frozenset({"personal_data.salary"})


@dataclass
class DocStore:
    docs: dict[str, str] = field(default_factory=dict)
    shared: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def read(self, doc: str) -> str:
        with self.lock:
            return self.docs.get(doc, "")


# --- the tool host: PEP in front of one resource ---------------------------------

@dataclass
class ToolHost:
    """One resource with its PEP. ``call`` is what an agent invokes."""

    name: str
    kind: str  # "hr", "docs" or "mail"
    pep: ReferencePEP
    issuer_key: bytes
    ledger: Ledger
    hr: HRStore | None = None
    docs: DocStore | None = None
    # How the mail resource reads a document at delivery time (by reference).
    doc_reader: Callable[[str], str] | None = None
    queue_delay: float = 0.0
    # Queue deliveries until ``release`` is set, instead of for a fixed delay.
    manual_queue: bool = False
    release: threading.Event = field(default_factory=threading.Event)
    expand_lists: bool = True
    allow_crash: bool = False
    # The PEP side of ARAP: on a requestable denial this host submits an
    # Access Request itself and hands the agent the task, never an approval.
    access_requests: AccessRequestClient | None = None
    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)

    def call(self, token: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        # Outcomes the PEP could not record are delivered again (profile, PEP
        # processing rules). Until they land their Acts stay open and hold
        # back the Acts of their sequences.
        self.pep.redeliver()
        claims = missions.verify(self.issuer_key, token)
        if claims is None:
            return {"ok": False, "reason": "invalid_mission_token"}
        # The Mission and the subject come from the verified token only. Any
        # "mission", "result_classes" or similar member in ``args`` is ignored.
        mission, sub = claims["mission"], claims["sub"]
        # An Access Request this host submitted: read its task, and once a
        # person approved it, evaluate again with the approval at
        # context.approval, unchanged (ARAP "Re-evaluate"). An approval
        # object handed in by the caller instead is put there as it is; the
        # PDP trusts none of it but the id it resolves in its own state.
        approval = args.get("approval")
        task_id = args.get("access_request_task")
        if isinstance(task_id, str):
            task = self.tasks.get(task_id)
            if task is None or self.access_requests is None:
                return {"ok": False, "reason": "unknown_access_request"}
            try:
                answer = self.access_requests.status(task)
            except (AccessRequestRefused, RemoteUnavailable, OSError, ValueError) as exc:
                return {"ok": False, "reason": "access_request_unavailable", "error": str(exc)}
            approval = AccessRequestClient.approval(answer)
            if approval is None:
                return {"ok": False, "reason": f"access_request_{answer['task']['status']}"}
        context = {"approval": dict(approval)} if isinstance(approval, dict) else None
        handler = getattr(self, f"_{self.kind}_{tool}", None)
        if handler is None:
            return {"ok": False, "reason": "unknown_tool"}
        try:
            result: dict[str, Any] = handler(mission, sub, args, context)
            return result
        except ValueError as exc:
            return {"ok": False, "reason": "bad_arguments", "error": str(exc)}

    def _enforce(self, mission: str, sub: str, action: str, rtype: str, rid: str,
                 perform: Callable[[], object],
                 context: dict[str, Any] | None,
                 properties: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            raw = self.pep.enforce(
                mission_id=mission, mission_issuer=ISSUER,
                subject=Subject(type="agent", id=sub),
                action=Action(action, dict(properties or {})),
                resource=Resource(type=rtype, id=rid), perform=perform, context=context,
            )
        except CompositionDenied as exc:
            out: dict[str, Any] = {"ok": False, "reason": exc.reason}
            if exc.evaluation_id:
                out["evaluation_id"] = exc.evaluation_id
            if exc.decision is not None and "next_action" in exc.decision.context:
                out["next_action"] = exc.decision.context["next_action"]
            if (self.access_requests is not None and exc.request is not None
                    and exc.decision is not None and exc.decision.access_request is not None):
                try:
                    # One Access Request per denial: a retry of the same
                    # submission finds the same task.
                    answer = self.access_requests.submit(
                        exc.request, exc.decision,
                        exc.decision.evaluation_id or secrets.token_hex(16))
                except (AccessRequestRefused, RemoteUnavailable, OSError, ValueError) as err:
                    out["access_request_error"] = str(err)
                else:
                    self.tasks[answer["task"]["id"]] = answer["task"]
                    out["access_request_task"] = answer["task"]["id"]
            return out
        except NotPerformed as exc:
            return {"ok": False, "reason": "not_performed", "error": str(exc)}
        except Exception as exc:  # PDP or History Authority unreachable
            return {"ok": False, "reason": "unavailable", "error": f"{type(exc).__name__}: {exc}"}
        if isinstance(raw, EffectPending):
            return {"ok": True, "queued": True}
        return {"ok": True, "result": raw}

    # HR ---------------------------------------------------------------------
    def _hr_read_record(self, mission: str, sub: str, args: dict[str, Any],
                        context: dict[str, Any] | None) -> dict[str, Any]:
        assert self.hr is not None
        employee = str(args["employee"])

        def perform() -> object:
            if employee == "crash" and self.allow_crash:
                # The PEP process dies after admission, before any outcome.
                os._exit(3)
            content, _ = self.hr.record(employee)  # type: ignore[union-attr]
            self.ledger.log(kind="read", host=self.name, mission=mission, target=employee,
                            content=content)
            return content

        return self._enforce(mission, sub, "read_record", "hr_record", f"hr:{employee}",
                             perform, context)

    # Docs -------------------------------------------------------------------
    def _docs_write_document(self, mission: str, sub: str, args: dict[str, Any],
                             context: dict[str, Any] | None) -> dict[str, Any]:
        assert self.docs is not None
        store, doc, text = self.docs, str(args["doc"]), str(args["text"])

        def perform() -> object:
            with store.lock:
                store.docs[doc] = text
                shared = doc in store.shared
            self.ledger.log(kind="write", host=self.name, mission=mission, target=doc,
                            content=text)
            if shared:
                # Writing into a publicly shared document exposes the content.
                self.ledger.log(kind="expose", audience="external", host=self.name,
                                mission=mission, target=f"link:{doc}", content=text)
            return "written"

        # What a write puts in the document is part of the request a person
        # approves: the same write with other text is another request.
        written = {"content_digest": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()}
        return self._enforce(mission, sub, "write_document", "document", f"doc:{doc}",
                             perform, context, written)

    def _docs_share_document(self, mission: str, sub: str, args: dict[str, Any],
                             context: dict[str, Any] | None) -> dict[str, Any]:
        assert self.docs is not None
        store, doc = self.docs, str(args["doc"])

        def perform() -> object:
            with store.lock:
                store.shared.add(doc)
                content = store.docs.get(doc, "")
            self.ledger.log(kind="expose", audience="external", host=self.name,
                            mission=mission, target=f"link:{doc}", content=content)
            return f"https://share.example/{doc}"

        return self._enforce(mission, sub, "share_document", "document", f"doc:{doc}",
                             perform, context)

    def _docs_read_document(self, mission: str, sub: str, args: dict[str, Any],
                            context: dict[str, Any] | None) -> dict[str, Any]:
        assert self.docs is not None
        store, doc = self.docs, str(args["doc"])
        return self._enforce(mission, sub, "read_document", "document", f"doc:{doc}",
                             lambda: store.read(doc), context)

    # Mail -------------------------------------------------------------------
    def _mail_send_message(self, mission: str, sub: str, args: dict[str, Any],
                           context: dict[str, Any] | None) -> dict[str, Any]:
        targets = canonical_targets(str(args["to"]), expand_lists=self.expand_lists)
        doc = args.get("doc")
        body = str(args.get("body", ""))
        approved = context is not None
        results = []
        for target in targets:
            def deliver(target: str = target) -> str:
                # The attachment is read at delivery time: by reference.
                attached = self.doc_reader(str(doc)) if doc and self.doc_reader else ""
                content = f"{body}\n{attached}".strip()
                audience = "internal" if target.startswith("internal:") else "external"
                self.ledger.log(kind="expose", audience=audience, host=self.name,
                                mission=mission, target=target, attachment=doc,
                                content=content, approved=approved)
                return "delivered"

            def perform(deliver: Callable[[], str] = deliver, target: str = target) -> object:
                if self.queue_delay <= 0 and not self.manual_queue:
                    return deliver()
                pending = EffectPending()

                def later() -> None:
                    if self.queue_delay > 0:
                        time.sleep(self.queue_delay)
                    else:
                        # Held until the operator of the run releases the
                        # queue, so effect timing is deterministic.
                        self.release.wait()
                    if target.startswith("external:bounce@"):
                        # The receiving server refused it: the resource
                        # confirms the effect never happened.
                        self.ledger.log(kind="bounce", host=self.name, mission=mission,
                                        target=target)
                        self.pep.effect_cancelled(pending)
                        return
                    raw = deliver()
                    self.pep.effect_landed(pending, "send_message", target, raw)

                threading.Thread(target=later, daemon=True).start()
                return pending

            # What is sent is part of the request a person approves: the
            # same send with another attachment or body is another request.
            sent = {"attachment": doc, "body": body}
            outcome = self._enforce(mission, sub, "send_message", "recipient", target,
                                    perform, context, sent)
            outcome["target"] = target
            results.append(outcome)
        ok = all(r["ok"] for r in results)
        out: dict[str, Any] = {"ok": ok, "targets": results}
        if not ok:
            first = next(r for r in results if not r["ok"])
            out["reason"] = first.get("reason")
            for member in ("evaluation_id", "access_request_task", "next_action"):
                if member in first:
                    out[member] = first[member]
        return out


SALARY_DLP = re.compile(r"\bsalary\b", re.IGNORECASE)


def classifier_for(kind: str, hr: HRStore | None, docs: DocStore | None = None,
                   dlp: bool = False) -> Callable[[str, str, object], frozenset[str]]:
    """What each resource labels its responses with (never the agent).

    With ``dlp``, the document system labels a document by its content after
    the write or share (a keyword rule, as DLP products use); otherwise every
    document is just ``document``.
    """
    def classify(action: str, resource: str, raw: object) -> frozenset[str]:
        if kind == "hr" and hr is not None:
            return hr.record(resource.removeprefix("hr:"))[1]
        if kind == "docs":
            if dlp and docs is not None and SALARY_DLP.search(
                    docs.read(resource.removeprefix("doc:"))):
                return frozenset({"personal_data.salary"})
            return frozenset({"document"})
        return frozenset()
    return classify


def http_doc_reader(docs_url: str) -> Callable[[str], str]:
    """Resource-to-resource read of a document at delivery time."""
    def read(doc: str) -> str:
        with urllib.request.urlopen(f"{docs_url}/internal/doc/{doc}", timeout=20) as resp:
            body: str = json.loads(resp.read())["content"]
            return body
    return read
