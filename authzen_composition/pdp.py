"""The composition PDP.

Decides each request against the Mission's history as read from the History
Authority, in the order of checks the profile gives ("Ordering rules"):

* no Mission for a Step-matching Act, or a history that cannot be read or
  used: ``history_unavailable``; a set the Mission is not pinned to:
  ``policy_mismatch``; in a batch, another request of the Mission that could
  fill a step of the same sequence: ``history_conflict``;
* a completed Restricted Sequence with no valid approval:
  ``prohibited_composition``, ARAP-requestable when policy allows;
* an open Act of the same sequence: ``history_pending`` (rule 5);
* a Step-matching Act whose PEP did not adopt ``mission_record``: plain deny;
* otherwise a permit, with ``mission_record`` naming the position at which
  the PEP admits the Act.

History and result classes come only from the History Authority, never from
the request.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from authzen_composition.mhs import HistoryAuthority, PolicyMismatch
from authzen_composition.model import Act, ActOutcome, CompositionPolicy, RestrictedSequence
from authzen_composition.types import (
    CAPABILITY_ACCESS_REQUEST,
    CAPABILITY_OBLIGATIONS,
    EXTENSION_OBLIGATIONS,
    OBLIGATION_MISSION_RECORD,
    REASON_HISTORY_CONFLICT,
    REASON_HISTORY_PENDING,
    REASON_HISTORY_UNAVAILABLE,
    REASON_POLICY_MISMATCH,
    REASON_PROHIBITED_COMPOSITION,
    Decision,
    EvaluationRequest,
    EvaluationResponse,
    EvaluationsSemantic,
    Obligation,
)


def rfc3339(when: datetime) -> str:
    """An RFC 3339 timestamp in UTC, in the `Z` form ARAP's examples use."""
    return when.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class _PendingApproval:
    """A requestable denial awaiting a person's decision.

    The approval is bound to the whole denied request (subject, action and
    resource with their properties, the Mission and the adoption
    declarations), to the history position it was denied at, and to the
    Restricted Sequences that denial completed. If any act is admitted in
    the meantime, or the act would now complete another sequence, the
    approval no longer applies and the PDP evaluates afresh.
    """

    mission_id: str
    action: str
    resource: str
    seq: int
    expires: datetime
    sequences: frozenset[str] = frozenset()
    # Digest of the whole evaluated request (subject, action and resource with
    # their properties). A person approved that request, not any request that
    # shares its action name and resource id: another agent, or the same send
    # with a different attachment, is a different request.
    request: str = ""
    # What ARAP's Access Request Service compares a submission with: the
    # Subject, Resource and Action as evaluated, and the authorization-relevant
    # Context: the Mission and the adoption declarations.
    bound: dict[str, Any] = field(default_factory=dict)
    # What an approver is shown of the history the denial was decided on, as
    # earlier attempts at its target (``_earlier_attempts``).
    earlier: tuple[dict[str, Any], ...] = ()
    # Set when a person approves: the latest expiry of its approvals, each
    # counted from its own approval, apart from the request's window
    # (`expires`). Each approval is checked against its own expiry.
    approved_until: datetime | None = None

    def done(self, now: datetime) -> bool:
        """Neither approvable (its window closed) nor usable (every approval
        of it expired), so it can be dropped."""
        return now >= self.expires and (self.approved_until is None
                                        or now >= self.approved_until)


def _bound(request: EvaluationRequest) -> dict[str, Any]:
    """The denied evaluation as ARAP binds an Access Request to it."""
    def obj(kind: str, members: dict[str, Any], props: dict[str, Any]) -> dict[str, Any]:
        # ARAP compares full objects, except subject.properties.act; an
        # empty properties member and an absent one compare the same here.
        out = dict(members)
        kept = {k: v for k, v in props.items() if not (kind == "subject" and k == "act")}
        if kept:
            out["properties"] = kept
        return out
    assert request.mission is not None
    # As the PEP sent them, where the request came from the wire: the
    # Access Request repeats them so, members this PDP ignores included.
    context: dict[str, Any] = {
        "mission": request.sent.get(
            "mission", {"id": request.mission.id, "issuer": request.mission.issuer}),
        "supported_mandatory_extensions": request.sent.get(
            "supported_mandatory_extensions", list(request.supported_mandatory_extensions)),
        "supported_obligations": request.sent.get(
            "supported_obligations", list(request.supported_obligations))}
    # The approval scope compares context.actor (``_request_digest``), so it
    # is authorization-relevant Context and binds the submission too (ARAP).
    if "actor" in request.context:
        context["actor"] = request.context["actor"]
    return {
        "subject": obj("subject", {"type": request.subject.type, "id": request.subject.id},
                       request.subject.properties),
        "resource": obj("resource", {"type": request.resource.type, "id": request.resource.id},
                        request.resource.properties),
        "action": obj("action", {"name": request.action.name}, request.action.properties),
        # The Context the denial binds (profile, Approvals, ARAP binding):
        # the Mission and, when present, context.actor, which are
        # authorization-relevant, and the adoption declarations, capability
        # declarations this record keeps for the shared-state binding until
        # ARAP binds them apart (openid/authzen issue #754), all as sent.
        "context": context,
        # Who may not approve it besides the Subject: the actors of its
        # delegation chain (profile, Approvals). Not compared.
        "actors": sorted(_chain(request.subject.properties.get("act"))
                         | _chain(request.context.get("actor"))),
    }


def _earlier_attempts(history: list[Act], resource: str) -> tuple[dict[str, Any], ...]:
    """Every Act of the history the denial was decided on that has the denied
    request's resource, whatever its action, and is not failed, the open ones
    first, each with the outcome read then (profile, Approvals, "What the
    approver sees"). An open one may still take effect; one completed with no
    result classes may be one an operator closed. An Act Record holds no
    properties, so another call to the same target is shown as well."""
    acts = sorted((a for a in history
                   if a.resource == resource and a.outcome is not ActOutcome.FAILED),
                  key=lambda a: (a.outcome is not ActOutcome.OPEN, a.seq))
    return tuple({"seq": a.seq, "action": a.action, "outcome": a.outcome.value,
                  "result_classes": sorted(a.result_classes)} for a in acts)


def _chain(actor: Any) -> set[str]:
    """The identifiers (``sub``, ``client_id``) of an actor and every prior
    actor nested in its ``act``."""
    found: set[str] = set()
    stack = [actor]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            found.update(v for k, v in item.items()
                         if k in ("sub", "client_id") and isinstance(v, str))
            stack.append(item.get("act"))
    return found


def _valid_act(act: Act) -> bool:
    """Whether an Act holds only what an Act Record allows (profile, History
    Authority): a History Authority, or a client, that hands the PDP anything
    else makes the history unusable (rule 4)."""
    return (isinstance(act.action, str) and bool(act.action)
            and isinstance(act.resource, str) and bool(act.resource)
            and isinstance(act.outcome, ActOutcome)
            and all(isinstance(c, str) and c and "*" not in c for c in act.result_classes)
            and not (act.outcome is ActOutcome.FAILED and act.result_classes))


def _actor(actor: Any) -> Any:
    """context.actor as the approval scope compares it."""
    if isinstance(actor, dict):
        return {k: v for k, v in actor.items() if k != "client_instance_id"}
    return actor


def _request_digest(request: EvaluationRequest) -> str:
    """Canonical digest of what a person is asked to approve."""
    body = {
        "subject": {"type": request.subject.type, "id": request.subject.id,
                    "properties": request.subject.properties},
        "action": {"name": request.action.name, "properties": request.action.properties},
        "resource": {"type": request.resource.type, "id": request.resource.id,
                     "properties": request.resource.properties},
        # The acting party, where it is carried in Context rather than in
        # subject.properties.act (the mission-bound drafts' context.actor):
        # an approval does not carry to another actor either way. Its
        # client_instance_id correlates one instance of the client, which ARAP
        # lets another instance replace, so it is left out.
        "actor": _actor(request.context.get("actor")),
        # The adoption declarations change what the PDP may return, so an
        # approval is bound to them (Obligations Core, Binding), as this
        # PDP reads them: an extension it does not implement is a no-op and a
        # type it did not advertise is absent (Support Opt-In, Item
        # Negotiation), so neither may change whether an approval applies.
        "adopts_obligations": EXTENSION_OBLIGATIONS in request.supported_mandatory_extensions,
        "supported_obligations": sorted(set(request.supported_obligations)
                                        & {OBLIGATION_MISSION_RECORD}),
    }
    blob = json.dumps(_by_value(body), sort_keys=True, separators=(",", ":"), default=repr)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _by_value(value: Any) -> Any:
    """``value`` with every integral number written as an integer, so that the
    approval scope compares numbers by value (1 and 1.0 are one number), as
    ARAP's structural comparison does at submission."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _by_value(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_by_value(v) for v in value]
    return value


# Denials that mean "evaluate again later" (the PEP may succeed by waiting).
_RETRY_REASONS = frozenset({REASON_HISTORY_PENDING, REASON_HISTORY_UNAVAILABLE,
                            REASON_HISTORY_CONFLICT, REASON_POLICY_MISMATCH})
# Seconds a PEP waits after `policy_mismatch`: this PDP would answer the same
# way at once, and ARAP's backoff without `retry_after` grows to one minute.
POLICY_MISMATCH_RETRY_AFTER = 60


def _retry_signal(request: EvaluationRequest, decision: Decision) -> Decision:
    """ARAP: on a re-evaluation that presents an approval, the PEP drives its
    next step from ``next_action``, which the PDP SHOULD send on every denial
    ("Deny a Re-evaluation"); these reasons are not registered with ARAP, so
    without it the PEP would fall back to "none" and abandon a valid
    approval. Only such a re-evaluation gets the signal."""
    if decision.decision or not isinstance(request.context.get("approval"), dict):
        return decision
    if decision.reason == REASON_HISTORY_UNAVAILABLE and request.mission is None:
        # Waiting cannot give the request a Mission: ARAP's next step is to stop.
        return replace(decision, context={**decision.context, "next_action": "none"})
    if decision.reason in _RETRY_REASONS:
        signal: dict[str, Any] = {"next_action": "retry"}
        if decision.reason == REASON_POLICY_MISMATCH:
            signal["retry_after"] = POLICY_MISMATCH_RETRY_AFTER
        return replace(decision, context={**decision.context, **signal})
    if decision.reason == REASON_PROHIBITED_COMPOSITION:
        # The approval does not apply (expired, spent, another request or
        # position). ARAP: request again if the denial is requestable, with
        # the fresh context.access_request it carries; otherwise stop.
        action = "request" if decision.access_request is not None else "none"
        return replace(decision, context={**decision.context, "next_action": action})
    # Any other denial, such as the plain deny of check (d) for a PEP that has
    # not opted in to mission_record: no approval can lead to a permit, so the
    # PEP stops. next_action is ARAP's, not the Obligations Core's, so the deny
    # stays a plain core DENY.
    return replace(decision, context={**decision.context, "next_action": "none"})


@dataclass
class CompositionPDP:
    """Policy Decision Point for the composition profile."""

    policy: CompositionPolicy
    mhs: HistoryAuthority
    request_ttl: timedelta = timedelta(minutes=15)
    # How long an approval stays valid, counted from the approval. The
    # request's expires_at bounds when it can be submitted and decided; the
    # Access Request Service's task expires with it.
    approval_ttl: timedelta = timedelta(minutes=5)
    # The deployment's ARAP Access Request Endpoint (an HTTPS URI). Without
    # one a requestable sequence is denied plainly: ARAP forbids
    # context.access_request unless an endpoint can process the request.
    # ``arap.AccessRequestService`` serves it, from this PDP's own state.
    access_request_endpoint: str | None = None
    # Only for local tests and the end-to-end harness: also accept a plain
    # http:// endpoint on the loopback address.
    allow_loopback_http: bool = False
    # Wall clock for approval expiry; injectable so the boundary is testable.
    # It returns timezone-aware datetimes, as the Access Request Service's does.
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC), repr=False)
    _pending: dict[str, _PendingApproval] = field(default_factory=dict, repr=False)
    # approval.id -> the evaluation_id of the requestable denial it approves,
    # its approved_until, and the PEP that requested it (None when unknown).
    _approvals: dict[str, tuple[str, datetime, str | None]] = field(default_factory=dict,
                                                                    repr=False)
    _approval_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # At most this many requestable denials of one Mission are stored at once;
    # past it a denial is not requestable until one is dropped, so an agent
    # that repeats or varies a prohibited call cannot grow the PDP's state
    # without bound. (ARAP forbids reusing an evaluation_id within its window,
    # so a repeated call is a new denial.)
    max_pending_per_mission: int = 64
    _per_mission: dict[str, int] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        endpoint = self.access_request_endpoint
        loopback = self.allow_loopback_http and endpoint is not None and (
            endpoint.startswith(("http://127.0.0.1:", "http://127.0.0.1/")))
        if endpoint is not None and not endpoint.startswith("https://") and not loopback:
            raise ValueError("access_request_endpoint must be an HTTPS URI (ARAP)")

    def metadata(self) -> dict[str, Any]:
        """PDP metadata: what the Obligations Core requires of a PDP that
        issues obligations, its capability URN and the types it issues, from
        which a PEP discovers this profile (`mission_record`). ARAP's
        capability and endpoint only when the deployment configured an
        endpoint."""
        meta: dict[str, Any] = {
            "capabilities": [CAPABILITY_OBLIGATIONS],
            "supported_obligations": [OBLIGATION_MISSION_RECORD],
        }
        if self.access_request_endpoint is not None:
            meta["capabilities"].append(CAPABILITY_ACCESS_REQUEST)
            meta["access_request_endpoint"] = self.access_request_endpoint
        return meta

    def approve(self, evaluation_id: str, requester: str | None = None) -> dict[str, str]:
        """Record a person's approval of the requestable denial identified by
        ``evaluation_id`` and return the ARAP ``approval`` object (``id``,
        ``approved_until``) the PEP presents at ``context.approval`` when it
        evaluates again. The Access Request Service calls it once a person
        approved (``arap.AccessRequestService.decide``); it is never driven
        by the agent."""
        with self._approval_lock:
            pending = self._pending.get(evaluation_id)
            now = self.clock()
            if pending is None or now >= pending.expires:
                # Unknown, spent or purged, or its window closed: it can no
                # longer be approved.
                raise KeyError(evaluation_id)
            # To the second, as published: the PDP enforces what it publishes.
            until = (now.astimezone(UTC) + self.approval_ttl).replace(microsecond=0)
            latest = until if pending.approved_until is None else max(pending.approved_until, until)
            self._pending[evaluation_id] = replace(pending, approved_until=latest)
            approval_id = "apr_" + uuid.uuid4().hex
            # The PEP that requested it, which alone may present it.
            self._approvals[approval_id] = (evaluation_id, until, requester)
            return {"id": approval_id, "approved_until": rfc3339(until)}

    def denial_binding(self, evaluation_id: str) -> tuple[dict[str, Any], datetime] | None:
        """For the Access Request Service: what the requestable denial
        ``evaluation_id`` bound and when it expires, or None if this PDP
        issued no such denial (or it was spent or purged)."""
        with self._approval_lock:
            pending = self._pending.get(evaluation_id)
            return None if pending is None else (pending.bound, pending.expires)

    def approver_view(self, evaluation_id: str) -> dict[str, Any] | None:
        """For the Access Request Service: what it shows an approver of the
        requestable denial ``evaluation_id`` (profile, Approvals, "What the
        approver sees"): the denied request as bound, the actors of its
        delegation chain, the names of the Restricted Sequences it completed
        and the earlier attempts at its target. None if this PDP issued no
        such denial (or it was spent or purged)."""
        with self._approval_lock:
            pending = self._pending.get(evaluation_id)
            if pending is None:
                return None
            bound = pending.bound
            # Copies: a caller that edits what it shows must not change the
            # denial binding later submissions are compared with.
            return copy.deepcopy({
                "request": {k: bound[k] for k in ("subject", "action", "resource")},
                "actors": bound["actors"],
                "sequences": sorted(pending.sequences),
                "earlier": list(pending.earlier),
            })

    def _approved(self, request: EvaluationRequest, candidate: Act,
                  completed: tuple[str, ...]) -> str | None:
        """The approval id of a valid, unused approval for exactly this act at
        exactly this history position, or None. The PDP resolves
        ``approval.id`` from its own state and trusts no other member the
        request carries. Checking does not use the approval up: it is consumed
        only by the permit it produces (see ``_consume``), so a later
        hold-back or opt-in denial does not burn it."""
        approval = request.context.get("approval")
        if not isinstance(approval, dict):
            return None
        approval_id = approval.get("id")
        if not isinstance(approval_id, str):
            return None
        with self._approval_lock:
            known = self._approvals.get(approval_id)
            pending = None if known is None else self._pending.get(known[0])
            if known is None or pending is None:
                # Unknown, or the access request it approved was already
                # spent (one request approved twice) or purged.
                return None
        assert request.mission is not None
        if (
            pending.mission_id != request.mission.id
            or pending.action != candidate.action
            or pending.resource != candidate.resource
            or pending.seq != candidate.seq
            or not set(completed) <= pending.sequences
            or pending.request != _request_digest(request)
            or self.clock() >= known[1]
            # Requested by another PEP than the one that presents it.
            or (known[2] is not None and request.caller is not None
                and request.caller != known[2])
        ):
            return None
        return approval_id

    def _drop(self, evaluation_id: str) -> bool:
        """Forget a stored denial; False if it was already gone. Under the lock."""
        denial = self._pending.pop(evaluation_id, None)
        if denial is None:
            return False
        left = self._per_mission[denial.mission_id] - 1
        if left:
            self._per_mission[denial.mission_id] = left
        else:
            del self._per_mission[denial.mission_id]
        return True

    def _prune(self, now: datetime) -> None:
        """Drop the stored denials that can no longer be approved or used, and
        the approvals of those dropped. Under the lock. Denials are stored in
        the order their windows close, so the scan stops at the first one still
        open; it reads only the closed ones, which an approval keeps at most
        for its own lifetime."""
        stale = []
        for evaluation_id, denial in self._pending.items():
            if now < denial.expires:
                break
            if denial.done(now):
                stale.append(evaluation_id)
        for evaluation_id in stale:
            self._drop(evaluation_id)
        if stale:
            for apr in [a for a, (e, *_) in self._approvals.items() if e not in self._pending]:
                del self._approvals[apr]

    def _consume(self, approval_id: str) -> bool:
        """Spend an approval, and with it the access request it approved.
        False if it can no longer be used: a concurrent evaluation spent it or
        another approval of the same request first, or it expired after
        `_approved` checked it."""
        with self._approval_lock:
            known = self._approvals.pop(approval_id, None)
            if known is None or self.clock() >= known[1]:
                return False
            # Another approval of the same request (approved twice) now
            # resolves to nothing in `_approved`; the purge on the next
            # requestable denial drops it.
            return self._drop(known[0])

    def _read_history(self, mission_id: str) -> list[Act] | Decision:
        """The Mission's history, or the fail-closed denial when it cannot be
        used: unreadable, not exactly positions 1 to n, or bound to another
        set of Restricted Sequences."""
        try:
            history = self.mhs.history(mission_id, policy=self.policy.digest)
        except PolicyMismatch:
            # This PDP applies a different set than the one the Mission is
            # bound to (a replica mid-rollout, or a changed policy). Deciding
            # would apply rule 5 and the predicate with the wrong sequences,
            # and Acts this set ignores may never have been admitted.
            return Decision(decision=False, reason=REASON_POLICY_MISMATCH)
        except Exception:
            # The History Authority cannot be read (HistoryUnavailable, or any
            # other failure of the read): fail closed for this request only,
            # with a reason distinct from a policy denial so the PEP can retry,
            # and never fail a whole batch (profile, PDP rules).
            return Decision(decision=False, reason=REASON_HISTORY_UNAVAILABLE)
        if [a.seq for a in history] != list(range(1, len(history) + 1)) or not all(
                map(_valid_act, history)):
            # A gap, a reordering or an invalid Act Record: the history is not
            # complete up to its own last position, so the predicate cannot be
            # evaluated (rule 4).
            return Decision(decision=False, reason=REASON_HISTORY_UNAVAILABLE)
        return history

    def _candidate(self, history: list[Act], request: EvaluationRequest) -> Act:
        """The act the request would admit, at the next sequence position."""
        assert request.mission is not None  # guarded by caller
        return Act(
            seq=len(history) + 1,
            action=request.action.name,
            resource=request.resource.id,
            outcome=ActOutcome.OPEN,
        )

    def evaluate(self, request: EvaluationRequest) -> Decision:
        """Evaluate a single Access Evaluation request."""
        return _retry_signal(request, self._evaluate(request))

    def _evaluate(self, request: EvaluationRequest) -> Decision:
        if request.mission is None:
            # No Mission, so no history to read. An Act that could fill a step
            # of a sequence in force depends on that history: fail closed, as
            # for an unreadable one (a PEP that omits the Mission, or a batch
            # item whose own context drops it, gets no permit). Any other Act
            # is outside this profile; core evaluation (a plain permit here)
            # is the deployment's concern.
            probe = Act(seq=1, action=request.action.name, resource=request.resource.id,
                        outcome=ActOutcome.OPEN)
            if self.policy.can_extend_prefix(probe):
                return Decision(decision=False, reason=REASON_HISTORY_UNAVAILABLE)
            return Decision(decision=True)

        # Adoption: a permit that carries mission_record requires the PEP to
        # have listed the Obligations Core in supported_mandatory_extensions
        # and mission_record in supported_obligations (an omitted list is
        # empty). Otherwise a plain deny rather than an obligation the PEP has
        # not committed to (Obligations Core, openid/authzen PR #697, "PDP
        # Outcome"). The profile adds no mandatory element of its own, so it
        # needs no signal of its own (Extensibility Model); any other entry,
        # `composition` included, is ignored.
        opted_in = (
            EXTENSION_OBLIGATIONS in request.supported_mandatory_extensions
            and OBLIGATION_MISSION_RECORD in request.supported_obligations
        )

        read = self._read_history(request.mission.id)
        if isinstance(read, Decision):
            return read
        history = read

        candidate = self._candidate(history, request)
        verdict = self.policy.completes(history, candidate)
        approval_id = (
            None if verdict.satisfied
            else self._approved(request, candidate, verdict.completed)
        )

        if not verdict.satisfied and approval_id is None:
            # Prohibited composition. Deny; make it ARAP-requestable when policy
            # marked the completed sequence requestable: context.access_request
            # with an RFC 3339 expires_at, bound by reference through
            # context.evaluation_id (the PDP is the Access Request Service's
            # shared state here). The denial does not name the sequence: the
            # request may originate with the agent, and naming the rule it hit
            # helps it route around it.
            access_request = None
            evaluation_id = None
            # Requestable only to a PEP that adopted mission_record: for any
            # other, the re-evaluation ends in the plain deny of check (d), so
            # no approval could lead to a permit.
            if (verdict.requestable and opted_in
                    and self.access_request_endpoint is not None):
                now = self.clock()
                # To the second, as published: the PDP enforces what it publishes.
                expires = (now.astimezone(UTC) + self.request_ttl).replace(microsecond=0)
                with self._approval_lock:
                    # Drop denials that can no longer be approved or used, so
                    # unanswered requests do not accumulate.
                    self._prune(now)
                    mission_id = request.mission.id
                    if self._per_mission.get(mission_id, 0) < self.max_pending_per_mission:
                        evaluation_id = "eval_" + uuid.uuid4().hex
                        self._pending[evaluation_id] = _PendingApproval(
                            mission_id=mission_id,
                            action=candidate.action,
                            resource=candidate.resource,
                            seq=candidate.seq,
                            expires=expires,
                            sequences=frozenset(verdict.completed),
                            request=_request_digest(request),
                            bound=_bound(request),
                            earlier=_earlier_attempts(history, candidate.resource),
                        )
                        self._per_mission[mission_id] = self._per_mission.get(mission_id, 0) + 1
                if evaluation_id is not None:
                    access_request = {"expires_at": rfc3339(expires)}
            return Decision(
                decision=False,
                reason=REASON_PROHIBITED_COMPOSITION,
                access_request=access_request,
                evaluation_id=evaluation_id,
            )

        # Effect order: an admitted act that has not finished could still
        # produce its effect after this one. Hold the candidate back.
        if self.policy.pending_conflict(history, candidate):
            return Decision(decision=False, reason=REASON_HISTORY_PENDING)

        # Permit. If the act can extend a restricted-sequence prefix, it must be
        # admitted under serialization: attach the mission_record obligation.
        serialized = self.policy.can_extend_prefix(candidate)
        if serialized and not opted_in:
            # Policy needs the obligation but the PEP has not adopted it: a
            # plain core deny with no reason and no obligations. It is not a
            # composition finding, so it carries no prohibited_composition
            # reason.
            return Decision(decision=False)

        obligations: tuple[Obligation, ...] = ()
        if serialized:
            obligations = (
                Obligation(
                    id="obl-mission-record",
                    type=OBLIGATION_MISSION_RECORD,
                    properties={
                        "mission": request.mission.id,
                        "expected_seq": candidate.seq,
                    },
                ),
            )
        if approval_id is not None and not self._consume(approval_id):
            # Spent by a concurrent evaluation, or expired, in the meantime:
            # decided again without it, so the denial is what a request whose
            # approval does not apply gets (requestable, with a fresh
            # access_request, where policy allows).
            return self._evaluate(replace(request, context={
                k: v for k, v in request.context.items() if k != "approval"}))
        return Decision(decision=True, obligations=obligations)

    def evaluate_batch(
        self,
        requests: tuple[EvaluationRequest, ...],
        semantic: EvaluationsSemantic = EvaluationsSemantic.EXECUTE_ALL,
    ) -> EvaluationResponse:
        """Evaluate an ``evaluations`` batch.

        Two acts of the same mission that could each extend a prefix of the same
        restricted sequence against the same history conflict: the first is
        decided normally, the rest are denied ``history_conflict``. The PEP
        re-evaluates them in turn after admitting the first. Under
        ``deny_on_first_deny`` the batch short-circuits on the first denial.
        """
        decisions: list[Decision] = []
        # Per Mission, the Restricted Sequences an already permitted Act of this
        # batch can extend. This PDP admits nothing while it decides a batch;
        # if another PEP admits in the meantime, a permit decided on the older
        # view fails admission (rule 2).
        claimed: dict[str, set[RestrictedSequence]] = {}

        for request in requests:
            if request.mission is not None:
                read = self._read_history(request.mission.id)
                if isinstance(read, Decision):
                    # Same fail-closed rule as a single evaluation.
                    decisions.append(_retry_signal(request, read))
                    if semantic is EvaluationsSemantic.DENY_ON_FIRST_DENY:
                        break
                    continue
                history = read
                candidate = self._candidate(history, request)
                extends = self.policy.extendable_sequences(candidate)
                taken = claimed.setdefault(request.mission.id, set())
                if extends & taken:
                    decision = _retry_signal(
                        request, Decision(decision=False, reason=REASON_HISTORY_CONFLICT))
                    decisions.append(decision)
                    if semantic is EvaluationsSemantic.DENY_ON_FIRST_DENY:
                        break
                    continue
                decision = self.evaluate(request)
                if extends and decision.decision:
                    taken |= extends
            else:
                decision = self.evaluate(request)

            decisions.append(decision)
            if semantic is EvaluationsSemantic.DENY_ON_FIRST_DENY and not decision.decision:
                break
            if semantic is EvaluationsSemantic.PERMIT_ON_FIRST_PERMIT and decision.decision:
                break

        return EvaluationResponse(evaluations=tuple(decisions))
