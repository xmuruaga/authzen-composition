"""AuthZEN Authorization API 1.0 request/response types.

Minimal, typed representation of the subset of the Authorization API this
profile uses: Access Evaluation (single and the ``evaluations`` batch),
decisions, the response ``context`` with ``reason`` and ``obligations``, and
the request ``context`` with ``mission``, ``supported_mandatory_extensions``
and ``supported_obligations``.

Field names follow the API 1.0 specification, the Obligations Core and ARAP
verbatim, so a wire payload maps onto these objects without
translation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


@dataclass(frozen=True)
class Subject:
    type: str
    id: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Action:
    name: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Resource:
    type: str
    id: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Mission:
    """The ``context.mission`` member.

    ``id`` alone identifies the Mission and keys its history; ``issuer`` is
    required, as in the mission-bound drafts, and informational here. Both
    come from a trusted input, never from the agent's request body.
    """

    id: str
    issuer: str

    def __post_init__(self) -> None:
        # The id keys the Mission's history: an empty one names no Mission.
        if not (isinstance(self.id, str) and self.id):
            raise ValueError("a Mission id is a non-empty string")
        if not (isinstance(self.issuer, str) and self.issuer):
            raise ValueError("a Mission issuer is a non-empty string")


@dataclass(frozen=True)
class EvaluationRequest:
    """A single AuthZEN Access Evaluation request."""

    subject: Subject
    action: Action
    resource: Resource
    mission: Mission | None = None
    supported_mandatory_extensions: tuple[str, ...] = ()
    supported_obligations: tuple[str, ...] = ()
    context: dict[str, Any] = field(default_factory=dict)
    # ``mission`` and the adoption declarations as the PEP sent them, for a
    # request read from the wire: an Access Request repeats them as sent and
    # is compared on them (profile, Approvals, ARAP binding). Not part of
    # what the request is.
    sent: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)
    # The authenticated PEP that sent the request, where the PDP authenticated
    # one: an approval applies only for the caller that requested it (ARAP,
    # Approval Verification).
    caller: str | None = field(default=None, compare=False, repr=False)


class EvaluationsSemantic(StrEnum):
    """The three ``options.evaluations_semantic`` values of the API."""

    EXECUTE_ALL = "execute_all"
    DENY_ON_FIRST_DENY = "deny_on_first_deny"
    PERMIT_ON_FIRST_PERMIT = "permit_on_first_permit"


@dataclass(frozen=True)
class Obligation:
    """An Obligations Core obligation object: ``{id, type, properties}``."""

    id: str
    type: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    """An AuthZEN decision with its response ``context``.

    ``reason`` is the machine-readable denial reason (ARAP ``context.reason``).
    ``access_request`` present marks the denial as ARAP-requestable, and
    ``evaluation_id`` is its by-reference denial binding (ARAP
    ``context.evaluation_id``). ``to_json`` gives the wire form, with every
    such member inside ``context``.
    """

    decision: bool
    reason: str | None = None
    obligations: tuple[Obligation, ...] = ()
    access_request: dict[str, Any] | None = None
    context: dict[str, Any] = field(default_factory=dict)
    evaluation_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        """The Access Evaluation response body for this decision."""
        ctx: dict[str, Any] = dict(self.context)
        if self.reason is not None:
            ctx["reason"] = self.reason
        if self.evaluation_id is not None:
            ctx["evaluation_id"] = self.evaluation_id
        if self.access_request is not None:
            ctx["access_request"] = dict(self.access_request)
        if self.obligations:
            ctx["obligations"] = [
                {"id": o.id, "type": o.type, "properties": dict(o.properties)}
                for o in self.obligations
            ]
        body: dict[str, Any] = {"decision": self.decision}
        if ctx:
            body["context"] = ctx
        return body


@dataclass(frozen=True)
class EvaluationResponse:
    """A single decision, or a batch under ``evaluations``."""

    decision: Decision | None = None
    evaluations: tuple[Decision, ...] = ()


# Denial reasons this profile registers.
REASON_PROHIBITED_COMPOSITION = "prohibited_composition"
REASON_HISTORY_UNAVAILABLE = "history_unavailable"
REASON_HISTORY_CONFLICT = "history_conflict"
REASON_HISTORY_PENDING = "history_pending"
REASON_POLICY_MISMATCH = "policy_mismatch"

# The profile has no extension identifier of its own: it is adopted through
# the Obligations Core, whose identifier this is (openid/authzen PR #697).
# A PEP lists it, and `mission_record` in supported_obligations, to receive
# `mission_record`.
EXTENSION_OBLIGATIONS = "obligations"
# Capability URN for PDP metadata (placeholder until registered).
# The Obligations Core's capability URN (openid/authzen PR #697).
CAPABILITY_OBLIGATIONS = "urn:openid:authzen:capability:obligations"
# ARAP, advertised only with a configured Access Request Endpoint.
CAPABILITY_ACCESS_REQUEST = "urn:openid:authzen:capability:access-request"
OBLIGATION_MISSION_RECORD = "mission_record"
