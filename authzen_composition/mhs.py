"""Mission History Service (MHS): the reference History Authority.

The MHS assigns each admitted act a gapless, mission-wide sequence position and
holds the ordered history the composition predicate reads. It is the standalone
History Authority (docs/mission-history-service.md). Key invariants:

* a new act is accepted only at the next sequence position (serializable
  admission); any other position is rejected with a conflict;
* an outcome moves only from OPEN to COMPLETED or FAILED, once;
* the writer identity is recorded by the service, never taken from the act:
  in process the caller passes the identity it authenticated, and the HTTP
  binding derives it from the credential;
* the agent never writes here: writers are PEPs the deployment trusts.

This in-memory implementation is the reference; the HTTP binding in
``http_binding`` is a thin shell over it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

from authzen_composition.model import Act, ActOutcome

# Bounds on what one Act holds (profile, Security considerations: Input size).
MAX_IDENTIFIER_LENGTH = 1024
MAX_RESULT_CLASSES = 16
MAX_CLASS_LENGTH = 128


class HistoryAuthority(Protocol):
    """What a PEP and a PDP need from the History Authority.

    ``MissionHistoryService`` implements it in memory;
    ``RemoteHistoryAuthority`` implements it over the HTTP binding, where the
    service takes the writer identity from the credential and ignores
    ``writer``.
    """

    def admit(self, mission_id: str, seq: int, action: str, resource: str,
              writer: str, admission_id: str | None = None) -> Act: ...

    def set_outcome(self, mission_id: str, seq: int, outcome: ActOutcome, writer: str,
                    result_classes: frozenset[str] = frozenset(),
                    admission_id: str | None = None) -> Act: ...

    def history(self, mission_id: str, policy: str | None = None) -> list[Act]: ...


class HistoryConflict(Exception):
    """Raised when an act is submitted at a position other than the next one."""


class UnknownAct(Exception):
    """Raised when an outcome is reported for a position that does not exist."""


class OutcomeAlreadySet(Exception):
    """Raised when an outcome transition is attempted on a non-open act."""


class UnauthenticatedWriter(Exception):
    """Raised when a writer is not recognized by the service."""


class NotPermitted(UnauthenticatedWriter):
    """Raised when an authenticated identity may not do this: a writer that is
    not trusted, a writer setting another writer's outcome, a caller without
    the role a read or a close needs. Over HTTP it is a 403, where a missing
    or invalid credential is a 401; a subclass, so that callers which catch
    ``UnauthenticatedWriter`` still catch it."""


class HistoryUnavailable(Exception):
    """Raised when the History Authority cannot provide a mission's history.

    A real deployment raises this when the authority is unreachable or cannot
    establish the history. The PDP fails closed.
    """


class PolicyMismatch(Exception):
    """Raised when a PDP reads a Mission bound to a different set of
    Restricted Sequences than the one it applies, or would pin a Mission not
    yet bound to a set the deployment has not designated for new Missions.
    The PDP fails closed."""


@dataclass
class _Record:
    act: Act
    recorded_by: str
    admission_id: str | None = None


class MissionHistoryService:
    """In-memory History Authority.

    Thread-safe. One instance may hold many missions; each has its own gapless
    sequence starting at position 1.
    """

    def __init__(self, trusted_writers: frozenset[str] = frozenset(),
                 operators: frozenset[str] = frozenset(),
                 new_mission_policies: frozenset[str] | None = None,
                 max_acts: int | None = None) -> None:
        self._trusted_writers = trusted_writers
        # The most Acts one Mission may hold (profile, Security considerations:
        # Availability, a deployment bounds a Mission's length); None: no bound.
        self._max_acts = max_acts
        self._operators = operators
        self._missions: dict[str, list[_Record]] = {}
        self._policy: dict[str, str] = {}
        # The digests a Mission not yet pinned may be pinned to (profile,
        # History Authority item 6). None: no designation, the first PDP read
        # pins whatever set it applies, which is enough for a deployment that
        # has only ever had one set. Empty: no new Mission can start.
        self._new_mission_policies = new_mission_policies
        self._lock = threading.Lock()

    def _check_writer(self, writer: str) -> None:
        # An empty trust set means "any authenticated writer"; a non-empty set
        # restricts to configured writers. Either way, a writer must be named.
        if not writer:
            raise UnauthenticatedWriter("writer identity is required")
        if self._trusted_writers and writer not in self._trusted_writers:
            raise NotPermitted(f"writer {writer!r} is not trusted")

    def next_seq(self, mission_id: str) -> int:
        """The position the next act must claim."""
        with self._lock:
            return len(self._missions.get(mission_id, [])) + 1

    def admit(
        self,
        mission_id: str,
        seq: int,
        action: str,
        resource: str,
        writer: str,
        admission_id: str | None = None,
    ) -> Act:
        """Admit an act at ``seq``. Must be the next position, else conflict.

        The act is recorded with outcome OPEN. The writer identity is recorded
        by the service. Returning from this call is the acknowledgement the
        PEP waits for before performing the action; a durable deployment
        commits the record before returning.

        ``admission_id`` makes admission idempotent: a retry by the same
        writer with the same id (for example after a lost acknowledgement)
        returns the act already admitted instead of conflicting or admitting
        a duplicate. The retry must name the same position, action and
        resource; reusing an id for a different act is a conflict, because
        returning the earlier act would tell the PEP that an act it never
        recorded was admitted.
        """
        self._check_writer(writer)
        if not (isinstance(action, str) and action and isinstance(resource, str) and resource):
            raise ValueError("an Act's action and resource are non-empty strings")
        if not (isinstance(mission_id, str) and mission_id):
            raise ValueError("a Mission id is a non-empty string")
        if admission_id is not None and not (isinstance(admission_id, str) and admission_id):
            raise ValueError("an admission_id is a non-empty string")
        if any(len(v) > MAX_IDENTIFIER_LENGTH
               for v in (mission_id, action, resource, admission_id or "")):
            raise ValueError("an identifier is longer than this History Authority accepts")
        with self._lock:
            # A Mission is recorded with its first Act, not by a refused
            # admission.
            records = self._missions.get(mission_id, [])
            if admission_id is not None:
                for r in records:
                    if r.admission_id == admission_id and r.recorded_by == writer:
                        if (r.act.seq, r.act.action, r.act.resource) != (seq, action, resource):
                            raise HistoryConflict(
                                f"mission {mission_id}: admission_id already used "
                                f"for a different act"
                            )
                        return r.act
            expected = len(records) + 1
            if seq != expected:
                raise HistoryConflict(
                    f"mission {mission_id}: seq {seq} is not the next position"
                )
            if self._max_acts is not None and len(records) >= self._max_acts:
                raise ValueError(f"mission {mission_id} holds the most Acts this "
                                 "History Authority keeps for one Mission")
            act = Act(seq=seq, action=action, resource=resource, outcome=ActOutcome.OPEN)
            records.append(_Record(act=act, recorded_by=writer, admission_id=admission_id))
            self._missions[mission_id] = records
            return act

    def set_outcome(
        self,
        mission_id: str,
        seq: int,
        outcome: ActOutcome,
        writer: str,
        result_classes: frozenset[str] = frozenset(),
        admission_id: str | None = None,
    ) -> Act:
        """Transition an act's outcome from OPEN to COMPLETED or FAILED, once.

        Only the writer that admitted the act may set its outcome: otherwise
        one PEP could mark another PEP's read as ``failed`` and hide it from
        the predicate. Re-sending the outcome already recorded is idempotent;
        a different outcome is rejected.
        """
        # Authenticate before looking at anything else, so an unauthenticated
        # caller learns nothing, not even whether its request was well formed.
        self._check_writer(writer)
        if outcome is ActOutcome.OPEN:
            raise OutcomeAlreadySet("cannot set an outcome back to open")
        if outcome is ActOutcome.FAILED and result_classes:
            raise ValueError("a failed outcome carries no result classes")
        if any(not (isinstance(c, str) and c) for c in result_classes):
            # A class names a category, so it is never empty.
            raise ValueError("a result class is a non-empty string")
        if len(result_classes) > MAX_RESULT_CLASSES or any(
                len(c) > MAX_CLASS_LENGTH for c in result_classes):
            raise ValueError("more or longer result classes than this History Authority keeps")
        if any("*" in c for c in result_classes):
            # A class must never read as a pattern or as the conservative
            # top, which only the PDP assigns.
            raise ValueError("a result class must not contain '*'")
        classes = result_classes if outcome is ActOutcome.COMPLETED else frozenset()
        with self._lock:
            records = self._missions.get(mission_id, [])
            if seq < 1 or seq > len(records):
                raise UnknownAct(f"mission {mission_id}: no act at seq {seq}")
            record = records[seq - 1]
            if record.recorded_by != writer:
                raise NotPermitted(
                    f"mission {mission_id} seq {seq}: only the writer that "
                    "admitted this act may set its outcome"
                )
            if record.admission_id is not None and admission_id != record.admission_id:
                # The outcome belongs to another admission: one this authority
                # lost and whose position it reused, even for the same writer.
                # Applying it would record another Act's outcome on this one.
                raise UnknownAct(
                    f"mission {mission_id} seq {seq}: no act of this admission"
                )
            if record.act.outcome is not ActOutcome.OPEN:
                if (
                    record.act.outcome is outcome
                    and record.act.result_classes == classes
                ):
                    return record.act  # duplicate delivery of the same outcome
                raise OutcomeAlreadySet(
                    f"mission {mission_id} seq {seq}: outcome already set"
                )
            record.act = Act(
                seq=seq,
                action=record.act.action,
                resource=record.act.resource,
                outcome=outcome,
                result_classes=classes,
            )
            return record.act

    def close_stranded(self, mission_id: str, seq: int, operator: str) -> Act:
        """Close an Open Act whose PEP will never report, as ``completed``
        with no result classes, which the PDP evaluates at the conservative
        top.

        This releases the Acts its sequences hold back (rule 5) without ever
        hiding the Act: it is never recorded ``failed``, because nobody but
        the admitting PEP can know the action had no effect. The operator
        calls it only once the effect can no longer start or still be in
        progress, for example the PEP is stopped and its credential to the
        resource revoked. Only configured operators may call it.
        """
        if not operator:
            raise UnauthenticatedWriter("operator identity is required")
        if operator not in self._operators:
            raise NotPermitted("only a configured operator may close an open act")
        with self._lock:
            records = self._missions.get(mission_id, [])
            if seq < 1 or seq > len(records):
                raise UnknownAct(f"mission {mission_id}: no act at seq {seq}")
            record = records[seq - 1]
            if record.act.outcome is not ActOutcome.OPEN:
                raise OutcomeAlreadySet(f"mission {mission_id} seq {seq}: outcome already set")
            record.act = Act(seq=seq, action=record.act.action, resource=record.act.resource,
                             outcome=ActOutcome.COMPLETED)
            return record.act

    def designate(self, policies: frozenset[str] | None) -> None:
        """Designate, by digest, the sets of Restricted Sequences a new Mission
        may be pinned to (None: any). A pin already set never moves, so a
        designation only decides which set the Missions that start afterwards
        get, whichever PDP reads them first. It can only refuse a read, never
        permit an Act."""
        with self._lock:
            self._new_mission_policies = policies

    def history(self, mission_id: str, policy: str | None = None) -> list[Act]:
        """The ordered history of a mission, up to its current next position.

        ``policy`` is the digest of the Restricted Sequences the reading PDP
        applies. The first read that names one pins it for the Mission, before
        any Act of the Mission can have been decided; a read naming another
        digest raises ``PolicyMismatch``, so a PDP with a different set (a
        replica mid-rollout, or after a policy change) never decides for a
        Mission that started under another set.
        """
        with self._lock:
            if policy is not None:
                designated = self._new_mission_policies
                if (mission_id not in self._policy and designated is not None
                        and policy not in designated):
                    # Refused, and nothing is pinned: a PDP that applies
                    # the designated set can still start this Mission.
                    raise PolicyMismatch(
                        f"mission {mission_id} is not bound yet, and this set is "
                        "not designated for new Missions"
                    )
                pinned = self._policy.setdefault(mission_id, policy)
                if pinned != policy:
                    raise PolicyMismatch(
                        f"mission {mission_id} is bound to another set of "
                        "Restricted Sequences"
                    )
            return [r.act for r in self._missions.get(mission_id, [])]

    def policy_of(self, mission_id: str) -> str | None:
        """The digest of the Restricted Sequences pinned for the Mission, if any."""
        with self._lock:
            return self._policy.get(mission_id)

    def recorded_by(self, mission_id: str, seq: int) -> str:
        with self._lock:
            records = self._missions.get(mission_id, [])
            if seq < 1 or seq > len(records):
                raise UnknownAct(f"mission {mission_id}: no act at seq {seq}")
            return records[seq - 1].recorded_by
