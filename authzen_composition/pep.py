"""The reference Policy Enforcement Point for the composition profile.

The PEP ties the pieces together exactly as the profile requires:

1. it takes the mission identifier from a trusted input (here, an argument of
   ``enforce`` standing in for a verified token claim), never from the agent;
2. it asks the PDP;
3. on a permit carrying a ``mission_record`` obligation, it records the act at
   the MHS at the named position *before* performing the action; a conflict
   means it must re-evaluate;
4. it performs the action only after the admission is acknowledged, then
   records the outcome and result classes;
5. if it cannot record the admission, it treats the permit as a deny (the
   Obligations Core's fail-closed rule);
6. it records ``failed`` only on affirmative non-execution (``NotPerformed``).
   Any other error leaves the act OPEN, evaluated at the conservative top.

Result classes come from the resource/PEP, never from the agent.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from authzen_composition.mhs import (
    HistoryAuthority,
    HistoryConflict,
    NoActAtPosition,
    NotPermitted,
    OutcomeAlreadySet,
    UnauthenticatedWriter,
    UnknownAct,
)
from authzen_composition.model import ActOutcome
from authzen_composition.types import (
    EXTENSION_OBLIGATIONS,
    OBLIGATION_MISSION_RECORD,
    Action,
    Decision,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)


class CompositionDenied(Exception):
    """Raised when the PEP must not perform the action.

    ``evaluation_id`` is set when the denial is ARAP-requestable: it is what a
    person approves, through the Access Request Service. ``decision`` and
    ``request`` are the PDP's denial and the evaluation it denied, which an
    Access Request echoes (``AccessRequestClient.submit``).
    """

    def __init__(self, reason: str | None, evaluation_id: str | None = None, *,
                 decision: Decision | None = None,
                 request: EvaluationRequest | None = None) -> None:
        super().__init__(reason or "denied")
        self.reason = reason
        self.evaluation_id = evaluation_id
        self.decision = decision
        self.request = request


class NotPerformed(Exception):
    """Raised by ``perform`` when the action affirmatively did not run.

    Only this exception lets the PEP record ``failed``. A timeout or crash is
    not proof of non-execution and must not be reported as one.
    """


def _approved_until(context: dict[str, Any] | None) -> datetime | None:
    """The ``approved_until`` of the approval the request presents, from which
    on the PEP neither admits the Act nor starts it (profile, rule 3); None
    when it presents none. One that cannot be read is taken as passed."""
    approval = (context or {}).get("approval")
    if not isinstance(approval, dict) or "approved_until" not in approval:
        return None
    try:
        until = datetime.fromisoformat(str(approval["approved_until"]))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return until if until.tzinfo is not None else datetime.min.replace(tzinfo=UTC)


@dataclass
class EffectPending:
    """Returned by ``perform`` when the call returned before its effect
    happened: a queued or scheduled send (``202 Accepted``), an asynchronous
    job. The Act stays open, which holds back the Acts of its sequences, until
    the integration calls ``ReferencePEP.effect_landed`` with the real result.
    Recording ``completed`` on the acceptance would let a later read land
    before the send that carries its data.
    """

    handle: object = None
    mission_id: str = ""
    seq: int = 0
    admission_id: str | None = None
    # An outcome that arrived before the PEP bound the handle to its Act (the
    # resource's callback ran before ``perform`` returned): the PEP records it
    # when it binds the handle.
    _early: tuple[ActOutcome, frozenset[str]] | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class DecisionPoint(Protocol):
    """What the PEP needs from a PDP: ``CompositionPDP`` in process, or
    ``remote.RemotePDP`` over the Access Evaluation API."""

    def evaluate(self, request: EvaluationRequest) -> Decision: ...


@dataclass
class ReferencePEP:
    """The reference PEP for one resource, writing to one History Authority."""

    pdp: DecisionPoint
    mhs: HistoryAuthority
    writer_id: str
    # Classifier: given (action, resource, raw_result) -> result classes.
    classifier: Callable[[str, str, object], frozenset[str]] = field(
        default=lambda action, resource, raw: frozenset()
    )
    can_record: bool = True
    # Outcomes that could not be recorded yet, kept for re-delivery, each with
    # the admission it reports on.
    unreported: list[tuple[str, int, ActOutcome, frozenset[str], str | None]] = field(
        default_factory=list
    )
    # Outcomes the authority refused for good (the Act already holds an
    # outcome, for example an operator closed it, or it does not exist):
    # never retried, kept here for the operator, with the authority's answer.
    refused: list[tuple[str, int, ActOutcome, frozenset[str], str]] = field(
        default_factory=list
    )
    # Admissions this PEP gave up on whose `failed` the authority refused for
    # want of an Act: they never committed, which is expected and not an
    # incident (profile, PEP rules). Should one commit later it stays open, at
    # the conservative top, until an operator closes it (profile, Security
    # considerations, Open Acts); kept with the authority's answer so that the
    # operator can watch for that.
    abandoned: list[tuple[str, int, str | None, str]] = field(default_factory=list)
    _given_up: set[tuple[str, int, str | None]] = field(default_factory=set, repr=False)
    _unreported_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # Wall clock for an approval's approved_until; injectable for tests.
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC), repr=False)

    def enforce(
        self,
        *,
        mission_id: str,
        mission_issuer: str,
        subject: Subject,
        action: Action,
        resource: Resource,
        perform: Callable[[], object],
        max_retries: int = 5,
        context: dict[str, Any] | None = None,
    ) -> object:
        """Enforce one action end to end. Returns the performed action's result.

        Raises CompositionDenied if the PDP denies or the obligation cannot be
        met. The mission id is supplied by the caller (a trusted claim), not by
        the agent. ``context`` is added to the request context, for example an
        ARAP ``approval``; the profile members are always set by the PEP.
        """
        until = _approved_until(context)
        for _ in range(max_retries):
            request = EvaluationRequest(
                subject=subject,
                action=action,
                resource=resource,
                mission=Mission(id=mission_id, issuer=mission_issuer),
                supported_mandatory_extensions=(EXTENSION_OBLIGATIONS,),
                supported_obligations=(OBLIGATION_MISSION_RECORD,),
                context=dict(context or {}),
            )
            decision = self.pdp.evaluate(request)

            if not decision.decision:
                raise CompositionDenied(decision.reason, decision.evaluation_id,
                                        decision=decision, request=request)

            if any(o.type != OBLIGATION_MISSION_RECORD for o in decision.obligations):
                # This PEP adopts the Obligations Core: a permit carrying
                # an obligation it does not understand is a deny.
                raise CompositionDenied("obligation_not_understood")

            if until is not None and self.clock() >= until:
                # Rule 3: no admission and no effect from the approval's
                # approved_until on; the PEP gives up instead.
                raise CompositionDenied("approval_expired")
            obligation = next(
                (o for o in decision.obligations if o.type == OBLIGATION_MISSION_RECORD),
                None,
            )
            if obligation is None:
                # Permit with no admission obligation: perform directly.
                return perform()
            props = obligation.properties
            seq_value = props.get("expected_seq")
            if (sum(o.type == OBLIGATION_MISSION_RECORD for o in decision.obligations) != 1
                    or set(props) != {"mission", "expected_seq"}
                    or props.get("mission") != mission_id
                    or not isinstance(seq_value, int) or isinstance(seq_value, bool)
                    or not 1 <= seq_value <= 2**53 - 1):
                # Cannot comply (Obligations Core, Non-Compliance): a deny,
                # and nothing is admitted for an Act that will not run.
                raise CompositionDenied("obligation_not_understood")

            if not self.can_record:
                # Cannot meet a mandatory obligation: treat the permit as deny.
                raise CompositionDenied("mission_record_unavailable")

            expected_seq = seq_value
            admission_id = uuid.uuid4().hex
            admitted = False
            for _attempt in range(2):
                try:
                    act = self.mhs.admit(
                        mission_id=mission_id,
                        seq=expected_seq,
                        action=action.name,
                        resource=resource.id,
                        writer=self.writer_id,
                        admission_id=admission_id,
                    )
                except HistoryConflict:
                    break
                except (UnauthenticatedWriter, ValueError):
                    # Refused for good (the writer is not authenticated or not
                    # trusted, or the Act is malformed): nothing was admitted,
                    # so no failed is owed (rule 3).
                    raise CompositionDenied("mission_record_unavailable") from None
                except Exception:
                    # Acknowledgement lost or authority unreachable. Retry once
                    # with the same admission id: if the first call committed,
                    # the retry returns that act instead of a duplicate.
                    continue
                if act.outcome is not ActOutcome.OPEN:
                    # The Act already has an outcome: this answers a retry of
                    # an admission that was resolved, and is not an
                    # acknowledgement. Nothing may start, and the Act is owed
                    # no outcome: it has one.
                    raise CompositionDenied("mission_record_unavailable")
                admitted = True
                break
            else:
                # No acknowledgement: the action MUST NOT start. The admission
                # may still have committed (only the acknowledgement lost):
                # resolve it as failed, which is true because the Act never
                # ran, so that it does not stay open and hold back its
                # sequences. Redelivery retries until the authority answers;
                # if nothing was admitted there, the outcome is refused.
                with self._unreported_lock:
                    self._given_up.add((mission_id, expected_seq, admission_id))
                    self.unreported.append(
                        (mission_id, expected_seq, ActOutcome.FAILED, frozenset(),
                         admission_id))
                raise CompositionDenied("mission_record_unavailable")
            if not admitted:
                # Someone admitted in between: re-evaluate from the top.
                continue

            if until is not None and self.clock() >= until:
                # The approval expired after the admission: the Act never ran,
                # so failed is true, and it releases the position.
                self._report(mission_id, expected_seq, ActOutcome.FAILED, frozenset(),
                             admission_id)
                raise CompositionDenied("approval_expired")
            # Admitted and acknowledged. Only now may the effect begin. Any
            # error other than NotPerformed (a timeout, a crash mid-call) leaves
            # the Act open, at the conservative top: the PEP cannot tell
            # whether the effect happened, and `failed` would hide it.
            try:
                raw = perform()
            except NotPerformed:
                # Affirmative non-execution: safe to release the position.
                self._report(mission_id, expected_seq, ActOutcome.FAILED, frozenset(),
                             admission_id)
                raise
            if isinstance(raw, EffectPending):
                # Accepted, not done. Leave the Act open until the effect
                # lands, unless it already settled.
                with raw._lock:
                    raw.mission_id, raw.seq = mission_id, expected_seq
                    raw.admission_id = admission_id
                    early, raw._early = raw._early, None
                if early is not None:
                    self._report(mission_id, expected_seq, *early, admission_id)
                return raw
            classes = self.classifier(action.name, resource.id, raw)
            self._report(mission_id, expected_seq, ActOutcome.COMPLETED, classes,
                         admission_id)
            return raw

        raise CompositionDenied("too_many_conflicts")

    def effect_landed(self, pending: EffectPending, action: str, resource: str,
                      raw: object) -> None:
        """The deferred effect of ``pending`` has now happened: record it."""
        self._settle(pending, ActOutcome.COMPLETED, self.classifier(action, resource, raw))

    def effect_cancelled(self, pending: EffectPending) -> None:
        """The deferred effect was cancelled before it happened, and the
        resource confirmed it never will: affirmative non-execution."""
        self._settle(pending, ActOutcome.FAILED, frozenset())

    def _settle(self, pending: EffectPending, outcome: ActOutcome,
                classes: frozenset[str]) -> None:
        with pending._lock:
            if not pending.seq:
                # Not yet bound to its Act: ``enforce`` records it when it is.
                pending._early = (outcome, classes)
                return
        self._report(pending.mission_id, pending.seq, outcome, classes, pending.admission_id)

    def _report(
        self, mission_id: str, seq: int, outcome: ActOutcome, classes: frozenset[str],
        admission_id: str | None = None,
    ) -> None:
        """Record an outcome. If the record cannot be written, the act stays OPEN.

        An unrecorded outcome never weakens the predicate: the act is matched at
        the conservative top until the outcome lands. The PEP keeps it for
        re-delivery, which the MHS accepts idempotently, unless the authority
        refused it for good (see ``refused``).
        """
        given_up = (mission_id, seq, admission_id)
        try:
            self.mhs.set_outcome(
                mission_id, seq, outcome, writer=self.writer_id, result_classes=classes,
                admission_id=admission_id,
            )
        except NoActAtPosition as exc:
            with self._unreported_lock:
                if given_up in self._given_up:
                    # The admission it gave up on never committed (rule 3).
                    self._given_up.discard(given_up)
                    self.abandoned.append((mission_id, seq, admission_id, str(exc)))
                else:
                    self.refused.append((mission_id, seq, outcome, classes, str(exc)))
            return
        except (OutcomeAlreadySet, UnknownAct, NotPermitted, ValueError) as exc:
            # A final answer: retrying cannot change it, and dropping the
            # outcome changes nothing the authority holds. It is an incident
            # for the operator: an outcome this PEP did not write now stands
            # for the Act (an operator's close, or another holder of this
            # writer identity), the position now holds another writer's Act,
            # or the authority lost an Act it acknowledged or refuses the
            # outcome itself (a 400). A failed credential (401) is not final:
            # it is kept and redelivered like any transient failure.
            with self._unreported_lock:
                self.refused.append((mission_id, seq, outcome, classes, str(exc)))
        except Exception:
            with self._unreported_lock:
                self.unreported.append((mission_id, seq, outcome, classes, admission_id))
            return
        # Recorded, or refused for good for another reason: no longer pending.
        with self._unreported_lock:
            self._given_up.discard(given_up)

    def redeliver(self) -> None:
        """Retry outcomes that could not be recorded (late delivery).

        Safe to call from several threads, and alongside deferred effects
        landing: each kept outcome is taken by exactly one call.
        """
        with self._unreported_lock:
            pending, self.unreported = self.unreported, []
        for mission_id, seq, outcome, classes, admission_id in pending:
            self._report(mission_id, seq, outcome, classes, admission_id)
