"""The composition model: acts, result classes, restricted sequences, policy.

A ``RestrictedSequence``
is an ordered tuple of ``SequenceStep`` patterns. ``CompositionPolicy.completes``
answers the one question the predicate asks: would admitting a candidate act
into the mission history, taken in admission order, complete a restricted
sequence with the candidate as one of its elements? Without persistent steps
the candidate is necessarily the final element.

Result classes are labels in the deployment's label domain, assigned by the
enforcing side. They are matched with a conservative top: an act whose outcome
is open, or whose result class the policy does not recognize, is treated as the
most sensitive, so a missing label never makes a sequence look harmless.
"""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_right
from dataclasses import dataclass, field
from enum import StrEnum
from functools import cached_property


class ActOutcome(StrEnum):
    """Lifecycle of an act's execution outcome."""

    OPEN = "open"          # admitted, outcome not yet reported
    COMPLETED = "completed"  # performed; result classes known
    FAILED = "failed"        # affirmative non-execution


# The conservative top: the most sensitive result class. An act that has not
# reported, or whose class is unknown, is evaluated as if it returned this.
CONSERVATIVE_TOP = "*"


@dataclass(frozen=True)
class Act:
    """One admitted action under a mission, in admission order.

    ``seq`` is the gapless, mission-wide position assigned by the ordering
    authority. ``result_classes`` are set by the enforcing side after execution,
    never by the agent.
    """

    seq: int
    action: str
    resource: str
    outcome: ActOutcome = ActOutcome.OPEN
    result_classes: frozenset[str] = frozenset()

    def effective_classes(self) -> frozenset[str]:
        """Classes to match against, applying the conservative top.

        An act that is not COMPLETED, or that reported no class, is treated as
        the conservative top, because its sensitivity is not established.
        """
        if self.outcome is ActOutcome.FAILED:
            return frozenset()  # affirmatively did nothing: no classes
        if self.outcome is not ActOutcome.COMPLETED or not self.result_classes:
            return frozenset({CONSERVATIVE_TOP})
        return self.result_classes


def _glob_match(pattern: str, value: str) -> bool:
    """Match a result class against a class pattern.

    ``*`` matches anything. ``a.*`` matches ``a.`` prefixes. Otherwise exact.
    The conservative top ``*`` on the act side matches any required class, so
    an unestablished act can complete any sequence step.
    """
    if value == CONSERVATIVE_TOP:
        return True
    return _name_match(pattern, value)


def _name_match(pattern: str, value: str) -> bool:
    """Match an action name or resource id against a pattern, as recorded.

    The conservative top applies to result classes only: an act's action and
    resource are known, so a value spelled ``*`` is just that string.
    """
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


@dataclass(frozen=True)
class SequenceStep:
    """One step of a restricted sequence: patterns an act must match.

    ``action`` matches the act's action name (exact or ``*``-glob).
    ``resources`` and ``result_classes``, when non-empty, each require the act
    to match at least one listed pattern. An empty set means "any".
    ``persistent`` marks a step whose effect does not end with the act: a
    public share link, a forwarding rule, a webhook, a credential issued to a
    third party, a recurring or scheduled job. An act matching it takes effect
    at its admission and at every later point of the Mission.
    """

    action: str
    resources: frozenset[str] = frozenset()
    result_classes: frozenset[str] = frozenset()
    persistent: bool = False

    def matches(self, act: Act) -> bool:
        """Profile "Step patterns": action, then resources, then classes;
        an empty set matches every value."""
        return (
            _name_match(self.action, act.action)
            and (not self.resources
                 or any(_name_match(p, act.resource) for p in self.resources))
            and (not self.result_classes
                 or any(_glob_match(req, have)
                        for req in self.result_classes
                        for have in act.effective_classes()))
        )


@dataclass(frozen=True)
class RestrictedSequence:
    """An ordered tuple of steps that policy prohibits when completed.

    ``requestable`` marks a completion that MAY be returned as an ARAP
    requestable denial, so a person can approve the final act.
    """

    name: str
    steps: tuple[SequenceStep, ...]
    requestable: bool = False

    def __post_init__(self) -> None:
        if len(self.steps) < 2:
            raise ValueError("a restricted sequence needs at least two steps")
        if self.steps[0].persistent:
            # Persistence lets an early Act fill a later step. The first step
            # has no step before it, so the mark would do nothing, and a
            # policy author who wrote it most likely meant the lasting effect
            # to come last, where it exposes the data.
            raise ValueError(
                "the first step cannot be persistent: put the lasting effect "
                "at the step where it exposes the data, usually the last"
            )

    @property
    def k(self) -> int:
        return len(self.steps)


def _completes(history: list[Act], candidate: Act, seq: RestrictedSequence) -> bool:
    """True if admitting ``candidate`` completes ``seq`` with the candidate in it.

    Positions are the Admission Order. An act matching a non-persistent step
    takes effect at its own position. An act matching a *persistent* step
    takes effect at its position and at every later point, including points
    after the candidate, so it can fill any step that comes after its
    admission. Without persistent steps this is exactly "the last step matches
    the candidate and the first k-1 steps are an ordered subsequence of the
    history".

    Each search state keeps the earliest position at which the first j steps
    can be filled, separately for embeddings that do and do not use the
    candidate; earliest is always best for what follows, so this is exact.
    Positions are pairs (base, offset): a persistent act re-used after
    position t sits at (t.base, t.offset + 1), strictly between t and the next
    admitted act.
    """
    if not any(step.matches(candidate) for step in seq.steps):
        # The candidate must fill some step; most sequences end here, before
        # any work proportional to the history.
        return False
    acts = [a for a in sorted(history, key=lambda a: a.seq)
            if a.outcome is not ActOutcome.FAILED]
    # FAILED acts had no effect and cannot be part of a composition; OPEN acts
    # are matched at the conservative top.
    positions = [a.seq for a in acts]
    Pos = tuple[int, int]

    def earliest(step: SequenceStep, t: Pos) -> Pos | None:
        """Earliest position after ``t`` at which a history act fills ``step``."""
        if step.persistent:
            # Any match takes effect from its own position on, so the first
            # match overall decides: at or before t it is in effect just
            # after t; otherwise it starts at its own position.
            for a in acts:
                if step.matches(a):
                    return (a.seq, 0) if (a.seq, 0) > t else (t[0], t[1] + 1)
            return None
        for i in range(bisect_right(positions, t[0]), len(acts)):
            if step.matches(acts[i]):
                return (acts[i].seq, 0)
        return None

    def at_candidate(step: SequenceStep, t: Pos) -> Pos | None:
        """Position at which the candidate fills ``step`` after ``t``, if it does."""
        if not step.matches(candidate):
            return None
        here = (candidate.seq, 0)
        if here > t:
            return here
        return (t[0], t[1] + 1) if step.persistent else None

    def better(a: Pos | None, b: Pos | None) -> Pos | None:
        if a is None:
            return b
        return a if b is None or a <= b else b

    # without / with: earliest position after filling the steps so far, by
    # embeddings that have not / have used the candidate. Earliest is always
    # best for what follows, so keeping only the minimum is exact.
    without: Pos | None = (0, 0)
    with_: Pos | None = None
    for step in seq.steps:
        new_without = earliest(step, without) if without is not None else None
        new_with = better(
            at_candidate(step, without) if without is not None else None,
            better(earliest(step, with_), at_candidate(step, with_))
            if with_ is not None else None,
        )
        without, with_ = new_without, new_with
    return with_ is not None


def _step_set(seq: RestrictedSequence, act: Act) -> frozenset[int]:
    """Indices of the steps of ``seq`` that ``act`` matches."""
    return frozenset(i for i, step in enumerate(seq.steps) if step.matches(act))


@dataclass(frozen=True)
class CompositionDecision:
    """Result of evaluating the composition predicate."""

    satisfied: bool
    completed: tuple[str, ...] = ()      # names of completed restricted sequences
    requestable: bool = False            # every completed sequence is requestable


def jcs(value: object) -> bytes:
    """RFC 8785 (JCS) bytes of a value made of strings, booleans, arrays and
    objects with ASCII member names, the only kinds a Policy Object holds.

    For that value space JCS is exactly this: members sorted, no whitespace,
    non-ASCII characters as UTF-8 rather than escapes, and the escapes JSON
    requires. A string that is not valid Unicode (a lone surrogate) cannot be
    encoded and is refused.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class CompositionPolicy:
    """The set of restricted sequences a deployment prohibits.

    Policy is out of scope of the profile; this type is how a deployment
    expresses it to the reference PDP.
    """

    sequences: tuple[RestrictedSequence, ...] = field(default_factory=tuple)
    # The label domain: class patterns for the result classes the deployment's
    # PEPs assign. A class outside it is the conservative top. When None, the
    # domain is the class patterns the steps name, which ties recognition to
    # the sequences present: adding a sequence that names a class then narrows
    # the top for the others. Declaring the domain makes adding a sequence
    # never permit more.
    label_domain: frozenset[str] | None = None

    def __post_init__(self) -> None:
        # A `*` class pattern, named by a step or declared, would recognize
        # every class, so none would be the conservative top. A step that
        # means any class names no class pattern.
        named = {p for s in self.sequences for st in s.steps for p in st.result_classes}
        if "*" in named or (self.label_domain is not None and "*" in self.label_domain):
            raise ValueError("a `*` class pattern would leave no class at the conservative top")

    @cached_property
    def digest(self) -> str:
        """A stable identifier of this exact set of Restricted Sequences.

        Every PDP that decides for a Mission must apply the same set, and the
        set must not change during the Mission. The History Authority pins
        the digest of the first PDP that evaluates for a Mission, so a replica
        with another set, for example mid-rollout, is detected and refused.

        The profile defines the form (Policy digest): the Policy Object with
        every member present, set-valued arrays sorted by their UTF-8 bytes
        without repeats, the sequences sorted by their own canonical bytes
        without repeats, serialized with JCS (RFC 8785), then SHA-256.
        """
        canonical = [
            {
                "name": s.name,
                "requestable": s.requestable,
                "steps": [
                    {
                        "action": st.action,
                        "resources": sorted(st.resources),
                        "result_classes": sorted(st.result_classes),
                        "persistent": st.persistent,
                    }
                    for st in s.steps
                ],
            }
            for s in self.sequences
        ]
        # A set: neither the order the sequences are listed in nor a repeat
        # changes it, so neither changes the digest. Each sequence is placed
        # by its own canonical text.
        unique = {jcs(c): c for c in canonical}
        body: dict[str, object] = {
            "restricted_sequences": [unique[k] for k in sorted(unique)]}
        if self.label_domain is not None:
            body["label_domain"] = sorted(self.label_domain)
        return "sha256:" + hashlib.sha256(jcs(body)).hexdigest()

    @cached_property
    def _vocab(self) -> frozenset[str]:
        """The class patterns that recognize a result class: the declared
        label domain, or else every class pattern a step names. A class none
        of them matches is the conservative top."""
        if self.label_domain is not None:
            return self.label_domain
        return frozenset(p for seq in self.sequences for step in seq.steps
                         for p in step.result_classes)

    def _normalize(self, act: Act) -> Act:
        """Replace unrecognized result classes with the conservative top.

        Each class of a COMPLETED act that matches no pattern in the policy is
        evaluated as the top, even when other classes of the same act are
        recognized; an open or classless act is the top already.
        """
        if act.outcome is not ActOutcome.COMPLETED:
            return act  # effective_classes already yields the top (or nothing)
        vocab = self._vocab
        recognized = {
            c for c in act.result_classes
            if any(_glob_match(p, c) for p in vocab)
        }
        if recognized == act.result_classes:
            return act
        # At least one class is unknown to the policy: that class is the top.
        # Recognizing some other class of the same act does not make the
        # unknown one harmless.
        return Act(
            seq=act.seq, action=act.action, resource=act.resource,
            outcome=ActOutcome.COMPLETED,
            result_classes=frozenset(recognized) | {CONSERVATIVE_TOP},
        )

    def completes(self, history: list[Act], candidate: Act) -> CompositionDecision:
        """Evaluate the composition predicate for ``candidate``.

        The predicate is *unsatisfied* (satisfied=False) when admitting the
        candidate would complete at least one restricted sequence.
        """
        norm_history = [self._normalize(a) for a in history]
        norm_candidate = self._normalize(candidate)
        completed = [
            s for s in self.sequences
            if _completes(norm_history, norm_candidate, s)
        ]
        if not completed:
            return CompositionDecision(satisfied=True)
        return CompositionDecision(
            satisfied=False,
            completed=tuple(s.name for s in completed),
            # Requestable only if a person may approve every sequence the act
            # completes: one approval must never cover a sequence policy
            # does not allow anyone to approve.
            requestable=all(s.requestable for s in completed),
        )

    def pending_conflict(self, history: list[Act], candidate: Act) -> tuple[str, ...]:
        """Sequences for which admitting ``candidate`` now could let effect
        order differ from admission order in a way that matters.

        An OPEN act has been admitted but may not have produced its effect
        yet, so its effect can still land after the candidate's. That is
        harmless only if both acts match exactly one step, the same one:
        whatever their true classes turn out to be, each then matches that
        step or nothing, and swapping them changes no embedding. Otherwise the
        candidate must wait until the open act finishes.
        """
        norm_candidate = self._normalize(candidate)
        hits: list[str] = []
        for seq in self.sequences:
            mine = _step_set(seq, norm_candidate)
            if not mine:
                continue
            for act in history:
                if act.outcome is not ActOutcome.OPEN:
                    continue
                theirs = _step_set(seq, self._normalize(act))
                if theirs and not (theirs == mine and len(mine) == 1):
                    hits.append(seq.name)
                    break
        return tuple(hits)

    def extendable_sequences(self, candidate: Act) -> frozenset[RestrictedSequence]:
        """The restricted sequences any step of which the candidate matches:
        the sequences themselves, since two different ones may share a name.

        Such an act can start, extend or complete that sequence, so its
        admission must be serialized (profile "Ordering rules",
        rule 2). This is deliberately history-independent: an act matching a
        final step is serialized even on an empty history, because a
        concurrent admission could supply the prefix.
        """
        return frozenset(
            seq for seq in self.sequences
            if any(step.matches(candidate) for step in seq.steps)
        )

    def can_extend_prefix(self, candidate: Act) -> bool:
        """True if the candidate matches any step of any restricted sequence.

        Acts that match no step need no serialized admission (profile
        "Ordering rules", rule 2). Deliberately history-independent; see
        ``extendable_sequences``.
        """
        return bool(self.extendable_sequences(candidate))
