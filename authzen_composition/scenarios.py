"""Reusable scenario fixtures shared by tests and interop vectors.

Each scenario builds a policy and a sequence of (action, resource, result)
steps, with the expected decision for each. The same definitions drive the
pytest suite and the exported interop test vectors, so the vectors are known to
match running code. Scenario ids are stable labels, not a dense sequence:
some scenarios live only in ``tests/test_scenarios.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from authzen_composition.model import (
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)


@dataclass(frozen=True)
class Step:
    """One act in a scenario, with the result class the resource assigns."""

    pep: str
    action: str
    resource: str
    result_classes: tuple[str, ...] = ()
    expect_permit: bool = True
    expect_reason: str | None = None
    # How the act's outcome is reported before the next act: "completed",
    # "open" (admitted, no outcome yet) or "failed" (affirmatively not run).
    # Used by the interop vectors; the pytest scenario driver completes acts.
    outcome: str = "completed"
    # Checked on the final act of an interop vector when not None:
    # the permit carries mission_record at this expected_seq (0 = no
    # obligation), and the denial's requestable flag. Only `False` is ever
    # required, where the profile says MUST NOT; requestable is a MAY.
    expect_obligation_seq: int | None = None
    expect_requestable: bool | None = None
    # What the PEP declares: the extensions it adopts (the Obligations
    # Core, to receive mission_record) and the Obligation Types it can
    # execute.
    extensions: tuple[str, ...] = ("obligations",)
    obligation_types: tuple[str, ...] = ("mission_record",)


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    policy: CompositionPolicy
    steps: tuple[Step, ...] = field(default_factory=tuple)


# The canonical restricted sequence used across several scenarios:
# read personal data -> write a document -> send it outside the owner's team.
EXFIL = RestrictedSequence(
    name="read_personal_write_send_external",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("write_document"),
        SequenceStep("send_message", resources=frozenset({"external:*"})),
    ),
    requestable=True,
)

EXFIL_POLICY = CompositionPolicy((EXFIL,))


def all_scenarios() -> tuple[Scenario, ...]:
    return (
        Scenario(
            id="S1",
            title="Ordered composition across three PEPs is denied at the send",
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.doc", "write_document", "doc:q4"),
                Step(
                    "pep.mail", "send_message", "external:all-staff",
                    expect_permit=False, expect_reason="prohibited_composition",
                ),
            ),
        ),
        Scenario(
            id="S2",
            title="Reverse order does not trigger (send before read)",
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.mail", "send_message", "external:all-staff"),
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.doc", "write_document", "doc:q4"),
            ),
        ),
        Scenario(
            id="S3",
            title=(
                "No read was admitted, so write then send is permitted: "
                "history holds only enforced acts"
            ),
            # The read is never admitted; without the mission-wide authority the
            # send would look harmless. The MHS is the only history source, so a
            # read the PEP omits simply is not there, and the send is permitted.
            # The attack is defeated by making the authority, not the agent, the
            # source of truth: a read that WAS enforced cannot be hidden.
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.doc", "write_document", "doc:q4"),
                Step("pep.mail", "send_message", "external:all-staff"),
            ),
        ),
        Scenario(
            id="S5",
            title="Open outcome is treated as the conservative top",
            policy=EXFIL_POLICY,
            steps=(),  # driven directly in the test (needs an un-reported act)
        ),
        Scenario(
            id="S6",
            title="Unknown result class is treated as the conservative top",
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("mystery.unknown",)),
                Step("pep.doc", "write_document", "doc:q4"),
                Step(
                    "pep.mail", "send_message", "external:all-staff",
                    expect_permit=False, expect_reason="prohibited_composition",
                ),
            ),
        ),
        Scenario(
            id="S11",
            title="Internal send does not complete the external-send sequence",
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.doc", "write_document", "doc:q4"),
                Step("pep.mail", "send_message", "internal:team"),
            ),
        ),
    )


READ_SEND = RestrictedSequence(
    name="read_personal_then_send_external",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send_message", resources=frozenset({"external:*"})),
    ),
)


def vector_only_scenarios() -> tuple[Scenario, ...]:
    """Scenarios exported only as interop vectors: rules an implementation
    can get wrong, non-completed outcomes among them. The verifier replays
    them and honors ``Step.outcome``."""
    return (
        Scenario(
            id="V1",
            title="An open read (outcome not yet reported) blocks the external send",
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", outcome="open"),
                Step("pep.doc", "write_document", "doc:q4"),
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V2",
            title="A failed read (affirmatively not run) does not count",
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", outcome="failed"),
                Step("pep.doc", "write_document", "doc:q4"),
                # The failed Act keeps its position: the send is admitted at 3.
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_obligation_seq=3),
            ),
        ),
        Scenario(
            id="V3",
            title="A send still in flight holds back a read of the same sequence",
            policy=CompositionPolicy((READ_SEND,)),
            steps=(
                Step("pep.mail", "send_message", "external:all-staff", outcome="open"),
                Step("pep.hr", "read_record", "hr:emp-1",
                     expect_permit=False, expect_reason="history_pending"),
            ),
        ),
        Scenario(
            id="V4",
            title="Once the send has finished, the read is admitted",
            policy=CompositionPolicy((READ_SEND,)),
            steps=(
                Step("pep.mail", "send_message", "external:all-staff"),
                Step("pep.hr", "read_record", "hr:emp-1", expect_obligation_seq=2),
            ),
        ),
        Scenario(
            id="V5",
            title="Two reads matching the same single step may run concurrently",
            policy=CompositionPolicy((READ_SEND,)),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", outcome="open"),
                Step("pep.hr", "read_record", "hr:emp-2", expect_obligation_seq=2),
            ),
        ),
        Scenario(
            id="V6",
            title="A share link created first is still live: read then write is denied",
            policy=SHARE_POLICY,
            steps=(
                Step("pep.doc", "share_public", "doc:q4"),
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.doc", "write_document", "doc:q4",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V7",
            title="A share link created between the read and the write is caught too",
            policy=SHARE_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.doc", "share_public", "doc:q4"),
                Step("pep.doc", "write_document", "doc:q4",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V8",
            title="Writing before the read puts nothing behind the link: permitted",
            policy=SHARE_POLICY,
            steps=(
                Step("pep.doc", "share_public", "doc:q4"),
                Step("pep.doc", "write_document", "doc:q4"),
                Step("pep.hr", "read_record", "hr:emp-1"),
            ),
        ),
        Scenario(
            id="V9",
            title="The same acts as V6 without the persistent mark: permitted",
            policy=CompositionPolicy((PLAIN_LINK,)),
            steps=(
                Step("pep.doc", "share_public", "doc:q4"),
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.doc", "write_document", "doc:q4"),
            ),
        ),
        Scenario(
            id="V10",
            title=(
                "A recognized class does not cover an unrecognized class of the "
                "same act: the unrecognized one is the top"
            ),
            policy=CompositionPolicy(
                (EXFIL,), label_domain=frozenset({"personal_data.*", "public.*"})),
            steps=(
                # public.faq is in the label domain but does not match
                # personal_data.*; mystery.unknown is outside it: the top.
                Step("pep.hr", "read_record", "hr:emp-1", ("public.faq", "mystery.unknown")),
                Step("pep.doc", "write_document", "doc:q4"),
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V11",
            title=(
                "A permit for an act that matches a step carries mission_record "
                "at the next position"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("public.faq",)),
                Step("pep.doc", "write_document", "doc:q4", expect_obligation_seq=2),
            ),
        ),
        Scenario(
            id="V12",
            title="A permit for an act that matches no step carries no obligation",
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.cal", "list_events", "cal:me", expect_obligation_seq=0),
            ),
        ),
        Scenario(
            id="V13",
            title=(
                "Completing a requestable and a non-requestable sequence at once: "
                "the denial MUST NOT be requestable"
            ),
            policy=CompositionPolicy((EXFIL, READ_SEND)),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.doc", "write_document", "doc:q4"),
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_permit=False, expect_reason="prohibited_composition",
                     expect_requestable=False),
            ),
        ),
        Scenario(
            id="V14",
            title=(
                "Without adopting the Obligations Core, an act that needs "
                "serialization gets a plain deny"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.doc", "write_document", "doc:q4",
                     expect_permit=False, expect_reason=None, extensions=()),
            ),
        ),
        Scenario(
            id="V15",
            title=(
                "A failed act still occupies its position: the candidate's "
                "position counts it"
            ),
            policy=CompositionPolicy((LINK_LAST,)),
            steps=(
                Step("pep.doc", "share_public", "doc:q4"),
                Step("pep.hr", "read_record", "hr:emp-1", outcome="failed"),
                Step("pep.hr", "read_record", "hr:emp-2"),
                Step("pep.doc", "write_document", "doc:q4",
                     expect_permit=False, expect_reason="prohibited_composition",
                     expect_obligation_seq=None),
            ),
        ),
        Scenario(
            id="V16",
            title=(
                "A persistent middle step admitted first: a later act fills the "
                "first step and the candidate the last"
            ),
            policy=CompositionPolicy((LINK_MIDDLE,)),
            steps=(
                Step("pep.doc", "share_public", "external:press"),
                Step("pep.mail", "send_message", "doc:d"),
                Step("pep.cal", "list_events", "cal:me",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V17",
            title=(
                "A declared but empty label domain recognizes no class: every "
                "class is the top"
            ),
            policy=CompositionPolicy((READ_PD_SEND,), label_domain=frozenset()),
            steps=(
                Step("pep.fin", "read_record", "fin:q4", ("finance.q4",)),
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V18",
            title=(
                "The same acts as V17 with a declared domain that recognizes the "
                "class: it does not match the step, permitted"
            ),
            policy=CompositionPolicy(
                (READ_PD_SEND,), label_domain=frozenset({"personal_data.*", "finance.*"})),
            steps=(
                Step("pep.fin", "read_record", "fin:q4", ("finance.q4",)),
                Step("pep.mail", "send_message", "external:all-staff"),
            ),
        ),
        Scenario(
            id="V19",
            title=(
                "One persistent Act fills two persistent steps, at two later "
                "points"
            ),
            policy=CompositionPolicy((TWO_PERSISTENT,)),
            steps=(
                Step("pep.mail", "forward_rule", "external:x"),
                Step("pep.hr", "read_record", "hr:emp-1",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V20",
            title=(
                "A sequence already completed in the history (the send was "
                "approved through ARAP) does not deny a candidate that is not "
                "part of it"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1"),
                Step("pep.doc", "write_document", "doc:q4"),
                # Denied when evaluated, then admitted on a person's approval.
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_permit=False, expect_reason="prohibited_composition"),
                Step("pep.doc", "write_document", "doc:q5", expect_obligation_seq=4),
            ),
        ),
        Scenario(
            id="V21",
            title=(
                "A completed read that reported no class is the conservative top: "
                "the send that completes the sequence is denied"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ()),
                Step("pep.doc", "write_document", "doc:q4"),
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V22",
            title=(
                "An Act that matches only the final step is serialized even on an "
                "empty history: a concurrent admission could supply the prefix"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_obligation_seq=1),
            ),
        ),
        Scenario(
            id="V23",
            title=(
                "An open read that could fill two steps holds back a read that could "
                "fill the same two: only one shared single step commutes"
            ),
            policy=CompositionPolicy((TWO_READS,)),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", outcome="open"),
                Step("pep.fin", "read_record", "fin:q4",
                     expect_permit=False, expect_reason="history_pending"),
            ),
        ),
        Scenario(
            id="V24",
            title=(
                "`personal_data.*` does not match `personal_data`: with the bare "
                "class recognized, the read does not fill the step"
            ),
            policy=CompositionPolicy(
                (READ_PD_SEND,), label_domain=frozenset({"personal_data.*", "personal_data"})),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data",)),
                Step("pep.mail", "send_message", "external:all-staff"),
            ),
        ),
        Scenario(
            id="V25",
            title=(
                "A PEP that lists `composition` but not the Obligations Core "
                "gets a plain deny, never mission_record: `composition` is not a signal"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.doc", "write_document", "doc:q4",
                     expect_permit=False, expect_reason=None, extensions=("composition",)),
            ),
        ),
        Scenario(
            id="V26",
            title=(
                "A PEP that adopts the Obligations Core but does not list "
                "mission_record in supported_obligations gets a plain deny"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.doc", "write_document", "doc:q4",
                     expect_permit=False, expect_reason=None, obligation_types=()),
            ),
        ),
        Scenario(
            id="V27",
            title=(
                "Rule 5 as written: an open write holds back an external send even "
                "with no read in the Mission (only one shared single step commutes)"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.doc", "write_document", "doc:notes", outcome="open"),
                Step("pep.mail", "send_message", "external:press",
                     expect_permit=False, expect_reason="history_pending"),
            ),
        ),
        Scenario(
            id="V28",
            title=(
                "Adopting the Obligations Core and listing mission_record is "
                "enough, and an extension the PDP does not implement is ignored: "
                "the profile has no separate opt-in signal"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_obligation_seq=1,
                     extensions=("obligations", "x-not-implemented")),
            ),
        ),
        Scenario(
            id="V29",
            title=(
                "Rule 5 as written: an open share link (a persistent step) holds back "
                "a read of its sequence"
            ),
            policy=SHARE_POLICY,
            steps=(
                Step("pep.doc", "share_public", "doc:q4", outcome="open"),
                Step("pep.hr", "read_record", "hr:emp-1",
                     expect_permit=False, expect_reason="history_pending"),
            ),
        ),
        Scenario(
            id="V30",
            title=(
                "A persistent Act also fills a step that is not persistent, at its "
                "own position: the same forwarding rule is the first step and, "
                "later, the last"
            ),
            policy=CompositionPolicy((FORWARD_AROUND,)),
            steps=(
                Step("pep.mail", "forward_rule", "external:x"),
                Step("pep.hr", "read_record", "hr:emp-1",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V31",
            title=(
                "The candidate fills two steps: one at its position and, being "
                "persistent, the last one after it"
            ),
            policy=CompositionPolicy((SHARE_TWICE,)),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1"),
                Step("pep.doc", "share_public", "doc:q4",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V32",
            title=(
                "A declared empty label domain: a class another sequence names "
                "is still the conservative top"
            ),
            policy=CompositionPolicy((FINANCE_ARCHIVE, READ_PD_SEND), label_domain=frozenset()),
            steps=(
                Step("pep.fin", "read_record", "fin:q4", ("finance.q4",)),
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V33",
            title=(
                "The same Acts with no declared domain: the class is recognized "
                "through the other sequence and matches no step of this one"
            ),
            policy=CompositionPolicy((FINANCE_ARCHIVE, READ_PD_SEND)),
            steps=(
                Step("pep.fin", "read_record", "fin:q4", ("finance.q4",)),
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_obligation_seq=2),
            ),
        ),
        Scenario(
            id="V34",
            title=(
                "A read that can match only a class-keyed step is Step-matching: "
                "mission_record on an empty history"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", expect_obligation_seq=1),
            ),
        ),
        Scenario(
            id="V35",
            title=(
                "A PEP that did not adopt the Obligations Core gets "
                "prohibited_composition, not requestable: check (b) comes before (d)"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.doc", "write_document", "doc:q4"),
                Step("pep.mail", "send_message", "external:all-staff",
                     expect_permit=False, expect_reason="prohibited_composition",
                     expect_requestable=False, extensions=()),
            ),
        ),
        Scenario(
            id="V36",
            title=(
                "A PEP that cannot execute mission_record gets history_pending: "
                "check (c) comes before (d)"
            ),
            policy=EXFIL_POLICY,
            steps=(
                Step("pep.doc", "write_document", "doc:notes", outcome="open"),
                Step("pep.mail", "send_message", "external:press",
                     expect_permit=False, expect_reason="history_pending",
                     obligation_types=()),
            ),
        ),
        Scenario(
            id="V37",
            title=(
                "Rule 5 counts the steps of each sequence on its own: two reads "
                "matching only the first step of two sequences may run together"
            ),
            policy=CompositionPolicy((READ_PD_SEND, READ_PD_UPLOAD)),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", outcome="open"),
                Step("pep.hr", "read_record", "hr:emp-2", expect_obligation_seq=2),
            ),
        ),
        Scenario(
            id="V38",
            title=(
                "Two persistent steps take effect between the same two "
                "consecutive Acts: the points are dense"
            ),
            policy=CompositionPolicy((FORWARD_SHARE_LIST,)),
            steps=(
                Step("pep.mail", "forward_rule", "external:x"),
                Step("pep.doc", "share_public", "doc:q4"),
                Step("pep.hr", "read_record", "hr:emp-1"),
                Step("pep.cal", "list_events", "cal:me",
                     expect_permit=False, expect_reason="prohibited_composition"),
            ),
        ),
        Scenario(
            id="V39",
            title="Patterns are case-sensitive: EXTERNAL:press does not match external:*",
            policy=CompositionPolicy((READ_PD_SEND,)),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.mail", "send_message", "EXTERNAL:press", expect_obligation_seq=0),
            ),
        ),
        Scenario(
            id="V40",
            title="Only the final * is a wildcard: external:** does not match external:x",
            policy=CompositionPolicy((STARRED_SEND,)),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.mail", "send_message", "external:x", expect_obligation_seq=0),
            ),
        ),
        Scenario(
            id="V41",
            title="A * inside a pattern is literal: ext*:x matches only ext*:x",
            policy=CompositionPolicy((MID_STAR_SEND,)),
            steps=(
                Step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)),
                Step("pep.mail", "send_message", "external:x", expect_obligation_seq=0),
            ),
        ),
    )


# A persistent step: a public share link keeps exposing the document after
# the Act that created it.
SHARE_LINK = RestrictedSequence(
    name="read_personal_write_shared_document",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("write_document", resources=frozenset({"doc:*"})),
        SequenceStep("share_public", resources=frozenset({"doc:*"}), persistent=True),
    ),
)
SHARE_POLICY = CompositionPolicy((SHARE_LINK,))
# V15: the persistent step is last, and the history holds a failed Act.
LINK_LAST = RestrictedSequence(
    name="read_write_shared",
    steps=(
        SequenceStep("read_record"),
        SequenceStep("write_document"),
        SequenceStep("share_public", persistent=True),
    ),
)
# V16: the persistent step is in the middle; the candidate fills the last step
# just after the point where the persistent Act is still live.
LINK_MIDDLE = RestrictedSequence(
    name="send_share_list",
    steps=(
        SequenceStep("send_message"),
        SequenceStep("share_public", resources=frozenset({"external:*"}), persistent=True),
        SequenceStep("list_events"),
    ),
)
# V17/V18: the same acts under an empty and a non-empty declared label domain.
READ_PD_SEND = RestrictedSequence(
    name="read_personal_send_external",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send_message", resources=frozenset({"external:*"})),
    ),
)
# V23: two steps with the same action, told apart only by the class read. An
# open read is the top, so it could fill either.
TWO_READS = RestrictedSequence(
    name="read_personal_read_finance_send_external",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("read_record", result_classes=frozenset({"finance.*"})),
        SequenceStep("send_message", resources=frozenset({"external:*"})),
    ),
)
# V19: one lasting effect admitted first fills both later persistent steps.
TWO_PERSISTENT = RestrictedSequence(
    name="read_forward_forward",
    steps=(
        SequenceStep("read_record"),
        SequenceStep("forward_rule", persistent=True),
        SequenceStep("forward_rule", persistent=True),
    ),
)
FORWARD_AROUND = RestrictedSequence(
    name="forward_read_forward",
    steps=(
        SequenceStep("forward_rule"),
        SequenceStep("read_record"),
        SequenceStep("forward_rule", persistent=True),
    ),
)
SHARE_TWICE = RestrictedSequence(
    name="read_share_share",
    steps=(
        SequenceStep("read_record"),
        SequenceStep("share_public"),
        SequenceStep("share_public", persistent=True),
    ),
)
PLAIN_LINK = RestrictedSequence(
    name="read_personal_write_shared_document",
    steps=tuple(SequenceStep(s.action, s.resources, s.result_classes) for s in SHARE_LINK.steps),
)


# Sequences of the vectors V32 to V41.
FINANCE_ARCHIVE = RestrictedSequence(
    name="read_finance_archive_external",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"finance.*"})),
        SequenceStep("archive", resources=frozenset({"external:*"})),
    ),
)
READ_PD_UPLOAD = RestrictedSequence(
    name="read_personal_upload_external",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("upload_file", resources=frozenset({"external:*"})),
    ),
)
FORWARD_SHARE_LIST = RestrictedSequence(
    name="read_forward_share_list",
    steps=(
        SequenceStep("read_record"),
        SequenceStep("forward_rule", persistent=True),
        SequenceStep("share_public", persistent=True),
        SequenceStep("list_events"),
    ),
)
STARRED_SEND = RestrictedSequence(
    name="read_personal_send_starred",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send_message", resources=frozenset({"external:**"})),
    ),
)
MID_STAR_SEND = RestrictedSequence(
    name="read_personal_send_mid",
    steps=(
        SequenceStep("read_record", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send_message", resources=frozenset({"ext*:x"})),
    ),
)


def _sequence(name: str, requestable: bool, *steps: tuple[str, list[str], list[str]]
              ) -> dict[str, object]:
    return {"name": name, "requestable": requestable,
            "steps": [{"action": action, "resources": resources,
                       "result_classes": classes, "persistent": False}
                      for action, resources, classes in steps]}


# Policies written as a person might, not as a Policy Object: members out of
# order and repeated, sequences repeated. An implementation computes the
# policy digest from the set they describe (profile, Policy digest).
DIGEST_CASES: tuple[tuple[str, str, dict[str, object]], ...] = (
    ("D1", "Patterns and sequences out of order and repeated; two names whose "
           "canonical order differs from their order as strings", {
        "restricted_sequences": [
            _sequence("b_seq", False,
                      ("read_record", [], ["q.*", "personal_data.*", "q.*"]),
                      ("send_message", ["y:*", "external:*", "y:*"], [])),
            _sequence("a_seq", True,
                      ("read_record", [], []), ("send_message", ["external:*"], [])),
            _sequence("a_seq 2", True,
                      ("read_record", [], []), ("upload_file", ["external:*"], [])),
            _sequence("b_seq", False,
                      ("read_record", [], ["personal_data.*", "q.*"]),
                      ("send_message", ["external:*", "y:*"], [])),
        ],
        "label_domain": ["q.*", "personal_data.*", "q.*"],
    }),
    ("D2", "Sets are sorted by their UTF-8 bytes (U+E000 before U+1F600), not by "
           "UTF-16 code units", {
        "restricted_sequences": [
            _sequence("read_personal_send_external", False,
                      ("read_record", [], ["personal_data.*"]),
                      ("send_message", ["external:*"], [])),
        ],
        "label_domain": ["\U0001F600.y", "\uE000.x", "caf\u00e9.*", "personal_data.*"],
    }),
)

