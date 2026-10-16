"""Relabeling, Mission identifier collision and trust-domain prefixes.

Relabeling: a class pattern on a step after the originating read is missed
when an intermediate operation honestly reclassifies its output with a
recognized class. The profile now says to key only the originating step on a
result class ({{patterns}}, Where to put class patterns). These tests pin both
halves: the fragile shape is a documented limitation, the recommended shape
blocks the same flow.

Mission identifier collision: under one set of Restricted Sequences a merged
history only adds Acts, so it never permits what either Mission alone would
deny. The merged Mission also has one pin, a documented limitation.
"""

from __future__ import annotations

from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import (
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.types import (
    REASON_POLICY_MISMATCH,
    REASON_PROHIBITED_COMPOSITION,
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
DOMAIN = frozenset({"pd.*", "public"})


def _req(action: str, res: str, mission: str = "m") -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject("agent", "a"), action=Action(action),
        resource=Resource("r", res), mission=Mission(mission, ISSUER),
        supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",))


def _run(pdp: CompositionPDP, mhs: MissionHistoryService, action: str, res: str,
         classes: frozenset[str] = frozenset(), mission: str = "m") -> bool:
    d = pdp.evaluate(_req(action, res, mission))
    if d.decision and d.obligations:
        seq = d.obligations[0].properties["expected_seq"]
        mhs.admit(mission, seq, action, res, writer="w")
        mhs.set_outcome(mission, seq, ActOutcome.COMPLETED, writer="w", result_classes=classes)
    return d.decision


def _flow(seq: RestrictedSequence) -> tuple[bool, str | None]:
    """Read salary, stage it through a summarizer that honestly labels its
    output public, then send it outside."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((seq,), label_domain=DOMAIN), mhs)
    assert _run(pdp, mhs, "read", "hr/1", frozenset({"pd.salary"}))
    assert _run(pdp, mhs, "stage", "doc/sum", frozenset({"public"}))
    d = pdp.evaluate(_req("send", "external:press"))
    return d.decision, d.reason


def test_class_pattern_on_a_later_step_is_missed_after_an_honest_relabel() -> None:
    """The fragile shape the profile advises against: the staging step
    requires pd.*, the summary is recognized as public, the chain is not
    completed. Documented limitation (Security considerations, Relabeling)."""
    fragile = RestrictedSequence("fragile", (
        SequenceStep("read", result_classes=frozenset({"pd.*"})),
        SequenceStep("stage", result_classes=frozenset({"pd.*"})),
        SequenceStep("send", resources=frozenset({"external:*"})),
    ))
    assert _flow(fragile) == (True, None)


def test_class_pattern_only_on_the_originating_read_blocks_the_relabelled_flow() -> None:
    """The recommended shape: only the read is keyed on a class, so the
    relabeled staging Act still fills its step and the send is denied."""
    robust = RestrictedSequence("robust", (
        SequenceStep("read", result_classes=frozenset({"pd.*"})),
        SequenceStep("stage"),
        SequenceStep("send", resources=frozenset({"external:*"})),
    ))
    assert _flow(robust) == (False, REASON_PROHIBITED_COMPOSITION)


def test_a_merged_mission_never_permits_what_one_mission_denies() -> None:
    """Two issuers minting the same mission id merge their Acts into one
    history. The extra Acts can only add completions."""
    seq = RestrictedSequence("s", (
        SequenceStep("read", result_classes=frozenset({"pd.*"})),
        SequenceStep("send", resources=frozenset({"external:*"})),
    ))
    policy = CompositionPolicy((seq,), label_domain=DOMAIN)

    alone = MissionHistoryService()
    pdp_alone = CompositionPDP(policy, alone)
    assert _run(pdp_alone, alone, "read", "hr/1", frozenset({"pd.salary"}))
    assert pdp_alone.evaluate(_req("send", "external:press")).decision is False

    merged = MissionHistoryService()
    pdp_merged = CompositionPDP(policy, merged)
    # The other issuer's unrelated Act lands first in the shared history.
    assert _run(pdp_merged, merged, "read", "kb/faq", frozenset({"public"}))
    assert _run(pdp_merged, merged, "read", "hr/1", frozenset({"pd.salary"}))
    d = pdp_merged.evaluate(_req("send", "external:press"))
    assert (d.decision, d.reason) == (False, REASON_PROHIBITED_COMPOSITION)


def test_a_merged_mission_is_decided_under_the_set_the_first_was_pinned_to() -> None:
    """The limitation the profile documents (Security considerations, Mission
    identifier collision): the merged Mission has one pin, so the later Mission
    is decided under the earlier one's set even once only a newer set is
    designated, and an Act of a sequence only the newer set has runs
    unadmitted."""
    read_send = RestrictedSequence("read-send", (
        SequenceStep("read", result_classes=frozenset({"pd.*"})),
        SequenceStep("send", resources=frozenset({"external:*"})),
    ))
    read_upload = RestrictedSequence("read-upload", (
        SequenceStep("read", result_classes=frozenset({"pd.*"})),
        SequenceStep("upload", resources=frozenset({"external:*"})),
    ))
    old = CompositionPolicy((read_send,), label_domain=DOMAIN)
    new = CompositionPolicy((read_send, read_upload), label_domain=DOMAIN)
    mhs = MissionHistoryService()
    old_pdp, new_pdp = CompositionPDP(old, mhs), CompositionPDP(new, mhs)
    # The first issuer's Mission starts under the old set.
    assert _run(old_pdp, mhs, "read", "kb/faq", frozenset({"public"}))
    mhs.designate(frozenset({new.digest}))
    # A Mission of its own is pinned to the new set, which denies the upload.
    assert _run(new_pdp, mhs, "read", "hr/1", frozenset({"pd.salary"}), mission="own")
    own = new_pdp.evaluate(_req("upload", "external:drop", "own"))
    assert (own.decision, own.reason) == (False, REASON_PROHIBITED_COMPOSITION)
    # The second issuer's Mission with the same id: the new set is refused,
    # the old set decides, and the upload runs without mission_record.
    assert new_pdp.evaluate(_req("read", "hr/1")).reason == REASON_POLICY_MISMATCH
    assert _run(old_pdp, mhs, "read", "hr/1", frozenset({"pd.salary"}))
    merged = old_pdp.evaluate(_req("upload", "external:drop"))
    assert merged.decision is True and not merged.obligations


def test_trust_domain_must_be_a_prefix_of_the_recorded_identifier() -> None:
    """Canonical identifiers: a bare email address puts the trust domain last,
    where a prefix pattern cannot see it. The profile requires the deployment's
    canonical form to put the classification first; recorded that way, the
    same send is caught."""
    seq = RestrictedSequence("s", (
        SequenceStep("read", result_classes=frozenset({"pd.*"})),
        SequenceStep("send", resources=frozenset({"external:*"})),
    ))
    for recorded, expected in (
        ("newsdesk@partner.example", (True, None)),
        ("external:newsdesk@partner.example", (False, REASON_PROHIBITED_COMPOSITION)),
    ):
        mhs = MissionHistoryService()
        pdp = CompositionPDP(CompositionPolicy((seq,), label_domain=DOMAIN), mhs)
        assert _run(pdp, mhs, "read", "hr/1", frozenset({"pd.salary"}))
        d = pdp.evaluate(_req("send", recorded))
        assert (d.decision, d.reason) == expected
