"""Model-level tests: matching, conservative top, policy, edge cases."""

from __future__ import annotations

import pytest

from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
    _completes,
    _glob_match,
)


def test_glob_match_variants() -> None:
    assert _glob_match("*", "anything")
    assert _glob_match("anything", "*")
    assert _glob_match("a.*", "a.b")
    assert not _glob_match("a.*", "b.a")
    assert _glob_match("exact", "exact")
    assert not _glob_match("exact", "other")


def test_effective_classes_conservative_top() -> None:
    assert Act(1, "a", "r").effective_classes() == frozenset({"*"})  # open
    done_no_class = Act(1, "a", "r", outcome=ActOutcome.COMPLETED)
    assert done_no_class.effective_classes() == frozenset({"*"})
    done = Act(1, "a", "r", outcome=ActOutcome.COMPLETED, result_classes=frozenset({"x"}))
    assert done.effective_classes() == frozenset({"x"})


def test_step_matches_resource_and_class() -> None:
    step = SequenceStep("read", frozenset({"hr:*"}), frozenset({"personal_data.*"}))
    good = Act(1, "read", "hr:1", ActOutcome.COMPLETED, frozenset({"personal_data.salary"}))
    assert step.matches(good)
    wrong_res = Act(1, "read", "fin:1", ActOutcome.COMPLETED, frozenset({"personal_data.salary"}))
    assert not step.matches(wrong_res)
    wrong_cls = Act(1, "read", "hr:1", ActOutcome.COMPLETED, frozenset({"public"}))
    assert not step.matches(wrong_cls)
    wrong_action = Act(1, "write", "hr:1", ActOutcome.COMPLETED, frozenset({"personal_data.x"}))
    assert not step.matches(wrong_action)


def test_sequence_needs_two_steps() -> None:
    with pytest.raises(ValueError):
        RestrictedSequence("x", (SequenceStep("a"),))


def test_sequence_k_property() -> None:
    seq = RestrictedSequence("x", (SequenceStep("a"), SequenceStep("b")))
    assert seq.k == 2


def test_completes_requires_ordered_prefix() -> None:
    seq = RestrictedSequence("x", (SequenceStep("a"), SequenceStep("b"), SequenceStep("c")))
    history = [Act(1, "a", "r"), Act(2, "b", "r")]
    assert _completes(history, Act(3, "c", "r"), seq)
    # candidate does not match the final step
    assert not _completes(history, Act(3, "d", "r"), seq)
    # prefix incomplete
    assert not _completes([Act(1, "a", "r")], Act(2, "c", "r"), seq)


def test_policy_completes_and_requestable() -> None:
    seq = RestrictedSequence(
        "x", (SequenceStep("a"), SequenceStep("b")), requestable=True
    )
    policy = CompositionPolicy((seq,))
    v = policy.completes([Act(1, "a", "r")], Act(2, "b", "r"))
    assert not v.satisfied
    assert v.completed == ("x",)
    assert v.requestable
    ok = policy.completes([], Act(1, "a", "r"))
    assert ok.satisfied


def test_can_extend_prefix() -> None:
    seq = RestrictedSequence("x", (SequenceStep("a"), SequenceStep("b")))
    policy = CompositionPolicy((seq,))
    assert policy.can_extend_prefix(Act(1, "a", "r"))   # matches first step
    assert policy.can_extend_prefix(Act(2, "b", "r"))   # final step, even with no prefix
    assert not policy.can_extend_prefix(Act(1, "z", "r"))  # unrelated action


def test_unrecognized_result_class_becomes_top() -> None:
    # Step requires personal_data.*; an act completed with an UNKNOWN class is
    # treated as the conservative top, so it still matches.
    seq = RestrictedSequence("x", (
        SequenceStep("read", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send"),
    ))
    policy = CompositionPolicy((seq,))
    unknown = Act(1, "read", "r", ActOutcome.COMPLETED, frozenset({"mystery.unknown"}))
    v = policy.completes([unknown], Act(2, "send", "r"))
    assert not v.satisfied


def test_recognized_result_class_is_kept() -> None:
    seq = RestrictedSequence("x", (
        SequenceStep("read", result_classes=frozenset({"personal_data.*"})),
        SequenceStep("send"),
    ))
    # 'public' is made "recognized" by appearing in a second sequence's vocab.
    seq2 = RestrictedSequence("y", (
        SequenceStep("noop", result_classes=frozenset({"public"})),
        SequenceStep("noop2"),
    ))
    policy = CompositionPolicy((seq, seq2))
    public = Act(1, "read", "r", ActOutcome.COMPLETED, frozenset({"public"}))
    v = policy.completes([public], Act(2, "send", "r"))
    assert v.satisfied  # 'public' recognized, does not match personal_data.*


def test_non_requestable_completion() -> None:
    seq = RestrictedSequence("x", (SequenceStep("a"), SequenceStep("b")))  # requestable=False
    policy = CompositionPolicy((seq,))
    v = policy.completes([Act(1, "a", "r")], Act(2, "b", "r"))
    assert not v.satisfied
    assert not v.requestable


def test_a_set_that_would_recognize_every_class_is_refused() -> None:
    # Profile, Result classes: a `*` class pattern, named by a step or in a
    # declared label domain, would put every class in the label domain, so no
    # class would be the conservative top, whatever the other sequences need.
    any_class = RestrictedSequence("any", (SequenceStep("read", result_classes=frozenset({"*"})),
                                           SequenceStep("send")))
    with pytest.raises(ValueError):
        CompositionPolicy((any_class,))
    plain = RestrictedSequence("plain", (SequenceStep("read"), SequenceStep("send")))
    with pytest.raises(ValueError):
        CompositionPolicy((plain,), label_domain=frozenset({"pd.*", "*"}))
    CompositionPolicy((plain,), label_domain=frozenset({"pd*"}))
