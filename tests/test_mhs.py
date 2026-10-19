"""MHS invariants: serializable admission, outcome transitions, writer auth."""

from __future__ import annotations

import contextlib
import threading
from typing import Any

import pytest

from authzen_composition.mhs import (
    MAX_CLASS_LENGTH,
    MAX_IDENTIFIER_LENGTH,
    MAX_RESULT_CLASSES,
    HistoryConflict,
    MissionHistoryService,
    OutcomeAlreadySet,
    UnauthenticatedWriter,
    UnknownAct,
)
from authzen_composition.model import ActOutcome


def test_two_writers_that_read_the_next_position_at_once_are_not_both_admitted() -> None:
    # History Authority item 2: admission is one linearizable step per
    # Mission. Two writers that both look up the Mission before either
    # appends must not both be admitted at position 1. The lookup waits for
    # the other writer to look up too, which makes the race certain where the
    # check and the append are separate steps: then both are acknowledged and
    # one record is lost. Under one step the second writer cannot look up
    # until the first has appended, the wait times out, and it conflicts.
    mhs = MissionHistoryService()
    barrier = threading.Barrier(2, timeout=0.5)
    lookups: list[str] = []

    class Rendezvous(dict[str, Any]):
        def get(self, key: str, default: Any = None) -> Any:
            value = super().get(key, default)
            lookups.append(key)
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait()
            return value

    mhs._missions = Rendezvous()
    results: list[object] = []

    def admit(writer: str) -> None:
        try:
            results.append(mhs.admit("m", 1, "read", "r", writer=writer))
        except HistoryConflict as exc:
            results.append(exc)

    threads = [threading.Thread(target=admit, args=(w,)) for w in ("pep.a", "pep.b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    # Both writers looked the Mission up, so the race was attempted.
    assert lookups == ["m", "m"]
    assert sorted(type(r).__name__ for r in results) == ["Act", "HistoryConflict"]
    assert [a.seq for a in mhs.history("m")] == [1]


def test_admit_requires_next_position() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="w")
    with pytest.raises(HistoryConflict):
        mhs.admit("m", 1, "a2", "r2", writer="w")  # race: position taken
    with pytest.raises(HistoryConflict):
        mhs.admit("m", 3, "a3", "r3", writer="w")  # gap
    mhs.admit("m", 2, "a2", "r2", writer="w")  # the loser re-evaluates and wins
    assert [a.seq for a in mhs.history("m")] == [1, 2]


def test_next_seq_tracks_length() -> None:
    mhs = MissionHistoryService()
    assert mhs.next_seq("m") == 1
    mhs.admit("m", 1, "a", "r", writer="w")
    assert mhs.next_seq("m") == 2


def test_outcome_transitions_once_and_from_open() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="w")
    mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w", result_classes=frozenset({"c"}))
    assert mhs.history("m")[0].result_classes == frozenset({"c"})
    with pytest.raises(OutcomeAlreadySet):
        mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w")


def test_failed_outcome_carries_no_classes() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="w")
    with pytest.raises(ValueError):
        mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w", result_classes=frozenset({"c"}))
    act = mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w")
    assert act.result_classes == frozenset()


def test_an_empty_result_class_is_rejected() -> None:
    # A result class names a category; an empty string names none.
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="w")
    with pytest.raises(ValueError):
        mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w", result_classes=frozenset({""}))


def test_set_outcome_to_open_is_rejected() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="w")
    with pytest.raises(OutcomeAlreadySet):
        mhs.set_outcome("m", 1, ActOutcome.OPEN, writer="w")


def test_set_outcome_unknown_act() -> None:
    mhs = MissionHistoryService()
    with pytest.raises(UnknownAct):
        mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w")


def test_writer_must_be_named() -> None:
    mhs = MissionHistoryService()
    with pytest.raises(UnauthenticatedWriter):
        mhs.admit("m", 1, "a", "r", writer="")


def test_untrusted_writer_rejected_when_trust_set_configured() -> None:
    mhs = MissionHistoryService(trusted_writers=frozenset({"pep.hr"}))
    mhs.admit("m", 1, "a", "r", writer="pep.hr")
    with pytest.raises(UnauthenticatedWriter):
        mhs.admit("m", 2, "a", "r", writer="pep.evil")


def test_recorded_by_identity() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="pep.hr")
    assert mhs.recorded_by("m", 1) == "pep.hr"
    with pytest.raises(UnknownAct):
        mhs.recorded_by("m", 2)


@pytest.mark.parametrize("action, resource", [("", "r"), ("a", ""), (None, "r"), ("a", 7)])
def test_admit_refuses_an_action_or_resource_that_is_not_a_non_empty_string(
        action: object, resource: object) -> None:
    # Profile, History Authority: an Act Record holds the action name and the
    # canonical resource identifier, each a non-empty string.
    mhs = MissionHistoryService()
    with pytest.raises(ValueError):
        mhs.admit("m", 1, action, resource, writer="w")  # type: ignore[arg-type]
    assert mhs.next_seq("m") == 1


@pytest.mark.parametrize("mission_id, admission_id", [("", None), ("m", ""), (7, None)])
def test_admit_refuses_an_empty_mission_or_admission_id(mission_id: object,
                                                        admission_id: object) -> None:
    mhs = MissionHistoryService()
    with pytest.raises(ValueError):
        mhs.admit(mission_id, 1, "a", "r", writer="w", admission_id=admission_id)


def test_a_result_class_that_is_not_a_string_is_refused() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="w")
    with pytest.raises(ValueError):
        mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w", result_classes=frozenset({7}))


@pytest.mark.parametrize("field", ["mission", "action", "resource", "admission_id"])
def test_an_identifier_longer_than_the_bound_is_refused(field: str) -> None:
    # Profile, Security considerations (Input size): a History Authority
    # bounds the length of the identifiers it records.
    mhs = MissionHistoryService()
    args = {"mission": "m", "action": "a", "resource": "r", "admission_id": "x"}
    args[field] = "z" * (MAX_IDENTIFIER_LENGTH + 1)
    with pytest.raises(ValueError):
        mhs.admit(args["mission"], 1, args["action"], args["resource"], writer="w",
                  admission_id=args["admission_id"])
    args[field] = "z" * MAX_IDENTIFIER_LENGTH
    assert mhs.admit(args["mission"], 1, args["action"], args["resource"], writer="w",
                     admission_id=args["admission_id"]).seq == 1


def test_result_classes_beyond_the_bound_are_refused() -> None:
    mhs = MissionHistoryService()
    for seq in (1, 2):
        mhs.admit("m", seq, "a", "r", writer="w")
    with pytest.raises(ValueError):
        mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w", result_classes=frozenset(
            f"c{i}" for i in range(MAX_RESULT_CLASSES + 1)))
    with pytest.raises(ValueError):
        mhs.set_outcome("m", 1, ActOutcome.COMPLETED, writer="w",
                        result_classes=frozenset({"c" * (MAX_CLASS_LENGTH + 1)}))
    assert mhs.set_outcome("m", 2, ActOutcome.COMPLETED, writer="w", result_classes=frozenset(
        f"c{i}" for i in range(MAX_RESULT_CLASSES))).outcome is ActOutcome.COMPLETED


def test_a_mission_holds_at_most_its_bound_of_acts() -> None:
    # Profile, Security considerations (Availability): a Mission's length is
    # bounded, so that every read of its history stays within what a PDP
    # will read.
    mhs = MissionHistoryService(max_acts=3)
    for seq in (1, 2, 3):
        mhs.admit("m", seq, "a", "r", writer="w")
    with pytest.raises(ValueError):
        mhs.admit("m", 4, "a", "r", writer="w")
    assert [a.seq for a in mhs.history("m")] == [1, 2, 3]


def test_a_refused_admission_leaves_no_trace_of_the_mission() -> None:
    mhs = MissionHistoryService()
    with pytest.raises(HistoryConflict):
        mhs.admit("never", 2, "a", "r", writer="w")
    assert "never" not in mhs._missions
