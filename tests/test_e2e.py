"""The end-to-end deployment (separate processes over HTTP) and the
false-positive study, run as part of the suite."""

from __future__ import annotations

from pathlib import Path

from e2e import fp_study, run_e2e
from e2e.tools import exposures


def test_every_scenario_passes_across_processes_and_nothing_leaks(tmp_path: Path) -> None:
    results, leaks, approved = run_e2e.run(tmp_path)
    failed = [(r.id, r.detail) for r in results if not r.passed]
    assert not failed
    assert len(results) == len(run_e2e.SCENARIOS)
    assert leaks == []
    assert approved == 1  # the one send a person approved in A1


def test_the_oracle_catches_a_pdp_without_the_effect_order_rule(tmp_path: Path) -> None:
    # Red check: with rule 5 switched off, the queued send by reference
    # carries the salary out (A4), across real processes.
    results, leaks, _ = run_e2e.run(tmp_path, sabotage="no_rule5", only={"A4"})
    assert leaks and all(leak["host"] == "pep.mail_manual" for leak in leaks)
    # The leak is attributed to the scenario, which then fails.
    assert [r.passed for r in results] == [False]


def test_the_oracle_does_not_take_the_approved_flag_on_trust() -> None:
    leak = {"kind": "expose", "audience": "external", "mission": "m1",
            "target": "external:press", "attachment": "doc-1",
            "content": "CANARY-emp-1-ab12", "approved": True}
    # Logged as approved, but no person granted anything: still a leak.
    assert exposures([leak]) == [leak]
    assert exposures([leak], frozenset({("m1", "external:other", "doc-1")})) == [leak]
    assert exposures([leak], frozenset({("m2", "external:press", "doc-1")})) == [leak]
    # A person approved another attachment to the same recipient: still a leak.
    assert exposures([leak], frozenset({("m1", "external:press", "doc-2")})) == [leak]
    assert exposures([leak], frozenset({("m1", "external:press", "doc-1")})) == []
    assert exposures([{**leak, "audience": "internal"}]) == []
    assert exposures([{**leak, "content": "no canary"}]) == []


# The matrix, pinned: a change in any cell is a change in behavior.
EXPECTED = {
    "T1": ["TN", "TN", "TN", "TN", "TN", "TN"],
    "T2": ["TN", "TN", "TN", "TN", "FP*", "TN"],
    "T3": ["FP*", "FP*", "TN", "FP*", "FP*", "FP*"],
    "T4": ["FP*", "FP*", "TN", "TN", "FP*", "FP*"],
    "T5": ["FP*", "FP*", "TN", "FP*", "FP*", "FP*"],
    "T6": ["TN", "TN", "TN", "TN", "TN", "TN"],
    "M1": ["TP", "TP", "FN", "TP", "TP", "TP"],
    "M2": ["TP", "FN", "TP", "TP", "TP", "TP"],
    "M3": ["TP", "TP", "FN", "TP", "TP", "FN"],
    "M4": ["TP", "TP", "FN", "TP", "TP", "TP"],
    "M5": ["TP", "TP", "FN", "FN", "TP", "TP"],
}


def test_false_positive_matrix() -> None:
    got = {tid: cells for tid, _, cells in fp_study.matrix()}
    assert got == EXPECTED
    recommended = [cells[0] for cells in got.values()]
    # The recommended policy misses no attack and never hard-blocks legitimate
    # work: every false positive can be approved by a person.
    assert "FN" not in recommended and "FP" not in recommended
